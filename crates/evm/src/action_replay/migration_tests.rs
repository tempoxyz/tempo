//! Replay must observe account migrations committed after parent-state prewarming.

use super::*;
use crate::test_utils::{TestExecutorBuilder, test_chainspec};
use alloy_evm::{FromRecoveredTx, block::TxResult};
use alloy_primitives::{Bytes, Signature, aliases::U96};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolEvent;
use reth_primitives_traits::Recovered;
use revm::{DatabaseCommit, context::JournalTr, state::AccountInfo};
use tempo_chainspec::TempoHardfork;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, INativeMultisig, ITIP20, ITIP20ChannelReserve, TIP20_CHANNEL_RESERVE_ADDRESS,
};
use tempo_precompiles::{
    account_keychain::AccountKeychain,
    storage::{StorageActions, StorageCtx},
    test_util::TIP20Setup,
    tip20_channel_reserve::TIP20ChannelReserve,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::{TempoTransaction, transaction::Call};
use tempo_revm::{TempoInvalidTransaction, TempoTxEnv, native_multisig::NativeMultisigError};

#[test]
fn replay_rejects_same_block_caller_and_sponsor_migration_without_committing() {
    for sponsored in [false, true] {
        let root = PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap();
        let other = PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
        let sender = if sponsored { &other } else { &root };
        let chainspec = test_chainspec();
        let mut db = State::builder().with_bundle_update().build();
        db.insert_account(
            root.address(),
            AccountInfo {
                nonce: 3,
                ..Default::default()
            },
        );
        db.insert_account(
            NONCE_PRECOMPILE_ADDRESS,
            AccountInfo {
                nonce: 1,
                ..Default::default()
            },
        );
        let mut executor = TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T14)
            .with_actions()
            .build(&mut db, &chainspec);
        executor.inner.evm.ctx_mut().cfg.chain_id = 1;
        executor.inner.evm.ctx_mut().block.account_migration_enabled = true;
        executor.inner.evm.ctx_mut().block.multisig_recovery_factory =
            Some(Address::repeat_byte(0x71));
        StorageCtx::enter_ctx(
            executor.inner.evm.ctx_mut(),
            StorageActions::disabled(),
            || {
                TIP403Registry::new().initialize()?;
                AccountKeychain::new().initialize()?;
                TIP20Setup::path_usd(root.address())
                    .with_issuer(root.address())
                    .with_mint(root.address(), U256::from(1_000_000_000_000u64))
                    .apply()
            },
        )
        .unwrap();
        let state = executor.inner.evm.ctx_mut().journaled_state.finalize();
        executor.inner.evm.db_mut().commit(state);
        let recipient = Address::repeat_byte(0x77);
        let mut payment = TempoTransaction {
            chain_id: 1,
            nonce_key: U256::from(7),
            gas_limit: 1_000_000,
            max_fee_per_gas: 1,
            fee_payer_signature: sponsored.then(Signature::test_signature),
            calls: vec![Call {
                to: DEFAULT_FEE_TOKEN.into(),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: recipient,
                    amount: U256::ONE,
                }
                .abi_encode()
                .into(),
            }],
            ..Default::default()
        };
        if sponsored {
            StorageCtx::enter_ctx(
                executor.inner.evm.ctx_mut(),
                StorageActions::disabled(),
                || {
                    TIP20Setup::path_usd(root.address())
                        .with_issuer(root.address())
                        .with_mint(sender.address(), U256::from(1_000_000_000_000u64))
                        .apply()
                },
            )
            .unwrap();
            let state = executor.inner.evm.ctx_mut().journaled_state.finalize();
            executor.inner.evm.db_mut().commit(state);
            payment.fee_payer_signature = Some(
                root.sign_hash_sync(&payment.fee_payer_signature_hash(sender.address()))
                    .unwrap(),
            );
        }
        let signature = sender.sign_hash_sync(&payment.signature_hash()).unwrap();
        let payment = TempoTxEnvelope::AA(payment.into_signed(signature.into()));
        assert!(supports_storage_action_replay(&payment));
        let output = executor
            .inner
            .evm
            .transact(TempoTxEnv::from_recovered_tx(&payment, sender.address()))
            .unwrap();
        assert!(
            output.result.is_success(),
            "prewarming: {:?}",
            output.result
        );
        let replay = StorageActionReplay {
            result: output.result,
            actions: executor.inner.evm.take_actions().unwrap(),
            expiring_nonce: None,
            validator_fee: executor.inner.evm.validator_fee(),
        };
        let migration = TempoTransaction {
            chain_id: 1,
            nonce: 3,
            gas_limit: 1_000_000,
            max_fee_per_gas: 1,
            calls: vec![Call {
                to: NATIVE_MULTISIG_ADDRESS.into(),
                value: U256::ZERO,
                input: INativeMultisig::upgradeAccountCall {
                    threshold: 1,
                    owners: vec![INativeMultisig::MultisigOwner {
                        owner: root.address(),
                        weight: 1,
                    }],
                }
                .abi_encode()
                .into(),
            }],
            ..Default::default()
        };
        let signature = root.sign_hash_sync(&migration.signature_hash()).unwrap();
        let migration = migration.into_signed(signature.into());
        let output = executor
            .inner
            .evm
            .transact(TempoTxEnv::from_recovered_tx(&migration, root.address()))
            .unwrap();
        assert!(output.result.is_success(), "migration: {:?}", output.result);
        executor.inner.evm.db_mut().commit(output.state);
        let env = TempoTxEnv::from_recovered_tx(&payment, sender.address());
        assert_eq!(
            executor.inner.evm.transact(env.clone()).unwrap_err(),
            revm::context::result::EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
                NativeMultisigError::RootKeyRetired {
                    account: root.address()
                }
            ))
        );
        let recovered = Recovered::new_unchecked(payment, sender.address());
        let error = executor
            .execute_transaction_with_actions((env, &recovered), replay, |_| {
                panic!("invalid replay must not be observed or committed")
            })
            .unwrap_err();
        assert_eq!(
            StorageActionReplayError::from_block_execution_error(&error),
            Some(StorageActionReplayError::UnsupportedAuthorization)
        );
        assert!(executor.replay_state.tx_changes.is_empty());
        assert!(executor.receipts().is_empty());
    }
}

#[test]
fn replay_and_serial_settlement_agree_after_funded_voucher_signer_migration() {
    let root = PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap();
    let payee = PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
    let chainspec = test_chainspec();
    let mut db = State::builder().with_bundle_update().build();
    for address in [root.address(), NONCE_PRECOMPILE_ADDRESS] {
        db.insert_account(
            address,
            AccountInfo {
                nonce: 1,
                ..Default::default()
            },
        );
    }
    let mut executor = TestExecutorBuilder::default()
        .with_spec(TempoHardfork::T14)
        .with_actions()
        .build(&mut db, &chainspec);
    executor.inner.evm.ctx_mut().cfg.chain_id = 1;
    executor.inner.evm.ctx_mut().block.basefee = 0;
    executor.inner.evm.ctx_mut().block.account_migration_enabled = true;
    executor.inner.evm.ctx_mut().block.multisig_recovery_factory = Some(Address::repeat_byte(0x71));
    StorageCtx::enter_ctx(
        executor.inner.evm.ctx_mut(),
        StorageActions::disabled(),
        || {
            TIP403Registry::new().initialize()?;
            AccountKeychain::new().initialize()?;
            TIP20ChannelReserve::new().initialize()?;
            TIP20Setup::path_usd(root.address())
                .with_issuer(root.address())
                .with_mint(root.address(), U256::from(1_000))
                .apply()
        },
    )
    .unwrap();
    let state = executor.inner.evm.ctx_mut().journaled_state.finalize();
    executor.inner.evm.db_mut().commit(state);
    let open = TempoTransaction {
        chain_id: 1,
        nonce: 1,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TIP20_CHANNEL_RESERVE_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIP20ChannelReserve::openCall {
                payee: payee.address(),
                operator: Address::ZERO,
                token: DEFAULT_FEE_TOKEN,
                deposit: U96::from(300),
                salt: B256::repeat_byte(0x77),
                authorizedSigner: Address::ZERO,
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    };
    let signature = root.sign_hash_sync(&open.signature_hash()).unwrap();
    let open = open.into_signed(signature.into());
    let output = executor
        .inner
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&open, root.address()))
        .unwrap();
    assert!(output.result.is_success());
    let opened = output
        .result
        .logs()
        .iter()
        .find_map(|log| ITIP20ChannelReserve::ChannelOpened::decode_log(log).ok())
        .unwrap()
        .data;
    executor.inner.evm.db_mut().commit(output.state);
    let cumulative = U96::from(120);
    let digest = StorageCtx::enter_ctx(
        executor.inner.evm.ctx_mut(),
        StorageActions::disabled(),
        || {
            TIP20ChannelReserve::new().get_voucher_digest(
                ITIP20ChannelReserve::getVoucherDigestCall {
                    channelId: opened.channelId,
                    cumulativeAmount: cumulative,
                },
            )
        },
    )
    .unwrap();
    let state = executor.inner.evm.ctx_mut().journaled_state.finalize();
    executor.inner.evm.db_mut().commit(state);
    let settle = TempoTransaction {
        chain_id: 1,
        nonce_key: U256::from(7),
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TIP20_CHANNEL_RESERVE_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIP20ChannelReserve::settleCall {
                descriptor: ITIP20ChannelReserve::ChannelDescriptor {
                    payer: root.address(),
                    payee: payee.address(),
                    operator: Address::ZERO,
                    token: DEFAULT_FEE_TOKEN,
                    salt: opened.salt,
                    authorizedSigner: Address::ZERO,
                    expiringNonceHash: opened.expiringNonceHash,
                },
                cumulativeAmount: cumulative,
                signature: Bytes::from(root.sign_hash_sync(&digest).unwrap().as_bytes()),
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    };
    let signature = payee.sign_hash_sync(&settle.signature_hash()).unwrap();
    let settle = TempoTxEnvelope::AA(settle.into_signed(signature.into()));
    assert!(supports_storage_action_replay(&settle));
    executor.inner.evm.clear_actions();
    let output = executor
        .inner
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&settle, payee.address()))
        .unwrap();
    assert!(output.result.is_success());
    let replay = StorageActionReplay {
        result: output.result,
        actions: executor.inner.evm.take_actions().unwrap(),
        expiring_nonce: None,
        validator_fee: executor.inner.evm.validator_fee(),
    };
    let migration = TempoTransaction {
        chain_id: 1,
        nonce: 2,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: NATIVE_MULTISIG_ADDRESS.into(),
            value: U256::ZERO,
            input: INativeMultisig::upgradeAccountCall {
                threshold: 1,
                owners: vec![INativeMultisig::MultisigOwner {
                    owner: root.address(),
                    weight: 1,
                }],
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    };
    let signature = root.sign_hash_sync(&migration.signature_hash()).unwrap();
    let migration = migration.into_signed(signature.into());
    let output = executor
        .inner
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&migration, root.address()))
        .unwrap();
    assert!(output.result.is_success());
    executor.inner.evm.db_mut().commit(output.state);
    let env = TempoTxEnv::from_recovered_tx(&settle, payee.address());
    let serial = executor.inner.evm.transact(env.clone()).unwrap();
    assert!(
        serial.result.is_success(),
        "funded voucher authority survives migration"
    );
    assert_eq!(replay.result.logs(), serial.result.logs());
    let recovered = Recovered::new_unchecked(settle, payee.address());
    executor
        .execute_transaction_with_actions((env, &recovered), replay, |result| {
            assert!(result.result().result.is_success());
            assert_eq!(result.result().result.logs(), serial.result.logs());
        })
        .unwrap();
    for (address, account) in serial.state {
        for (key, slot) in account.storage {
            if slot.is_changed() {
                assert_eq!(
                    executor.inner.evm.db_mut().storage(address, key).unwrap(),
                    slot.present_value()
                );
            }
        }
    }
    assert_eq!(executor.receipts().len(), 1);
}
