//! Signed migration through the production handler, including same-block retirement and rollback.
use super::*;
use alloy_evm::FromRecoveredTx;
use alloy_primitives::{Bytes, aliases::U96, keccak256};
use alloy_sol_types::SolEvent;
use revm::context::result::EVMError;
use std::num::NonZeroU64;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, ITIP20, ITIP20ChannelReserve, TIP20_CHANNEL_RESERVE_ADDRESS,
};
use tempo_precompiles::tip20_channel_reserve::TIP20ChannelReserve;
use tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;
use tempo_revm::{
    ExecutionContext, TempoInvalidTransaction, TempoTxEnv, native_multisig::NativeMultisigError,
};

fn fixture() -> Fixture {
    let mut f = Fixture::with_parent(false);
    f.evm.ctx_mut().block.account_migration_enabled = true;
    f.config.version = 1;
    f.config.salt =
        keccak256([b"tempo:multisig:upgrade".as_slice(), f.account.as_slice()].concat());
    f
}

fn upgrade(f: &Fixture) -> Call {
    Call {
        to: NATIVE_MULTISIG_ADDRESS.into(),
        value: U256::ZERO,
        input: INativeMultisig::upgradeAccountCall {
            threshold: f.config.threshold,
            owners: f
                .config
                .owners
                .iter()
                .map(|owner| INativeMultisig::MultisigOwner {
                    owner: owner.owner,
                    weight: owner.weight,
                })
                .collect(),
        }
        .abi_encode()
        .into(),
    }
}

fn root_signed(f: &Fixture, nonce: u64, gas_limit: u64, calls: Vec<Call>) -> AASigned {
    let tx = TempoTransaction {
        chain_id: 1,
        nonce,
        gas_limit,
        calls,
        ..Default::default()
    };
    let signature = f.owner.sign_hash_sync(&tx.signature_hash()).unwrap();
    tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        signature,
    )))
}

#[test]
fn migration_runtime_same_block_root_retirement_and_explicit_owner_signing() {
    let mut f = fixture();
    let block = f.evm.ctx_mut().block.clone();
    let tx = root_signed(&f, 3, 1_000_000, vec![upgrade(&f)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(
        INativeMultisig::upgradeAccountCall::abi_decode_returns(output.result.output().unwrap())
            .unwrap(),
        f.config.commitment().unwrap()
    );
    assert_eq!(output.state[&f.account].info.balance, U256::from(42));
    f.evm.db_mut().commit(output.state);
    let old_root = root_signed(&f, 4, 1_000_000, vec![f.getter()]);
    let error = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&old_root, f.account))
        .unwrap_err();
    assert_eq!(
        error,
        EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
            NativeMultisigError::RootKeyRetired { account: f.account }
        ))
    );
    let tx = f.signed(4, vec![f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    assert_eq!(f.evm.ctx_mut().block.timestamp, block.timestamp);
    assert_eq!(f.evm.ctx_mut().block.number, block.number);
}

#[test]
fn migration_runtime_out_of_gas_rolls_back_commitment_and_event_not_nonce() {
    let mut probe = fixture();
    let tx = root_signed(&probe, 3, 1_000_000, vec![upgrade(&probe)]);
    let output = probe
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, probe.account))
        .unwrap();
    assert!(output.result.is_success());
    let used = output.result.tx_gas_used();
    let mut f = fixture();
    let tx = root_signed(&f, 3, used - 1, vec![upgrade(&f)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(!output.result.is_success(), "{:?}", output.result);
    assert_eq!(
        decode_config_commitment(&output.state[&f.account].info.extension, true).unwrap(),
        B256::ZERO
    );
    assert_eq!(output.state[&f.account].info.nonce, 4);
    assert!(
        output
            .result
            .logs()
            .iter()
            .all(|log| log.address != NATIVE_MULTISIG_ADDRESS)
    );
    f.evm.db_mut().commit(output.state);
    let retry = root_signed(&f, 4, 1_000_000, vec![upgrade(&f)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&retry, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
}

#[test]
fn migration_runtime_simulation_is_noncommitting_and_does_not_seed_next_transaction() {
    let mut f = fixture();
    let tx = root_signed(&f, 3, 1_000_000, vec![upgrade(&f)]);
    let mut env = TempoTxEnv::from_recovered_tx(&tx, f.account);
    env.execution_context = ExecutionContext::Simulation;
    let output = f.evm.transact(env).unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    // RPC callers discard state. The next transaction must authenticate its own context.
    assert_eq!(f.commitment(), B256::ZERO);
    let delegated = f.signed(3, vec![upgrade(&f)]);
    let error = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&delegated, f.account))
        .unwrap_err();
    assert!(matches!(
        error,
        EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
            NativeMultisigError::InvalidAccount { .. }
        ))
    ));
    assert_eq!(f.commitment(), B256::ZERO);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
}

#[test]
fn migration_runtime_charges_empty_leaf_once_for_2d_and_expiring_nonces() {
    let gas = tempo_gas_params(TempoHardfork::T14);
    let creation_cost = gas.get(revm::context_interface::cfg::GasId::new_account_cost())
        + gas.new_account_state_gas();
    for (nonce_key, nonce) in [
        (U256::from(7), 0),
        (U256::from(7), 1),
        (TEMPO_EXPIRING_NONCE_KEY, 0),
    ] {
        let execute = |empty| {
            let mut f = fixture();
            // Model the genesis precompile account so EIP-161 does not clear
            // the nonce-manager storage in this otherwise-empty database.
            f.evm.db_mut().insert_account(
                tempo_precompiles::NONCE_PRECOMPILE_ADDRESS,
                AccountInfo {
                    nonce: 1,
                    ..Default::default()
                },
            );
            if nonce != 0 {
                StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
                    tempo_precompiles::nonce::NonceManager::new()
                        .increment_nonce(f.account, nonce_key)
                })
                .unwrap();
                let state = f.evm.ctx_mut().journaled_state.finalize();
                f.evm.db_mut().commit(state);
            }
            let mut account = Account::new_not_existing(TransactionId::ZERO);
            account.info.nonce = 0;
            account.info.balance = if empty { U256::ZERO } else { U256::from(42) };
            account.mark_touch();
            f.evm
                .db_mut()
                .commit([(f.account, account)].into_iter().collect());
            let tx = TempoTransaction {
                chain_id: 1,
                nonce,
                nonce_key,
                valid_before: (nonce_key == TEMPO_EXPIRING_NONCE_KEY)
                    .then(|| NonZeroU64::new(60).unwrap()),
                gas_limit: 1_000_000,
                calls: vec![upgrade(&f)],
                ..Default::default()
            };
            let signature = f.owner.sign_hash_sync(&tx.signature_hash()).unwrap();
            let tx = tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                signature,
            )));
            let output = f
                .evm
                .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
                .unwrap();
            assert!(output.result.is_success(), "{:?}", output.result);
            assert_eq!(output.state[&f.account].info.nonce, 0);
            assert_eq!(
                decode_config_commitment(&output.state[&f.account].info.extension, true).unwrap(),
                f.config.commitment().unwrap()
            );
            output.result.tx_gas_used()
        };
        let funded_leaf_gas = execute(false);
        let empty_leaf_gas = execute(true);
        assert_eq!(
            empty_leaf_gas - funded_leaf_gas,
            if nonce_key == TEMPO_EXPIRING_NONCE_KEY || nonce != 0 {
                creation_cost
            } else {
                0
            },
            "account creation charge for nonce key {nonce_key}, nonce {nonce}"
        );
    }
}

#[test]
fn migration_runtime_presigned_funded_voucher_remains_redeemable() {
    let mut f = fixture();
    let payee = PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
    let token = StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20ChannelReserve::new().initialize()?;
        TIP20Setup::path_usd(f.account)
            .with_issuer(f.account)
            .with_mint(f.account, U256::from(1_000))
            .apply()
    })
    .unwrap();
    let state = f.evm.ctx_mut().journaled_state.finalize();
    f.evm.db_mut().commit(state);
    let tx = root_signed(
        &f,
        3,
        1_000_000,
        vec![Call {
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
    );
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    let opened = output
        .result
        .logs()
        .iter()
        .find_map(|log| ITIP20ChannelReserve::ChannelOpened::decode_log(log).ok())
        .unwrap()
        .data;
    f.evm.db_mut().commit(output.state);
    let cumulative = U96::from(120);
    let digest = StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20ChannelReserve::new().get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
            channelId: opened.channelId,
            cumulativeAmount: cumulative,
        })
    })
    .unwrap();
    let state = f.evm.ctx_mut().journaled_state.finalize();
    f.evm.db_mut().commit(state);
    let voucher = Bytes::from(f.owner.sign_hash_sync(&digest).unwrap().as_bytes());
    let tx = root_signed(&f, 4, 1_000_000, vec![upgrade(&f)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    f.evm.db_mut().commit(output.state);
    let tx = root_signed(&f, 5, 1_000_000, vec![f.getter()]);
    assert_eq!(
        f.evm
            .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
            .unwrap_err(),
        EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
            NativeMultisigError::RootKeyRetired { account: f.account }
        ))
    );
    let tx = TempoTransaction {
        chain_id: 1,
        nonce: 0,
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TIP20_CHANNEL_RESERVE_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIP20ChannelReserve::settleCall {
                descriptor: ITIP20ChannelReserve::ChannelDescriptor {
                    payer: f.account,
                    payee: payee.address(),
                    operator: Address::ZERO,
                    token: DEFAULT_FEE_TOKEN,
                    salt: opened.salt,
                    authorizedSigner: Address::ZERO,
                    expiringNonceHash: opened.expiringNonceHash,
                },
                cumulativeAmount: cumulative,
                signature: voucher,
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    };
    let signature = payee.sign_hash_sync(&tx.signature_hash()).unwrap();
    let tx = tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        signature,
    )));
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, payee.address()))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    f.evm.db_mut().commit(output.state);
    let received = StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        token.balance_of(ITIP20::balanceOfCall {
            account: payee.address(),
        })
    })
    .unwrap();
    assert_eq!(received, U256::from(120));
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
}
