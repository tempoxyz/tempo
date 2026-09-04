//! Opt-in checked replay for incoming native-payment blocks.

use crate::{
    ExpiringNonceReplay, StorageActionReplay, TempoBlockExecutionCtx, TempoBlockExecutor, TempoEvm,
    TempoEvmConfig, TempoEvmEnv, TempoTxEnv, record_storage_action_replay,
};
use alloy_consensus::transaction::Recovered;
use reth_evm::{
    BlockExecutionError, BlockExecutor, ExecutableTxParts, ExecutorTx, GasOutput, RecoveredTx,
    execute::PrewarmExecution,
};
use reth_evm_ethereum::EthBlockExecutionCtx;
use std::borrow::Cow;
use tempo_primitives::TempoTxEnvelope;

/// Owned block context for independent worker initialization. Tempo forbids ommers.
#[derive(Debug, Clone)]
pub struct TempoPrewarmContext(TempoBlockExecutionCtx<'static>);

fn eligible(tx: &TempoTxEnvelope) -> bool {
    !tx.is_system_tx()
        && tx.subblock_proposer().is_none()
        && tx.is_payment_v2()
        && tx.nonce_key().is_some_and(|key| !key.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
    use alloy_sol_types::SolCall;
    use evm2::evm::{AccountInfo, InMemoryDB};
    use reth_evm::{BlockExecutorFactory, Database};
    use tempo_chainspec::{TempoHardfork, spec::DEV};
    use tempo_precompiles::{
        PATH_USD_ADDRESS, storage::StorageCtx, test_util::TIP20Setup, tip20::ITIP20,
    };
    use tempo_primitives::transaction::{
        AASigned, Call, PrimitiveSignature, TempoSignature, TempoTransaction,
    };

    fn fixture() -> (
        TempoEvmConfig,
        TempoEvmEnv,
        TempoBlockExecutionCtx<'static>,
        InMemoryDB,
        Address,
    ) {
        let chain = DEV.clone();
        let sender = Address::repeat_byte(1);
        let mut seed = crate::test_utils::TestExecutorBuilder::default()
            .with_spec(TempoHardfork::T12)
            .with_epoch_length(1000)
            .build(InMemoryDB::default(), &chain);
        let evm = seed.evm_mut();
        for (address, _) in tempo_contracts::precompiles::SYSTEM_PRECOMPILES {
            evm.overlay_db_mut().insert_account_info(
                address,
                AccountInfo::default().with_code(evm2::bytecode::Bytecode::new_raw(
                    Bytes::from_static(&[0xef]),
                )),
            );
        }
        StorageCtx::enter_evm_without_tip1060_accounting(evm, || {
            TIP20Setup::path_usd(sender)
                .with_issuer(sender)
                .with_mint(sender, U256::from(1_000_000_000_000_000u64))
                .with_mint(
                    Address::repeat_byte(0x11),
                    U256::from(1_000_000_000_000_000u64),
                )
                .with_mint(
                    Address::repeat_byte(0x12),
                    U256::from(1_000_000_000_000_000u64),
                )
                .with_mint(Address::repeat_byte(0x20), U256::ONE)
                .with_mint(Address::repeat_byte(0x21), U256::ONE)
                .with_mint(Address::repeat_byte(0x22), U256::ONE)
                .apply()
        })
        .unwrap();
        evm.state_mut().commit_transaction();
        evm.state_mut().clear_transaction_state();
        let mut backing = InMemoryDB::default();
        backing.cache = evm.overlay_db().cache.clone();
        let mut block = *evm.block();
        block.basefee = U256::from(1_000_000_000u64);
        block.number = U256::ONE;
        let config = TempoEvmConfig::new(chain.clone()).with_incoming_replay(true);
        // Use the same environment resolution as incoming header validation. Tempo disables
        // ETH balance checks; its native fee collection checks TIP-20 balances instead.
        let env = config.resolved_env(TempoHardfork::T12, block, None);
        assert!(!env.version.feature(evm2::EvmFeatures::BALANCE_CHECK));
        assert!(env.version.feature(evm2::EvmFeatures::FEE_CHARGE));
        assert!(env.version.feature(evm2::EvmFeatures::NONCE_CHECK));
        let ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: B256::ZERO,
                parent_beacon_block_root: Some(B256::ZERO),
                ommers: &[],
                withdrawals: None,
                extra_data: Bytes::new(),
                tx_count_hint: None,
                slot_number: None,
            },
            general_gas_limit: 30_000_000,
            shared_gas_limit: 0,
            validator_set: None,
            consensus_context: None,
            subblock_fee_recipients: Default::default(),
        };
        (config, env, ctx, backing, sender)
    }

    fn mint(
        chain_id: u64,
        sender: Address,
        recipient: u8,
        nonce_key: U256,
    ) -> Recovered<TempoTxEnvelope> {
        Recovered::new_unchecked(
            TempoTxEnvelope::AA(AASigned::new_unhashed(
                TempoTransaction {
                    chain_id,
                    fee_token: Some(PATH_USD_ADDRESS),
                    max_fee_per_gas: 1_000_000_000,
                    max_priority_fee_per_gas: 1,
                    gas_limit: 1_000_000,
                    calls: vec![Call {
                        to: TxKind::Call(PATH_USD_ADDRESS),
                        value: U256::ZERO,
                        input: ITIP20::mintCall {
                            to: Address::repeat_byte(recipient),
                            amount: U256::from(1000),
                        }
                        .abi_encode()
                        .into(),
                    }],
                    nonce_key,
                    valid_before: Some(20.try_into().unwrap()),
                    ..Default::default()
                },
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    Signature::test_signature(),
                )),
            )),
            sender,
        )
    }

    #[test]
    fn incoming_replay_matches_serial_pre_execution_receipts_and_complete_state() {
        let (config, env, ctx, backing, sender) = fixture();
        let context = config.prewarm_context(&env, &ctx).unwrap();
        let mut worker = config
            .prepare_prewarm_evm(config.evm_with_env(backing.clone(), env.clone()), &context)
            .unwrap();
        let mut serial = config.create_executor(
            config.evm_with_env(backing.clone(), env.clone()),
            ctx.clone(),
        );
        let mut candidate = config.create_executor(config.evm_with_env(backing, env.clone()), ctx);
        serial.apply_pre_execution_changes().unwrap();
        candidate.apply_pre_execution_changes().unwrap();
        assert_eq!(worker.overlay_db().cache, serial.evm().overlay_db().cache);
        let txs = (2..5)
            .map(|to| mint(env.version.chain_id, sender, to, U256::MAX))
            .collect::<Vec<_>>();
        let artifacts = txs
            .iter()
            .enumerate()
            .map(|(index, tx)| {
                let mut tx_env: TempoTxEnv = tx.clone().into();
                tx_env.set_expiring_nonce_idx(Some(index));
                config
                    .prewarm_transaction(
                        &mut worker,
                        (Recovered::new_unchecked(tx_env, sender), tx.clone()),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for (index, (tx, artifact)) in txs.into_iter().zip(artifacts).enumerate() {
            let expected_gas = serial.execute_transaction(tx.clone()).unwrap();
            let actual = config
                .execute_transaction_with_prewarm(&mut candidate, tx, Some(artifact))
                .unwrap();
            assert_eq!(actual.gas.tx_gas_used(), expected_gas.tx_gas_used());
            assert_eq!(
                actual.gas.regular_gas_used(),
                expected_gas.regular_gas_used()
            );
            assert_eq!(actual.gas.state_gas_used(), expected_gas.state_gas_used());
            assert_eq!(
                actual.replayed,
                index == 0,
                "later mints conflict and must execute normally"
            );
            assert!(actual.continue_speculation);
            assert_eq!(candidate.receipts(), serial.receipts());
        }
        assert_eq!(candidate.finish().unwrap(), serial.finish().unwrap());
    }

    #[test]
    fn incoming_replay_declines_disabled_checks_and_stops_after_unsupported_transaction() {
        let (config, env, ctx, backing, sender) = fixture();
        let mut unchecked = env.clone();
        unchecked
            .version
            .features
            .remove(evm2::EvmFeatures::NONCE_CHECK);
        assert!(config.prewarm_context(&unchecked, &ctx).is_none());
        unchecked = env.clone();
        unchecked
            .version
            .features
            .remove(evm2::EvmFeatures::FEE_CHARGE);
        assert!(config.prewarm_context(&unchecked, &ctx).is_none());
        assert!(
            config
                .clone()
                .with_incoming_replay(false)
                .prewarm_context(&env, &ctx)
                .is_none()
        );
        let mut serial = config.create_executor(
            config.evm_with_env(backing.clone(), env.clone()),
            ctx.clone(),
        );
        let mut candidate = config.create_executor(config.evm_with_env(backing, env.clone()), ctx);
        serial.apply_pre_execution_changes().unwrap();
        candidate.apply_pre_execution_changes().unwrap();
        let tx = mint(env.version.chain_id, sender, 7, U256::ZERO);
        assert!(!eligible(tx.inner()));
        serial.execute_transaction(tx.clone()).unwrap();
        let actual = config
            .execute_transaction_with_prewarm(&mut candidate, tx, None)
            .unwrap();
        assert!(!actual.replayed && !actual.continue_speculation);
        assert_eq!(candidate.finish().unwrap(), serial.finish().unwrap());
    }

    #[test]
    fn incoming_replay_preserves_canonical_native_fee_balance_rejection() {
        let (config, env, ctx, backing, _) = fixture();
        let context = config.prewarm_context(&env, &ctx).unwrap();
        let mut worker = config
            .prepare_prewarm_evm(config.evm_with_env(backing.clone(), env.clone()), &context)
            .unwrap();
        let unfunded = Address::repeat_byte(0x44);
        let tx = mint(env.version.chain_id, unfunded, 7, U256::MAX);
        assert!(
            config
                .prewarm_transaction(&mut worker, tx.clone())
                .is_none()
        );
        let mut serial = config.create_executor(
            config.evm_with_env(backing.clone(), env.clone()),
            ctx.clone(),
        );
        let mut untouched = config.create_executor(
            config.evm_with_env(backing.clone(), env.clone()),
            ctx.clone(),
        );
        let mut candidate = config.create_executor(config.evm_with_env(backing, env), ctx);
        untouched.apply_pre_execution_changes().unwrap();
        serial.apply_pre_execution_changes().unwrap();
        candidate.apply_pre_execution_changes().unwrap();
        let expected = serial.execute_transaction(tx.clone()).unwrap_err();
        let actual = config
            .execute_transaction_with_prewarm(&mut candidate, tx, None)
            .unwrap_err();
        assert_eq!(actual.to_string(), expected.to_string());
        assert!(actual.to_string().contains("fee token balance"), "{actual}");
        assert!(candidate.receipts().is_empty());
        let pristine = untouched.finish().unwrap();
        assert_eq!(candidate.finish().unwrap(), pristine);
        assert_eq!(serial.finish().unwrap(), pristine);
    }

    #[test]
    fn incoming_replay_refreshes_nonce_pointer_after_missing_artifact() {
        use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, nonce::NonceManager};
        let (config, mut env, ctx, backing, _) = fixture();
        // Zero effective fees isolate nonce-pointer ordering from shared fee-token storage.
        // Canonical nonce checks and native fee collection remain enabled.
        env.block.basefee = U256::ZERO;
        let context = config.prewarm_context(&env, &ctx).unwrap();
        let mut worker = config
            .prepare_prewarm_evm(config.evm_with_env(backing.clone(), env.clone()), &context)
            .unwrap();
        let mut serial = config.create_executor(
            config.evm_with_env(backing.clone(), env.clone()),
            ctx.clone(),
        );
        let mut candidate = config.create_executor(config.evm_with_env(backing, env.clone()), ctx);
        serial.apply_pre_execution_changes().unwrap();
        candidate.apply_pre_execution_changes().unwrap();
        let txs = [1, 0x11, 0x12]
            .into_iter()
            .enumerate()
            .map(|(index, sender)| {
                let sender = Address::repeat_byte(sender);
                Recovered::new_unchecked(
                    TempoTxEnvelope::AA(AASigned::new_unhashed(
                        TempoTransaction {
                            chain_id: env.version.chain_id,
                            fee_token: Some(PATH_USD_ADDRESS),
                            max_fee_per_gas: 1_000_000_000,
                            max_priority_fee_per_gas: 0,
                            gas_limit: 1_000_000,
                            calls: vec![Call {
                                to: TxKind::Call(PATH_USD_ADDRESS),
                                value: U256::ZERO,
                                input: ITIP20::transferCall {
                                    to: Address::repeat_byte(0x20 + index as u8),
                                    amount: U256::from(1000),
                                }
                                .abi_encode()
                                .into(),
                            }],
                            nonce_key: U256::MAX,
                            valid_before: Some(20.try_into().unwrap()),
                            ..Default::default()
                        },
                        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                            Signature::test_signature(),
                        )),
                    )),
                    sender,
                )
            })
            .collect::<Vec<_>>();
        let artifacts = txs
            .iter()
            .enumerate()
            .map(|(index, tx)| {
                let mut tx_env: TempoTxEnv = tx.clone().into();
                tx_env.set_expiring_nonce_idx(Some(index));
                let artifact = config
                    .prewarm_transaction(
                        &mut worker,
                        (Recovered::new_unchecked(tx_env, tx.signer()), tx.clone()),
                    )
                    .unwrap();
                assert!(artifact.result.status);
                (index != 1).then_some(artifact)
            })
            .collect::<Vec<_>>();
        for (index, (tx, artifact)) in txs.into_iter().zip(artifacts).enumerate() {
            serial.execute_transaction(tx.clone()).unwrap();
            let actual = config
                .execute_transaction_with_prewarm(&mut candidate, tx, artifact)
                .unwrap();
            assert_eq!(
                actual.replayed,
                index != 1,
                "the independent transfer at index {index} must really replay"
            );
            let slot = NonceManager::new().expiring_nonce_ring_ptr.slot();
            let expected = serial
                .evm_mut()
                .overlay_db_mut()
                .get_storage(&NONCE_PRECOMPILE_ADDRESS, &slot)
                .unwrap();
            let actual = candidate
                .evm_mut()
                .overlay_db_mut()
                .get_storage(&NONCE_PRECOMPILE_ADDRESS, &slot)
                .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(actual, U256::from(index + 1));
            assert_eq!(candidate.receipts(), serial.receipts());
        }
        assert_eq!(candidate.finish().unwrap(), serial.finish().unwrap());
    }
}

impl TempoEvmConfig {
    pub(crate) fn incoming_prewarm_context(
        &self,
        env: &TempoEvmEnv,
        ctx: &TempoBlockExecutionCtx<'_>,
    ) -> Option<TempoPrewarmContext> {
        if !self.incoming_replay
            || !env.tempo_spec.is_t5()
            || !ctx.inner.ommers.is_empty()
            || !env.version.feature(evm2::EvmFeatures::NONCE_CHECK)
            // Tempo deliberately disables ETH BALANCE_CHECK. FEE_CHARGE retains its
            // native TIP-20 fee-token balance validation and collection.
            || !env.version.feature(evm2::EvmFeatures::FEE_CHARGE)
            || env.version.feature(evm2::EvmFeatures::BALANCE_TOP_UP)
        {
            return None;
        }
        Some(TempoPrewarmContext(TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                tx_count_hint: ctx.inner.tx_count_hint,
                parent_hash: ctx.inner.parent_hash,
                parent_beacon_block_root: ctx.inner.parent_beacon_block_root,
                ommers: &[],
                withdrawals: ctx
                    .inner
                    .withdrawals
                    .as_ref()
                    .map(|w| Cow::Owned(w.to_vec())),
                extra_data: ctx.inner.extra_data.clone(),
                slot_number: ctx.inner.slot_number,
            },
            general_gas_limit: ctx.general_gas_limit,
            shared_gas_limit: ctx.shared_gas_limit,
            validator_set: ctx.validator_set.clone(),
            consensus_context: ctx.consensus_context.clone(),
            subblock_fee_recipients: ctx.subblock_fee_recipients.clone(),
        }))
    }

    pub(crate) fn prepare_incoming_prewarm_evm<'a>(
        &self,
        evm: TempoEvm<'a>,
        context: &TempoPrewarmContext,
    ) -> Option<TempoEvm<'a>> {
        // Exactly the canonical pre-execution path, including fork-boundary deployments and
        // system calls. Only this worker's independent parent-state provider is changed.
        let mut executor = TempoBlockExecutor::new(evm, context.0.clone(), self.chain_spec());
        executor.apply_pre_execution_changes().ok()?;
        let mut evm = executor.inner.into_evm();
        self.evm_factory.enable_storage_actions(&mut evm);
        Some(evm)
    }

    pub(crate) fn record_incoming_transaction(
        &self,
        evm: &mut TempoEvm<'_>,
        transaction: impl ExecutableTxParts<Recovered<TempoTxEnv>, TempoTxEnvelope>,
    ) -> Option<StorageActionReplay> {
        let (tx_env, tx) = transaction.into_parts();
        if !eligible(tx.tx()) {
            return None;
        }
        // Keep the converted env: its block-local expiring-nonce index is prepared by the
        // payload iterator. Reconstructing it from the envelope loses that index.
        let expiring_nonce = if tx.tx().is_expiring_nonce() {
            let aa = tx.tx().as_aa()?;
            Some(ExpiringNonceReplay {
                hash: aa.expiring_nonce_hash(*tx.signer()),
                valid_before: aa.tx().valid_before?.get(),
            })
        } else {
            None
        };
        record_storage_action_replay(evm, &tx_env, expiring_nonce)
    }

    pub(crate) fn execute_incoming_transaction<'a>(
        &self,
        executor: &mut TempoBlockExecutor<'a>,
        transaction: impl ExecutorTx<TempoBlockExecutor<'a>>,
        artifact: Option<StorageActionReplay>,
    ) -> Result<PrewarmExecution, BlockExecutionError> {
        let (tx_env, tx) = transaction.into_parts();
        if !eligible(tx.tx()) {
            // Unsupported prior writes may alter dependencies beyond semantic storage actions.
            // Execute this transaction and the complete remaining suffix normally.
            executor.invalidate_expiring_nonce_cache();
            return executor
                .execute_transaction((tx_env, tx))
                .map(|gas| PrewarmExecution {
                    gas,
                    replayed: false,
                    continue_speculation: false,
                });
        }
        let Some(artifact) = artifact else {
            executor.invalidate_expiring_nonce_cache();
            return executor
                .execute_transaction((tx_env, tx))
                .map(|gas| PrewarmExecution {
                    gas,
                    replayed: false,
                    continue_speculation: true,
                });
        };
        let mut gas = GasOutput::default();
        let replayed = executor.execute_transaction_with_actions(
            (tx_env, tx),
            artifact,
            |result| {
                gas = GasOutput::new_with_regular(
                    result.result().tx_gas_used(),
                    result.result().execution_gas_spent(),
                    result.result().state_gas_spent(),
                );
            },
            false,
        )?;
        Ok(PrewarmExecution {
            gas,
            replayed,
            continue_speculation: true,
        })
    }
}
