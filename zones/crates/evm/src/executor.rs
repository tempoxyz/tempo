//! Zone block executor.
//!
//! A simplified block executor for zone nodes that wraps [`EthBlockExecutor`] directly.
//! Unlike the Tempo L1 `TempoBlockExecutor`, this executor does **not** enforce subblock
//! ordering, shared-gas accounting, or the end-of-block subblock metadata system transaction.

use alloy_consensus::TxReceipt as _;
use alloy_evm::{
    Database, Evm, RecoveredTx,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockValidationError,
        ExecutableTx, GasOutput, TxResult,
    },
    eth::{EthBlockExecutor, EthTxResult},
};
use alloy_sol_types::{SolCall as _, SolEvent as _};
use reth_evm::block::StateDB;
use reth_revm::{Inspector, context::result::ResultAndState};
use tempo_evm::{TempoBlockExecutionCtx, TempoReceiptBuilder};
use tempo_primitives::{TempoReceipt, TempoTxEnvelope, TempoTxType};
use tempo_revm::evm::TempoContext;
use tempo_zone_contracts::{IZoneOutbox, TempoAdvanced};
use zone_chainspec::ZoneChainSpec;
use zone_l1::state::L1StateProvider;
use zone_precompiles::{ADVANCE_TEMPO_HEADERS_SELECTOR, ADVANCE_TEMPO_SELECTOR, L1StorageReader};
use zone_primitives::constants::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS};

use crate::{L1OverlayDB, ZoneEvm};

/// The current transaction-ordering phase of a zone block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ZoneBlockPhase {
    /// The block has not yet committed its required opening `advanceTempo` transaction.
    AwaitingAdvanceTempo,
    /// The block has committed `advanceTempo` and may execute ordinary transactions.
    Executing,
    /// The block authenticated Tempo headers and must contain no further transactions.
    CheckpointOnly,
    /// The block has finalized withdrawals and cannot accept any more transactions.
    WithdrawalsFinalized,
}

impl ZoneBlockPhase {
    fn validate_transaction(self, tx: &TempoTxEnvelope) -> Result<Self, BlockExecutionError> {
        if tx.has_sub_block_nonce_key_prefix() {
            return Err(BlockValidationError::msg(
                "subblock transactions are not supported in zone blocks",
            )
            .into());
        }

        let tx_kind = ZoneTransactionKind::classify(tx);

        match (self, tx_kind) {
            (Self::AwaitingAdvanceTempo, ZoneTransactionKind::AdvanceTempo) => Ok(Self::Executing),
            (Self::AwaitingAdvanceTempo, ZoneTransactionKind::AdvanceTempoHeaders) => {
                Ok(Self::CheckpointOnly)
            }
            (Self::AwaitingAdvanceTempo, _) => Err(BlockValidationError::msg(
                "advanceTempo must be the first transaction in a zone block",
            )
            .into()),
            (Self::Executing, ZoneTransactionKind::AdvanceTempo) => Err(BlockValidationError::msg(
                "advanceTempo must only execute once per zone block",
            )
            .into()),
            (Self::Executing, ZoneTransactionKind::AdvanceTempoHeaders) => Err(
                BlockValidationError::msg("advanceTempoHeaders must only open a zone block").into(),
            ),
            (Self::Executing, ZoneTransactionKind::Regular) => Ok(Self::Executing),
            (Self::Executing, ZoneTransactionKind::FinalizeWithdrawalBatch) => {
                Ok(Self::WithdrawalsFinalized)
            }
            (Self::Executing, ZoneTransactionKind::UnexpectedSystem) => {
                Err(BlockValidationError::msg(
                    "system transactions after advanceTempo must call \
                     ZoneOutbox.finalizeWithdrawalBatch",
                )
                .into())
            }
            (Self::WithdrawalsFinalized, _) => Err(BlockValidationError::msg(
                "finalizeWithdrawalBatch must be the last transaction in a zone block",
            )
            .into()),
            (Self::CheckpointOnly, _) => Err(BlockValidationError::msg(
                "advanceTempoHeaders must be the only transaction in a zone block",
            )
            .into()),
        }
    }

    /// Commit a successfully executed transition without allowing stale results to regress phase.
    fn advance_to(&mut self, next: Self) {
        *self = (*self).max(next);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZoneTransactionKind {
    AdvanceTempo,
    AdvanceTempoHeaders,
    Regular,
    FinalizeWithdrawalBatch,
    UnexpectedSystem,
}

impl ZoneTransactionKind {
    fn classify(tx: &TempoTxEnvelope) -> Self {
        if !tx.is_system_tx() {
            return Self::Regular;
        }

        if tx.calls().any(|(kind, input)| {
            kind.to() == Some(&ZONE_INBOX_ADDRESS) && input.starts_with(&ADVANCE_TEMPO_SELECTOR)
        }) {
            return Self::AdvanceTempo;
        }

        if tx.calls().any(|(kind, input)| {
            kind.to() == Some(&ZONE_INBOX_ADDRESS)
                && input.starts_with(&ADVANCE_TEMPO_HEADERS_SELECTOR)
        }) {
            return Self::AdvanceTempoHeaders;
        }

        if tx.calls().any(|(kind, input)| {
            kind.to() == Some(&ZONE_OUTBOX_ADDRESS)
                && input.starts_with(&IZoneOutbox::finalizeWithdrawalBatchCall::SELECTOR)
        }) {
            return Self::FinalizeWithdrawalBatch;
        }

        Self::UnexpectedSystem
    }
}

/// Zone transaction result with the block phase to apply if the result is committed.
#[derive(Debug)]
pub struct ZoneTxResult<H, T> {
    inner: EthTxResult<H, T>,
    next_phase: ZoneBlockPhase,
}

impl<H, T> TxResult for ZoneTxResult<H, T>
where
    H: Send + 'static,
    T: Send + 'static,
{
    type HaltReason = H;

    fn result(&self) -> &ResultAndState<Self::HaltReason> {
        self.inner.result()
    }

    fn into_result(self) -> ResultAndState<Self::HaltReason> {
        self.inner.into_result()
    }
}

/// Simplified block executor for zone nodes.
///
/// Enforces the successful block-opening `advanceTempo` system transaction and same-block
/// finalization of requested withdrawals and T13 processed deposits, then delegates ordinary
/// execution to [`EthBlockExecutor`] without Tempo subblock validation, gas-section tracking, or
/// end-of-block metadata requirements.
pub struct ZoneBlockExecutor<'a, DB: Database, I, L1: L1StorageReader = L1StateProvider> {
    inner: EthBlockExecutor<'a, ZoneEvm<DB, I, L1>, &'a ZoneChainSpec, TempoReceiptBuilder>,
    phase: ZoneBlockPhase,
}

impl<'a, DB, I, L1> ZoneBlockExecutor<'a, DB, I, L1>
where
    DB: StateDB,
    L1: L1StorageReader,
    I: Inspector<TempoContext<L1OverlayDB<DB, L1>>>,
{
    /// Create a zone block executor for `evm` and the current block context.
    pub fn new(
        evm: ZoneEvm<DB, I, L1>,
        ctx: TempoBlockExecutionCtx<'a>,
        chain_spec: &'a ZoneChainSpec,
    ) -> Self {
        Self {
            inner: EthBlockExecutor::new(
                evm,
                ctx.inner,
                chain_spec,
                TempoReceiptBuilder::default(),
            ),
            phase: ZoneBlockPhase::AwaitingAdvanceTempo,
        }
    }
}

impl<'a, DB, I, L1> BlockExecutor for ZoneBlockExecutor<'a, DB, I, L1>
where
    DB: StateDB,
    L1: L1StorageReader,
    I: Inspector<TempoContext<L1OverlayDB<DB, L1>>>,
{
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;
    type Evm = ZoneEvm<DB, I, L1>;
    type Result = ZoneTxResult<<Self::Evm as Evm>::HaltReason, TempoTxType>;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        if self
            .inner
            .ctx
            .withdrawals
            .as_ref()
            .is_some_and(|withdrawals| !withdrawals.is_empty())
        {
            return Err(BlockValidationError::msg("withdrawals are not permitted").into());
        }

        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        let (mut tx_env, recovered) = tx.into_parts();
        // Remove any prewarming-specific context that was added to the tx env.
        if let Some(tempo_tx_env) = tx_env.tempo_tx_env.as_mut() {
            tempo_tx_env.expiring_nonce_idx = None;
        }

        let next_phase = self.phase.validate_transaction(recovered.tx())?;

        let result = self
            .inner
            .execute_transaction_without_commit((tx_env, recovered));

        self.evm_mut().clear_l1_overlay_state();
        Ok(ZoneTxResult {
            inner: result?,
            next_phase,
        })
    }

    fn commit_transaction(&mut self, output: Self::Result) -> GasOutput {
        self.phase.advance_to(output.next_phase);
        self.inner.commit_transaction(output.inner)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        if self.phase == ZoneBlockPhase::AwaitingAdvanceTempo {
            return Err(BlockValidationError::msg(
                "zone block is missing its advanceTempo system transaction",
            )
            .into());
        }

        let requested_withdrawal = self
            .inner
            .receipts()
            .iter()
            .flat_map(|receipt| receipt.logs())
            .any(|log| {
                log.address == ZONE_OUTBOX_ADDRESS
                    && log.topics().first()
                        == Some(&IZoneOutbox::WithdrawalRequested::SIGNATURE_HASH)
            });
        if requested_withdrawal && self.phase != ZoneBlockPhase::WithdrawalsFinalized {
            return Err(BlockValidationError::msg(
                "zone block with withdrawal requests is missing its finalizeWithdrawalBatch \
                 system transaction",
            )
            .into());
        }

        let processed_deposit = self.inner.evm.cfg_env().spec.is_t13()
            && self
                .inner
                .receipts()
                .iter()
                .flat_map(|receipt| receipt.logs())
                .filter(|log| {
                    log.address == ZONE_INBOX_ADDRESS
                        && log.topics().first() == Some(&TempoAdvanced::SIGNATURE_HASH)
                })
                .any(|log| {
                    TempoAdvanced::decode_log(log)
                        .is_ok_and(|event| !event.depositsProcessed.is_zero())
                });
        if processed_deposit && self.phase != ZoneBlockPhase::WithdrawalsFinalized {
            return Err(BlockValidationError::msg(
                "zone block with processed deposits is missing its finalizeWithdrawalBatch \
                 system transaction",
            )
            .into());
        }

        self.inner.finish()
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ADVANCE_TEMPO_SELECTOR, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, ZoneBlockExecutor,
        ZoneBlockPhase, ZoneTransactionKind,
    };

    use alloy_consensus::{Header, Sealable as _, Signed, TxLegacy};
    use alloy_evm::{EvmEnv, EvmFactory, block::BlockExecutor, eth::EthBlockExecutionCtx};
    use alloy_primitives::{Address, B256, Bytes, Log, Signature, U256};
    use alloy_sol_types::{SolCall, SolEvent};
    use reth_chainspec::EthChainSpec as _;
    use reth_primitives_traits::Recovered;
    use revm::database::InMemoryDB;
    use tempo_chainspec::{hardfork::TempoHardfork, spec::DEV};
    use tempo_evm::{TempoBlockEnv, TempoBlockExecutionCtx};
    use tempo_precompiles::{
        DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS,
        storage::{ContractStorage, Handler, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip_fee_manager::{TipFeeManager, amm::PoolKey},
    };
    use tempo_primitives::{
        TempoHeader, TempoReceipt, TempoTxEnvelope, TempoTxType,
        subblock::TEMPO_SUBBLOCK_NONCE_KEY_PREFIX,
        transaction::{
            Call, TempoSignature, TempoTransaction,
            envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
        },
    };
    use tempo_revm::{TempoBatchCallEnv, TempoTxEnv};
    use tempo_zone_contracts::{
        ChaumPedersenProof, DecryptionData, IZoneInbox, IZoneOutbox, LegacyTempoAdvanced,
        TempoAdvanced,
    };
    use zone_chainspec::ZoneChainSpec;
    use zone_precompiles::{
        tempo_state::{TEMPO_BLOCK_NUMBER_SLOT, slots::TEMPO_BLOCK_HASH},
        test_utils::MockL1Reader,
    };
    use zone_primitives::constants::{TEMPO_STATE_ADDRESS, zone_chain_id};

    use crate::ZoneEvmFactory;

    fn system_tx(to: Address, input: Bytes) -> TempoTxEnvelope {
        TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                to: to.into(),
                input,
                ..Default::default()
            },
            TEMPO_SYSTEM_TX_SIGNATURE,
        ))
    }

    fn advance_tempo_tx() -> TempoTxEnvelope {
        system_tx(ZONE_INBOX_ADDRESS, ADVANCE_TEMPO_SELECTOR.into())
    }

    fn finalize_withdrawal_batch_tx() -> TempoTxEnvelope {
        system_tx(
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::finalizeWithdrawalBatchCall {
                count: U256::ZERO,
                blockNumber: 1,
                encryptedSenders: vec![],
            }
            .abi_encode()
            .into(),
        )
    }

    fn withdrawal_requested_receipt(address: Address) -> TempoReceipt {
        let event = IZoneOutbox::WithdrawalRequested {
            withdrawalIndex: 0,
            sender: Address::repeat_byte(0x11),
            token: Address::repeat_byte(0x22),
            to: Address::repeat_byte(0x33),
            amount: 1,
            fee: 0,
            memo: B256::ZERO,
            gasLimit: 0,
            fallbackNonce: 1,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        };
        TempoReceipt {
            tx_type: TempoTxType::Legacy,
            success: true,
            cumulative_gas_used: 0,
            logs: vec![Log {
                address,
                data: event.encode_log_data(),
            }],
        }
    }

    fn ordinary_tx(to: Address, input: Bytes) -> TempoTxEnvelope {
        TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                to: to.into(),
                input,
                ..Default::default()
            },
            Signature::test_signature(),
        ))
    }

    fn subblock_tx() -> TempoTxEnvelope {
        let mut nonce_key = [0u8; 32];
        nonce_key[0] = TEMPO_SUBBLOCK_NONCE_KEY_PREFIX;

        TempoTxEnvelope::AA(
            TempoTransaction {
                calls: vec![Call {
                    to: Address::ZERO.into(),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                nonce_key: U256::from_be_bytes(nonce_key),
                ..Default::default()
            }
            .into_signed(TempoSignature::from(Signature::test_signature())),
        )
    }

    #[test]
    fn discarded_advance_tempo_does_not_change_committed_ordering_state() {
        let advance_tempo = advance_tempo_tx();
        let mut phase = ZoneBlockPhase::AwaitingAdvanceTempo;

        let next_phase = phase.validate_transaction(&advance_tempo).unwrap();
        assert_eq!(phase, ZoneBlockPhase::AwaitingAdvanceTempo);
        assert_eq!(next_phase, ZoneBlockPhase::Executing);

        // Only committing the result records the opening transaction.
        phase.advance_to(next_phase);
        assert_eq!(phase, ZoneBlockPhase::Executing);
    }

    #[test]
    fn advance_tempo_ordering_errors_are_reported() {
        let advance_tempo = advance_tempo_tx();
        let ordinary = system_tx(Address::ZERO, Bytes::new());

        let missing_first = ZoneBlockPhase::AwaitingAdvanceTempo
            .validate_transaction(&ordinary)
            .unwrap_err();
        assert_eq!(
            missing_first.to_string(),
            "advanceTempo must be the first transaction in a zone block"
        );

        let duplicate = ZoneBlockPhase::Executing
            .validate_transaction(&advance_tempo)
            .unwrap_err();
        assert_eq!(
            duplicate.to_string(),
            "advanceTempo must only execute once per zone block"
        );
    }

    #[test]
    fn only_withdrawal_finalization_system_transactions_are_allowed_after_advance_tempo() {
        let finalize = finalize_withdrawal_batch_tx();
        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&finalize)
                .unwrap(),
            ZoneBlockPhase::WithdrawalsFinalized
        );

        let setter = system_tx(
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::setMaxWithdrawalsPerBlockCall {
                _maxWithdrawalsPerBlock: 1,
            }
            .abi_encode()
            .into(),
        );
        let error = ZoneBlockPhase::Executing
            .validate_transaction(&setter)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "system transactions after advanceTempo must call \
             ZoneOutbox.finalizeWithdrawalBatch"
        );

        let malformed_finalize = system_tx(
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::finalizeWithdrawalBatchCall::SELECTOR.into(),
        );
        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&malformed_finalize)
                .unwrap(),
            ZoneBlockPhase::WithdrawalsFinalized
        );

        let mut trailing_calldata = IZoneOutbox::finalizeWithdrawalBatchCall {
            count: U256::ZERO,
            blockNumber: 1,
            encryptedSenders: vec![],
        }
        .abi_encode();
        trailing_calldata.extend_from_slice(&[0; 32]);
        let trailing_finalize = system_tx(ZONE_OUTBOX_ADDRESS, trailing_calldata.into());
        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&trailing_finalize)
                .unwrap(),
            ZoneBlockPhase::WithdrawalsFinalized
        );
    }

    #[test]
    fn malformed_t11_finalization_does_not_advance_block_phase() {
        let mut zone_genesis = DEV.genesis().clone();
        zone_genesis.config.chain_id = zone_chain_id(DEV.chain_id(), 2).unwrap();
        let chain_spec = std::sync::Arc::new(ZoneChainSpec::from_genesis(zone_genesis).unwrap());
        let factory = ZoneEvmFactory::new(MockL1Reader::default(), Address::ZERO);
        let mut env = EvmEnv::default();
        env.cfg_env.spec = TempoHardfork::T11;
        let evm = factory.create_evm(InMemoryDB::default(), env);
        let ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: B256::ZERO,
                parent_beacon_block_root: None,
                ommers: &[],
                withdrawals: None,
                extra_data: Bytes::new(),
                tx_count_hint: Some(1),
                slot_number: None,
            },
            general_gas_limit: 0,
            shared_gas_limit: 0,
            consensus_context: None,
        };
        let mut executor = ZoneBlockExecutor::new(evm, ctx, &chain_spec);
        executor.phase = ZoneBlockPhase::Executing;

        let tx = Recovered::new_unchecked(
            system_tx(
                ZONE_OUTBOX_ADDRESS,
                IZoneOutbox::finalizeWithdrawalBatchCall::SELECTOR.into(),
            ),
            TEMPO_SYSTEM_TX_SENDER,
        );
        let error = executor.execute_transaction_without_commit(tx).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("system transaction execution failed"),
            "unexpected error: {error}"
        );
        assert_eq!(executor.phase, ZoneBlockPhase::Executing);
    }

    #[test]
    fn ordinary_transactions_are_allowed_after_advance_tempo() {
        let ordinary = ordinary_tx(Address::ZERO, Bytes::new());
        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&ordinary)
                .unwrap(),
            ZoneBlockPhase::Executing
        );
    }

    #[test]
    fn withdrawal_requests_require_same_block_finalization() {
        let mut zone_genesis = DEV.genesis().clone();
        zone_genesis.config.chain_id = zone_chain_id(DEV.chain_id(), 2).unwrap();
        let chain_spec = std::sync::Arc::new(ZoneChainSpec::from_genesis(zone_genesis).unwrap());
        let factory = ZoneEvmFactory::new(MockL1Reader::default(), Address::ZERO);
        let evm = factory.create_evm(InMemoryDB::default(), EvmEnv::default());
        let ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: B256::ZERO,
                parent_beacon_block_root: None,
                ommers: &[],
                withdrawals: None,
                extra_data: Bytes::new(),
                tx_count_hint: Some(1),
                slot_number: None,
            },
            general_gas_limit: 0,
            shared_gas_limit: 0,
            consensus_context: None,
        };
        let mut executor = ZoneBlockExecutor::new(evm, ctx, &chain_spec);
        executor.phase = ZoneBlockPhase::Executing;
        executor
            .inner
            .receipts
            .push(withdrawal_requested_receipt(ZONE_OUTBOX_ADDRESS));

        let error = match executor.finish() {
            Ok(_) => panic!("withdrawal request block without finalization was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "zone block with withdrawal requests is missing its finalizeWithdrawalBatch system \
             transaction"
        );
    }

    #[test]
    fn processed_deposits_require_same_block_finalization() {
        use ZoneBlockPhase::{Executing, WithdrawalsFinalized};

        for (address, deposits, phase, legacy, spec, must_reject) in [
            (
                ZONE_INBOX_ADDRESS,
                1,
                Executing,
                false,
                TempoHardfork::T12,
                false,
            ),
            (
                ZONE_INBOX_ADDRESS,
                1,
                Executing,
                true,
                TempoHardfork::T12,
                false,
            ),
            (
                ZONE_INBOX_ADDRESS,
                1,
                Executing,
                false,
                TempoHardfork::T13,
                true,
            ),
            (
                ZONE_INBOX_ADDRESS,
                0,
                Executing,
                false,
                TempoHardfork::T13,
                false,
            ),
            (
                ZONE_INBOX_ADDRESS,
                1,
                WithdrawalsFinalized,
                false,
                TempoHardfork::T13,
                false,
            ),
            (
                Address::ZERO,
                1,
                Executing,
                false,
                TempoHardfork::T13,
                false,
            ),
        ] {
            let mut zone_genesis = DEV.genesis().clone();
            zone_genesis.config.chain_id = zone_chain_id(DEV.chain_id(), 2).unwrap();
            let chain_spec =
                std::sync::Arc::new(ZoneChainSpec::from_genesis(zone_genesis).unwrap());
            let factory = ZoneEvmFactory::new(MockL1Reader::default(), Address::ZERO);
            let mut env: EvmEnv<TempoHardfork, TempoBlockEnv> = EvmEnv::default();
            env.cfg_env.spec = spec;
            let evm = factory.create_evm(InMemoryDB::default(), env);
            let ctx = TempoBlockExecutionCtx {
                inner: EthBlockExecutionCtx {
                    parent_hash: B256::ZERO,
                    parent_beacon_block_root: None,
                    ommers: &[],
                    withdrawals: None,
                    extra_data: Bytes::new(),
                    tx_count_hint: Some(1),
                    slot_number: None,
                },
                general_gas_limit: 0,
                shared_gas_limit: 0,
                consensus_context: None,
            };
            let mut executor = ZoneBlockExecutor::new(evm, ctx, &chain_spec);
            executor.phase = phase;
            let event = TempoAdvanced {
                tempoBlockHash: B256::ZERO,
                tempoBlockNumber: 1,
                depositsProcessed: U256::from(deposits),
                newProcessedDepositQueueHash: B256::ZERO,
                lastProcessedDepositNumber: deposits,
                lastProcessedEnabledTokenCount: 0,
            };
            let data = if legacy {
                LegacyTempoAdvanced {
                    tempoBlockHash: event.tempoBlockHash,
                    tempoBlockNumber: event.tempoBlockNumber,
                    depositsProcessed: event.depositsProcessed,
                    newProcessedDepositQueueHash: event.newProcessedDepositQueueHash,
                    lastProcessedDepositNumber: event.lastProcessedDepositNumber,
                }
                .encode_log_data()
            } else {
                event.encode_log_data()
            };
            executor.inner.receipts.push(TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 0,
                logs: vec![Log { address, data }],
            });

            let result = executor.finish();
            if must_reject {
                let error = match result {
                    Ok(_) => panic!("deposit block without finalization was accepted"),
                    Err(error) => error,
                };
                assert_eq!(
                    error.to_string(),
                    "zone block with processed deposits is missing its finalizeWithdrawalBatch system transaction"
                );
            } else {
                assert!(
                    result.is_ok(),
                    "unexpected rejection: address={address}, deposits={deposits}, phase={phase:?}, legacy={legacy}, spec={spec:?}"
                );
            }
        }
    }

    #[test]
    fn subblock_transactions_are_rejected_in_every_block_phase() {
        let subblock = subblock_tx();
        assert!(subblock.has_sub_block_nonce_key_prefix());

        for phase in [
            ZoneBlockPhase::AwaitingAdvanceTempo,
            ZoneBlockPhase::Executing,
            ZoneBlockPhase::WithdrawalsFinalized,
        ] {
            let error = phase.validate_transaction(&subblock).unwrap_err();
            assert_eq!(
                error.to_string(),
                "subblock transactions are not supported in zone blocks"
            );
        }
    }

    #[test]
    fn withdrawal_finalization_is_the_last_transaction() {
        let finalize = finalize_withdrawal_batch_tx();
        let ordinary = ordinary_tx(Address::ZERO, Bytes::new());
        let advance_tempo = advance_tempo_tx();
        let mut phase = ZoneBlockPhase::Executing;

        let next_phase = phase.validate_transaction(&finalize).unwrap();
        assert_eq!(phase, ZoneBlockPhase::Executing);

        phase.advance_to(next_phase);
        for tx in [&ordinary, &finalize, &advance_tempo] {
            let error = phase.validate_transaction(tx).unwrap_err();
            assert_eq!(
                error.to_string(),
                "finalizeWithdrawalBatch must be the last transaction in a zone block"
            );
        }
    }

    #[test]
    fn zone_block_phase_transition_table_is_exhaustive() {
        let advance = advance_tempo_tx();
        let regular = ordinary_tx(Address::ZERO, Bytes::new());
        let finalize = finalize_withdrawal_batch_tx();
        let unexpected_system = system_tx(Address::ZERO, Bytes::new());

        assert_eq!(
            ZoneBlockPhase::AwaitingAdvanceTempo
                .validate_transaction(&advance)
                .unwrap(),
            ZoneBlockPhase::Executing
        );
        for tx in [&regular, &finalize, &unexpected_system] {
            assert_eq!(
                ZoneBlockPhase::AwaitingAdvanceTempo
                    .validate_transaction(tx)
                    .unwrap_err()
                    .to_string(),
                "advanceTempo must be the first transaction in a zone block"
            );
        }

        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&regular)
                .unwrap(),
            ZoneBlockPhase::Executing
        );
        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&finalize)
                .unwrap(),
            ZoneBlockPhase::WithdrawalsFinalized
        );
        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&advance)
                .unwrap_err()
                .to_string(),
            "advanceTempo must only execute once per zone block"
        );
        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&unexpected_system)
                .unwrap_err()
                .to_string(),
            "system transactions after advanceTempo must call \
             ZoneOutbox.finalizeWithdrawalBatch"
        );

        for tx in [&advance, &regular, &finalize, &unexpected_system] {
            assert_eq!(
                ZoneBlockPhase::WithdrawalsFinalized
                    .validate_transaction(tx)
                    .unwrap_err()
                    .to_string(),
                "finalizeWithdrawalBatch must be the last transaction in a zone block"
            );
        }
    }

    #[test]
    fn discarded_finalization_and_stale_results_do_not_regress_phase() {
        let finalize = finalize_withdrawal_batch_tx();
        let ordinary = ordinary_tx(Address::ZERO, Bytes::new());
        let mut phase = ZoneBlockPhase::Executing;

        let ordinary_phase = phase.validate_transaction(&ordinary).unwrap();
        let finalized_phase = phase.validate_transaction(&finalize).unwrap();
        assert_eq!(phase, ZoneBlockPhase::Executing);

        phase.advance_to(finalized_phase);
        phase.advance_to(ordinary_phase);
        assert_eq!(phase, ZoneBlockPhase::WithdrawalsFinalized);
    }

    #[test]
    fn non_system_selector_lookalikes_are_regular_transactions() {
        let advance_lookalike = ordinary_tx(ZONE_INBOX_ADDRESS, ADVANCE_TEMPO_SELECTOR.into());
        let finalize_lookalike = ordinary_tx(
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::finalizeWithdrawalBatchCall {
                count: U256::ZERO,
                blockNumber: 1,
                encryptedSenders: vec![],
            }
            .abi_encode()
            .into(),
        );

        assert_eq!(
            ZoneTransactionKind::classify(&advance_lookalike),
            ZoneTransactionKind::Regular
        );
        assert_eq!(
            ZoneTransactionKind::classify(&finalize_lookalike),
            ZoneTransactionKind::Regular
        );
        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&advance_lookalike)
                .unwrap(),
            ZoneBlockPhase::Executing
        );
        assert_eq!(
            ZoneBlockPhase::Executing
                .validate_transaction(&finalize_lookalike)
                .unwrap(),
            ZoneBlockPhase::Executing
        );
    }

    #[test]
    fn reverted_advance_tempo_does_not_satisfy_block_guard() {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let child = TempoHeader {
            inner: Header {
                parent_hash: genesis_hash,
                number: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut db = InMemoryDB::default();
        db.insert_account_storage(TEMPO_STATE_ADDRESS, TEMPO_BLOCK_HASH, genesis_hash.into())
            .unwrap();
        db.insert_account_storage(TEMPO_STATE_ADDRESS, TEMPO_BLOCK_NUMBER_SLOT, U256::ZERO)
            .unwrap();
        let mut zone_genesis = DEV.genesis().clone();
        zone_genesis.config.chain_id = zone_chain_id(DEV.chain_id(), 1).unwrap();
        let chain_spec = std::sync::Arc::new(ZoneChainSpec::from_genesis(zone_genesis).unwrap());
        let factory = ZoneEvmFactory::new(MockL1Reader::default(), Address::ZERO);
        let evm = factory.create_evm(db, EvmEnv::default());
        let ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: B256::ZERO,
                parent_beacon_block_root: None,
                ommers: &[],
                withdrawals: None,
                extra_data: Bytes::new(),
                tx_count_hint: Some(1),
                slot_number: None,
            },
            general_gas_limit: 0,
            shared_gas_limit: 0,
            consensus_context: None,
        };
        let mut executor = ZoneBlockExecutor::new(evm, ctx, &chain_spec);

        // The header is the valid next checkpoint, but a decryption entry without an encrypted
        // deposit makes the Inbox precompile revert after attempting the checkpoint transition.
        let calldata = IZoneInbox::advanceTempoCall {
            header: alloy_rlp::encode(&child).into(),
            deposits: Vec::new(),
            decryptions: vec![DecryptionData {
                sharedSecret: B256::ZERO,
                sharedSecretYParity: 2,
                cpProof: ChaumPedersenProof {
                    s: B256::ZERO,
                    c: B256::ZERO,
                },
            }],
            enabledTokens: Vec::new(),
        }
        .abi_encode();
        let tx = Recovered::new_unchecked(
            system_tx(ZONE_INBOX_ADDRESS, calldata.into()),
            TEMPO_SYSTEM_TX_SENDER,
        );
        let error = executor.execute_transaction_without_commit(tx).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("system transaction execution failed"),
            "unexpected error: {error}"
        );
        let finish_error = match executor.finish() {
            Ok(_) => panic!("reverted advanceTempo unexpectedly satisfied the block guard"),
            Err(error) => error,
        };
        assert_eq!(
            finish_error.to_string(),
            "zone block is missing its advanceTempo system transaction"
        );
    }

    #[test]
    fn clears_only_prewarming_expiring_nonce_index() {
        let mut tx_env = TempoTxEnv {
            tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                valid_before: Some(123),
                expiring_nonce_idx: Some(3),
                ..Default::default()
            })),
            ..Default::default()
        };

        if let Some(tempo_tx_env) = tx_env.tempo_tx_env.as_mut() {
            tempo_tx_env.expiring_nonce_idx = None;
        }

        let tempo_tx_env = tx_env.tempo_tx_env.unwrap();
        assert_eq!(tempo_tx_env.expiring_nonce_idx, None);
        assert_eq!(tempo_tx_env.valid_before, Some(123));
    }

    /// Simulates the zone executor's per-tx validator token override and runs
    /// the full fee lifecycle across multiple TIP-20 tokens, verifying:
    ///
    /// 1. Default validator token is PATH_USD (no explicit preference set).
    /// 2. No FeeAMM liquidity exists for any token pair.
    /// 3. Paying fees in betaUSD, gammaUSD, and pathUSD all succeed when the
    ///    validator token is overridden per-tx.
    /// 4. Fees are credited in the user's token (no conversion).
    /// 5. FeeAMM pool reserves remain zero throughout.
    #[test]
    fn multi_token_fees_with_validator_override() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let sequencer = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Deploy three tokens.
            let path_usd = TIP20Setup::create("PathUSD", "pUSD", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10_000_000u64))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;
            let beta_usd = TIP20Setup::create("BetaUSD", "bUSD", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10_000_000u64))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;
            let gamma_usd = TIP20Setup::create("GammaUSD", "gUSD", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10_000_000u64))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let fee_manager = TipFeeManager::new();

            // 1. Validator token defaults to PATH_USD.
            assert_eq!(
                fee_manager.get_validator_token(sequencer)?,
                DEFAULT_FEE_TOKEN
            );

            // 2. No FeeAMM pools exist.
            for (a, b) in [
                (beta_usd.address(), DEFAULT_FEE_TOKEN),
                (gamma_usd.address(), DEFAULT_FEE_TOKEN),
                (beta_usd.address(), gamma_usd.address()),
            ] {
                let pool = fee_manager.pools[PoolKey::new(a, b).get_id()].read()?;
                assert_eq!(pool.reserve_user_token, 0);
                assert_eq!(pool.reserve_validator_token, 0);
            }

            // 3. Three transactions, each paying in a different token.
            let txs = [
                (
                    beta_usd.address(),
                    U256::from(5_000u64),
                    U256::from(3_000u64),
                ),
                (
                    gamma_usd.address(),
                    U256::from(8_000u64),
                    U256::from(7_000u64),
                ),
                (
                    path_usd.address(),
                    U256::from(4_000u64),
                    U256::from(2_000u64),
                ),
            ];

            let mut fee_manager = TipFeeManager::new();
            for (token, max, used) in &txs {
                // Zone executor override: validatorTokens[sequencer] = fee_token.
                fee_manager.validator_tokens[sequencer].write(*token)?;

                fee_manager.collect_fee_pre_tx(user, *token, *max, sequencer, false)?;
                fee_manager.collect_fee_post_tx(user, *used, *max - *used, *token, sequencer)?;
            }

            // 4. Fees credited per-token — no conversion happened.
            for (token, _, used) in &txs {
                let collected = fee_manager.collected_fees[sequencer][*token].read()?;
                assert_eq!(collected, *used, "fees should be credited in {token}");
            }

            // 5. FeeAMM pools still empty — never touched.
            for (a, b) in [
                (beta_usd.address(), DEFAULT_FEE_TOKEN),
                (gamma_usd.address(), DEFAULT_FEE_TOKEN),
                (beta_usd.address(), gamma_usd.address()),
            ] {
                let pool = fee_manager.pools[PoolKey::new(a, b).get_id()].read()?;
                assert_eq!(
                    pool.reserve_user_token, 0,
                    "pool {a}-{b} user reserve should be 0"
                );
                assert_eq!(
                    pool.reserve_validator_token, 0,
                    "pool {a}-{b} validator reserve should be 0"
                );
            }

            Ok(())
        })
    }

    /// Validator token slot computation is deterministic and the storage
    /// write produces the expected value when read back via TipFeeManager.
    #[test]
    fn validator_token_slot_roundtrip() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sequencer = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            // Write via the Mapping handler (what the executor does via journal sstore).
            fee_manager.validator_tokens[sequencer].write(token)?;

            // Read back via TipFeeManager API.
            let read_back = fee_manager.get_validator_token(sequencer)?;
            assert_eq!(read_back, token);

            Ok(())
        })
    }
}
