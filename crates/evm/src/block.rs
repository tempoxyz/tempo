use crate::{TempoBlockExecutionCtx, evm::TempoEvm};
use alloy_consensus::{Transaction, transaction::TxHashRef};
use alloy_evm::{
    Database, Evm,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockValidationError,
        ExecutableTx, OnStateHook,
    },
    eth::{
        EthBlockExecutor,
        receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
    },
};
use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use reth_revm::{Inspector, State, context::result::ResultAndState};
use tempo_chainspec::TempoChainSpec;
use tempo_precompiles::{
    STABLECOIN_EXCHANGE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP20_REWARDS_REGISTRY_ADDRESS,
    stablecoin_exchange::IStablecoinExchange, tip_fee_manager::IFeeManager,
    tip20_rewards_registry::ITIP20RewardsRegistry,
};
use tempo_primitives::{TempoReceipt, TempoTxEnvelope};
use tempo_revm::evm::TempoContext;
use tracing::trace;

/// Builder for [`TempoReceipt`].
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub(crate) struct TempoReceiptBuilder;

impl ReceiptBuilder for TempoReceiptBuilder {
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;

    fn build_receipt<E: Evm>(
        &self,
        ctx: ReceiptBuilderCtx<'_, Self::Transaction, E>,
    ) -> Self::Receipt {
        let ReceiptBuilderCtx {
            tx,
            result,
            cumulative_gas_used,
            ..
        } = ctx;
        TempoReceipt {
            tx_type: tx.tx_type(),
            // Success flag was added in `EIP-658: Embedding transaction status code in
            // receipts`.
            success: result.is_success(),
            cumulative_gas_used,
            logs: result.into_logs(),
        }
    }
}

/// Block executor for Tempo. Wraps an inner [`EthBlockExecutor`].
pub(crate) struct TempoBlockExecutor<'a, DB: Database, I> {
    pub(crate) inner: EthBlockExecutor<
        'a,
        TempoEvm<&'a mut State<DB>, I>,
        &'a TempoChainSpec,
        TempoReceiptBuilder,
    >,

    general_gas_left: u64,
    seen_fee_manager_system_tx: bool,
    seen_stablecoin_dex_system_tx: bool,
    seen_tip20_rewards_registry_system_tx: bool,
}

impl<'a, DB, I> TempoBlockExecutor<'a, DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<&'a mut State<DB>>>,
{
    pub(crate) fn new(
        evm: TempoEvm<&'a mut State<DB>, I>,
        ctx: TempoBlockExecutionCtx<'a>,
        chain_spec: &'a TempoChainSpec,
    ) -> Self {
        Self {
            general_gas_left: ctx.general_gas_limit,
            inner: EthBlockExecutor::new(
                evm,
                ctx.inner,
                chain_spec,
                TempoReceiptBuilder::default(),
            ),
            seen_fee_manager_system_tx: false,
            seen_stablecoin_dex_system_tx: false,
            seen_tip20_rewards_registry_system_tx: false,
        }
    }

    /// Validates a system transaction.
    fn validate_system_tx(&self, tx: &TempoTxEnvelope) -> Result<(), BlockValidationError> {
        let block = self.evm().block().number.to_be_bytes_vec();
        let to = tx.to().unwrap_or_default();
        if to == TIP_FEE_MANAGER_ADDRESS {
            let fee_input = IFeeManager::executeBlockCall
                .abi_encode()
                .into_iter()
                .chain(block)
                .collect::<Bytes>();
            if *tx.input() == fee_input && self.seen_fee_manager_system_tx {
                Err(BlockValidationError::msg(
                    "duplicate fee manager system transaction",
                ))
            } else {
                Ok(())
            }
        } else if to == STABLECOIN_EXCHANGE_ADDRESS {
            let dex_input = IStablecoinExchange::executeBlockCall {}
                .abi_encode()
                .into_iter()
                .chain(block)
                .collect::<Bytes>();
            if *tx.input() == dex_input && self.seen_stablecoin_dex_system_tx {
                Err(BlockValidationError::msg(
                    "duplicate stablecoin DEX system transaction",
                ))
            } else {
                Ok(())
            }
        } else if to == TIP20_REWARDS_REGISTRY_ADDRESS {
            let finalize_streams_input = ITIP20RewardsRegistry::finalizeStreamsCall {}
                .abi_encode()
                .into_iter()
                .chain(block)
                .collect::<Bytes>();
            if *tx.input() == finalize_streams_input && self.seen_tip20_rewards_registry_system_tx {
                Err(BlockValidationError::msg(
                    "duplicate stablecoin TIP20 rewards registry system transaction",
                ))
            } else {
                Ok(())
            }
        } else {
            Err(BlockValidationError::msg("invalid system transaction"))
        }
    }
}

impl<'a, DB, I> BlockExecutor for TempoBlockExecutor<'a, DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<&'a mut State<DB>>>,
{
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;
    type Evm = TempoEvm<&'a mut State<DB>, I>;

    fn apply_pre_execution_changes(&mut self) -> Result<(), alloy_evm::block::BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<ResultAndState, BlockExecutionError> {
        let is_payment = tx.tx().is_payment();
        let is_system = tx.tx().is_system_tx();
        let gas_limit = tx.tx().gas_limit();

        if is_system {
            self.validate_system_tx(tx.tx())?;
        } else if self.seen_fee_manager_system_tx
            || self.seen_stablecoin_dex_system_tx
            || self.seen_tip20_rewards_registry_system_tx
        {
            trace!(target: "tempo::block", tx_hash = ?tx.tx().tx_hash(), "Rejecting: regular transaction after system transaction");
            return Err(BlockValidationError::msg(
                "regular transaction can't follow system transaction",
            )
            .into());
        } else if !is_payment && gas_limit > self.general_gas_left {
            trace!(
                target: "tempo::block",
                gas_limit = gas_limit,
                tx_hash = ?tx.tx().tx_hash(),
                general_gas_left = self.general_gas_left,
                "Rejecting: non-payment gas limit exceeded"
            );
            return Err(BlockValidationError::msg(
                "transaction gas limit exceeds non-payment gas limit",
            )
            .into());
        }

        self.inner.execute_transaction_without_commit(tx)
    }

    fn commit_transaction(
        &mut self,
        output: ResultAndState,
        tx: impl ExecutableTx<Self>,
    ) -> Result<u64, BlockExecutionError> {
        let gas_used = self.inner.commit_transaction(output, &tx)?;

        let inner_tx = tx.tx();
        if inner_tx.is_system_tx() {
            match inner_tx.to() {
                Some(addr) if addr == TIP_FEE_MANAGER_ADDRESS => {
                    self.seen_fee_manager_system_tx = true;
                }
                Some(addr) if addr == STABLECOIN_EXCHANGE_ADDRESS => {
                    self.seen_stablecoin_dex_system_tx = true;
                }
                Some(addr) if addr == TIP20_REWARDS_REGISTRY_ADDRESS => {
                    self.seen_tip20_rewards_registry_system_tx = true;
                }
                _ => {}
            }
        }

        self.general_gas_left = self.general_gas_left.saturating_sub(gas_used);

        Ok(gas_used)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        if !self.seen_fee_manager_system_tx {
            return Err(BlockValidationError::msg(
                "fee manager system transaction not seen in block",
            )
            .into());
        }
        if !self.seen_stablecoin_dex_system_tx {
            return Err(BlockValidationError::msg(
                "stablecoin DEX system transaction not seen in block",
            )
            .into());
        }
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}
