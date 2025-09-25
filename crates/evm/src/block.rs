use crate::{TempoBlockExecutionCtx, evm::TempoEvm};
use alloy_consensus::Transaction;
use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use reth_evm::{
    Database, Evm, OnStateHook,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockValidationError,
        ExecutableTx,
    },
    eth::{
        EthBlockExecutor,
        receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
    },
};
use reth_revm::{Inspector, State, context::result::ResultAndState};
use tempo_chainspec::TempoChainSpec;
use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, contracts::IFeeManager::executeBlockCall};
use tempo_primitives::{TempoReceipt, TempoTxEnvelope};
use tempo_revm::evm::TempoContext;
use tracing::{debug, trace};

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

    non_payment_gas_left: u64,

    seen_payment_tx: bool,
    seen_system_tx: bool,
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
            non_payment_gas_left: ctx.non_payment_gas_limit,
            inner: EthBlockExecutor::new(
                evm,
                ctx.inner,
                chain_spec,
                TempoReceiptBuilder::default(),
            ),
            seen_payment_tx: false,
            seen_system_tx: false,
        }
    }

    /// Validates a system transaction.
    fn validate_system_tx(&self, tx: &TempoTxEnvelope) -> Result<(), BlockValidationError> {
        // todo: we likely want to change this once we have more system transactions
        if self.seen_system_tx {
            return Err(BlockValidationError::msg(
                "only expecting one system transaction per block",
            ));
        }

        let expected_calldata = executeBlockCall
            .abi_encode()
            .into_iter()
            .chain(self.evm().block().number.to_be_bytes_vec())
            .collect::<Bytes>();

        if tx.to() != Some(TIP_FEE_MANAGER_ADDRESS) || tx.input() != &expected_calldata {
            return Err(BlockValidationError::msg(
                "system transaction is not a fee manager execute block transaction",
            ));
        }

        Ok(())
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

    fn apply_pre_execution_changes(&mut self) -> Result<(), reth_evm::block::BlockExecutionError> {
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
        } else if self.seen_system_tx {
            debug!(target: "tempo::block", "Rejecting: regular transaction after system transaction");
            return Err(BlockValidationError::msg(
                "regular transaction can't follow system transaction",
            )
            .into());
        } else if self.seen_payment_tx && !is_payment {
            debug!(target: "tempo::block", "Rejecting: non-payment transaction after payment transaction");
            return Err(BlockValidationError::msg(
                "non-payment transaction can't follow payment transaction",
            )
            .into());
        } else if !is_payment && gas_limit > self.non_payment_gas_left {
            debug!(
                target: "tempo::block",
                gas_limit = gas_limit,
                non_payment_gas_left = self.non_payment_gas_left,
                "Rejecting: non-payment gas limit exceeded"
            );
            return Err(BlockValidationError::msg(
                "transaction gas limit exceeds non-payment gas limit",
            )
            .into());
        }

        trace!(target: "tempo::block", "Transaction validation passed, executing");
        self.inner.execute_transaction_without_commit(tx)
    }

    fn commit_transaction(
        &mut self,
        output: ResultAndState,
        tx: impl ExecutableTx<Self>,
    ) -> Result<u64, BlockExecutionError> {
        let gas_used = self.inner.commit_transaction(output, &tx)?;

        let is_payment = tx.tx().is_payment();
        let is_system = tx.tx().is_system_tx();

        debug!(
            target: "tempo::block",
            is_payment = is_payment,
            is_system = is_system,
            gas_used = gas_used,
            non_payment_gas_left_before = self.non_payment_gas_left,
            "Committing transaction"
        );

        if is_system {
            self.seen_system_tx = true;
            debug!(target: "tempo::block", "Marked system transaction as seen");
        } else if is_payment {
            self.seen_payment_tx = true;
            debug!(target: "tempo::block", "Marked payment transaction as seen");
        } else {
            self.non_payment_gas_left = self.non_payment_gas_left.saturating_sub(gas_used);
            debug!(
                target: "tempo::block",
                non_payment_gas_left_after = self.non_payment_gas_left,
                "Updated non-payment gas left"
            );
        }

        Ok(gas_used)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        if !self.seen_system_tx {
            return Err(BlockValidationError::msg("system transaction not seen in block").into());
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
