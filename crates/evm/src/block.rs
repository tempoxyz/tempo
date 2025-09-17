use crate::evm::TempoEvm;
use alloy_consensus::Transaction;
use alloy_sol_types::SolCall;
use reth_evm::{
    Database, Evm, OnStateHook,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockValidationError,
        ExecutableTx,
    },
    eth::{
        EthBlockExecutionCtx, EthBlockExecutor,
        receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
    },
};
use reth_revm::{Inspector, State, context::result::ResultAndState};
use tempo_chainspec::TempoChainSpec;
use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, contracts::IFeeManager::executeBlockCall};
use tempo_primitives::{TempoReceipt, TempoTxEnvelope};
use tempo_revm::evm::TempoContext;

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

    seen_system_tx: bool,
}

impl<'a, DB, I> TempoBlockExecutor<'a, DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<&'a mut State<DB>>>,
{
    pub(crate) fn new(
        evm: TempoEvm<&'a mut State<DB>, I>,
        ctx: EthBlockExecutionCtx<'a>,
        chain_spec: &'a TempoChainSpec,
    ) -> Self {
        Self {
            inner: EthBlockExecutor::new(evm, ctx, chain_spec, TempoReceiptBuilder::default()),
            seen_system_tx: false,
        }
    }

    /// Validates a system transaction.
    fn validate_system_tx(&self, tx: &TempoTxEnvelope) -> Result<(), BlockValidationError> {
        // todo: we likely want to change this once we have more system transactions
        if self.seen_system_tx {
            // todo: change once <https://github.com/alloy-rs/evm/pull/176> is merged
            return Err(BlockValidationError::DepositRequestDecode(
                "only expecting one system transaction per block".to_string(),
            ));
        }

        if tx.to() != Some(TIP_FEE_MANAGER_ADDRESS) || tx.input() != &executeBlockCall.abi_encode()
        {
            // todo: change once <https://github.com/alloy-rs/evm/pull/176> is merged
            return Err(BlockValidationError::DepositRequestDecode(
                "system transaction is not a fee manager execute block transaction".to_string(),
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
        if tx.tx().is_system_tx() {
            self.validate_system_tx(tx.tx())?;
        } else if self.seen_system_tx {
            // todo: change once <https://github.com/alloy-rs/evm/pull/176> is merged
            return Err(BlockValidationError::DepositRequestDecode(
                "regular transaction can't follow system transaction".to_string(),
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

        if tx.tx().is_system_tx() {
            self.seen_system_tx = true;
        }

        Ok(gas_used)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        if !self.seen_system_tx {
            return Err(BlockValidationError::DepositRequestDecode(
                "system transaction not seen in block".to_string(),
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
