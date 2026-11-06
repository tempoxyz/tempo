//! reth's block executor traits for [`TempoBlockExecutor`] and [`TempoReceiptBuilder`], delegating
//! to their evm2 implementations.

use crate::{TempoBlockExecutor, TempoEvm, TempoEvmTypes, TempoReceiptBuilder, TempoTxResult};
use alloy_eip7928::{BlockAccessIndex, BlockAccessList};
use evm2::{
    EvmTypes, TxResult, TxStateChanges,
    block::{
        BlockExecutionError, BundleState, CommitChanges, GasOutput, ReceiptBuilderCtx, StateUpdate,
    },
    evm::Bal,
};
use reth_evm::{BlockExecutionOutput, BlockExecutor, ExecutorTx, ReceiptBuilder, RecoveredTx};
use std::sync::Arc;
use tempo_primitives::{TempoReceipt, TempoTxEnvelope, TempoTxType};

impl ReceiptBuilder for TempoReceiptBuilder {
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;

    fn build_receipt<T: EvmTypes>(
        &self,
        ctx: ReceiptBuilderCtx<TempoTxType, TxResult<T>>,
    ) -> Self::Receipt {
        evm2::block::ReceiptBuilder::build_receipt::<T>(self, ctx)
    }
}

impl<'a> BlockExecutor for TempoBlockExecutor<'a> {
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;
    type Evm = TempoEvm<'a>;
    type TransactionResultWithState = TempoTxResult;
    type BlockAccessList = Bal;

    fn evm(&self) -> &Self::Evm {
        evm2::block::BlockExecutor::evm(self)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        evm2::block::BlockExecutor::evm_mut(self)
    }

    fn set_state_hook(&mut self, hook: impl FnMut(StateUpdate) + Send + 'static) -> bool {
        evm2::block::BlockExecutor::set_state_hook(self, hook)
    }

    fn convert_block_access_list(
        block_access_list: &BlockAccessList,
    ) -> Result<Self::BlockAccessList, BlockExecutionError> {
        Bal::try_from(block_access_list.as_slice()).map_err(BlockExecutionError::other)
    }

    fn set_block_access_list(&mut self, block_access_list: Arc<Self::BlockAccessList>) {
        evm2::block::BlockExecutor::set_block_access_list(self, block_access_list);
    }

    fn set_block_access_index(&mut self, index: BlockAccessIndex) {
        evm2::block::BlockExecutor::set_block_access_index(self, index);
    }

    fn enable_block_access_list_builder(&mut self) {
        evm2::block::BlockExecutor::enable_block_access_list_builder(self);
    }

    fn take_block_access_list(&mut self) -> Option<BlockAccessList> {
        evm2::block::BlockExecutor::take_block_access_list(self).map(Into::into)
    }

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        evm2::block::BlockExecutor::apply_pre_execution_changes(self)
    }

    fn into_state(self) -> BundleState {
        evm2::block::BlockExecutor::into_state(self)
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutorTx<Self>,
        f: impl FnOnce(&TxResult<TempoEvmTypes>, TxStateChanges<'_>) -> CommitChanges,
    ) -> Result<Option<GasOutput>, BlockExecutionError> {
        let (tx_env, recovered) = tx.into_parts();
        evm2::block::BlockExecutor::execute_transaction_with_commit_condition(
            self,
            (tx_env, recovered.tx()),
            f,
        )
    }

    fn validate_transaction_gas_limit(
        &mut self,
        gas_limit: u64,
    ) -> Result<(), BlockExecutionError> {
        evm2::block::BlockExecutor::validate_transaction_gas_limit(self, gas_limit)
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutorTx<Self>,
    ) -> Result<Self::TransactionResultWithState, BlockExecutionError> {
        let (tx_env, recovered) = tx.into_parts();
        evm2::block::BlockExecutor::execute_transaction_without_commit(
            self,
            (tx_env, recovered.tx()),
        )
    }

    fn commit_transaction(
        &mut self,
        output: Self::TransactionResultWithState,
    ) -> Result<GasOutput, BlockExecutionError> {
        evm2::block::BlockExecutor::commit_transaction(self, output)
    }

    fn receipts(&self) -> &[Self::Receipt] {
        evm2::block::BlockExecutor::receipts(self)
    }

    fn finish_with_block_access_list(
        self,
    ) -> Result<(BlockExecutionOutput<Self::Receipt>, Option<BlockAccessList>), BlockExecutionError>
    {
        let (output, bal) = self.finish_with_prepared_block_access_list()?;
        Ok((output, bal.map(Into::into)))
    }

    fn finish_with_prepared_block_access_list(
        self,
    ) -> Result<(BlockExecutionOutput<Self::Receipt>, Option<Bal>), BlockExecutionError> {
        let (output, bal) = evm2::block::BlockExecutor::finish_with_block_access_list(self)?;
        Ok((output.into(), bal))
    }
}
