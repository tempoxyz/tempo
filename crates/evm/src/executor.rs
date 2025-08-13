use alloy_consensus::{Transaction, TxReceipt};
use alloy_eips::Encodable2718;
use alloy_primitives::B256;
use reth::revm::{Inspector, State};
use reth_chainspec::{ChainHardforks, Hardforks};
use reth_evm::{
    Database, Evm, EvmFactory, FromRecoveredTx, FromTxWithEncoded,
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, CommitChanges, ExecutableTx, OnStateHook, SystemCaller,
    },
    eth::{
        EthBlockExecutionCtx,
        receipt_builder::{AlloyReceiptBuilder, ReceiptBuilder},
    },
    revm::context::result::ExecutionResult,
};
// use revm::{
//     DatabaseCommit, Inspector,
//     context::result::{ExecutionResult, ResultAndState},
//     database::State,
// };

use crate::TempoEvmFactory;

#[derive(Debug, Clone, Default, Copy)]
pub struct TempoBlockExecutorFactory<
    R = AlloyReceiptBuilder,
    Spec = ChainHardforks,
    EvmFactory = TempoEvmFactory,
> {
    /// Receipt builder.
    receipt_builder: R,
    /// Chain specification.
    spec: Spec,
    /// EVM factory.
    evm_factory: EvmFactory,
}

impl<R, Spec, EvmF> BlockExecutorFactory for TempoBlockExecutorFactory<R, Spec, EvmF>
where
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt> + Copy,
    Spec: Hardforks + Copy,
    EvmF:
        EvmFactory<Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>> + Copy,
    Self: 'static,
{
    type EvmFactory = EvmF;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: EvmF::Evm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<EvmF::Context<&'a mut State<DB>>> + 'a,
    {
        TempoBlockExecutor::new(
            evm,
            TempoBlockExecutionCtx {
                parent_hash: ctx.parent_hash,
            },
            self.spec,
            self.receipt_builder,
        )
    }
}

/// Context for Tempo block execution.
#[derive(Debug, Default, Clone)]
pub struct TempoBlockExecutionCtx {
    /// Parent block hash.
    pub parent_hash: B256,
}

/// Block executor for Tempo.
#[derive(Debug)]
pub struct TempoBlockExecutor<Evm, R: ReceiptBuilder, Spec> {
    /// Spec.
    spec: Spec,
    /// Receipt builder.
    receipt_builder: R,
    /// Context for block execution.
    ctx: TempoBlockExecutionCtx,
    /// The EVM used by executor.
    evm: Evm,
    /// Receipts of executed transactions.
    receipts: Vec<R::Receipt>,
    /// Total gas used by executed transactions.
    gas_used: u64,
    /// Utility to call system smart contracts.
    system_caller: SystemCaller<Spec>,
}

impl<E, R, Spec> TempoBlockExecutor<E, R, Spec>
where
    E: Evm,
    R: ReceiptBuilder,
    Spec: Hardforks + Copy,
{
    pub fn new(evm: E, ctx: TempoBlockExecutionCtx, spec: Spec, receipt_builder: R) -> Self {
        Self {
            spec,
            receipt_builder,
            ctx,
            evm,
            receipts: Vec::new(),
            gas_used: 0,
            system_caller: SystemCaller::new(spec),
        }
    }
}

impl<'db, DB, E, R, Spec> BlockExecutor for TempoBlockExecutor<E, R, Spec>
where
    DB: Database + 'db,
    E: Evm<
            DB = &'db mut State<DB>,
            Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
        >,
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt>,
    Spec: Hardforks,
{
    type Transaction = R::Transaction;
    type Receipt = R::Receipt;
    type Evm = E;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        Ok(())
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        _tx: impl ExecutableTx<Self>,
        _f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        Ok(None)
    }

    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<R::Receipt>), BlockExecutionError> {
        Ok((
            self.evm,
            BlockExecutionResult {
                receipts: self.receipts,
                requests: Default::default(),
                gas_used: 0,
            },
        ))
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.system_caller.with_state_hook(hook);
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        &mut self.evm
    }

    fn evm(&self) -> &Self::Evm {
        &self.evm
    }
}
