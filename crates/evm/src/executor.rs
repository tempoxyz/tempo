use std::borrow::Cow;

use alloy_consensus::{Header, Transaction, TxReceipt};
use alloy_eips::{Encodable2718, eip4895::Withdrawals};
use alloy_primitives::B256;
use reth::revm::{Inspector, State};
use reth_chainspec::{ChainHardforks, ChainSpec, EthereumHardforks, Hardforks};
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
use reth_evm_ethereum::RethReceiptBuilder;

use crate::TempoEvmFactory;

#[derive(Debug, Clone, Default, Copy)]
pub struct TempoBlockExecutorFactory<
    R = AlloyReceiptBuilder,
    Spec = ChainSpec,
    EvmFactory = TempoEvmFactory,
> {
    /// Receipt builder.
    receipt_builder: R,
    /// Chain specification.
    spec: Spec,
    /// EVM factory.
    evm_factory: EvmFactory,
}

impl<R, Spec, EvmFactory> TempoBlockExecutorFactory<R, Spec, EvmFactory> {
    /// Creates a new [`TempoBlockExecutorFactory`] with the given spec, [`EvmFactory`], and
    /// [`ReceiptBuilder`].
    pub const fn new(receipt_builder: R, spec: Spec, evm_factory: EvmFactory) -> Self {
        Self {
            receipt_builder,
            spec,
            evm_factory,
        }
    }

    /// Exposes the receipt builder.
    pub const fn receipt_builder(&self) -> &R {
        &self.receipt_builder
    }

    /// Exposes the chain specification.
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Exposes the EVM factory.
    pub const fn evm_factory(&self) -> &EvmFactory {
        &self.evm_factory
    }
}

impl<R, Spec, EvmF> BlockExecutorFactory for TempoBlockExecutorFactory<R, Spec, EvmF>
where
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt> + Copy,
    Spec: EthereumHardforks + Clone,
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
        TempoBlockExecutor::new(evm, ctx, self.spec.clone(), self.receipt_builder)
    }
}

/// Context for Tempo block execution.
#[derive(Debug, Default, Clone)]
pub struct TempoBlockExecutionCtx<'a> {
    /// Parent block hash.
    pub parent_hash: B256,
    /// Parent beacon block root.
    pub parent_beacon_block_root: Option<B256>,
    /// Block ommers
    pub ommers: &'a [Header],
    /// Block withdrawals.
    pub withdrawals: Option<Cow<'a, Withdrawals>>,
}

/// Block executor for Tempo.
#[derive(Debug)]
pub struct TempoBlockExecutor<'a, Evm, R: ReceiptBuilder, Spec> {
    /// Spec.
    spec: Spec,
    /// Receipt builder.
    receipt_builder: R,
    /// Context for block execution.
    ctx: EthBlockExecutionCtx<'a>,
    /// The EVM used by executor.
    evm: Evm,
    /// Receipts of executed transactions.
    receipts: Vec<R::Receipt>,
    /// Total gas used by executed transactions.
    gas_used: u64,
    /// Utility to call system smart contracts.
    system_caller: SystemCaller<Spec>,
}

impl<'a, E, R, Spec> TempoBlockExecutor<'a, E, R, Spec>
where
    E: Evm,
    R: ReceiptBuilder,
    Spec: EthereumHardforks + Clone,
{
    pub fn new(evm: E, ctx: EthBlockExecutionCtx<'a>, spec: Spec, receipt_builder: R) -> Self {
        Self {
            spec: spec.clone(),
            receipt_builder,
            ctx,
            evm,
            receipts: Vec::new(),
            gas_used: 0,
            system_caller: SystemCaller::new(spec),
        }
    }
}

impl<'a, 'db, DB, E, R, Spec> BlockExecutor for TempoBlockExecutor<'a, E, R, Spec>
where
    DB: Database + 'db,
    E: Evm<
            DB = &'db mut State<DB>,
            Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
        >,
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt>,
    Spec: EthereumHardforks + Clone,
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
