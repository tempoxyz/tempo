use alloy_consensus::{ReceiptEnvelope, TxEnvelope, TxReceipt};
use alloy_eips::Encodable2718;
use reth::revm::{Database, Inspector, State, handler::EthPrecompiles};
use reth_chainspec::{ChainHardforks, Hardforks};
use reth_evm::{
    EthEvm, EvmFactory, FromRecoveredTx, FromTxWithEncoded,
    block::{BlockExecutorFactory, BlockExecutorFor},
    eth::{
        EthBlockExecutionCtx, EthEvmContext,
        receipt_builder::{AlloyReceiptBuilder, ReceiptBuilder},
    },
};
use reth_primitives_traits::Transaction;

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
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt>,
    Spec: Hardforks,
    EvmF: EvmFactory<Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>>,
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
        todo!()
    }
}
