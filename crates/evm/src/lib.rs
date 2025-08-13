pub mod executor;

use crate::executor::TempoBlockExecutorFactory;
use alloy_consensus::Header;
use reth::revm::{
    Inspector,
    context::{
        TxEnv,
        result::{EVMError, HaltReason},
    },
    inspector::NoOpInspector,
    primitives::hardfork::SpecId,
};
use reth_chainspec::{ChainSpec, EthChainSpec, Hardforks};
use reth_evm::{
    ConfigureEvm, Database, EthEvm, EthEvmFactory, EvmEnv, EvmFactory, NextBlockEnvAttributes,
    eth::{
        EthBlockExecutionCtx, EthEvmContext,
        receipt_builder::{AlloyReceiptBuilder, ReceiptBuilder},
    },
    precompiles::PrecompilesMap,
};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig};
use reth_primitives::{EthPrimitives, NodePrimitives, SealedHeader};
use reth_primitives_traits::{Receipt, SignedTransaction};
use std::{convert::Infallible, fmt::Debug, sync::Arc};
use tempo_precompiles::precompiles::extend_tempo_precompiles;

/// Tempo EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig<
    C = ChainSpec,
    N: NodePrimitives = EthPrimitives,
    R: Debug = AlloyReceiptBuilder,
> {
    pub inner: EthEvmConfig,
    pub executor_factory: TempoBlockExecutorFactory<R, Arc<C>>,
    _pd: core::marker::PhantomData<N>,
}

impl<ChainSpec: Hardforks, N: NodePrimitives, R: Debug> TempoEvmConfig<ChainSpec, N, R> {
    /// Creates a new [`TempoEvmConfig`] with the given chain spec.
    pub fn new(chain_spec: Arc<ChainSpec>, receipt_builder: R) -> Self {
        Self {
            inner: EthEvmConfig::new(chain_spec.clone()),
            executor_factory: TempoBlockExecutorFactory::new(
                receipt_builder,
                chain_spec,
                TempoEvmFactory::default(),
            ),
            _pd: core::marker::PhantomData,
        }
    }
}

// TODO: configure evm for TempoEvmConfig
impl<ChainSpec, N, R> ConfigureEvm for TempoEvmConfig<ChainSpec, N, R>
where
    ChainSpec: EthChainSpec<Header = Header> + Hardforks,
    N: NodePrimitives<
            Receipt = R::Receipt,
            SignedTx = R::Transaction,
            BlockHeader = Header,
            BlockBody = alloy_consensus::BlockBody<R::Transaction>,
            Block = alloy_consensus::Block<R::Transaction>,
        >,
    R: ReceiptBuilder<Receipt: Receipt, Transaction: SignedTransaction> + Debug + Copy,
    Self: Send + Sync + Unpin + Clone + 'static,
{
    type Primitives = N;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = TempoBlockExecutorFactory<R, Arc<ChainSpec>>;
    type BlockAssembler = EthBlockAssembler<ChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> EvmEnv {
        todo!()
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        todo!()
    }

    fn context_for_block<'a>(&self, block: &'a SealedBlock<Block>) -> EthBlockExecutionCtx<'a> {
        todo!()
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> EthBlockExecutionCtx {
        todo!()
    }
}

#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoEvmFactory {
    inner: EthEvmFactory,
}

impl EvmFactory for TempoEvmFactory {
    type Evm<DB: Database, I: Inspector<Self::Context<DB>>> = EthEvm<DB, I, PrecompilesMap>;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Tx = TxEnv;
    type Error<DBError: std::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let mut evm = self.inner.create_evm(db, input);
        extend_tempo_precompiles(&mut evm);
        evm
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let mut evm = self.inner.create_evm_with_inspector(db, input, inspector);
        extend_tempo_precompiles(&mut evm);
        evm
    }
}
