pub mod executor;

use crate::executor::TempoBlockExecutorFactory;
use reth::revm::{
    Inspector,
    context::{
        TxEnv,
        result::{EVMError, HaltReason},
    },
    inspector::NoOpInspector,
    primitives::hardfork::SpecId,
};
use reth_chainspec::{ChainSpec, Hardforks};
use reth_evm::{
    Database, EthEvm, EthEvmFactory, EvmEnv, EvmFactory,
    eth::{EthEvmContext, receipt_builder::AlloyReceiptBuilder},
    precompiles::PrecompilesMap,
};
use reth_evm_ethereum::EthBlockAssembler;
use reth_primitives::{EthPrimitives, NodePrimitives};
use std::sync::Arc;
use tempo_precompiles::precompiles::extend_tempo_precompiles;

/// Tempo EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig<C = ChainSpec, N: NodePrimitives = EthPrimitives, R = AlloyReceiptBuilder>
{
    pub executor_factory: TempoBlockExecutorFactory<R, Arc<C>>,
    pub block_assembler: EthBlockAssembler<C>,
    _pd: core::marker::PhantomData<N>,
}

impl<ChainSpec: Hardforks, N: NodePrimitives, R> TempoEvmConfig<ChainSpec, N, R> {
    /// Creates a new [`TempoEvmConfig`] with the given chain spec.
    pub fn new(chain_spec: Arc<ChainSpec>, receipt_builder: R) -> Self {
        Self {
            block_assembler: EthBlockAssembler::new(chain_spec.clone()),
            executor_factory: TempoBlockExecutorFactory::new(
                receipt_builder,
                chain_spec,
                TempoEvmFactory::default(),
            ),
            _pd: core::marker::PhantomData,
        }
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
