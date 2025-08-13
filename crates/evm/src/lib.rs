pub mod build;
pub mod executor;

use crate::{
    build::TempoBlockAssembler,
    executor::{TempoBlockExecutionCtx, TempoBlockExecutorFactory},
};
use alloy_consensus::{Block, EthBlock, Header};
use reth::revm::{
    Inspector,
    context::{
        TxEnv,
        result::{EVMError, HaltReason},
    },
    inspector::NoOpInspector,
    primitives::hardfork::SpecId,
};
use reth_chainspec::{BaseFeeParams, ChainSpec, EthChainSpec, EthereumHardforks, Hardforks};
use reth_evm::{
    ConfigureEvm, Database, EthEvm, EthEvmFactory, EvmEnv, EvmFactory, FromRecoveredTx,
    FromTxWithEncoded, NextBlockEnvAttributes,
    eth::{
        EthBlockExecutionCtx, EthEvmContext,
        receipt_builder::{AlloyReceiptBuilder, ReceiptBuilder},
    },
    precompiles::PrecompilesMap,
};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig, RethReceiptBuilder};
use reth_primitives::{EthPrimitives, NodePrimitives, SealedBlock, SealedHeader, Transaction};
use reth_primitives_traits::{Receipt, SignedTransaction};
use std::{convert::Infallible, fmt::Debug, sync::Arc};
use tempo_precompiles::precompiles::extend_tempo_precompiles;

/// Tempo EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig<
    C = ChainSpec,
    N: NodePrimitives = EthPrimitives,
    R: ReceiptBuilder = RethReceiptBuilder,
> {
    pub executor_factory: TempoBlockExecutorFactory<R, Arc<C>>,
    pub block_assembler: EthBlockAssembler<C>,
    _pd: core::marker::PhantomData<N>,
}

impl<ChainSpec: EthereumHardforks, N: NodePrimitives, R: ReceiptBuilder>
    TempoEvmConfig<ChainSpec, N, R>
{
    /// Creates a new [`TempoEvmConfig`] with the given chain spec.
    pub fn new(chain_spec: Arc<ChainSpec>, receipt_builder: R) -> Self {
        Self {
            executor_factory: TempoBlockExecutorFactory::new(
                receipt_builder,
                chain_spec.clone(),
                TempoEvmFactory::default(),
            ),
            block_assembler: EthBlockAssembler::new(chain_spec),
            _pd: core::marker::PhantomData,
        }
    }
}

impl ConfigureEvm for TempoEvmConfig {
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = TempoBlockExecutorFactory<RethReceiptBuilder, Arc<ChainSpec>>;
    type BlockAssembler = EthBlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> EvmEnv {
        EvmEnv::default()
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        Ok(EvmEnv::default())
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<reth_ethereum_primitives::Block>,
    ) -> EthBlockExecutionCtx<'a> {
        todo!()
        // EthBlockExecutionCtx::default()
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> EthBlockExecutionCtx {
        todo!()
        // TempoBlockExecutionCtx::default()
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
