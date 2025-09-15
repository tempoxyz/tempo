//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod evm;
use std::{convert::Infallible, sync::Arc};

use alloy_evm::eth::EthBlockExecutorFactory;
use alloy_primitives::Bytes;
pub use evm::TempoEvmFactory;
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_evm::{
    self, ConfigureEngineEvm, ConfigureEvm, EvmEnv, EvmEnvFor, ExecutableTxIterator,
    ExecutionCtxFor, NextBlockEnvAttributes, eth::EthBlockExecutionCtx,
};
use reth_primitives_traits::{Header, SealedBlock, SealedHeader, SignedTransaction};
use tempo_payload_types::TempoExecutionData;

use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig, RethReceiptBuilder};
use tempo_chainspec::TempoChainSpec;

/// Tempo-related EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig {
    /// Inner evm config
    pub inner: EthEvmConfig<TempoChainSpec, TempoEvmFactory>,
}

impl TempoEvmConfig {
    /// Create a new [`TempoEvmConfig`] with the given chain spec and EVM factory.
    pub fn new(chain_spec: Arc<TempoChainSpec>, evm_factory: TempoEvmFactory) -> Self {
        let inner = EthEvmConfig::new_with_evm_factory(chain_spec, evm_factory);
        Self { inner }
    }

    /// Create a new [`TempoEvmConfig`] with the given chain spec and default EVM factory.
    pub fn new_with_default_factory(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self::new(chain_spec, TempoEvmFactory::default())
    }

    /// Returns the chain spec
    pub const fn chain_spec(&self) -> &Arc<TempoChainSpec> {
        self.inner.chain_spec()
    }

    /// Returns the inner EVM config
    pub const fn inner(&self) -> &EthEvmConfig<TempoChainSpec, TempoEvmFactory> {
        &self.inner
    }

    /// Sets the extra data for the block assembler.
    pub fn with_extra_data(mut self, extra_data: Bytes) -> Self {
        self.inner = self.inner.with_extra_data(extra_data.clone());
        self.inner.block_assembler.extra_data = extra_data;
        self
    }
}

impl ConfigureEvm for TempoEvmConfig {
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory =
        EthBlockExecutorFactory<RethReceiptBuilder, Arc<TempoChainSpec>, TempoEvmFactory>;
    type BlockAssembler = EthBlockAssembler<TempoChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self.inner.block_executor_factory()
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        self.inner.block_assembler()
    }

    fn evm_env(&self, header: &Header) -> EvmEnv {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(&self, block: &'a SealedBlock<Block>) -> EthBlockExecutionCtx<'a> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> EthBlockExecutionCtx<'_> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

impl ConfigureEngineEvm<TempoExecutionData> for TempoEvmConfig {
    fn evm_env_for_payload(&self, payload: &TempoExecutionData) -> EvmEnvFor<Self> {
        self.evm_env(&payload.0)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a TempoExecutionData,
    ) -> ExecutionCtxFor<'a, Self> {
        self.context_for_block(&payload.0)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> impl ExecutableTxIterator<Self> {
        payload
            .0
            .body()
            .transactions
            .clone()
            .into_iter()
            .map(|tx| tx.try_recover().map(|signer| tx.with_signer(signer)))
    }
}
