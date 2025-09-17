//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod block;
pub mod evm;
use std::{borrow::Cow, convert::Infallible, sync::Arc};

use alloy_primitives::Bytes;
pub use evm::TempoEvmFactory;
use reth_evm::{
    self, ConfigureEngineEvm, ConfigureEvm, Database, EvmEnv, EvmEnvFor, ExecutableTxIterator,
    ExecutionCtxFor, NextBlockEnvAttributes,
    block::{BlockExecutorFactory, BlockExecutorFor},
    eth::{EthBlockExecutionCtx, EthBlockExecutor},
    revm::{Inspector, database::State},
};
use reth_primitives_traits::{Header, SealedBlock, SealedHeader, SignedTransaction};
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::{Block, TempoPrimitives, TempoReceipt, TempoTxEnvelope};

use crate::{block::TempoReceiptBuilder, evm::TempoEvm};
use reth_evm_ethereum::{EthBlockAssembler, EthEvmConfig};
use tempo_chainspec::TempoChainSpec;
use tempo_revm::evm::TempoContext;

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

impl BlockExecutorFactory for TempoEvmConfig {
    type EvmFactory = TempoEvmFactory;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: TempoEvm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<TempoContext<&'a mut State<DB>>> + 'a,
    {
        EthBlockExecutor::new(evm, ctx, self.chain_spec(), TempoReceiptBuilder::default())
    }
}

impl ConfigureEvm for TempoEvmConfig {
    type Primitives = TempoPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory = Self;
    type BlockAssembler = EthBlockAssembler<TempoChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
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
        EthBlockExecutionCtx {
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            ommers: &block.body().ommers,
            withdrawals: block.body().withdrawals.as_ref().map(Cow::Borrowed),
        }
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> EthBlockExecutionCtx<'_> {
        EthBlockExecutionCtx {
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(Cow::Owned),
        }
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
