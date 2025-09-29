//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod assemble;
pub use assemble::TempoBlockAssembler;
mod block;
mod context;
pub use context::{TempoBlockExecutionCtx, TempoNextBlockEnvAttributes};
use tempo_consensus::TempoExtraData;
pub mod evm;
use std::{borrow::Cow, convert::Infallible, sync::Arc};

use alloy_primitives::Bytes;
pub use evm::TempoEvmFactory;
use reth_evm::{
    self, ConfigureEngineEvm, ConfigureEvm, Database, EvmEnv, EvmEnvFor, ExecutableTxIterator,
    ExecutionCtxFor,
    block::{BlockExecutorFactory, BlockExecutorFor},
    eth::EthBlockExecutionCtx,
    revm::{Inspector, database::State},
};
use reth_primitives_traits::{Header, SealedBlock, SealedHeader, SignedTransaction};
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::{Block, TempoPrimitives, TempoReceipt, TempoTxEnvelope};

use crate::{block::TempoBlockExecutor, evm::TempoEvm};
use reth_evm_ethereum::EthEvmConfig;
use tempo_chainspec::TempoChainSpec;
use tempo_revm::evm::TempoContext;

/// Tempo-related EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig {
    /// Inner evm config
    pub inner: EthEvmConfig<TempoChainSpec, TempoEvmFactory>,

    /// Block assembler
    pub block_assembler: TempoBlockAssembler,
}

impl TempoEvmConfig {
    /// Create a new [`TempoEvmConfig`] with the given chain spec and EVM factory.
    pub fn new(chain_spec: Arc<TempoChainSpec>, evm_factory: TempoEvmFactory) -> Self {
        let inner = EthEvmConfig::new_with_evm_factory(chain_spec.clone(), evm_factory);
        Self {
            inner,
            block_assembler: TempoBlockAssembler::new(chain_spec),
        }
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
        self.block_assembler.inner.extra_data = extra_data;
        self
    }
}

impl BlockExecutorFactory for TempoEvmConfig {
    type EvmFactory = TempoEvmFactory;
    type ExecutionCtx<'a> = TempoBlockExecutionCtx<'a>;
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
        TempoBlockExecutor::new(evm, ctx, self.chain_spec())
    }
}

impl ConfigureEvm for TempoEvmConfig {
    type Primitives = TempoPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = TempoNextBlockEnvAttributes;
    type BlockExecutorFactory = Self;
    type BlockAssembler = TempoBlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv, Self::Error> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnv, Self::Error> {
        self.inner.next_evm_env(parent, &attributes.inner)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<TempoBlockExecutionCtx<'a>, Self::Error> {
        let non_payment_gas_limit = TempoExtraData::decode(&block.header().extra_data)
            .map(|data| data.non_payment_gas_limit)
            .unwrap_or(0);
        Ok(TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: block.header().parent_hash,
                parent_beacon_block_root: block.header().parent_beacon_block_root,
                ommers: &block.body().ommers,
                withdrawals: block.body().withdrawals.as_ref().map(Cow::Borrowed),
            },
            non_payment_gas_limit,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<TempoBlockExecutionCtx<'_>, Self::Error> {
        let ctx = TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: parent.hash(),
                parent_beacon_block_root: attributes.parent_beacon_block_root,
                ommers: &[],
                withdrawals: attributes.inner.withdrawals.map(Cow::Owned),
            },
            non_payment_gas_limit: attributes.non_payment_gas_limit,
        };

        Ok(ctx)
    }
}

impl ConfigureEngineEvm<TempoExecutionData> for TempoEvmConfig {
    fn evm_env_for_payload(&self, payload: &TempoExecutionData) -> EvmEnvFor<Self> {
        self.evm_env(&payload.0).expect("TODO: handle error")
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a TempoExecutionData,
    ) -> ExecutionCtxFor<'a, Self> {
        self.context_for_block(&payload.0)
            .expect("TODO: handle error")
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
