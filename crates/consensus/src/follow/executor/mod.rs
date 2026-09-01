//! Execution-layer synchronization for follow mode.
//!
//! This is intentionally smaller than the validator executor: it receives
//! already-verified finalized tips, drives forkchoice updates, and advances
//! marshal's floor after execution-layer progress is durable.

use std::future::Future;

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdated, PayloadStatus};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme, types::Finalization as SimplexFinalization,
    },
    types::{FixedEpocher, Height},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{Clock, Pacer, Spawner};
use eyre::OptionExt as _;
use futures::channel::mpsc;
use reth_engine_primitives::ConsensusEngineHandle;
use reth_ethereum::{chainspec::EthChainSpec as _, rpc::eth::primitives::BlockNumHash};
use reth_primitives_traits::{NodePrimitives, SealedHeader};
use reth_provider::{
    BlockHashReader, BlockIdReader, ChainSpecProvider as _, DatabaseProviderFactory as _,
    HeaderProvider,
    providers::{BlockchainProvider, ProviderNodeTypes},
};
use tempo_node::{TempoExecutionData, TempoPayloadTypes};
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::TempoHeader;

use crate::consensus::{Digest, block::Block};

mod actor;
mod fcu;
mod ingress;

#[cfg(test)]
mod test;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

pub(crate) struct Config<P, E, M = crate::alias::marshal::Mailbox> {
    pub(crate) execution_provider: P,
    pub(crate) execution_engine: E,
    pub(crate) marshal: M,
    pub(crate) epoch_strategy: FixedEpocher,
    pub(crate) floor: Height,
    pub(crate) fcu_heartbeat_interval: std::time::Duration,
}

pub(crate) fn init<TContext, P, E, M>(
    context: TContext,
    config: Config<P, E, M>,
) -> (Actor<TContext, P, E, M>, Mailbox)
where
    TContext: Clock + Pacer + Spawner,
    P: FinalizedBlockProvider + 'static,
    E: Clone + ExecutionEngine + 'static,
    M: Marshal + 'static,
{
    let (sender, receiver) = mpsc::unbounded();
    (Actor::new(context, config, receiver), Mailbox::new(sender))
}

/// Finalized block state needed to initialize and advance the follower.
pub(crate) trait FinalizedBlockProvider: Send + Sync {
    /// Execution layer's finalized block, falling back to genesis if no
    /// block has been explicitly finalized yet.
    fn finalized_num_hash(&self) -> eyre::Result<BlockNumHash>;

    /// Execution layer's effective finalized header. Returns genesis when no
    /// explicit finalized marker exists on a fresh chain.
    fn finalized_header(&self) -> eyre::Result<SealedHeader<TempoHeader>>;

    /// Persisted database block hash at `height`, excluding in-memory state.
    fn durable_block_hash(&self, height: u64) -> eyre::Result<Option<B256>>;
}

/// Engine commands issued by the follower executor.
pub(crate) trait ExecutionEngine: Send + Sync {
    /// Submit a finalized execution payload.
    fn new_payload(
        &self,
        payload: TempoExecutionData,
    ) -> impl Future<Output = eyre::Result<PayloadStatus>> + Send + 'static;

    /// Update the execution layer's head, safe, and finalized forkchoice.
    fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
        attributes: Option<TempoPayloadAttributes>,
    ) -> impl Future<Output = eyre::Result<ForkchoiceUpdated>> + Send + 'static;
}

/// Narrow marshal capability used by the follower executor.
pub(crate) trait Marshal: Clone + Send + Sync {
    type Finalization: Send;

    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send;

    fn get_finalization(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<Self::Finalization>> + Send;

    fn set_floor(&self, finalization: Self::Finalization);
}

impl<N> FinalizedBlockProvider for BlockchainProvider<N>
where
    N: ProviderNodeTypes,
    N::Primitives: NodePrimitives<BlockHeader = TempoHeader>,
{
    fn finalized_num_hash(&self) -> eyre::Result<BlockNumHash> {
        Ok(BlockIdReader::finalized_block_num_hash(self)?
            .unwrap_or_else(|| BlockNumHash::new(0, self.chain_spec().genesis_hash())))
    }

    fn finalized_header(&self) -> eyre::Result<SealedHeader<TempoHeader>> {
        HeaderProvider::sealed_header_by_hash(self, self.finalized_num_hash()?.hash)
            .map_err(eyre::Report::new)?
            .ok_or_eyre("finalized execution block is missing its header")
    }

    fn durable_block_hash(&self, height: u64) -> eyre::Result<Option<B256>> {
        self.database_provider_ro()
            .map_err(eyre::Report::new)?
            .block_hash(height)
            .map_err(eyre::Report::new)
    }
}

impl ExecutionEngine for ConsensusEngineHandle<TempoPayloadTypes> {
    fn new_payload(
        &self,
        payload: TempoExecutionData,
    ) -> impl Future<Output = eyre::Result<PayloadStatus>> + Send + 'static {
        let engine = self.clone();
        async move { engine.new_payload(payload).await.map_err(eyre::Report::new) }
    }

    fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
        attributes: Option<TempoPayloadAttributes>,
    ) -> impl Future<Output = eyre::Result<ForkchoiceUpdated>> + Send + 'static {
        let engine = self.clone();
        async move {
            engine
                .fork_choice_updated(state, attributes)
                .await
                .map_err(eyre::Report::new)
        }
    }
}

impl Marshal for crate::alias::marshal::Mailbox {
    type Finalization = SimplexFinalization<Scheme<PublicKey, MinSig>, Digest>;

    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send {
        let mailbox = self.clone();
        async move { mailbox.get_block(height).await }
    }

    fn get_finalization(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<Self::Finalization>> + Send {
        let mailbox = self.clone();
        async move { mailbox.get_finalization(height).await }
    }

    fn set_floor(&self, finalization: Self::Finalization) {
        Self::set_floor(self, finalization);
    }
}
