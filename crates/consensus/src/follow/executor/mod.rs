//! Execution-layer synchronization for follow mode.
//!
//! This is intentionally smaller than the validator executor: it receives
//! already-verified finalized tips, drives forkchoice updates, acknowledges
//! finalized blocks once the execution layer durably persisted them, and
//! advances marshal's floor after execution-layer progress is durable.

use std::future::Future;

use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdated, PayloadStatus};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme, types::Finalization as SimplexFinalization,
    },
    types::{FixedEpocher, Height},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{Clock, Pacer, Spawner};
use eyre::{OptionExt as _, WrapErr as _};
use futures::channel::mpsc;
use reth_engine_primitives::{BeaconForkChoiceUpdateError, ConsensusEngineHandle};
use reth_ethereum::{chainspec::EthChainSpec as _, rpc::eth::primitives::BlockNumHash};
use reth_primitives_traits::{NodePrimitives, SealedHeader};
use reth_provider::{
    BlockHashReader, BlockIdReader, ChainSpecProvider as _, DatabaseProviderFactory as _,
    HeaderProvider, StageCheckpointReader as _,
    providers::{BlockchainProvider, ProviderNodeTypes},
};
use reth_stages_types::StageId;
use tempo_node::{TempoExecutionData, TempoPayloadTypes};
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::TempoHeader;
use tokio::sync::watch;

use crate::consensus::Digest;

mod actor;
mod ingress;
mod target;

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
///
/// Clones must observe the same live execution-layer state.
pub(crate) trait FinalizedBlockProvider: Clone + Send + Sync {
    /// Execution layer's effective finalized header. Returns genesis when no
    /// explicit finalized marker exists on a fresh chain.
    fn finalized_header(&self) -> eyre::Result<SealedHeader<TempoHeader>>;

    /// The block the execution layer durably persisted at
    /// `min(durable frontier, height)`, as for the validator executor.
    fn durable_block_at_or_below(&self, height: u64) -> eyre::Result<BlockNumHash>;

    /// Subscribes to the execution layer's persistence runs. The carried
    /// value must be ignored; re-read [`Self::durable_block_at_or_below`].
    fn subscribe_persisted_block(&self) -> watch::Receiver<Option<BlockNumHash>>;
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
    ) -> impl Future<Output = Result<ForkchoiceUpdated, BeaconForkChoiceUpdateError>> + Send + 'static;
}

/// Narrow marshal capability used by the follower executor.
pub(crate) trait Marshal: Clone + Send + Sync {
    type Finalization: Send;

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
    fn finalized_header(&self) -> eyre::Result<SealedHeader<TempoHeader>> {
        let hash = BlockIdReader::finalized_block_num_hash(self)?
            .map(|tip| tip.hash)
            .unwrap_or_else(|| self.chain_spec().genesis_hash());
        HeaderProvider::sealed_header_by_hash(self, hash)
            .map_err(eyre::Report::new)?
            .ok_or_eyre("finalized execution block is missing its header")
    }

    fn durable_block_at_or_below(&self, height: u64) -> eyre::Result<BlockNumHash> {
        // Reth's persisted-block notification carries the database tip, but
        // the hashed state and trie of its newest `num_state_masking_blocks`
        // are kept in memory only, and after a crash reth unwinds the
        // database to the partial state-trie frontier.
        let database = self
            .database_provider_ro()
            .wrap_err("failed opening a read-only database provider")?;

        let frontier = database
            .get_stage_checkpoint(StageId::Finish)
            .wrap_err("failed reading the finish stage checkpoint")?
            .map_or(0, |checkpoint| {
                checkpoint
                    .finish_stage_checkpoint()
                    .and_then(|finish| finish.partial_state_trie())
                    .unwrap_or(checkpoint.block_number)
            });
        let height = frontier.min(height);

        let hash = database
            .block_hash(height)
            .wrap_err_with(|| {
                format!("failed reading the database block hash at height `{height}`")
            })?
            .ok_or_eyre("the database has no block below the partial state-trie frontier")?;

        Ok(BlockNumHash::new(height, hash))
    }

    fn subscribe_persisted_block(&self) -> watch::Receiver<Option<BlockNumHash>> {
        self.canonical_in_memory_state().subscribe_persisted_block()
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
    ) -> impl Future<Output = Result<ForkchoiceUpdated, BeaconForkChoiceUpdateError>> + Send + 'static
    {
        let engine = self.clone();
        async move { engine.fork_choice_updated(state, attributes).await }
    }
}

impl Marshal for crate::alias::marshal::Mailbox {
    type Finalization = SimplexFinalization<Scheme<PublicKey, MinSig>, Digest>;

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
