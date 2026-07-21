//! Execution-layer synchronization for follow mode.
//!
//! This is intentionally smaller than the validator executor: it receives
//! already-verified finalized tips, drives forkchoice updates, and advances
//! marshal's floor after execution-layer progress is durable.

use std::future::Future;

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdated, PayloadStatus};
use commonware_consensus::types::{FixedEpocher, Height};
use commonware_runtime::{Clock, Pacer, Spawner};
use futures::channel::mpsc;
use reth_engine_primitives::ConsensusEngineHandle;
use reth_ethereum::{chainspec::EthChainSpec as _, rpc::eth::primitives::BlockNumHash};
use reth_provider::{
    BlockHashReader as _, BlockIdReader, ChainSpecProvider as _, DatabaseProviderFactory as _,
    providers::{BlockchainProvider, ProviderNodeTypes},
};
use tempo_node::{TempoExecutionData, TempoPayloadTypes};
use tempo_payload_types::TempoPayloadAttributes;

mod actor;
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
    /// Execution layer's effective finalized block. Returns genesis when no
    /// explicit finalized marker exists on a fresh chain.
    fn finalized_block_num_hash(&self) -> eyre::Result<BlockNumHash>;

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
    fn set_floor(&self, height: Height) -> impl Future<Output = ()> + Send;
}

impl<N> FinalizedBlockProvider for BlockchainProvider<N>
where
    N: ProviderNodeTypes,
{
    fn finalized_block_num_hash(&self) -> eyre::Result<BlockNumHash> {
        Ok(BlockIdReader::finalized_block_num_hash(self)?
            .unwrap_or_else(|| BlockNumHash::new(0, self.chain_spec().genesis_hash())))
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
    fn set_floor(&self, height: Height) -> impl Future<Output = ()> + Send {
        let mailbox = self.clone();
        async move { mailbox.set_floor(height).await }
    }
}
