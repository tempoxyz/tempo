//! The executor is sending fork-choice-updates to the execution layer.
use std::{future::Future, sync::Arc};

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdated, PayloadId, PayloadStatus};
use commonware_consensus::{
    marshal::core::DigestFallback,
    types::{Height, Round},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{Clock, Metrics, Spawner};
use reth_ethereum::{chainspec::EthChainSpec as _, rpc::eth::primitives::BlockNumHash};
use reth_node_builder::PayloadKind;
use reth_provider::{BlockHashReader as _, BlockReader as _, BlockSource};
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tokio::sync::oneshot;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
use eyre::WrapErr as _;
use futures::channel::mpsc;
pub(crate) use ingress::Mailbox;

use crate::consensus::{Digest, block::Block};

/// The execution-layer surface the executor actor drives.
///
/// The abstraction sits at the transport level - engine-API requests and
/// canonical-chain reads - so that all of the actor's scheduling and
/// convergence logic stays on the testable side of the seam. Domain types
/// ([`Block`], [`TempoExecutionData`], [`PayloadStatus`]) are deliberately
/// not abstracted.
///
/// Implementations are cheap-clone handles: clones are moved into the
/// actor's spawned execution tasks.
pub(crate) trait ExecutionLayer: Clone + Send + Sync + 'static {
    /// The execution layer's finalized block, falling back to genesis if no
    /// block has been explicitly finalized yet.
    fn finalized_num_hash(&self) -> BlockNumHash;

    /// The hash of the genesis block.
    fn genesis_hash(&self) -> B256;

    /// The hash of the canonical execution block at `height`, if the
    /// canonical chain covers it.
    fn canonical_block_hash(&self, height: u64) -> eyre::Result<Option<B256>>;

    /// Looks up a full block by its digest in the execution layer's stores.
    fn block_by_digest(&self, digest: Digest) -> eyre::Result<Option<Block>>;

    /// Submits a block to the execution layer via a new-payload request.
    fn new_payload(
        &self,
        payload: TempoExecutionData,
    ) -> impl Future<Output = eyre::Result<PayloadStatus>> + Send + 'static;

    /// Updates the execution layer's head and finalized blocks, optionally
    /// registering a payload build.
    fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
        attributes: Option<TempoPayloadAttributes>,
    ) -> impl Future<Output = eyre::Result<ForkchoiceUpdated>> + Send + 'static;

    /// Resolves the payload registered under `payload_id` from the payload
    /// builder, waiting for a pending build to finish.
    ///
    /// Returns `None` if no build job is registered under the ID. Dropping
    /// the returned future must abort the build job.
    fn resolve_payload(
        &self,
        payload_id: PayloadId,
    ) -> impl Future<Output = Option<eyre::Result<TempoBuiltPayload>>> + Send + 'static;
}

/// The narrow marshal-actor capability used by the executor actor.
pub(crate) trait Marshal: Clone + Send + Sync + 'static {
    /// A best-effort attempt to retrieve a finalized block from marshal's
    /// local storage.
    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send;

    /// Retrieves `(height, digest)` finalization info for `height` from
    /// marshal's local storage.
    fn get_info(&self, height: Height) -> impl Future<Output = Option<(Height, Digest)>> + Send;

    /// Subscribes to the block with `digest`, falling back to fetching it
    /// from peers by the round it was notarized in.
    ///
    /// Dropping the receiver cancels the subscription; marshal dropping the
    /// sender means it gave up on delivering the block.
    fn subscribe_by_digest(
        &self,
        digest: Digest,
        notarized_in: Round,
    ) -> oneshot::Receiver<Arc<Block>>;
}

impl ExecutionLayer for Arc<TempoFullNode> {
    fn finalized_num_hash(&self) -> BlockNumHash {
        self.provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .unwrap_or_else(|| BlockNumHash::new(0, self.genesis_hash()))
    }

    fn genesis_hash(&self) -> B256 {
        self.chain_spec().genesis_hash()
    }

    fn canonical_block_hash(&self, height: u64) -> eyre::Result<Option<B256>> {
        self.provider.block_hash(height).map_err(Into::into)
    }

    fn block_by_digest(&self, digest: Digest) -> eyre::Result<Option<Block>> {
        Ok(self
            .provider
            .find_sealed_or_recovered_block(digest.0, BlockSource::Any)?
            .map(|block| Block::from_execution_block_unchecked(block, None)))
    }

    fn new_payload(
        &self,
        payload: TempoExecutionData,
    ) -> impl Future<Output = eyre::Result<PayloadStatus>> + Send + 'static {
        let engine = self.add_ons_handle.beacon_engine_handle.clone();
        async move { engine.new_payload(payload).await.map_err(Into::into) }
    }

    fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
        attributes: Option<TempoPayloadAttributes>,
    ) -> impl Future<Output = eyre::Result<ForkchoiceUpdated>> + Send + 'static {
        let engine = self.add_ons_handle.beacon_engine_handle.clone();
        async move {
            engine
                .fork_choice_updated(state, attributes)
                .await
                .map_err(Into::into)
        }
    }

    fn resolve_payload(
        &self,
        payload_id: PayloadId,
    ) -> impl Future<Output = Option<eyre::Result<TempoBuiltPayload>>> + Send + 'static {
        let builder = self.payload_builder_handle.clone();
        async move {
            builder
                .resolve_kind(payload_id, PayloadKind::WaitForPending)
                .await
                .map(|resolved| resolved.map_err(Into::into))
        }
    }
}

impl Marshal for crate::alias::marshal::Mailbox {
    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send {
        let mailbox = self.clone();
        async move { mailbox.get_block(height).await }
    }

    fn get_info(&self, height: Height) -> impl Future<Output = Option<(Height, Digest)>> + Send {
        let mailbox = self.clone();
        async move { mailbox.get_info(height).await }
    }

    fn subscribe_by_digest(
        &self,
        digest: Digest,
        notarized_in: Round,
    ) -> oneshot::Receiver<Arc<Block>> {
        Self::subscribe_by_digest(
            self,
            digest,
            DigestFallback::FetchByRound {
                round: notarized_in,
            },
        )
    }
}

pub(crate) fn init<TContext, TExecutionLayer, TMarshal>(
    context: TContext,
    config: Config<TExecutionLayer, TMarshal>,
) -> eyre::Result<(Actor<TContext, TExecutionLayer, TMarshal>, Mailbox)>
where
    TContext: Clock + Metrics + Spawner,
    TExecutionLayer: ExecutionLayer,
    TMarshal: Marshal,
{
    let (tx, rx) = mpsc::unbounded();
    let mailbox = Mailbox { inner: tx };
    let actor = Actor::init(context, config, rx).wrap_err("failed initializing actor")?;
    Ok((actor, mailbox))
}

pub(crate) struct Config<TExecutionLayer, TMarshal> {
    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    pub(crate) execution_node: TExecutionLayer,

    /// Marshal sync floor. This is the sync target the executor actor will try
    /// to reach because the marshal actor will only send finalized heights
    /// above this value.
    pub(crate) finalized_floor: Height,

    /// Finalized tip reported by marshal at startup, together with the
    /// round it was finalized in (the zero round for genesis).
    pub(crate) finalized_tip: (Round, Height, Digest),

    /// The mailbox of the marshal actor. Used to backfill blocks.
    pub(crate) marshal: TMarshal,

    /// The interval at which to send a forkchoice update heartbeat to the
    /// execution layer.
    pub(crate) fcu_heartbeat_interval: std::time::Duration,

    /// The node's ed25519 public key if the node is participating in
    /// consensus. Not set if not, for example for followers.
    pub(crate) public_key: Option<PublicKey>,
}
