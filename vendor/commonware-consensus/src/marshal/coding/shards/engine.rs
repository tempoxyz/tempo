//! Shard engine for erasure-coded block distribution and reconstruction.
//!
//! This module implements the core logic for distributing blocks as erasure-coded
//! shards and reconstructing blocks from received shards.
//!
//! # Overview
//!
//! The shard engine serves two primary functions:
//! 1. Broadcast: When a node proposes a block, the engine broadcasts
//!    erasure-coded shards to all participants and to non-participants in
//!    aggregate membership (peers in [`commonware_p2p::PeerSetUpdate::all`]
//!    but not in the epoch participant list).
//!    The leader sends each participant their indexed shard.
//! 2. Block Reconstruction: When a node receives shards from peers, the engine
//!    validates them and reconstructs the original block once enough valid
//!    shards are available. Both participants and non-participants can
//!    reconstruct blocks: participants receive their own indexed shard from
//!    the leader, while non-participants reconstruct from shards gossiped
//!    by participants. All participants gossip their validated shard to peers.
//!
//! # Message Flow
//!
//! ```text
//!                           PROPOSER
//!                              |
//!                              | Proposed(block)
//!                              v
//!                    +------------------+
//!                    |   Shard Engine   |
//!                    +------------------+
//!                              |
//!            broadcast_shards (each participant's indexed shard)
//!                              |
//!         +--------------------+--------------------+
//!         |                    |                    |
//!         v                    v                    v
//!    Participant 0        Participant 1        Participant N
//!         |                    |                    |
//!         | (receive shard     | (receive shard     |
//!         |  for own index)    |  for own index)    |
//!         v                    v                    v
//!    +----------+         +----------+         +----------+
//!    | Validate |         | Validate |         | Validate |
//!    | (check)  |         | (check)  |         | (check)  |
//!    +----------+         +----------+         +----------+
//!         |                    |                    |
//!         +--------------------+--------------------+
//!                              |
//!                    (gossip validated shards)
//!                              |
//!         +--------------------+--------------------+
//!         |                    |                    |
//!         v                    v                    v
//!    Accumulate checked shards until minimum_shards reached
//!         |                    |                    |
//!         v                    v                    v
//!            Batch verify pending shards at quorum
//!         |                    |                    |
//!         v                    v                    v
//!    +-------------+      +-------------+      +-------------+
//!    | Reconstruct |      | Reconstruct |      | Reconstruct |
//!    |    Block    |      |    Block    |      |    Block    |
//!    +-------------+      +-------------+      +-------------+
//! ```
//!
//! # Reconstruction State Machine
//!
//! For each [`Commitment`] that is either leader-discovered or notarized, nodes
//! (both participants and non-participants) maintain a [`ReconstructionState`].
//! Before either consensus signal is observed (a leader announcement or a
//! notarization for the commitment), shards are buffered in bounded per-peer
//! queues:
//!
//! ```text
//!    +----------------------+
//!    | AwaitingQuorum       |
//!    | - leader known       |
//!    | - assigned shard     |  <--- verified immediately on receipt
//!    |   verified eagerly   |
//!    | - other shards       |  <--- buffered in pending_shards
//!    |   buffered           |
//!    +----------------------+
//!               |
//!               | quorum met + batch validation passes
//!               v
//!    +----------------------+
//!    | Ready                |
//!    | - checked shards     |
//!    | - no new gossip      |
//!    |   shards accepted    |
//!    | - assigned shard may |
//!    |   still arrive late  |
//!    +----------------------+
//!               |
//!               | checked_shards.len() >= minimum_shards
//!               v
//!    +----------------------+
//!    | Reconstruction       |
//!    | Attempt              |
//!    +----------------------+
//!               |
//!          +----+----+
//!          |         |
//!          v         v
//!       Success    Failure
//!          |         |
//!          v         v
//!       Cache      Remove
//!       Block      State
//! ```
//!
//! _Per-peer buffers are only kept for peers in `latest.primary`, matching [`commonware_broadcast::buffered`].
//! When a peer is no longer in `latest.primary`, all its buffered shards are evicted._
//!
//! # Peer Validation and Blocking Rules
//!
//! The engine enforces strict validation to prevent Byzantine attacks:
//!
//! - All shards MUST be sent by participants in the current epoch.
//! - Any participant may deliver the recipient's assigned shard.
//! - Any participant may gossip its own shard.
//! - All shards MUST pass cryptographic verification against the commitment.
//! - Each shard index may only contribute ONE shard per commitment.
//! - Sending a second shard for the same index with different data
//!   (equivocation) results in blocking. Exact duplicates are silently
//!   ignored.
//!
//! Peers violating these rules are blocked via the [`Blocker`] trait.
//! Validation and blocking rules are applied while a commitment is actively
//! tracked in reconstruction state. Once a block is already reconstructed and
//! cached, additional shards for that commitment are ignored.
//!
//! _Before proposal context is known, shards are buffered in fixed-size per-peer
//! queues until consensus signals the proposal via [`Mailbox::discovered`]
//! or a notarization via [`Mailbox::notarized`]. A notarization activates
//! reconstruction interest without a leader, so only sender-indexed gossip
//! shards can be ingested. Other shards remain buffered until proposal
//! discovery._

use super::{
    mailbox::{Mailbox, Message},
    metrics::ShardMetrics,
};
use crate::{
    Block, CertifiableBlock, Heightable,
    marshal::{
        coding::{
            types::{CodedBlock, Shard},
            validation::{ReconstructionError as InvariantError, validate_reconstruction},
        },
        core::Retirement,
    },
    types::{Epoch, Round, coding::Commitment},
};
use commonware_actor::mailbox;
use commonware_codec::{Decode, Error as CodecError, Read};
use commonware_coding::{Config as CodingConfig, Scheme as CodingScheme};
use commonware_cryptography::{
    Committable, Digestible, Hasher, PublicKey,
    certificate::{Provider, Scheme as CertificateScheme},
};
use commonware_macros::select_loop;
use commonware_p2p::{
    Blocker, Provider as PeerProvider, Receiver, Recipients, Sender,
    utils::codec::{WrappedBackgroundReceiver, WrappedSender},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::HistogramExt,
};
use commonware_utils::{
    bitmap::BitMap,
    channel::{fallible::OneshotExt, oneshot},
    ordered::{Quorum, Set},
};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    num::NonZeroUsize,
    sync::Arc,
};
use thiserror::Error;
use tracing::{debug, warn};

/// An error that can occur during reconstruction of a [`CodedBlock`] from [`Shard`]s
#[derive(Debug, Error)]
pub enum Error<C: CodingScheme> {
    /// An error occurred while recovering the encoded blob from the [`Shard`]s
    #[error(transparent)]
    Coding(C::Error),

    /// An error occurred while decoding the reconstructed blob into a [`CodedBlock`]
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// The reconstructed block's digest does not match the commitment's block digest
    #[error("block digest mismatch: reconstructed block does not match commitment digest")]
    DigestMismatch,

    /// The reconstructed block's config does not match the commitment's coding config
    #[error("block config mismatch: reconstructed config does not match commitment config")]
    ConfigMismatch,

    /// The reconstructed block's embedded context does not match the commitment context digest
    #[error("block context mismatch: reconstructed context does not match commitment context")]
    ContextMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum BlockSubscriptionKey<K, D> {
    Commitment(K),
    Digest(D),
}

/// Configuration for the [`Engine`].
pub struct Config<P, S, X, D, C, H, B, T>
where
    P: PublicKey,
    S: Provider<Scope = Epoch>,
    X: Blocker<PublicKey = P>,
    D: PeerProvider<PublicKey = P>,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    T: Strategy,
{
    /// The scheme provider.
    pub scheme_provider: S,

    /// The peer blocker.
    pub blocker: X,

    /// [`Read`] configuration for decoding [`Shard`]s.
    pub shard_codec_cfg: <Shard<B, C, H> as Read>::Cfg,

    /// [`commonware_codec::Read`] configuration for decoding blocks.
    pub block_codec_cfg: B::Cfg,

    /// The strategy used for parallel computation.
    pub strategy: T,

    /// The size of the mailbox buffer.
    pub mailbox_size: NonZeroUsize,

    /// Number of shards to buffer per peer.
    ///
    /// Shards for commitments without a reconstruction state are buffered per
    /// peer in a fixed-size ring to bound memory under Byzantine spam. These
    /// shards are only ingested when consensus provides a leader via
    /// [`Mailbox::discovered`] or reports a notarization via
    /// [`Mailbox::notarized`].
    ///
    /// The worst-case total memory usage for the set of shard buffers is
    /// `num_participants * peer_buffer_size * max_shard_size`.
    pub peer_buffer_size: NonZeroUsize,

    /// Capacity of the channel between the background receiver and the engine.
    ///
    /// The background receiver decodes incoming network messages in a separate
    /// task and forwards them to the engine over a mailbox with this
    /// capacity.
    pub background_channel_capacity: NonZeroUsize,

    /// Provider for peer set information. Pre-leader shards are buffered per
    /// peer only while that peer appears in the
    /// [`commonware_p2p::PeerSetUpdate::latest`] primary set, matching
    /// [`commonware_broadcast::buffered::Engine`]. Broadcast delivery uses the
    /// aggregate [`commonware_p2p::PeerSetUpdate::all`] union.
    pub peer_provider: D,
}

/// The data currently owned for a consensus commitment.
enum CommitmentPhase<B, C, H, P>
where
    B: Block,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    /// Shards are still being accumulated or validated.
    Reconstructing(ReconstructionState<P, B, C, H>),
    /// The block is cached. Reconstruction state remains only while shard-specific
    /// evidence may still arrive.
    Cached {
        block: Arc<CodedBlock<B, C, H>>,
        reconstruction: Option<ReconstructionState<P, B, C, H>>,
    },
}

/// The single lifecycle owner for a consensus commitment.
///
/// The observation round determines both retention and the epoch whose participant
/// scheme classifies shards. Keeping it outside the phase prevents cached and
/// reconstructing views of the same commitment from diverging.
struct CommitmentRecord<B, C, H, P>
where
    B: Block,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    round: Round,
    phase: CommitmentPhase<B, C, H, P>,
    proposed: bool,
}

/// Lifecycle records keyed by the complete commitment, including its coding
/// root and configuration.
type CommitmentRecords<B, C, H, P> = BTreeMap<Commitment<B, C, H>, CommitmentRecord<B, C, H, P>>;

/// The current lifecycle status of a commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitmentStatus {
    /// No record exists for the commitment.
    Absent,
    /// The commitment is accumulating or validating shards.
    Reconstructing,
    /// The commitment has an available block.
    Cached,
}

/// Why a commitment is eligible for retirement.
#[derive(Clone, Copy)]
enum RetirementReason {
    /// Durable progress explicitly retired the commitment.
    Exact,
    /// The commitment's last observation is covered by the durable round floor.
    Floor,
}

impl<B, C, H, P> CommitmentRecord<B, C, H, P>
where
    B: Block,
    C: CodingScheme,
    H: Hasher,
    P: PublicKey,
{
    /// Creates a record that is reconstructing a commitment observed at `round`.
    const fn reconstructing(round: Round, reconstruction: ReconstructionState<P, B, C, H>) -> Self {
        Self {
            round,
            phase: CommitmentPhase::Reconstructing(reconstruction),
            proposed: false,
        }
    }

    /// Creates a record for a block already available at `round`.
    const fn cached(round: Round, block: Arc<CodedBlock<B, C, H>>) -> Self {
        Self {
            round,
            phase: CommitmentPhase::Cached {
                block,
                reconstruction: None,
            },
            proposed: false,
        }
    }

    /// Returns the latest valid observation round.
    const fn round(&self) -> Round {
        self.round
    }

    /// Ensures that `round` uses the epoch that owns this commitment record.
    fn validate_epoch(&self, round: Round) -> Result<(), Epoch> {
        let existing_epoch = self.round.epoch();
        if existing_epoch != round.epoch() {
            return Err(existing_epoch);
        }
        Ok(())
    }

    /// Records a same-epoch observation without moving the retention round backward.
    fn observe(&mut self, round: Round) -> Result<(), Epoch> {
        self.validate_epoch(round)?;
        self.round = self.round.max(round);
        Ok(())
    }

    /// Returns the cached block, if available.
    const fn block(&self) -> Option<&Arc<CodedBlock<B, C, H>>> {
        match &self.phase {
            CommitmentPhase::Reconstructing(_) => None,
            CommitmentPhase::Cached { block, .. } => Some(block),
        }
    }

    /// Returns shard reconstruction state retained for the commitment, if any.
    const fn reconstruction(&self) -> Option<&ReconstructionState<P, B, C, H>> {
        match &self.phase {
            CommitmentPhase::Reconstructing(reconstruction) => Some(reconstruction),
            CommitmentPhase::Cached { reconstruction, .. } => reconstruction.as_ref(),
        }
    }

    /// Returns mutable shard reconstruction state retained for the commitment, if any.
    const fn reconstruction_mut(&mut self) -> Option<&mut ReconstructionState<P, B, C, H>> {
        match &mut self.phase {
            CommitmentPhase::Reconstructing(reconstruction) => Some(reconstruction),
            CommitmentPhase::Cached { reconstruction, .. } => reconstruction.as_mut(),
        }
    }

    /// Returns whether the local validator can satisfy its assigned-shard obligation.
    fn is_assigned_shard_ready(&self) -> bool {
        self.proposed
            || self
                .reconstruction()
                .is_some_and(ReconstructionState::is_assigned_shard_verified)
    }

    /// Records that the local validator built and cached this commitment.
    const fn mark_proposed(&mut self) {
        self.proposed = true;
    }

    /// Caches `block` while preserving reconstruction state needed for shard readiness.
    ///
    /// If a block is already cached, retains and returns the existing instance.
    fn install_block(&mut self, block: Arc<CodedBlock<B, C, H>>) -> Arc<CodedBlock<B, C, H>> {
        let previous = std::mem::replace(
            &mut self.phase,
            CommitmentPhase::Cached {
                block: Arc::clone(&block),
                reconstruction: None,
            },
        );
        self.phase = match previous {
            CommitmentPhase::Reconstructing(reconstruction) => CommitmentPhase::Cached {
                block: Arc::clone(&block),
                reconstruction: Some(reconstruction),
            },
            cached @ CommitmentPhase::Cached { .. } => cached,
        };
        self.block()
            .cloned()
            .expect("installing a block must leave a cached phase")
    }
}

/// A network layer for broadcasting and receiving [`CodedBlock`]s as [`Shard`]s.
///
/// When enough [`Shard`]s are present in the mailbox, the [`Engine`] may facilitate
/// reconstruction of the original [`CodedBlock`] and notify any subscribers waiting for it.
pub struct Engine<E, S, X, D, C, H, B, P, T>
where
    E: BufferPooler + Rng + Spawner + Metrics + Clock,
    S: Provider<Scope = Epoch>,
    S::Scheme: CertificateScheme<PublicKey = P>,
    X: Blocker,
    D: PeerProvider<PublicKey = P>,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    P: PublicKey,
    T: Strategy,
{
    /// Context held by the actor.
    context: ContextCell<E>,

    /// Receiver for incoming messages to the actor.
    mailbox: mailbox::Receiver<Message<B, C, H, P>>,

    /// The scheme provider.
    scheme_provider: S,

    /// The peer blocker.
    blocker: X,

    /// [`Read`] configuration for decoding [`Shard`]s.
    shard_codec_cfg: <Shard<B, C, H> as Read>::Cfg,

    /// [`Read`] configuration for decoding [`CodedBlock`]s.
    block_codec_cfg: B::Cfg,

    /// The strategy used for parallel shard verification.
    strategy: T,

    /// The cache and reconstruction lifecycle for each observed [`Commitment`].
    records: CommitmentRecords<B, C, H, P>,

    /// Per-peer ring buffers for shards received before leader announcement.
    ///
    /// Empty buffers are retained for active peers and only evicted when the
    /// peer leaves `latest.primary`.
    peer_buffers: BTreeMap<P, VecDeque<Shard<B, C, H>>>,

    /// Maximum buffered pre-leader shards per peer.
    peer_buffer_size: NonZeroUsize,

    /// Provider for peer set information.
    peer_provider: D,

    /// Latest union of peer membership from the peer set subscription
    /// ([`commonware_p2p::PeerSetUpdate::all`]).
    aggregate_peers: Set<P>,

    /// Latest primary peers allowed to retain pre-leader shard buffers.
    latest_primary_peers: Set<P>,

    /// Capacity of the background receiver channel.
    background_channel_capacity: NonZeroUsize,

    /// Open subscriptions for assigned shard verification for the keyed
    /// [`Commitment`].
    ///
    /// For participants, readiness is satisfied once the shard for the local
    /// participant index has been verified. Reconstruction from peer gossip is
    /// tracked separately and does not satisfy this readiness condition.
    ///
    /// Proposers are a special case: they satisfy readiness once their local
    /// proposal is cached because they already hold all shards.
    assigned_shard_verified_subscriptions: BTreeMap<Commitment<B, C, H>, Vec<oneshot::Sender<()>>>,

    /// Open subscriptions for the reconstruction of a [`CodedBlock`] with
    /// the keyed [`Commitment`].
    #[allow(clippy::type_complexity)]
    block_subscriptions: BTreeMap<
        BlockSubscriptionKey<Commitment<B, C, H>, B::Digest>,
        Vec<oneshot::Sender<Arc<CodedBlock<B, C, H>>>>,
    >,

    /// Metrics for the shard engine.
    metrics: ShardMetrics<P>,
}

impl<E, S, X, D, C, H, B, P, T> Engine<E, S, X, D, C, H, B, P, T>
where
    E: BufferPooler + Rng + Spawner + Metrics + Clock,
    S: Provider<Scope = Epoch>,
    S::Scheme: CertificateScheme<PublicKey = P>,
    X: Blocker<PublicKey = P>,
    D: PeerProvider<PublicKey = P>,
    C: CodingScheme,
    H: Hasher,
    B: CertifiableBlock,
    P: PublicKey,
    T: Strategy,
{
    /// Create a new [`Engine`] with the given configuration.
    pub fn new(context: E, config: Config<P, S, X, D, C, H, B, T>) -> (Self, Mailbox<B, C, H, P>) {
        let metrics = ShardMetrics::new(&context);
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                scheme_provider: config.scheme_provider,
                blocker: config.blocker,
                shard_codec_cfg: config.shard_codec_cfg,
                block_codec_cfg: config.block_codec_cfg,
                strategy: config.strategy,
                records: BTreeMap::new(),
                peer_buffers: BTreeMap::new(),
                peer_buffer_size: config.peer_buffer_size,
                peer_provider: config.peer_provider,
                aggregate_peers: Set::default(),
                latest_primary_peers: Set::default(),
                background_channel_capacity: config.background_channel_capacity,
                assigned_shard_verified_subscriptions: BTreeMap::new(),
                block_subscriptions: BTreeMap::new(),
                metrics,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the engine.
    pub fn start(
        mut self,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(network))
    }

    /// Run the shard engine's event loop.
    async fn run(
        mut self,
        (sender, receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let mut sender = WrappedSender::<_, Shard<B, C, H>>::new(
            self.context.network_buffer_pool().clone(),
            sender,
        );
        let (receiver_service, mut receiver) =
            WrappedBackgroundReceiver::<_, P, X, _, Shard<B, C, H>, T>::new(
                self.context.child("shard_ingress"),
                receiver,
                self.shard_codec_cfg.clone(),
                self.blocker.clone(),
                self.background_channel_capacity,
                self.strategy.clone(),
            );
        // Keep the handle alive to prevent the background receiver from being aborted.
        let _receiver_handle = receiver_service.start();
        let mut peer_set_subscription = self.peer_provider.subscribe().await;

        select_loop! {
            self.context,
            on_start => {
                // Clean up closed subscriptions.
                self.block_subscriptions.retain(|_, subscribers| {
                    subscribers.retain(|tx| !tx.is_closed());
                    !subscribers.is_empty()
                });
                self.assigned_shard_verified_subscriptions
                    .retain(|_, subscribers| {
                        subscribers.retain(|tx| !tx.is_closed());
                        !subscribers.is_empty()
                    });
            },
            on_stopped => {
                debug!("received shutdown signal, stopping shard engine");
            },
            Some(update) = peer_set_subscription.recv() else {
                debug!("peer set subscription closed");
                return;
            } => {
                let all_peers = update.all.union();
                self.update_latest_primary_peers(update.latest.primary);
                self.aggregate_peers = all_peers;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("shard mailbox closed, stopping shard engine");
                return;
            } => {
                if message.response_closed() {
                    continue;
                }

                match message {
                    Message::Proposed { block, round } => {
                        self.broadcast_shards(&mut sender, round, block);
                    }
                    Message::Discovered {
                        commitment,
                        leader,
                        round,
                    } => {
                        self.handle_external_proposal(&mut sender, commitment, leader, round);
                    }
                    Message::Notarized { commitment, round } => {
                        self.handle_notarized_commitment(&mut sender, commitment, round);
                    }
                    Message::GetByCommitment {
                        commitment,
                        response,
                    } => {
                        let block = self
                            .records
                            .get(&commitment)
                            .and_then(CommitmentRecord::block)
                            .cloned();
                        response.send_lossy(block);
                    }
                    Message::GetByDigest { digest, response } => {
                        let block = self.records.values().find_map(|record| {
                            let block = record.block()?;
                            (block.digest() == digest).then(|| Arc::clone(block))
                        });
                        response.send_lossy(block);
                    }
                    Message::SubscribeAssignedShardVerified {
                        commitment,
                        response,
                    } => {
                        self.handle_assigned_shard_verified_subscription(commitment, response);
                    }
                    Message::SubscribeByCommitment {
                        commitment,
                        response,
                    } => {
                        self.handle_block_subscription(
                            BlockSubscriptionKey::Commitment(commitment),
                            response,
                        );
                    }
                    Message::SubscribeByDigest { digest, response } => {
                        self.handle_block_subscription(
                            BlockSubscriptionKey::Digest(digest),
                            response,
                        );
                    }
                    Message::Retire { update } => {
                        self.retire(update);
                    }
                }
            },
            Some((peer, shard)) = receiver.recv() else {
                debug!("receiver closed, stopping shard engine");
                return;
            } => {
                self.handle_network_shard(&mut sender, peer, shard);
            },
        }
    }

    /// Handles a decoded shard received from the network.
    fn handle_network_shard<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        peer: P,
        shard: Shard<B, C, H>,
    ) {
        self.metrics.shards_received.get_or_create_by(&peer).inc();

        let commitment = shard.commitment();
        if !self.should_handle_network_shard(commitment) {
            return;
        }

        if let Some(record) = self.records.get(&commitment)
            && let Some(existing) = record.reconstruction()
        {
            let round = record.round();
            let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
                warn!(%commitment, "no scheme for epoch, ignoring shard");
                return;
            };

            // Notarized recovery can create state before leader discovery. Until
            // the leader is known, only sender-indexed gossip shards are safe to
            // ingest: a participant may only gossip its own shard.
            if existing.leader().is_none()
                && let Some(sender_index) = scheme.participants().index(&peer)
            {
                let expected_index: u16 = sender_index
                    .get()
                    .try_into()
                    .expect("participant index impossibly out of bounds");
                if shard.index() != expected_index {
                    // A mismatched shard may be assigned to us, but it cannot be
                    // classified until consensus supplies the proposal context.
                    self.buffer_peer_shard(peer, shard);
                    return;
                }
            }

            let state = self
                .records
                .get_mut(&commitment)
                .and_then(CommitmentRecord::reconstruction_mut)
                .expect("reconstruction checked as present");
            let progressed = state.on_network_shard(
                peer,
                shard,
                InsertCtx::new(scheme.as_ref(), &self.strategy),
                &mut self.blocker,
            );
            if progressed {
                self.try_advance(sender, commitment);
            }
        } else {
            self.buffer_peer_shard(peer, shard);
        }
    }

    /// Returns whether an incoming network shard should still be processed.
    ///
    /// Shards for reconstructed commitments are normally ignored. The only
    /// exception is a late shard for the assigned index, which we still accept
    /// so we can notify readiness and gossip it to slower peers.
    fn should_handle_network_shard(&self, commitment: Commitment<B, C, H>) -> bool {
        if let Some(record) = self.records.get(&commitment)
            && record.block().is_some()
        {
            // State can be populated before our assigned shard is verified. Keep
            // handling shards until that state is complete.
            return record
                .reconstruction()
                .is_some_and(|s| !s.is_assigned_shard_verified());
        }
        true
    }

    /// Attempts to reconstruct a [`CodedBlock`] from the checked [`Shard`]s present in the
    /// [`ReconstructionState`].
    ///
    /// # Returns
    /// - `Ok(Some(block))` if reconstruction was successful or the block was already reconstructed.
    /// - `Ok(None)` if reconstruction could not be attempted due to insufficient checked shards.
    /// - `Err(_)` if reconstruction was attempted but failed.
    #[allow(clippy::type_complexity)]
    fn try_reconstruct(
        &mut self,
        commitment: Commitment<B, C, H>,
    ) -> Result<Option<Arc<CodedBlock<B, C, H>>>, Error<C>> {
        let Some(record) = self.records.get_mut(&commitment) else {
            return Ok(None);
        };
        if let Some(block) = record.block() {
            return Ok(Some(Arc::clone(block)));
        }
        let round = record.round();
        let state = record
            .reconstruction_mut()
            .expect("an uncached commitment record must be reconstructing");
        if state.checked_shards().len() < usize::from(commitment.config().minimum_shards.get()) {
            debug!(%commitment, "not enough checked shards to reconstruct block");
            return Ok(None);
        }
        // Attempt to reconstruct the encoded blob
        let start = self.context.current();
        let blob = C::decode(
            &commitment.config(),
            &commitment.root(),
            state.checked_shards().iter(),
            &self.strategy,
        )
        .map_err(Error::Coding)?;
        self.metrics
            .erasure_decode_duration
            .observe_between(start, self.context.current());

        // Attempt to decode the block from the encoded blob
        let (inner, config): (B, CodingConfig) =
            Decode::decode_cfg(&mut blob.as_slice(), &(self.block_codec_cfg.clone(), ()))?;

        match validate_reconstruction(&inner, config, commitment) {
            Ok(()) => {}
            Err(InvariantError::BlockDigest) => {
                return Err(Error::DigestMismatch);
            }
            Err(InvariantError::CodingConfig) => {
                warn!(
                    %commitment,
                    expected_config = ?commitment.config(),
                    actual_config = ?config,
                    "reconstructed block config does not match commitment config, but digest matches"
                );
                return Err(Error::ConfigMismatch);
            }
            Err(InvariantError::ContextDigest(expected, actual)) => {
                warn!(
                    %commitment,
                    expected_context_digest = ?expected,
                    actual_context_digest = ?actual,
                    "reconstructed block context digest does not match commitment context digest"
                );
                return Err(Error::ContextMismatch);
            }
        }

        // Construct a coding block with a _trusted_ commitment. `S::decode` verified the blob's
        // integrity against the commitment, so shards can be lazily re-constructed if need be.
        let block = self
            .cache_block(round, Arc::new(CodedBlock::new_trusted(inner, commitment)))
            .expect("reconstruction uses its commitment record's epoch");
        self.metrics.blocks_reconstructed_total.inc();
        Ok(Some(block))
    }

    /// Handles leader announcements for a commitment and advances reconstruction.
    fn handle_external_proposal<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        commitment: Commitment<B, C, H>,
        leader: P,
        round: Round,
    ) {
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%commitment, "no scheme for epoch, ignoring external proposal");
            return;
        };
        let participants = scheme.participants();
        if participants.index(&leader).is_none() {
            warn!(?leader, %commitment, "leader update for non-participant, ignoring");
            return;
        }
        // A reconstructed block normally makes duplicate leader announcements
        // redundant, unless notarized recovery created leaderless state first.
        // In that case, the leader announcement must still populate the
        // leader-dependent path.
        let Some(status) = self.observe_existing_commitment(commitment, round) else {
            return;
        };
        if status == CommitmentStatus::Cached
            && self
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::reconstruction)
                .is_none_or(|state| state.leader().is_some())
        {
            return;
        }
        if let Some(state) = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
        {
            if let Some(existing) = state.leader() {
                if existing != &leader {
                    // A later leader is expected when this commitment is
                    // re-proposed. Retaining the first does not impede participant
                    // readiness because assigned shards are source-independent.
                    debug!(
                        existing = ?existing,
                        ?leader,
                        %commitment,
                        "commitment already has a leader, ignoring update"
                    );
                }
                return;
            }
            state
                .set_leader(leader)
                .expect("leader was checked as absent");
        } else {
            let participants_len = u64::try_from(participants.len())
                .expect("participant count impossibly out of bounds");
            self.insert_reconstruction_record(
                commitment,
                round,
                ReconstructionState::new(Some(leader), participants_len),
            );
        }
        let buffered_progress = self.ingest_buffered_shards(commitment);
        if buffered_progress {
            self.try_advance(sender, commitment);
        }
    }

    /// Handles notarized reconstruction interest before the leader is known.
    ///
    /// This is intentionally narrower than leader discovery: it may reconstruct
    /// the block from sender-indexed gossip shards, but it cannot mark the
    /// local assigned shard as verified.
    fn handle_notarized_commitment<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        commitment: Commitment<B, C, H>,
        round: Round,
    ) {
        let Some(status) = self.observe_existing_commitment(commitment, round) else {
            return;
        };
        if status == CommitmentStatus::Cached {
            return;
        }
        if status == CommitmentStatus::Reconstructing {
            let buffered_progress = self.ingest_buffered_shards(commitment);
            if buffered_progress {
                self.try_advance(sender, commitment);
            }
            return;
        }
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%commitment, "no scheme for epoch, ignoring notarized commitment");
            return;
        };
        let participants_len = u64::try_from(scheme.participants().len())
            .expect("participant count impossibly out of bounds");
        self.insert_reconstruction_record(
            commitment,
            round,
            ReconstructionState::new(None, participants_len),
        );
        let buffered_progress = self.ingest_buffered_shards(commitment);
        if buffered_progress {
            self.try_advance(sender, commitment);
        }
    }

    /// Buffer a shard from a peer until a leader is known.
    fn buffer_peer_shard(&mut self, peer: P, shard: Shard<B, C, H>) {
        if self.latest_primary_peers.position(&peer).is_none() {
            debug!(
                ?peer,
                "pre-leader shard from peer outside latest.primary not buffered"
            );
            return;
        }
        let queue = self.peer_buffers.entry(peer).or_default();
        if queue.len() >= self.peer_buffer_size.get() {
            let _ = queue.pop_front();
        }
        queue.push_back(shard);
    }

    fn update_latest_primary_peers(&mut self, peers: Set<P>) {
        self.peer_buffers
            .retain(|peer, _| peers.position(peer).is_some());
        self.latest_primary_peers = peers;
    }

    /// Ingest buffered pre-leader shards for a commitment into active state.
    ///
    /// Before proposal context is known, only sender-indexed gossip is
    /// actionable. Once context exists, the local assigned index is valid from
    /// any participant because its proof is bound to the commitment.
    fn ingest_buffered_shards(&mut self, commitment: Commitment<B, C, H>) -> bool {
        let record = self
            .records
            .get(&commitment)
            .expect("buffered shards can only be ingested with a commitment record");
        let round = record.round();
        let state = record
            .reconstruction()
            .expect("buffered shards can only be ingested with reconstruction state");
        let leader_known = state.leader().is_some();
        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%commitment, "no scheme for epoch, dropping buffered shards");
            return false;
        };

        let mut buffered = Vec::new();
        for (peer, queue) in self.peer_buffers.iter_mut() {
            let mut i = 0;
            while i < queue.len() {
                if queue[i].commitment() != commitment {
                    i += 1;
                    continue;
                }
                if !leader_known {
                    let Some(sender_index) = scheme.participants().index(peer) else {
                        i += 1;
                        continue;
                    };
                    let expected_index: u16 = sender_index
                        .get()
                        .try_into()
                        .expect("participant index impossibly out of bounds");
                    if queue[i].index() != expected_index {
                        i += 1;
                        continue;
                    }
                }
                let shard = queue.swap_remove_back(i).expect("index is valid");
                buffered.push((peer.clone(), shard));
            }
        }

        let state = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
            .expect("reconstruction state checked before buffered shard drain");

        // Ingest buffered shards into the active reconstruction state. Batch verification
        // will be triggered if there are enough shards to meet the quorum threshold.
        let mut progressed = false;
        let ctx = InsertCtx::new(scheme.as_ref(), &self.strategy);
        for (peer, shard) in buffered {
            progressed |= state.on_network_shard(peer, shard, ctx, &mut self.blocker);
        }
        progressed
    }

    /// Records a consensus observation on an existing commitment owner.
    ///
    /// Returns the record's phase, [`CommitmentStatus::Absent`] if it has no
    /// owner yet, or `None` when its owner is bound to a different epoch.
    fn observe_existing_commitment(
        &mut self,
        commitment: Commitment<B, C, H>,
        round: Round,
    ) -> Option<CommitmentStatus> {
        let observed_epoch = round.epoch();
        let Some(record) = self.records.get_mut(&commitment) else {
            return Some(CommitmentStatus::Absent);
        };
        if let Err(existing_epoch) = record.observe(round) {
            warn!(
                %commitment,
                %existing_epoch,
                %observed_epoch,
                "commitment observation has conflicting epoch, ignoring"
            );
            return None;
        }
        Some(if record.block().is_some() {
            CommitmentStatus::Cached
        } else {
            CommitmentStatus::Reconstructing
        })
    }

    /// Creates the first lifecycle record for a reconstructing commitment.
    fn insert_reconstruction_record(
        &mut self,
        commitment: Commitment<B, C, H>,
        round: Round,
        reconstruction: ReconstructionState<P, B, C, H>,
    ) {
        let Entry::Vacant(entry) = self.records.entry(commitment) else {
            unreachable!("commitment status was checked as absent");
        };
        entry.insert(CommitmentRecord::reconstructing(round, reconstruction));
        self.metrics.reconstruction_states_count.inc();
    }

    /// Cache a block and notify all subscribers waiting on it.
    fn cache_block(
        &mut self,
        round: Round,
        block: Arc<CodedBlock<B, C, H>>,
    ) -> Result<Arc<CodedBlock<B, C, H>>, Epoch> {
        let commitment = block.commitment();
        let cached = match self.records.entry(commitment) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().observe(round)?;
                let newly_cached = entry.get().block().is_none();
                let cached = entry.get_mut().install_block(block);
                if newly_cached {
                    self.metrics.reconstructed_blocks_cache_count.inc();
                }
                cached
            }
            Entry::Vacant(entry) => {
                entry.insert(CommitmentRecord::cached(round, Arc::clone(&block)));
                self.metrics.reconstructed_blocks_cache_count.inc();
                block
            }
        };
        self.notify_block_subscribers(Arc::clone(&cached));
        Ok(cached)
    }

    /// Broadcasts the shards of a [`CodedBlock`] and caches the block.
    ///
    /// - Participants receive the shard matching their participant index.
    /// - Non-participants in aggregate membership receive the leader's shard.
    fn broadcast_shards<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        round: Round,
        block: Arc<CodedBlock<B, C, H>>,
    ) {
        let commitment = block.commitment();

        if let Some(record) = self.records.get(&commitment)
            && let Err(existing_epoch) = record.validate_epoch(round)
        {
            warn!(
                %commitment,
                %existing_epoch,
                observed_epoch = %round.epoch(),
                "local proposal has conflicting epoch, ignoring"
            );
            return;
        }

        let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
            warn!(%commitment, "no scheme available, cannot broadcast shards");
            return;
        };
        let participants = scheme.participants();
        let Some(me) = scheme.me() else {
            warn!(
                %commitment,
                "cannot broadcast shards: local proposer is not a participant"
            );
            return;
        };

        let shard_count = block.shards(&self.strategy).len();
        if shard_count != participants.len() {
            warn!(
                %commitment,
                shard_count,
                participants = participants.len(),
                "cannot broadcast shards: participant/shard count mismatch"
            );
            return;
        }

        let my_index = me.get() as usize;
        let leader_shard = block
            .shard(my_index as u16)
            .expect("proposer's shard must exist");

        // Broadcast each participant their corresponding shard.
        for (index, peer) in participants.iter().enumerate() {
            if index == my_index {
                continue;
            }

            let Some(shard) = block.shard(index as u16) else {
                warn!(
                    %commitment,
                    index,
                    "cannot broadcast shards: missing shard for participant index"
                );
                return;
            };
            let _ = sender.send(Recipients::One(peer.clone()), shard, true);
        }

        // Send the leader's shard to peers in aggregate membership who are not participants.
        let non_participants: Vec<P> = self
            .aggregate_peers
            .iter()
            .filter(|peer| participants.index(peer).is_none())
            .cloned()
            .collect();
        if !non_participants.is_empty() {
            let _ = sender.send(Recipients::Some(non_participants), leader_shard, true);
        }

        // Cache the block so we don't have to reconstruct it again.
        self.cache_block(round, block)
            .expect("local proposal epoch was validated before broadcast");
        self.records
            .get_mut(&commitment)
            .expect("caching a local proposal must create a commitment record")
            .mark_proposed();

        // Local proposals bypass reconstruction, so shard subscribers waiting
        // for "our valid shard arrived" still need a notification.
        self.notify_assigned_shard_verified_subscribers(commitment);

        debug!(?commitment, "broadcasted shards");
    }

    /// Gossips a validated [`Shard`] using [`commonware_p2p::Recipients::All`].
    fn broadcast_shard<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        shard: Shard<B, C, H>,
    ) {
        let commitment = shard.commitment();
        let peers = sender.send(Recipients::All, shard, true);
        debug!(
            ?commitment,
            peers = peers.len(),
            "broadcasted shard to all peers"
        );
    }

    /// Broadcasts any pending validated shard and attempts reconstruction.
    ///
    /// Successful reconstruction caches the block while retaining any shard state
    /// still needed for assigned-shard readiness. Failed reconstruction retires the
    /// commitment and its commitment-specific subscriptions.
    fn try_advance<Sr: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<Sr, Shard<B, C, H>>,
        commitment: Commitment<B, C, H>,
    ) {
        if let Some(state) = self
            .records
            .get_mut(&commitment)
            .and_then(CommitmentRecord::reconstruction_mut)
        {
            match state.take_pending_action() {
                Some(AssignedShardVerifiedAction::Broadcast(shard)) => {
                    self.broadcast_shard(sender, shard);
                    self.notify_assigned_shard_verified_subscribers(commitment);
                }
                Some(AssignedShardVerifiedAction::NotifyOnly) => {
                    self.notify_assigned_shard_verified_subscribers(commitment);
                }
                None => {}
            }
        }

        match self.try_reconstruct(commitment) {
            Ok(Some(block)) => {
                // Do not prune other reconstruction state here. A Byzantine
                // leader can equivocate by proposing multiple commitments in
                // the same round, so more than one block may be reconstructed
                // for a given round. Retirement is deferred until durable
                // application progress supplies both eligibility signals.
                debug!(
                    %commitment,
                    parent = %block.parent(),
                    height = %block.height(),
                    "successfully reconstructed block from shards"
                );
            }
            Ok(None) => {
                debug!(%commitment, "not enough checked shards to reconstruct block");
            }
            Err(err) => {
                warn!(%commitment, ?err, "failed to reconstruct block from checked shards");
                self.retire_commitment(commitment, RetirementReason::Exact);
                self.metrics.reconstruction_failures_total.inc();
            }
        }
    }

    /// Handles the registry of an assigned shard verification subscription.
    ///
    /// For participants this is tied to verification of the shard for the local
    /// index, not to generic block reconstruction.
    fn handle_assigned_shard_verified_subscription(
        &mut self,
        commitment: Commitment<B, C, H>,
        response: oneshot::Sender<()>,
    ) {
        // Answer immediately if our own shard has been verified or we built the block.
        if self
            .records
            .get(&commitment)
            .is_some_and(CommitmentRecord::is_assigned_shard_ready)
        {
            response.send_lossy(());
            return;
        }

        self.assigned_shard_verified_subscriptions
            .entry(commitment)
            .or_default()
            .push(response);
    }

    /// Handles the registry of a block subscription.
    fn handle_block_subscription(
        &mut self,
        key: BlockSubscriptionKey<Commitment<B, C, H>, B::Digest>,
        response: oneshot::Sender<Arc<CodedBlock<B, C, H>>>,
    ) {
        let block = match key {
            BlockSubscriptionKey::Commitment(commitment) => self
                .records
                .get(&commitment)
                .and_then(CommitmentRecord::block),
            BlockSubscriptionKey::Digest(digest) => self
                .records
                .values()
                .filter_map(CommitmentRecord::block)
                .find(|block| block.digest() == digest),
        };

        // Answer immediately if we have the block cached.
        if let Some(block) = block {
            response.send_lossy(Arc::clone(block));
            return;
        }

        self.block_subscriptions
            .entry(key)
            .or_default()
            .push(response);
    }

    /// Notifies and cleans up any subscriptions waiting for assigned shard
    /// verification.
    fn notify_assigned_shard_verified_subscribers(&mut self, commitment: Commitment<B, C, H>) {
        if let Some(mut subscribers) = self
            .assigned_shard_verified_subscriptions
            .remove(&commitment)
        {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(());
            }
        }
    }

    /// Notifies and cleans up any subscriptions for a reconstructed block.
    fn notify_block_subscribers(&mut self, block: Arc<CodedBlock<B, C, H>>) {
        let commitment = block.commitment();
        let digest = block.digest();

        // Notify by-commitment subscribers.
        if let Some(mut subscribers) = self
            .block_subscriptions
            .remove(&BlockSubscriptionKey::Commitment(commitment))
        {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(Arc::clone(&block));
            }
        }

        // Notify by-digest subscribers.
        if let Some(mut subscribers) = self
            .block_subscriptions
            .remove(&BlockSubscriptionKey::Digest(digest))
        {
            for subscriber in subscribers.drain(..) {
                subscriber.send_lossy(Arc::clone(&block));
            }
        }
    }

    /// Retires one commitment and applies the subscription policy for the cause.
    fn retire_commitment(&mut self, commitment: Commitment<B, C, H>, reason: RetirementReason) {
        let had_reconstruction = self.records.remove(&commitment).is_some_and(|record| {
            let had_reconstruction = record.reconstruction().is_some();
            if had_reconstruction {
                self.metrics.reconstruction_states_count.dec();
            }
            if record.block().is_some() {
                self.metrics.reconstructed_blocks_cache_count.dec();
            }
            had_reconstruction
        });

        if matches!(reason, RetirementReason::Exact) || had_reconstruction {
            self.assigned_shard_verified_subscriptions
                .remove(&commitment);
        }
        if matches!(reason, RetirementReason::Exact) {
            // Before marshal accepts a block, a candidate can claim a digest it cannot
            // reconstruct. Retiring it therefore does not prove the digest unavailable.
            self.block_subscriptions
                .remove(&BlockSubscriptionKey::Commitment(commitment));
        }
    }

    /// Retires cached blocks and reconstruction state after durable application progress.
    ///
    /// Retirement waits for durable progress because a Byzantine leader may produce multiple
    /// valid commitments in one round.
    fn retire(&mut self, update: Retirement<Commitment<B, C, H>>) {
        let Retirement {
            round_floor,
            exact_retirements,
        } = update;
        // Durable processing makes existing exact-commitment and assigned-shard waits for these
        // states obsolete. Digest waits are not commitment-specific.
        for commitment in exact_retirements {
            self.retire_commitment(commitment, RetirementReason::Exact);
        }

        // Entries observed in later rounds may still be needed for certification. Block
        // subscriptions remain open because local ingress can still satisfy them after a floor.
        let retired = self
            .records
            .iter()
            .filter_map(|(commitment, record)| {
                (record.round() <= round_floor).then_some(*commitment)
            })
            .collect::<Vec<_>>();
        for commitment in retired {
            self.retire_commitment(commitment, RetirementReason::Floor);
        }
    }
}

/// Erasure coded block reconstruction state machine.
enum ReconstructionState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// Stage 1: accumulate shards. The shard for our assigned index is verified
    /// immediately. All other shards are buffered until enough are available
    /// for batch verification.
    AwaitingQuorum(AwaitingQuorumState<P, B, C, H>),
    /// Stage 2: batch validation passed. Checked shards are available for
    /// reconstruction.
    Ready(ReadyState<P, B, C, H>),
}

/// Action to take once assigned shard verification has been established.
///
/// Participants broadcast the shard to all peers, while non-participants
/// only notify local subscribers.
enum AssignedShardVerifiedAction<B: Digestible, C: CodingScheme, H: Hasher> {
    /// Broadcast the shard to all peers and notify local subscribers.
    Broadcast(Shard<B, C, H>),
    /// Only notify local subscribers (non-participant validated the leader's shard).
    NotifyOnly,
}

/// A coding shard paired with its participant index.
struct IndexedShard<C: CodingScheme> {
    index: u16,
    data: C::Shard,
}

/// State shared across all reconstruction phases.
struct CommonState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// The leader associated with this reconstruction state, if consensus has
    /// provided it.
    leader: Option<P>,
    /// Our validated shard and the action to take with it.
    pending_action: Option<AssignedShardVerifiedAction<B, C, H>>,
    /// Shards that have been verified and are ready to contribute to reconstruction.
    checked_shards: Vec<C::CheckedShard>,
    /// Bitmap tracking which participant indices have contributed a shard.
    contributed: BitMap,
    /// Raw shard data received per index, retained for equivocation detection.
    /// Keyed by shard index.
    received_shards: BTreeMap<u16, C::Shard>,
    /// Whether the shard for our assigned index has been verified.
    assigned_shard_verified: bool,
}

/// Phase data for `ReconstructionState::AwaitingQuorum`.
///
/// In this phase, the leader may be unknown. Sender-indexed shards can still be
/// buffered until enough are available to attempt batch validation. Once proposal
/// context is known, the shard for our assigned index is verified eagerly via
/// `C::check`, regardless of which participant delivered it.
struct AwaitingQuorumState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    common: CommonState<P, B, C, H>,
    /// Shards pending batch validation, keyed by sender.
    pending_shards: BTreeMap<P, IndexedShard<C>>,
}

/// Phase data for `ReconstructionState::Ready`.
///
/// Batch validation has passed. Checked shards are available for
/// reconstruction.
struct ReadyState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    common: CommonState<P, B, C, H>,
}

impl<P, B, C, H> CommonState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// Create a new empty common state for the provided leader.
    fn new(leader: Option<P>, participants_len: u64) -> Self {
        Self {
            leader,
            pending_action: None,
            checked_shards: Vec::new(),
            contributed: BitMap::zeroes(participants_len),
            received_shards: BTreeMap::new(),
            assigned_shard_verified: false,
        }
    }
}

impl<P, B, C, H> CommonState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// Verify the assigned shard and store it.
    ///
    /// When `is_participant` is true, the validated shard is stored for
    /// broadcasting to peers. When false (non-participant), only subscriber
    /// notification is scheduled.
    ///
    /// Returns `false` if verification fails (sender is blocked), `true` on
    /// success.
    fn verify_assigned_shard(
        &mut self,
        sender: P,
        commitment: Commitment<B, C, H>,
        shard: IndexedShard<C>,
        is_participant: bool,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) -> bool {
        // Store data for equivocation detection first (move), then clone
        // once for check. This avoids a second clone compared to cloning
        // for both check and storage.
        self.received_shards.insert(shard.index, shard.data);
        let data = self.received_shards.get(&shard.index).unwrap();
        let Ok(checked) = C::check(&commitment.config(), &commitment.root(), shard.index, data)
        else {
            self.received_shards.remove(&shard.index);
            commonware_p2p::block!(blocker, sender, "invalid assigned shard received");
            return false;
        };

        self.contributed.set(u64::from(shard.index), true);
        self.checked_shards.push(checked);
        self.assigned_shard_verified = true;
        self.pending_action = Some(if is_participant {
            AssignedShardVerifiedAction::Broadcast(Shard::new(
                commitment,
                shard.index,
                data.clone(),
            ))
        } else {
            AssignedShardVerifiedAction::NotifyOnly
        });
        true
    }
}

impl<P, B, C, H> AwaitingQuorumState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// Check whether quorum is met and, if so, batch-validate all pending
    /// shards in parallel. Returns `Some(ReadyState)` on successful transition.
    fn try_transition(
        &mut self,
        commitment: Commitment<B, C, H>,
        participants_len: u64,
        strategy: &impl Strategy,
        blocker: &mut impl Blocker<PublicKey = P>,
    ) -> Option<ReadyState<P, B, C, H>> {
        let minimum = usize::from(commitment.config().minimum_shards.get());
        if self.common.checked_shards.len() + self.pending_shards.len() < minimum {
            return None;
        }

        // Batch-validate all pending weak shards in parallel.
        let pending = std::mem::take(&mut self.pending_shards);
        let (new_checked, to_block) =
            strategy.map_partition_collect_vec(pending, |(peer, shard)| {
                let checked = C::check(
                    &commitment.config(),
                    &commitment.root(),
                    shard.index,
                    &shard.data,
                );
                (peer, checked.ok())
            });

        for peer in to_block {
            commonware_p2p::block!(blocker, peer, "invalid shard received");
        }
        for checked in new_checked {
            self.common.checked_shards.push(checked);
        }

        // After validation, some may have failed; recheck threshold.
        if self.common.checked_shards.len() < minimum {
            return None;
        }

        // Transition to Ready.
        let leader = self.common.leader.clone();
        let common =
            std::mem::replace(&mut self.common, CommonState::new(leader, participants_len));
        Some(ReadyState { common })
    }
}

/// Context required for processing incoming network shards.
struct InsertCtx<'a, Sch, S>
where
    Sch: CertificateScheme,
    S: Strategy,
{
    scheme: &'a Sch,
    strategy: &'a S,
    participants_len: u64,
}

impl<Sch: CertificateScheme, S: Strategy> Clone for InsertCtx<'_, Sch, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Sch: CertificateScheme, S: Strategy> Copy for InsertCtx<'_, Sch, S> {}

impl<'a, Sch: CertificateScheme, S: Strategy> InsertCtx<'a, Sch, S> {
    fn new(scheme: &'a Sch, strategy: &'a S) -> Self {
        let participants_len = u64::try_from(scheme.participants().len())
            .expect("participant count impossibly out of bounds");
        Self {
            scheme,
            strategy,
            participants_len,
        }
    }
}

impl<P, B, C, H> ReconstructionState<P, B, C, H>
where
    P: PublicKey,
    B: Digestible,
    C: CodingScheme,
    H: Hasher,
{
    /// Create an initial reconstruction state for a commitment.
    fn new(leader: Option<P>, participants_len: u64) -> Self {
        Self::AwaitingQuorum(AwaitingQuorumState {
            common: CommonState::new(leader, participants_len),
            pending_shards: BTreeMap::new(),
        })
    }

    /// Access common state shared across all phases.
    const fn common(&self) -> &CommonState<P, B, C, H> {
        match self {
            Self::AwaitingQuorum(state) => &state.common,
            Self::Ready(state) => &state.common,
        }
    }

    /// Mutably access common state shared across all phases.
    const fn common_mut(&mut self) -> &mut CommonState<P, B, C, H> {
        match self {
            Self::AwaitingQuorum(state) => &mut state.common,
            Self::Ready(state) => &mut state.common,
        }
    }

    /// Return the leader associated with this state.
    const fn leader(&self) -> Option<&P> {
        self.common().leader.as_ref()
    }

    /// Set the leader for this state if it has not already been set.
    fn set_leader(&mut self, leader: P) -> Result<(), P> {
        if self.common().leader.is_some() {
            return Err(leader);
        }
        self.common_mut().leader = Some(leader);
        Ok(())
    }

    /// Returns whether the shard for our assigned index has been verified.
    const fn is_assigned_shard_verified(&self) -> bool {
        self.common().assigned_shard_verified
    }

    /// Returns all verified shards accumulated for reconstruction.
    const fn checked_shards(&self) -> &[C::CheckedShard] {
        self.common().checked_shards.as_slice()
    }

    /// Takes the pending action for this commitment's validated shard.
    ///
    /// Returns [`None`] if the assigned shard hasn't been validated yet.
    const fn take_pending_action(&mut self) -> Option<AssignedShardVerifiedAction<B, C, H>> {
        self.common_mut().pending_action.take()
    }

    /// Handle an incoming network shard.
    ///
    /// Returns `true` only when the shard caused state progress (buffered,
    /// validated, or transitioned), and `false` when rejected/blocked.
    ///
    /// ## Peer Blocking Rules
    ///
    /// The `sender` may be blocked via the provided [`Blocker`] if any of
    /// the following rules are violated:
    ///
    /// - MUST be sent by a participant in the current epoch. Non-participant
    ///   senders are blocked.
    /// - A participant's assigned index may be delivered by any participant.
    /// - Other shards MUST match the sender's participant index.
    /// - Once proposal context is known, any other shard index results in
    ///   blocking.
    /// - Each shard index may only contribute ONE shard per commitment.
    ///   Sending a second shard for the same index with different data
    ///   (equivocation) results in blocking the sender.
    /// - The assigned shard is verified eagerly via [`CodingScheme::check`].
    ///   If verification fails, the sender is blocked.
    /// - Own-index shards are buffered in `pending_shards` and
    ///   batch-validated when quorum is reached. Invalid shards discovered
    ///   during batch validation result in blocking their respective
    ///   senders.
    ///
    /// ## Silent Discard Rules
    ///
    /// The following conditions cause a shard to be silently ignored
    /// without blocking the sender:
    ///
    /// - Exact duplicate of a previously received shard for the same index.
    /// - The index has already been marked as contributed (via the bitmap,
    ///   e.g. after batch validation).
    /// - Own-index shards that arrive after the state has transitioned to
    ///   [`ReconstructionState::Ready`] (i.e., batch validation has already
    ///   passed). An assigned shard for our index is still accepted in
    ///   `Ready` state to ensure we verify and re-broadcast it.
    /// - Before a reconstruction state exists, shards are buffered at the
    ///   engine level in bounded per-peer queues until [`Mailbox::discovered`]
    ///   or [`Mailbox::notarized`] creates state for this commitment.
    fn on_network_shard<Sch, S, X>(
        &mut self,
        sender: P,
        shard: Shard<B, C, H>,
        ctx: InsertCtx<'_, Sch, S>,
        blocker: &mut X,
    ) -> bool
    where
        Sch: CertificateScheme<PublicKey = P>,
        S: Strategy,
        X: Blocker<PublicKey = P>,
    {
        let Some(sender_index) = ctx.scheme.participants().index(&sender) else {
            commonware_p2p::block!(blocker, sender, "shard sent by non-participant");
            return false;
        };
        let commitment = shard.commitment();
        let indexed = IndexedShard {
            index: shard.index(),
            data: shard.into_inner(),
        };

        // A participant's assigned shard is source-independent because it is
        // verified eagerly. Every other shard must be sender-owned so each sender
        // contributes at most one shard before batch verification.
        let sender_index: u16 = sender_index
            .get()
            .try_into()
            .expect("participant index impossibly out of bounds");
        let assigned_index: Option<u16> = ctx.scheme.me().map(|assigned_index| {
            assigned_index
                .get()
                .try_into()
                .expect("participant index impossibly out of bounds")
        });
        let is_from_leader = self.leader().is_some_and(|leader| leader == &sender);
        let is_assigned_shard = assigned_index
            .is_some_and(|assigned_index| indexed.index == assigned_index)
            || assigned_index.is_none() && is_from_leader && indexed.index == sender_index;
        let is_gossip_shard = indexed.index == sender_index;
        if !is_assigned_shard && !is_gossip_shard {
            if self.leader().is_some() {
                commonware_p2p::block!(
                    blocker,
                    sender,
                    shard_index = indexed.index,
                    "shard index is neither assigned nor sender-owned"
                );
            }
            return false;
        }

        // Equivocation/duplicate check.
        if let Some(existing) = self.common().received_shards.get(&indexed.index) {
            if existing != &indexed.data {
                commonware_p2p::block!(blocker, sender, "shard equivocation");
            }
            return false;
        }

        // Check if this index already contributed (via batch validation).
        if self.common().contributed.get(u64::from(indexed.index)) {
            return false;
        }

        // The assigned shard is always verified eagerly, even after transitioning
        // to Ready. This ensures we broadcast it to help slower peers reach quorum.
        if is_assigned_shard && !self.common().assigned_shard_verified {
            let progressed = self.common_mut().verify_assigned_shard(
                sender,
                commitment,
                indexed,
                ctx.scheme.me().is_some(),
                blocker,
            );

            if progressed
                && let Self::AwaitingQuorum(state) = self
                && let Some(ready) =
                    state.try_transition(commitment, ctx.participants_len, ctx.strategy, blocker)
            {
                *self = Self::Ready(ready);
            }
            return progressed;
        }

        // Gossip shards are only accepted while awaiting quorum.
        let Self::AwaitingQuorum(state) = self else {
            return false;
        };

        // Buffer for batch validation.
        state
            .common
            .received_shards
            .insert(indexed.index, indexed.data.clone());
        state.common.contributed.set(u64::from(indexed.index), true);
        state.pending_shards.insert(sender, indexed);
        if let Some(ready) =
            state.try_transition(commitment, ctx.participants_len, ctx.strategy, blocker)
        {
            *self = Self::Ready(ready);
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{coding::types::coding_config_for_participants, mocks::block::EmptyBlock},
        types::{Epoch, Height, View},
    };
    use bytes::Bytes;
    use commonware_codec::Encode;
    use commonware_coding::{
        CodecConfig, Config as CodingConfig, PhasedAsScheme, ReedSolomon, Zoda,
    };
    use commonware_cryptography::{
        Committable, Digest, Sha256, Signer,
        certificate::{Scoped, Subject},
        ed25519::{PrivateKey, PublicKey},
        impl_certificate_ed25519,
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{
        Manager as _, TrackedPeers,
        simulated::{self, Control, Link, Oracle},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Quota, Runner, Supervisor as _, deterministic};
    use commonware_utils::{
        N3f1, NZUsize, Participant, channel::oneshot::error::TryRecvError, ordered::Set,
        probability,
    };
    use std::{
        future::Future,
        marker::PhantomData,
        num::{NonZeroU32, NonZeroUsize},
        sync::{
            Arc,
            atomic::{AtomicIsize, Ordering},
        },
        time::Duration,
    };

    #[derive(Clone, Debug)]
    pub struct TestSubject {
        pub message: Bytes,
    }

    impl Subject for TestSubject {
        type Namespace = Vec<u8>;

        fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
            derived
        }

        fn message(&self) -> Bytes {
            self.message.clone()
        }
    }

    impl_certificate_ed25519!(TestSubject, Vec<u8>, N3f1);

    const SCHEME_NAMESPACE: &[u8] = b"_COMMONWARE_SHARD_ENGINE_TEST";

    /// The max size of a shard sent over the wire.
    const MAX_SHARD_SIZE: usize = 1024 * 1024; // 1 MiB

    /// The default link configuration for tests.
    const DEFAULT_LINK: Link = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::ZERO,
        success_rate: probability!(1.0),
    };

    /// Rate limit quota for tests (effectively unlimited).
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    /// The parallelization strategy used for tests.
    const STRATEGY: Sequential = Sequential;

    /// A scheme provider that maps each epoch to a potentially different scheme.
    ///
    /// For most tests only epoch 0 is registered, matching the previous
    /// `ConstantProvider` behaviour. Cross-epoch tests register additional
    /// epochs with different participant sets.
    #[derive(Clone)]
    struct MultiEpochProvider {
        schemes: BTreeMap<Epoch, Arc<Scheme>>,
    }

    impl MultiEpochProvider {
        fn single(scheme: Scheme) -> Self {
            let mut schemes = BTreeMap::new();
            schemes.insert(Epoch::zero(), Arc::new(scheme));
            Self { schemes }
        }

        fn with_epoch(mut self, epoch: Epoch, scheme: Scheme) -> Self {
            self.schemes.insert(epoch, Arc::new(scheme));
            self
        }
    }

    impl Provider for MultiEpochProvider {
        type Scope = Epoch;
        type Scheme = Scheme;

        fn scoped(&self, scope: Epoch) -> Option<Scoped<Scheme>> {
            self.schemes.get(&scope).cloned().map(Scoped::scheme)
        }
    }

    /// A one-epoch scheme provider that churns to `None` after a fixed number
    /// of successful scope lookups.
    #[derive(Clone)]
    struct ChurningProvider {
        scheme: Arc<Scheme>,
        remaining_successes: Arc<AtomicIsize>,
    }

    impl ChurningProvider {
        fn new(scheme: Scheme, successes: isize) -> Self {
            Self {
                scheme: Arc::new(scheme),
                remaining_successes: Arc::new(AtomicIsize::new(successes)),
            }
        }
    }

    impl Provider for ChurningProvider {
        type Scope = Epoch;
        type Scheme = Scheme;

        fn scoped(&self, scope: Epoch) -> Option<Scoped<Scheme>> {
            if scope != Epoch::zero() {
                return None;
            }
            if self.remaining_successes.fetch_sub(1, Ordering::AcqRel) <= 0 {
                return None;
            }
            Some(Scoped::scheme(Arc::clone(&self.scheme)))
        }
    }

    // Type aliases for test convenience.
    type B = EmptyBlock<H>;
    type H = Sha256;
    type P = PublicKey;
    type C = ReedSolomon<H>;
    type X = Control<P, deterministic::Context>;
    type O = Oracle<P, deterministic::Context>;
    type Prov = MultiEpochProvider;
    type NetworkSender = simulated::Sender<P, deterministic::Context>;
    type D = simulated::Manager<P, deterministic::Context>;
    type ShardEngine<S> = Engine<deterministic::Context, Prov, X, D, S, H, B, P, Sequential>;
    type ChurningShardEngine<S> =
        Engine<deterministic::Context, ChurningProvider, X, D, S, H, B, P, Sequential>;

    async fn assert_blocked(oracle: &O, blocker: &P, blocked: &P) {
        let blocked_peers = oracle.blocked().await.unwrap();
        let is_blocked = blocked_peers
            .iter()
            .any(|(a, b)| a == blocker && b == blocked);
        assert!(is_blocked, "expected {blocker} to have blocked {blocked}");
    }

    /// A participant in the test network with its engine mailbox and blocker.
    struct Peer<S: CodingScheme = C> {
        /// The peer's public key.
        public_key: PublicKey,
        /// The peer's index in the participant set.
        index: Participant,
        /// The mailbox for sending messages to the peer's shard engine.
        mailbox: Mailbox<B, S, H, P>,
        /// Raw network sender for injecting messages (e.g., byzantine behavior).
        sender: NetworkSender,
    }

    /// A non-participant in the test network with its engine mailbox.
    #[allow(dead_code)]
    struct NonParticipant<S: CodingScheme = C> {
        /// The peer's public key.
        public_key: PublicKey,
        /// The mailbox for sending messages to the peer's shard engine.
        mailbox: Mailbox<B, S, H, P>,
        /// Raw network sender for injecting messages.
        sender: NetworkSender,
    }

    /// Test fixture for setting up multiple participants with shard engines.
    struct Fixture<S: CodingScheme = C> {
        /// Number of primary peers created during setup.
        num_primary_peers: usize,
        /// Number of secondary peers created during setup.
        num_secondary_peers: usize,
        /// Number of peers introduced after setup.
        num_future_peers: usize,
        /// Additional epochs that use the fixture's participant set.
        additional_scheme_epochs: Vec<Epoch>,
        /// Network link configuration.
        link: Link,
        /// Per-peer capacity for shards received before leader discovery.
        peer_buffer_size: NonZeroUsize,
        /// Marker for the coding scheme type parameter.
        _marker: PhantomData<S>,
    }

    impl<S: CodingScheme> Default for Fixture<S> {
        fn default() -> Self {
            Self {
                num_primary_peers: 4,
                num_secondary_peers: 0,
                num_future_peers: 0,
                additional_scheme_epochs: Vec::new(),
                link: DEFAULT_LINK,
                peer_buffer_size: NZUsize!(64),
                _marker: PhantomData,
            }
        }
    }

    impl<S: CodingScheme> Fixture<S> {
        pub fn start<F: Future<Output = ()>>(
            self,
            f: impl FnOnce(
                Self,
                deterministic::Context,
                O,
                Vec<Peer<S>>,
                Vec<NonParticipant<S>>,
                CodingConfig,
            ) -> F,
        ) {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let mut private_keys = (0..self.num_primary_peers)
                    .map(|i| PrivateKey::from_seed(i as u64))
                    .collect::<Vec<_>>();
                private_keys.sort_by_key(|s| s.public_key());
                let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();

                let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

                let mut np_private_keys = (0..self.num_secondary_peers)
                    .map(|i| PrivateKey::from_seed((self.num_primary_peers + i) as u64))
                    .collect::<Vec<_>>();
                np_private_keys.sort_by_key(|s| s.public_key());
                let np_keys: Vec<P> = np_private_keys.iter().map(|k| k.public_key()).collect();

                let (network, oracle) =
                    simulated::Network::<deterministic::Context, P>::new_with_split_peers(
                        context.child("network"),
                        simulated::Config {
                            max_size: MAX_SHARD_SIZE as u32,
                            max_peers_per_set: NZUsize!(
                                self.num_primary_peers
                                    + self.num_secondary_peers.max(self.num_future_peers)
                            ),
                            disconnect_on_block: true,
                            tracked_peer_sets: NZUsize!(1),
                        },
                        peer_keys.clone(),
                        np_keys.clone(),
                    )
                    .await;
                network.start();

                let all_keys: Vec<P> = peer_keys.iter().chain(np_keys.iter()).cloned().collect();

                let mut registrations = BTreeMap::new();
                for key in all_keys.iter() {
                    let control = oracle.control(key.clone());
                    let (sender, receiver) = control
                        .register(0, TEST_QUOTA)
                        .await
                        .expect("registration should succeed");
                    registrations.insert(key.clone(), (control, sender, receiver));
                }
                for p1 in all_keys.iter() {
                    for p2 in all_keys.iter() {
                        if p2 == p1 {
                            continue;
                        }
                        oracle
                            .add_link(p1.clone(), p2.clone(), self.link.clone())
                            .await
                            .expect("link should be added");
                    }
                }

                let coding_config =
                    coding_config_for_participants(u16::try_from(self.num_primary_peers).unwrap());

                let mut peers = Vec::with_capacity(self.num_primary_peers);
                for (idx, peer_key) in peer_keys.iter().enumerate() {
                    let (control, sender, receiver) = registrations
                        .remove(peer_key)
                        .expect("peer should be registered");

                    let participant = Participant::new(idx as u32);
                    let engine_context = context.child("peer").with_attribute("index", idx);

                    let scheme = Scheme::signer(
                        SCHEME_NAMESPACE,
                        participants.clone(),
                        private_keys[idx].clone(),
                    )
                    .expect("signer scheme should be created");
                    let mut scheme_provider = MultiEpochProvider::single(scheme);
                    for epoch in self.additional_scheme_epochs.iter().copied() {
                        let scheme = Scheme::signer(
                            SCHEME_NAMESPACE,
                            participants.clone(),
                            private_keys[idx].clone(),
                        )
                        .expect("signer scheme should be created");
                        scheme_provider = scheme_provider.with_epoch(epoch, scheme);
                    }

                    let config = Config {
                        scheme_provider,
                        blocker: control.clone(),
                        shard_codec_cfg: CodecConfig {
                            maximum_shard_size: MAX_SHARD_SIZE,
                        },
                        block_codec_cfg: (),
                        strategy: STRATEGY,
                        mailbox_size: NZUsize!(1024),
                        peer_buffer_size: self.peer_buffer_size,
                        background_channel_capacity: NZUsize!(1024),
                        peer_provider: oracle.manager(),
                    };

                    let (engine, mailbox) = ShardEngine::new(engine_context, config);
                    let sender_clone = sender.clone();
                    engine.start((sender, receiver));

                    peers.push(Peer {
                        public_key: peer_key.clone(),
                        index: participant,
                        mailbox,
                        sender: sender_clone,
                    });
                }

                let mut non_participants = Vec::with_capacity(self.num_secondary_peers);
                for (idx, np_key) in np_keys.iter().enumerate() {
                    let (control, sender, receiver) = registrations
                        .remove(np_key)
                        .expect("non-participant should be registered");

                    let engine_context = context
                        .child("non_participant")
                        .with_attribute("index", idx);

                    let scheme = Scheme::verifier(SCHEME_NAMESPACE, participants.clone());
                    let mut scheme_provider = MultiEpochProvider::single(scheme);
                    for epoch in self.additional_scheme_epochs.iter().copied() {
                        scheme_provider = scheme_provider.with_epoch(
                            epoch,
                            Scheme::verifier(SCHEME_NAMESPACE, participants.clone()),
                        );
                    }

                    let config = Config {
                        scheme_provider,
                        blocker: control.clone(),
                        shard_codec_cfg: CodecConfig {
                            maximum_shard_size: MAX_SHARD_SIZE,
                        },
                        block_codec_cfg: (),
                        strategy: STRATEGY,
                        mailbox_size: NZUsize!(1024),
                        peer_buffer_size: self.peer_buffer_size,
                        background_channel_capacity: NZUsize!(1024),
                        peer_provider: oracle.manager(),
                    };

                    let (engine, mailbox) = ShardEngine::new(engine_context, config);
                    let sender_clone = sender.clone();
                    engine.start((sender, receiver));

                    non_participants.push(NonParticipant {
                        public_key: np_key.clone(),
                        mailbox,
                        sender: sender_clone,
                    });
                }

                f(
                    self,
                    context,
                    oracle,
                    peers,
                    non_participants,
                    coding_config,
                )
                .await;
            });
        }
    }

    #[test_traced]
    fn test_e2e_broadcast_and_reconstruction() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform all peers of the leader so shards are processed.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency).await;

                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("shard subscription should complete");
                }
                context.sleep(config.link.latency).await;

                for peer in peers.iter_mut() {
                    let reconstructed = peer
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("block should be reconstructed");
                    assert_eq!(reconstructed.commitment(), commitment);
                    assert_eq!(reconstructed.height(), coded_block.height());
                }
            },
        );
    }

    #[test_traced]
    fn test_e2e_broadcast_and_reconstruction_zoda() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, PhasedAsScheme<Zoda<H>>, H>::new(
                    inner,
                    coding_config,
                    &STRATEGY,
                );
                let commitment = coded_block.commitment();

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform all peers of the leader so shards are processed.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency).await;

                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("shard subscription should complete");
                }
                context.sleep(config.link.latency).await;

                for peer in peers.iter_mut() {
                    let reconstructed = peer
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("block should be reconstructed");
                    assert_eq!(reconstructed.commitment(), commitment);
                    assert_eq!(reconstructed.height(), coded_block.height());
                }
            },
        );
    }

    #[test_traced]
    fn test_block_subscriptions() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let digest = coded_block.digest();

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                // Subscribe before broadcasting.
                let commitment_sub = peers[1].mailbox.subscribe(commitment);
                let digest_sub = peers[2].mailbox.subscribe_by_digest(digest);

                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform all peers of the leader so shards are processed.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency * 2).await;

                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("shard subscription should complete");
                }
                context.sleep(config.link.latency).await;

                let block_by_commitment =
                    commitment_sub.await.expect("subscription should resolve");
                assert_eq!(block_by_commitment.commitment(), commitment);
                assert_eq!(block_by_commitment.height(), coded_block.height());

                let block_by_digest = digest_sub.await.expect("subscription should resolve");
                assert_eq!(block_by_digest.commitment(), commitment);
                assert_eq!(block_by_digest.height(), coded_block.height());
            },
        );
    }

    #[test_traced]
    fn test_proposer_preproposal_subscriptions_resolve_after_local_cache() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(|config, context, _, peers, _, coding_config| async move {
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();
            let digest = coded_block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Subscribe on the proposer before it caches the locally proposed block.
            let shard_sub = peers[0].mailbox.subscribe_assigned_shard_verified(commitment);
            let commitment_sub = peers[0].mailbox.subscribe(commitment);
            let digest_sub = peers[0].mailbox.subscribe_by_digest(digest);

            peers[0].mailbox.proposed(round, coded_block.clone());
            context.sleep(config.link.latency).await;

            select! {
                result = shard_sub => {
                    result.expect("shard subscription should resolve");
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("shard subscription did not resolve after local proposal cache");
                }
            }

            let block_by_commitment = select! {
                result = commitment_sub => {
                    result.expect("block subscription by commitment should resolve")
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("block subscription by commitment did not resolve after local proposal cache");
                }
            };
            assert_eq!(block_by_commitment.commitment(), commitment);
            assert_eq!(block_by_commitment.height(), coded_block.height());

            let block_by_digest = select! {
                result = digest_sub => {
                    result.expect("block subscription by digest should resolve")
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("block subscription by digest did not resolve after local proposal cache");
                }
            };
            assert_eq!(block_by_digest.commitment(), commitment);
            assert_eq!(block_by_digest.height(), coded_block.height());
        });
    }

    #[test_traced]
    fn test_shard_subscription_rejects_invalid_shard() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // peers[0] = byzantine
                // peers[1] = honest proposer
                // peers[2] = receiver

                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let receiver_index = peers[2].index.get() as u16;

                let valid_shard = coded_block.shard(receiver_index).expect("missing shard");

                // Corrupt the shard's index to one that doesn't match
                // peers[0]'s participant index, triggering a block.
                let mut invalid_shard = valid_shard.clone();
                invalid_shard.index = peers[3].index.get() as u16;

                // Receiver subscribes to their shard and learns the leader.
                let receiver_pk = peers[2].public_key.clone();
                let leader = peers[1].public_key.clone();
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // Byzantine peer sends the invalid shard.
                let invalid_bytes = invalid_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), invalid_bytes, true);

                context.sleep(config.link.latency * 2).await;

                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "subscription should not resolve from invalid shard"
                );
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;

                // Honest proposer sends the valid shard.
                let valid_bytes = valid_shard.encode();
                peers[1]
                    .sender
                    .send(Recipients::One(receiver_pk), valid_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Subscription should now resolve.
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("subscription did not complete after valid shard arrival");
                    },
                };
            },
        );
    }

    #[test_traced]
    fn test_retire_uses_inclusive_retirement_floor() {
        let fixture = Fixture::<C>::default();
        fixture.start(|_, context, _, mut peers, _, coding_config| async move {
            // The processed commitment was re-proposed above the retirement floor. A malicious
            // candidate was observed below it.
            let processed = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
                &STRATEGY,
            );
            let malicious = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(u64::MAX), 100),
                coding_config,
                &STRATEGY,
            );
            let equal = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(3), 100),
                coding_config,
                &STRATEGY,
            );
            let later = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(2), 100),
                coding_config,
                &STRATEGY,
            );
            let processed_commitment = processed.commitment();
            let malicious_commitment = malicious.commitment();
            let equal_commitment = equal.commitment();
            let later_commitment = later.commitment();

            // Cache all blocks via `proposed`.
            let peer = &mut peers[0];
            peer.mailbox
                .proposed(Round::new(Epoch::zero(), View::new(1)), processed.clone());
            peer.mailbox
                .proposed(Round::new(Epoch::zero(), View::new(2)), malicious);
            peer.mailbox
                .proposed(Round::new(Epoch::zero(), View::new(3)), equal);
            peer.mailbox
                .proposed(Round::new(Epoch::zero(), View::new(1)), later.clone());
            // Re-proposals refresh ownership independently of the commitment's
            // original context round.
            peer.mailbox
                .proposed(Round::new(Epoch::zero(), View::new(5)), processed);
            peer.mailbox
                .proposed(Round::new(Epoch::zero(), View::new(4)), later);
            context.sleep(Duration::from_millis(10)).await;

            // Verify all blocks are in the cache.
            assert!(
                peer.mailbox.get(processed_commitment).await.is_some(),
                "processed block should be cached"
            );
            assert!(
                peer.mailbox.get(malicious_commitment).await.is_some(),
                "malicious block should be cached"
            );
            assert!(
                peer.mailbox.get(equal_commitment).await.is_some(),
                "equal-round block should be cached"
            );
            assert!(
                peer.mailbox.get(later_commitment).await.is_some(),
                "later block should be cached"
            );

            // The authoritative retirement floor removes every earlier candidate and the exact
            // processed commitment, even when that commitment was observed above the floor.
            peer.mailbox.retire(Retirement {
                round_floor: Round::new(Epoch::zero(), View::new(3)),
                exact_retirements: vec![processed_commitment],
            });
            context.sleep(Duration::from_millis(10)).await;

            assert!(
                peer.mailbox.get(processed_commitment).await.is_none(),
                "exact processed block should be pruned above the floor"
            );
            assert!(
                peer.mailbox.get(malicious_commitment).await.is_none(),
                "earlier malicious block should be pruned"
            );
            assert!(
                peer.mailbox.get(equal_commitment).await.is_none(),
                "block observed at the retirement floor should be pruned"
            );
            assert!(
                peer.mailbox.get(later_commitment).await.is_some(),
                "non-target block observed above the floor should remain cached"
            );
        });
    }

    #[test_traced]
    fn test_retire_unseen_commitment_applies_floor() {
        let fixture = Fixture::<C>::default();
        fixture.start(|_, context, _, mut peers, _, coding_config| async move {
            let make_block = |id| {
                CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(id), id),
                    coding_config,
                    &STRATEGY,
                )
            };
            let cached_old = make_block(1);
            let cached_equal = make_block(2);
            let cached_later = make_block(3);
            let state_old = make_block(4).commitment();
            let state_equal = make_block(5).commitment();
            let state_later = make_block(6).commitment();
            let unseen = make_block(7).commitment();
            let cached_old_commitment = cached_old.commitment();
            let cached_equal_commitment = cached_equal.commitment();
            let cached_later_commitment = cached_later.commitment();
            let old_round = Round::new(Epoch::zero(), View::new(2));
            let floor = Round::new(Epoch::zero(), View::new(3));
            let later_round = Round::new(Epoch::zero(), View::new(4));
            let leader = peers[1].public_key.clone();
            let peer = &mut peers[0];

            peer.mailbox.proposed(old_round, cached_old);
            peer.mailbox.proposed(floor, cached_equal);
            peer.mailbox.proposed(later_round, cached_later);
            peer.mailbox
                .discovered(state_old, leader.clone(), old_round);
            peer.mailbox.discovered(state_equal, leader.clone(), floor);
            peer.mailbox
                .discovered(state_later, leader.clone(), old_round);
            peer.mailbox.discovered(state_later, leader, later_round);
            let mut state_old_sub = peer.mailbox.subscribe(state_old);
            let mut state_equal_sub = peer.mailbox.subscribe(state_equal);
            let mut state_later_sub = peer.mailbox.subscribe(state_later);
            context.sleep(Duration::from_millis(10)).await;

            peer.mailbox.retire(Retirement {
                round_floor: floor,
                exact_retirements: vec![unseen],
            });
            context.sleep(Duration::from_millis(10)).await;

            assert!(peer.mailbox.get(cached_old_commitment).await.is_none());
            assert!(peer.mailbox.get(cached_equal_commitment).await.is_none());
            assert!(peer.mailbox.get(cached_later_commitment).await.is_some());
            assert!(matches!(state_old_sub.try_recv(), Err(TryRecvError::Empty)));
            assert!(matches!(
                state_equal_sub.try_recv(),
                Err(TryRecvError::Empty)
            ));
            assert!(matches!(
                state_later_sub.try_recv(),
                Err(TryRecvError::Empty)
            ));
        });
    }

    #[test_traced]
    fn test_local_reproposal_refreshes_existing_reconstruction_state() {
        let fixture = Fixture::<C>::default();
        fixture.start(|_, context, _, mut peers, _, coding_config| async move {
            let live = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
                &STRATEGY,
            );
            let unseen = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                coding_config,
                &STRATEGY,
            )
            .commitment();
            let state_first = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(3), 300),
                coding_config,
                &STRATEGY,
            );
            let live_commitment = live.commitment();
            let state_first_commitment = state_first.commitment();
            let leader = peers[0].public_key.clone();
            let original_round = Round::new(Epoch::zero(), View::new(1));
            let floor = Round::new(Epoch::zero(), View::new(3));
            let reproposal_round = Round::new(Epoch::zero(), View::new(4));
            let peer = &mut peers[0];

            peer.mailbox
                .discovered(live_commitment, leader, original_round);
            peer.mailbox.proposed(reproposal_round, live);
            peer.mailbox
                .notarized(state_first_commitment, reproposal_round);
            peer.mailbox.proposed(floor, state_first);
            assert!(peer.mailbox.get(live_commitment).await.is_some());

            let mut shard_sub = peer
                .mailbox
                .subscribe_assigned_shard_verified(live_commitment);
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                matches!(shard_sub.try_recv(), Ok(())),
                "late subscription should resolve after a local reproposal"
            );

            peer.mailbox.retire(Retirement {
                round_floor: floor,
                exact_retirements: vec![unseen],
            });
            context.sleep(Duration::from_millis(10)).await;

            assert!(peer.mailbox.get(live_commitment).await.is_some());
            assert!(peer.mailbox.get(state_first_commitment).await.is_some());
            let mut retained_shard_sub = peer
                .mailbox
                .subscribe_assigned_shard_verified(live_commitment);
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                matches!(retained_shard_sub.try_recv(), Ok(())),
                "retained local proposal should resolve a late subscription"
            );
        });
    }

    #[test_traced]
    fn test_duplicate_leader_shard_ignored() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's own-index shard (the one the leader sends them).
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = peer2_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send peer 2 their shard from peer 0 (leader, first time - should succeed).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes.clone(), true);
                context.sleep(config.link.latency * 2).await;

                // Send the same shard again from peer 0 (leader duplicate - ignored).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // The leader should NOT be blocked for sending an identical duplicate.
                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[0].public_key);
                assert!(
                    !is_blocked,
                    "leader should not be blocked for duplicate shard"
                );
            },
        );
    }

    #[test_traced]
    fn test_equivocating_leader_shard_blocks_peer() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment = coded_block1.commitment();

                // Create a second block with different payload to get different shard data.
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(1), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's shard from both blocks.
                let peer2_index = peers[2].index.get() as u16;
                let shard_bytes1 = coded_block1
                    .shard(peer2_index)
                    .expect("missing shard")
                    .encode();
                let mut equivocating_shard =
                    coded_block2.shard(peer2_index).expect("missing shard");
                // Override the commitment so it targets the same reconstruction state.
                equivocating_shard.commitment = commitment;
                let shard_bytes2 = equivocating_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send peer 2 their shard from the leader (first time - succeeds).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes1, true);
                context.sleep(config.link.latency * 2).await;

                // Send a different shard from the leader (equivocation - should block).
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes2, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 2 should have blocked the leader for equivocation.
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_non_leader_wrong_index_shard_blocked() {
        // Test that a non-leader sending a shard with the wrong index is blocked.
        // Non-leaders must send shards at their own participant index.
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get a shard that belongs to neither the sender nor receiver.
                let unrelated_index = peers[3].index.get() as u16;
                let unrelated_shard = coded_block.shard(unrelated_index).expect("missing shard");
                let shard_bytes = unrelated_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Peer 1 (not the leader) sends peer 2 a shard for peer 3. It
                // cannot be either sender-indexed gossip or an assigned shard.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked by peer 2 for wrong shard index.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_buffered_wrong_index_shard_blocked_on_leader_arrival() {
        // Test that when a non-leader's shard with the wrong index is buffered
        // (leader unknown) and then the leader arrives, the sender is blocked.
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get a shard that belongs to neither the sender nor receiver.
                let unrelated_index = peers[3].index.get() as u16;
                let unrelated_shard = coded_block.shard(unrelated_index).expect("missing shard");
                let shard_bytes = unrelated_shard.encode();

                let peer2_pk = peers[2].public_key.clone();

                // Peer 1 sends peer 3's shard before the leader is known.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Nobody should be blocked yet (shard is buffered, leader unknown).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked while leader is unknown"
                );

                // Now inform peer 2 that peer 0 is the leader.
                // This drains the impossible candidate: it belongs to neither
                // peer 1 nor peer 2.
                let leader = peers[0].public_key.clone();
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                context.sleep(Duration::from_millis(10)).await;

                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_assigned_shard_from_non_leader_accepted() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |_config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 2's assigned shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = peer2_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Subscribe before shards arrive so we can verify acceptance.
                let shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // Discover the proposal under peer 0.
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // The assigned shard is commitment-bound, so another participant
                // may deliver it without being treated as a conflicting proposer.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);

                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("subscription did not complete after assigned shard");
                    },
                };

                assert!(oracle.blocked().await.unwrap().is_empty());
            },
        );
    }

    #[test_traced]
    fn test_non_participant_external_proposed_ignored() {
        let fixture = Fixture::<C>::default();
        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get the shard the leader would send to peer 2 (at peer 2's index).
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = peer2_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let non_participant_leader = PrivateKey::from_seed(10_000).public_key();

                // Subscribe before shards arrive.
                let shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // A non-participant leader update should be ignored.
                peers[2].mailbox.discovered(
                    commitment,
                    non_participant_leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Leader unknown path: this shard should be buffered, not blocked.
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes.clone(), true);
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                let leader_blocked = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &leader);
                assert!(
                    !leader_blocked,
                    "leader should not be blocked when non-participant update is ignored"
                );

                // A valid leader update should then process buffered shards and resolve subscription.
                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                context.sleep(config.link.latency * 2).await;

                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("subscription did not complete after valid leader update");
                    },
                };
            },
        );
    }

    #[test_traced]
    fn test_rejected_leader_does_not_refresh_retirement_round() {
        let fixture = Fixture::<C>::default();
        fixture.start(|_, context, _, mut peers, _, coding_config| async move {
            let block = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
                &STRATEGY,
            );
            let commitment = block.commitment();
            let unrelated = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                coding_config,
                &STRATEGY,
            )
            .commitment();
            let leader = peers[0].public_key.clone();
            let non_participant = PrivateKey::from_seed(10_000).public_key();
            let receiver = &mut peers[2];

            let mut subscription = receiver
                .mailbox
                .subscribe_assigned_shard_verified(commitment);
            receiver.mailbox.discovered(
                commitment,
                leader,
                Round::new(Epoch::zero(), View::new(1)),
            );
            receiver.mailbox.discovered(
                commitment,
                non_participant,
                Round::new(Epoch::zero(), View::new(10)),
            );
            receiver.mailbox.retire(Retirement {
                round_floor: Round::new(Epoch::zero(), View::new(5)),
                exact_retirements: vec![unrelated],
            });
            context.sleep(Duration::from_millis(10)).await;

            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Closed)));
        });
    }

    #[test_traced]
    fn test_cross_epoch_observations_do_not_refresh_retirement_round() {
        let fixture = Fixture::<C> {
            additional_scheme_epochs: vec![Epoch::new(1)],
            ..Default::default()
        };
        fixture.start(|_, context, _, mut peers, _, coding_config| async move {
            let cached = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                coding_config,
                &STRATEGY,
            );
            let incomplete = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                coding_config,
                &STRATEGY,
            );
            let incomplete_commitment = incomplete.commitment();
            let unrelated = CodedBlock::<B, C, H>::new(
                B::new(Sha256Digest::EMPTY, Height::new(3), 300),
                coding_config,
                &STRATEGY,
            )
            .commitment();
            let cached_commitment = cached.commitment();
            let leader = peers[0].public_key.clone();
            let receiver = &mut peers[2];
            let original_round = Round::new(Epoch::zero(), View::new(1));

            receiver.mailbox.proposed(original_round, cached);
            receiver
                .mailbox
                .discovered(incomplete_commitment, leader, original_round);
            let mut subscription = receiver
                .mailbox
                .subscribe_assigned_shard_verified(incomplete_commitment);

            let conflicting_round = Round::new(Epoch::new(1), View::new(10));
            receiver.mailbox.proposed(conflicting_round, incomplete);
            receiver
                .mailbox
                .notarized(cached_commitment, conflicting_round);
            receiver
                .mailbox
                .notarized(incomplete_commitment, conflicting_round);
            receiver.mailbox.retire(Retirement {
                round_floor: Round::new(Epoch::zero(), View::new(5)),
                exact_retirements: vec![unrelated],
            });
            context.sleep(Duration::from_millis(10)).await;

            assert!(receiver.mailbox.get(cached_commitment).await.is_none());
            assert!(matches!(subscription.try_recv(), Err(TryRecvError::Closed)));
        });
    }

    #[test_traced]
    fn test_shard_from_non_participant_blocks_peer() {
        let fixture = Fixture {
            num_future_peers: 1,
            ..Fixture::<C>::default()
        };
        fixture.start(
            |config, context, oracle, peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let leader = peers[0].public_key.clone();
                let receiver_pk = peers[2].public_key.clone();

                let non_participant_key = PrivateKey::from_seed(10_000);
                let non_participant_pk = non_participant_key.public_key();

                let non_participant_control = oracle.control(non_participant_pk.clone());
                let (mut non_participant_sender, _non_participant_receiver) =
                    non_participant_control
                        .register(0, TEST_QUOTA)
                        .await
                        .expect("registration should succeed");
                oracle
                    .add_link(
                        non_participant_pk.clone(),
                        receiver_pk.clone(),
                        DEFAULT_LINK,
                    )
                    .await
                    .expect("link should be added");
                oracle.manager().track(
                    2,
                    TrackedPeers::new(
                        Set::from_iter_dedup(peers.iter().map(|peer| peer.public_key.clone())),
                        Set::from_iter_dedup([non_participant_pk.clone()]),
                    ),
                );
                context.sleep(Duration::from_millis(10)).await;

                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                let peer2_index = peers[2].index.get() as u16;
                let shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = shard.encode();

                non_participant_sender.send(Recipients::One(receiver_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[2].public_key, &non_participant_pk).await;
            },
        );
    }

    #[test_traced]
    fn test_preleader_shard_from_non_participant_is_not_buffered() {
        let fixture = Fixture {
            num_future_peers: 1,
            ..Fixture::<C>::default()
        };
        fixture.start(
            |config, context, oracle, peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let leader = peers[0].public_key.clone();
                let receiver_pk = peers[2].public_key.clone();

                let non_participant_key = PrivateKey::from_seed(10_000);
                let non_participant_pk = non_participant_key.public_key();

                let non_participant_control = oracle.control(non_participant_pk.clone());
                let (mut non_participant_sender, _non_participant_receiver) =
                    non_participant_control
                        .register(0, TEST_QUOTA)
                        .await
                        .expect("registration should succeed");
                oracle
                    .add_link(
                        non_participant_pk.clone(),
                        receiver_pk.clone(),
                        DEFAULT_LINK,
                    )
                    .await
                    .expect("link should be added");
                oracle.manager().track(
                    2,
                    TrackedPeers::new(
                        Set::from_iter_dedup(peers.iter().map(|peer| peer.public_key.clone())),
                        Set::from_iter_dedup([non_participant_pk.clone()]),
                    ),
                );
                context.sleep(Duration::from_millis(10)).await;

                let peer2_index = peers[2].index.get() as u16;
                let shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = shard.encode();
                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                non_participant_sender.send(Recipients::One(receiver_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                peers[2].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                let non_participant_blocked = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &non_participant_pk);
                assert!(
                    !non_participant_blocked,
                    "non-participant should not be blocked when its pre-leader shard is ignored"
                );
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "pre-leader shard from non-participant should not be buffered"
                );
            },
        );
    }

    #[test_traced]
    fn test_duplicate_shard_ignored() {
        // Use 10 peers so minimum_shards=4, giving us time to send duplicate before reconstruction.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's shard (from the leader).
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");

                // Get peer 1's shard.
                let peer1_index = peers[1].index.get() as u16;
                let peer1_shard = coded_block.shard(peer1_index).expect("missing shard");

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 of the leader.
                peers[2].mailbox.discovered(
                    coded_block.commitment(),
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send peer 2 their shard from the leader (1 checked shard).
                let leader_shard_bytes = peer2_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), leader_shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's shard to peer 2 (first time - should succeed, 2 checked shards).
                let peer1_shard_bytes = peer1_shard.encode();
                peers[1].sender.send(
                    Recipients::One(peer2_pk.clone()),
                    peer1_shard_bytes.clone(),
                    true,
                );
                context.sleep(config.link.latency * 2).await;

                // Send the same shard again (exact duplicate - should be ignored, not blocked).
                // With 10 peers, minimum_shards=4, so we haven't reconstructed yet.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), peer1_shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should NOT be blocked for sending an identical duplicate.
                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key);
                assert!(
                    !is_blocked,
                    "peer should not be blocked for exact duplicate shard"
                );
            },
        );
    }

    #[test_traced]
    fn test_equivocating_shard_blocks_peer() {
        // Use 10 peers so minimum_shards=4, giving us time to send equivocating shard.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);

                // Create a second block with different payload to get different shard data.
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(1), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 1's shard from block 1.
                let peer1_index = peers[1].index.get() as u16;
                let peer1_shard = coded_block1.shard(peer1_index).expect("missing shard");

                // Get peer 1's shard from block 2 (different data, same index).
                let mut peer1_equivocating_shard =
                    coded_block2.shard(peer1_index).expect("missing shard");
                // Override the commitment to match block 1 so the shard targets
                // the same reconstruction state.
                peer1_equivocating_shard.commitment = coded_block1.commitment();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 of the leader.
                peers[2].mailbox.discovered(
                    coded_block1.commitment(),
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send peer 2 the leader's shard (verified immediately).
                let peer2_index = peers[2].index.get() as u16;
                let leader_shard = coded_block1.shard(peer2_index).expect("missing shard");
                let leader_shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), leader_shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Send peer 1's valid shard to peer 2 (first time - succeeds).
                let shard_bytes = peer1_shard.encode();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Send a different shard from peer 1 (equivocation - should block).
                let equivocating_bytes = peer1_equivocating_shard.encode();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), equivocating_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 2 should have blocked peer 1 for equivocation.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_reconstruction_states_pruned_at_or_below_reconstructed_view() {
        // Use 10 peers so minimum_shards=4.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Commitment A at lower view (1).
                let block_a = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_a = block_a.commitment();

                // Commitment B at higher view (2), which we will reconstruct.
                let block_b = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_b = block_b.commitment();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Create state for A and ingest one shard from peer1.
                peers[2].mailbox.discovered(
                    commitment_a,
                    leader.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let shard_a = block_a
                    .shard(peers[1].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_a.clone(), true);
                context.sleep(config.link.latency * 2).await;

                // Create/reconstruct B at higher view.
                peers[2].mailbox.discovered(
                    commitment_b,
                    leader,
                    Round::new(Epoch::zero(), View::new(2)),
                );
                // Leader's shard for peer2.
                let leader_shard_b = block_b
                    .shard(peers[2].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), leader_shard_b, true);

                // Three shards for minimum threshold (4 total with leader's).
                for i in [1usize, 3usize, 4usize] {
                    let shard = block_b
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(peer2_pk.clone()), shard, true);
                }
                context.sleep(config.link.latency * 4).await;

                // B should reconstruct.
                let reconstructed = peers[2]
                    .mailbox
                    .get(commitment_b)
                    .await
                    .expect("block B should reconstruct");
                assert_eq!(reconstructed.commitment(), commitment_b);

                // A state should be pruned (at/below reconstructed view). Sending the same
                // shard for A again should NOT be treated as duplicate.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_a, true);
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                let blocked_peer1 = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key);
                assert!(
                    !blocked_peer1,
                    "peer1 should not be blocked after lower-view state was pruned"
                );
            },
        );
    }

    #[test_traced]
    fn test_later_notarization_refreshes_reconstruction_state_round() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let live = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );
                let finalized = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let live_commitment = live.commitment();
                let finalized_commitment = finalized.commitment();
                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();

                peers[receiver_idx].mailbox.discovered(
                    live_commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let mut live_sub = peers[receiver_idx].mailbox.subscribe(live_commitment);

                // The same commitment becomes live in a later round while the application
                // still has an older finalization to acknowledge.
                peers[receiver_idx]
                    .mailbox
                    .notarized(live_commitment, Round::new(Epoch::zero(), View::new(4)));
                context.sleep(Duration::from_millis(10)).await;
                peers[receiver_idx].mailbox.retire(Retirement {
                    round_floor: Round::new(Epoch::zero(), View::new(3)),
                    exact_retirements: vec![finalized_commitment],
                });
                context.sleep(Duration::from_millis(10)).await;

                assert!(
                    matches!(live_sub.try_recv(), Err(TryRecvError::Empty)),
                    "later-round reconstruction subscription should remain open"
                );

                let leader_shard = live
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing leader shard");
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    leader_shard.encode(),
                    true,
                );
                for i in [1usize, 2usize, 4usize] {
                    let shard = live
                        .shard(peers[i].index.get() as u16)
                        .expect("missing gossip shard");
                    peers[i].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
                }

                select! {
                    result = live_sub => {
                        let reconstructed =
                            result.expect("later-round reconstruction should remain live");
                        assert_eq!(reconstructed.commitment(), live_commitment);
                    },
                    _ = context.sleep(config.link.latency * 10) => {
                        panic!("later-round reconstruction did not complete");
                    },
                }
            },
        );
    }

    #[test_traced]
    fn test_cached_observations_refresh_reconstruction_state_round() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _, mut peers, _, coding_config| async move {
                let live = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );
                let finalized = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let live_commitment = live.commitment();
                let finalized_commitment = finalized.commitment();
                let leader = peers[0].public_key.clone();
                let receivers = [3usize, 6usize];
                let receiver_keys = [
                    peers[receivers[0]].public_key.clone(),
                    peers[receivers[1]].public_key.clone(),
                ];
                let original_round = Round::new(Epoch::zero(), View::new(1));

                for &receiver_idx in &receivers {
                    peers[receiver_idx].mailbox.discovered(
                        live_commitment,
                        leader.clone(),
                        original_round,
                    );
                }

                // Reconstruct from gossip while leaving assigned-shard verification pending.
                for sender_idx in [1usize, 2usize, 4usize, 5usize] {
                    let shard = live
                        .shard(peers[sender_idx].index.get() as u16)
                        .expect("missing gossip shard")
                        .encode();
                    for receiver in &receiver_keys {
                        peers[sender_idx].sender.send(
                            Recipients::One(receiver.clone()),
                            shard.clone(),
                            true,
                        );
                    }
                }
                context.sleep(config.link.latency * 4).await;

                for &receiver_idx in &receivers {
                    assert!(
                        peers[receiver_idx]
                            .mailbox
                            .get(live_commitment)
                            .await
                            .is_some(),
                        "block should be cached before its round is refreshed"
                    );
                }

                let mut notarized_sub = peers[receivers[0]]
                    .mailbox
                    .subscribe_assigned_shard_verified(live_commitment);
                let mut discovered_sub = peers[receivers[1]]
                    .mailbox
                    .subscribe_assigned_shard_verified(live_commitment);
                let later_round = Round::new(Epoch::zero(), View::new(4));
                peers[receivers[0]]
                    .mailbox
                    .notarized(live_commitment, later_round);
                peers[receivers[1]].mailbox.discovered(
                    live_commitment,
                    leader,
                    later_round,
                );
                context.sleep(Duration::from_millis(10)).await;

                let prune_round = Round::new(Epoch::zero(), View::new(3));
                for &receiver_idx in &receivers {
                    peers[receiver_idx].mailbox.retire(Retirement {
                        round_floor: prune_round,
                        exact_retirements: vec![finalized_commitment],
                    });
                }
                context.sleep(Duration::from_millis(10)).await;

                assert!(
                    matches!(notarized_sub.try_recv(), Err(TryRecvError::Empty)),
                    "cached notarization should keep reconstruction state live"
                );
                assert!(
                    matches!(discovered_sub.try_recv(), Err(TryRecvError::Empty)),
                    "cached discovery should keep reconstruction state live"
                );
                for &receiver_idx in &receivers {
                    assert!(
                        peers[receiver_idx]
                            .mailbox
                            .get(live_commitment)
                            .await
                            .is_some(),
                        "cached observation should keep the reconstructed block live"
                    );
                }

                for (&receiver_idx, receiver) in receivers.iter().zip(&receiver_keys) {
                    let leader_shard = live
                        .shard(peers[receiver_idx].index.get() as u16)
                        .expect("missing leader shard");
                    peers[0].sender.send(
                        Recipients::One(receiver.clone()),
                        leader_shard.encode(),
                        true,
                    );
                }

                select! {
                    result = notarized_sub => {
                        result.expect("notarized reconstruction state should accept the leader shard");
                    },
                    _ = context.sleep(config.link.latency * 10) => {
                        panic!("notarized reconstruction state did not accept the leader shard");
                    },
                }
                select! {
                    result = discovered_sub => {
                        result.expect("discovered reconstruction state should accept the leader shard");
                    },
                    _ = context.sleep(config.link.latency * 10) => {
                        panic!("discovered reconstruction state did not accept the leader shard");
                    },
                }
            },
        );
    }

    #[test_traced]
    fn test_local_proposal_prune_clears_older_reconstruction_state() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let block_a = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_a = block_a.commitment();

                let block_b = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_b = block_b.commitment();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();
                let round_a = Round::new(Epoch::zero(), View::new(1));
                let round_b = Round::new(Epoch::zero(), View::new(2));

                peers[2].mailbox.discovered(commitment_a, leader, round_a);

                let peer1_index = peers[1].index.get() as u16;
                let shard_a = block_a.shard(peer1_index).expect("missing shard");

                let block_a_equivocating = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 300),
                    coding_config,
                    &STRATEGY,
                );
                let mut equivocating_shard = block_a_equivocating
                    .shard(peer1_index)
                    .expect("missing shard");
                equivocating_shard.commitment = commitment_a;

                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_a.encode(), true);
                context.sleep(config.link.latency * 2).await;

                peers[2].mailbox.proposed(round_b, block_b);
                assert!(
                    peers[2].mailbox.get(commitment_b).await.is_some(),
                    "local proposal should be cached before pruning"
                );
                peers[2].mailbox.retire(Retirement {
                    round_floor: round_b,
                    exact_retirements: vec![commitment_b],
                });

                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), equivocating_shard.encode(), true);
                context.sleep(config.link.latency * 2).await;

                let blocked = oracle.blocked().await.unwrap();
                let blocked_peer1 = blocked
                    .iter()
                    .any(|(a, b)| a == &peers[2].public_key && b == &peers[1].public_key);
                assert!(
                    !blocked_peer1,
                    "peer1 should not be blocked after older state was pruned"
                );
            },
        );
    }

    #[test_traced]
    fn test_pending_shards_batch_validated_at_quorum() {
        // Test that shards buffered in pending_shards are batch-validated once
        // the minimum shard threshold is met, enabling reconstruction.
        //
        // With 10 peers: minimum_shards = (10-1)/3 + 1 = 4
        // The leader (peer 0) sends peer 3 their own-index shard (verified
        // immediately). Peers 1, 2, 4 send their own shards (buffered in
        // pending_shards). Once the leader's shard + 3 pending shards >= 4,
        // batch validation fires and reconstruction succeeds.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 3 that peer 0 is the leader.
                peers[3].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send shards from peers 1, 2, 4 (their own indices).
                // These are buffered in pending_shards for batch validation.
                for &sender_idx in &[1, 2, 4] {
                    let shard = coded_block
                        .shard(peers[sender_idx].index.get() as u16)
                        .expect("missing shard");
                    let shard_bytes = shard.encode();
                    peers[sender_idx].sender.send(
                        Recipients::One(peer3_pk.clone()),
                        shard_bytes,
                        true,
                    );
                }

                context.sleep(config.link.latency * 2).await;

                // Block should not be reconstructed yet (no leader shard verified).
                let block = peers[3].mailbox.get(commitment).await;
                assert!(block.is_none(), "block should not be reconstructed yet");

                // Now the leader (peer 0) sends peer 3's own-index shard.
                // This is verified immediately, and with the 3 pending shards
                // we reach minimum_shards=4 -> batch validation + reconstruction.
                let peer3_index = peers[3].index.get() as u16;
                let leader_shard = coded_block.shard(peer3_index).expect("missing shard");
                let leader_shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk), leader_shard_bytes, true);

                context.sleep(config.link.latency * 2).await;

                // No peers should be blocked (all shards were valid).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked for valid pending shards"
                );

                // Block should now be reconstructed (4 checked shards >= minimum_shards).
                let block = peers[3].mailbox.get(commitment).await;
                assert!(
                    block.is_some(),
                    "block should be reconstructed after batch validation"
                );

                // Verify the reconstructed block has the correct commitment.
                let reconstructed = block.unwrap();
                assert_eq!(
                    reconstructed.commitment(),
                    commitment,
                    "reconstructed block should have correct commitment"
                );
            },
        );
    }

    #[test_traced]
    fn test_peer_shards_buffered_until_external_proposed() {
        // Test that shards received before leader announcement do not progress
        // reconstruction until Discovered is delivered.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Subscribe before any shards arrive.
                let mut shard_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                // Send the leader's shard (for receiver's index) and three shards,
                // all before leader announcement.
                let leader_shard = coded_block
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), leader_shard, true);

                for i in [1usize, 2usize, 4usize] {
                    let shard = coded_block
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard, true);
                }

                context.sleep(config.link.latency * 2).await;

                // No leader yet: shard subscription should still be pending and block unavailable.
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription should not resolve before leader announcement"
                );
                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_none(),
                    "block should not reconstruct before leader announcement"
                );

                // Announce leader, which drains buffered shards and should progress immediately.
                peers[receiver_idx].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after leader announcement");
                    },
                }

                context.sleep(config.link.latency * 2).await;
                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_some(),
                    "block should reconstruct after buffered shards are ingested"
                );

                // All shards were valid and from participants.
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked for valid buffered shards"
                );
            },
        );
    }

    #[test_traced]
    fn test_notarized_commitment_reconstructs_from_buffered_peer_shards_without_leader() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let receiver_idx = 3usize;
                let receiver = peers[receiver_idx].public_key.clone();

                let block_sub = peers[receiver_idx].mailbox.subscribe(commitment);

                // Four sender-indexed shards are enough to reconstruct without
                // classifying any sender as the leader.
                for sender_idx in [1usize, 2, 4, 5] {
                    let shard = coded_block
                        .shard(peers[sender_idx].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[sender_idx].sender.send(
                        Recipients::One(receiver.clone()),
                        shard,
                        true,
                    );
                }
                context.sleep(config.link.latency * 2).await;

                assert!(
                    peers[receiver_idx].mailbox.get(commitment).await.is_none(),
                    "block should not reconstruct before the commitment is notarized"
                );

                peers[receiver_idx].mailbox.notarized(commitment, round);

                select! {
                    _ = block_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("block subscription did not resolve after notarized reconstruction interest");
                    },
                }

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(commitment)
                    .await
                    .expect("block should reconstruct from buffered peer shards");
                assert_eq!(reconstructed.commitment(), commitment);

                let mut assigned = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                assert!(
                    matches!(assigned.try_recv(), Err(TryRecvError::Empty)),
                    "leaderless reconstruction must not satisfy assigned shard readiness"
                );

                let leader = peers[0].public_key.clone();
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);
                let leader_shard = coded_block
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing leader shard")
                    .encode();
                peers[0].sender.send(
                    Recipients::One(receiver),
                    leader_shard,
                    true,
                );

                select! {
                    _ = assigned => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("assigned shard subscription did not resolve after leader discovery");
                    },
                }

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid sender-indexed shards should not block peers"
                );
            },
        );
    }

    #[test_traced]
    fn test_late_subscription_uses_notarized_cache_after_peer_buffer_pressure() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            peer_buffer_size: NZUsize!(1),
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let target = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 1),
                    coding_config,
                    &STRATEGY,
                );
                let target_commitment = target.commitment();
                let receiver_idx = 3usize;
                let receiver = peers[receiver_idx].public_key.clone();
                let initial_round = Round::new(Epoch::zero(), View::new(1));
                let refreshed_round = Round::new(Epoch::zero(), View::new(4));

                for sender_idx in [1usize, 2, 4, 5] {
                    let shard = target
                        .shard(peers[sender_idx].index.get() as u16)
                        .expect("missing target shard")
                        .encode();
                    peers[sender_idx].sender.send(
                        Recipients::One(receiver.clone()),
                        shard,
                        true,
                    );
                }
                context.sleep(config.link.latency * 2).await;

                peers[receiver_idx]
                    .mailbox
                    .notarized(target_commitment, initial_round);
                let target_sub = peers[receiver_idx].mailbox.subscribe(target_commitment);
                select! {
                    result = target_sub => {
                        let block = result.expect("notarized target should reconstruct");
                        assert_eq!(block.commitment(), target_commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("notarized target did not reconstruct");
                    },
                }

                // A later certification observation refreshes the cached record's retention
                // round. The record owns the block independently of bounded pre-leader shard
                // buffers.
                peers[receiver_idx]
                    .mailbox
                    .notarized(target_commitment, refreshed_round);
                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(target_commitment)
                        .await
                        .is_some(),
                    "target should be cached after its notarization is refreshed"
                );

                // The fixture retains one pre-leader shard per peer. One authenticated peer
                // sends two distinct codec-valid shards to exercise the same eviction boundary.
                let pressure_blocks = [2u64, 3].map(|id| {
                    CodedBlock::<B, C, H>::new(
                        B::new(Sha256Digest::EMPTY, Height::new(id), id),
                        coding_config,
                        &STRATEGY,
                    )
                });
                for block in &pressure_blocks {
                    let shard = block
                        .shard(peers[1].index.get() as u16)
                        .expect("missing pressure shard")
                        .encode();
                    peers[1].sender.send(
                        Recipients::One(receiver.clone()),
                        shard,
                        true,
                    );
                }
                context.sleep(config.link.latency * 2).await;

                let [evicted_block, retained_block] = &pressure_blocks;
                for (block, should_reconstruct) in
                    [(evicted_block, false), (retained_block, true)]
                {
                    for sender_idx in [2usize, 4, 5] {
                        let shard = block
                            .shard(peers[sender_idx].index.get() as u16)
                            .expect("missing complementary pressure shard")
                            .encode();
                        peers[sender_idx].sender.send(
                            Recipients::One(receiver.clone()),
                            shard,
                            true,
                        );
                    }
                    context.sleep(config.link.latency * 2).await;

                    let commitment = block.commitment();
                    peers[receiver_idx]
                        .mailbox
                        .notarized(commitment, initial_round);
                    if should_reconstruct {
                        let block_sub = peers[receiver_idx].mailbox.subscribe(commitment);
                        select! {
                            result = block_sub => {
                                let block = result.expect("retained pressure block should reconstruct");
                                assert_eq!(block.commitment(), commitment);
                            },
                            _ = context.sleep(Duration::from_secs(5)) => {
                                panic!("retained same-peer shard did not reconstruct");
                            },
                        }
                    } else {
                        assert!(
                            peers[receiver_idx]
                                .mailbox
                                .get(commitment)
                                .await
                                .is_none(),
                            "evicted same-peer shard should not reconstruct"
                        );
                    }
                }

                peers[receiver_idx].mailbox.retire(Retirement {
                    round_floor: Round::new(Epoch::zero(), View::new(3)),
                    exact_retirements: Vec::new(),
                });

                // This is the subscription used by Coding's Marshal buffer. It is installed
                // only after peer pressure and retirement, with no resolver in this fixture.
                let late_sub = peers[receiver_idx].mailbox.subscribe(target_commitment);
                select! {
                    result = late_sub => {
                        let block = result.expect("refreshed target should remain cached");
                        assert_eq!(block.commitment(), target_commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("late target subscription lost cached ownership");
                    },
                }

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid pressure shards should not block peers"
                );
            },
        );
    }

    #[test_traced]
    fn test_leader_shard_after_notarized_is_buffered_until_discovered() {
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader_idx = 0usize;
                let receiver_idx = 3usize;
                let leader = peers[leader_idx].public_key.clone();
                let receiver = peers[receiver_idx].public_key.clone();

                peers[receiver_idx].mailbox.notarized(commitment, round);
                let assigned = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);

                let leader_shard = coded_block
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing receiver shard")
                    .encode();
                peers[leader_idx]
                    .sender
                    .send(Recipients::One(receiver), leader_shard, true);

                context.sleep(config.link.latency * 2).await;
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment, leader, round);

                assigned
                    .await
                    .expect("assigned shard should resolve after leader discovery");
                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "valid leader shard should not block peers"
                );
            },
        );
    }

    #[test_traced]
    fn test_post_leader_shards_processed_immediately() {
        // Test that shards arriving after leader announcement are processed
        // without waiting for any extra trigger.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();

                let shard_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                peers[receiver_idx].mailbox.discovered(
                    commitment,
                    leader.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Send leader's shard (for receiver's index) after leader is known.
                let leader_shard = coded_block
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), leader_shard, true);

                // Subscription should resolve from the leader's shard.
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after post-leader shard");
                    },
                }

                // Send enough shards after leader known to reconstruct.
                for i in [1usize, 2usize, 4usize] {
                    let shard = coded_block
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard, true);
                }

                context.sleep(config.link.latency * 2).await;
                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(commitment)
                    .await
                    .expect("block should reconstruct from post-leader shards");
                assert_eq!(reconstructed.commitment(), commitment);

                assert!(
                    oracle.blocked().await.unwrap().is_empty(),
                    "no peers should be blocked for valid post-leader shards"
                );
            },
        );
    }

    #[test_traced]
    fn test_invalid_shard_codec_blocks_peer() {
        // Test that receiving an invalid shard (codec failure) blocks the sender.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 4,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, _coding_config| async move {
                let peer0_pk = peers[0].public_key.clone();
                let peer1_pk = peers[1].public_key.clone();

                // Send garbage bytes that will fail codec decoding.
                let garbage = Bytes::from(vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB]);
                peers[1]
                    .sender
                    .send(Recipients::One(peer0_pk.clone()), garbage, true);

                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked by peer 0 for sending invalid shard.
                assert_blocked(&oracle, &peer0_pk, &peer1_pk).await;
            },
        );
    }

    #[test_traced]
    fn test_duplicate_buffered_shard_does_not_block_before_leader() {
        // Test that duplicate shards before leader announcement are
        // buffered and do not immediately block the sender.
        let fixture: Fixture<C> = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);

                // Get peer 2's shard.
                let peer2_index = peers[2].index.get() as u16;
                let peer2_shard = coded_block.shard(peer2_index).expect("missing shard");
                let shard_bytes = peer2_shard.encode();

                let peer2_pk = peers[2].public_key.clone();

                // Do NOT set a leader — shards should be buffered.

                // Peer 1 sends the shard to peer 2 (buffered, leader unknown).
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), shard_bytes.clone(), true);
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet.
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Peer 1 sends the same shard AGAIN (duplicate while leader unknown).
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Still no blocking before a leader is known.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peers should be blocked before leader"
                );
            },
        );
    }

    #[test_traced]
    fn test_invalid_leader_shard_crypto_blocks_leader() {
        // Test that a leader shard failing cryptographic verification
        // results in the leader being blocked.
        let fixture: Fixture<C> = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Create two different blocks — shard from block2 won't verify
                // against commitment from block1.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's shard from block2, but re-wrap it with
                // block1's commitment so it fails verification.
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong_shard = coded_block2.shard(peer2_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Leader (peer 0) sends the invalid shard.
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 0 (leader) should be blocked for invalid crypto.
                assert_blocked(&oracle, &peers[2].public_key, &peers[0].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_invalid_assigned_shard_from_non_leader_blocks_only_sender() {
        // A Byzantine participant can race the leader with garbage at the
        // victim's assigned index, since the assigned index is accepted from
        // any participant. The sender must be blocked without poisoning the
        // slot: the leader's genuine shard must still verify afterward.
        let fixture: Fixture<C> = Fixture {
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Create two different blocks — shard from block2 won't verify
                // against commitment from block1.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 2's shard from block2, but re-wrap it with
                // block1's commitment so it fails verification.
                let peer2_index = peers[2].index.get() as u16;
                let mut wrong_shard = coded_block2.shard(peer2_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer2_pk = peers[2].public_key.clone();
                let leader = peers[0].public_key.clone();

                let mut shard_sub = peers[2]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment1);

                // Inform peer 2 that peer 0 is the leader.
                peers[2].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Non-leader peer 1 sends the invalid shard at peer 2's
                // assigned index.
                peers[1]
                    .sender
                    .send(Recipients::One(peer2_pk.clone()), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for invalid crypto, and the assigned
                // slot must not be treated as satisfied.
                assert_blocked(&oracle, &peers[2].public_key, &peers[1].public_key).await;
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "subscription should not resolve from invalid shard"
                );

                // The leader's genuine shard for the same index must still verify.
                let real_bytes = coded_block1
                    .shard(peer2_index)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer2_pk), real_bytes, true);
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("genuine assigned shard did not verify after invalid one");
                    },
                };
            },
        );
    }

    #[test_traced]
    fn test_shard_index_mismatch_blocks_peer() {
        // Test that a shard whose shard index doesn't match the sender's
        // participant index results in blocking the sender.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                // Get peer 3's leader shard so peer 3 can validate shards.
                let peer3_index = peers[3].index.get() as u16;
                let leader_shard = coded_block.shard(peer3_index).expect("missing shard");

                // Get peer 1's valid shard, then change the index to peer 4's index.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_index_shard = coded_block.shard(peer1_index).expect("missing shard");
                // Mutate the index so it doesn't match sender (peer 1).
                wrong_index_shard.index = peers[4].index.get() as u16;
                let wrong_bytes = wrong_index_shard.encode();

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 3 of the leader and send them the leader shard.
                peers[3].mailbox.discovered(
                    commitment,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends a shard with a mismatched index to peer 3.
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for shard index mismatch.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_invalid_shard_crypto_blocks_peer() {
        // Test that a shard failing cryptographic verification
        // results in blocking the sender once batch validation fires at quorum.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Create two different blocks.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 3's leader shard from block1 (valid).
                let peer3_index = peers[3].index.get() as u16;
                let leader_shard = coded_block1.shard(peer3_index).expect("missing shard");

                // Get peer 1's shard from block2, but re-wrap with block1's
                // commitment so verification fails.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_shard = coded_block2.shard(peer1_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer3_pk = peers[3].public_key.clone();
                let leader = peers[0].public_key.clone();

                // Inform peer 3 of the leader and send the valid leader shard.
                peers[3].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 sends the invalid shard.
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // No block yet: batch validation deferred until quorum.
                // Send valid shards from peers 2 and 4 to reach quorum
                // (minimum_shards = 4: 1 leader + 3 pending).
                for &idx in &[2, 4] {
                    let peer_index = peers[idx].index.get() as u16;
                    let shard = coded_block1.shard(peer_index).expect("missing shard");
                    let bytes = shard.encode();
                    peers[idx]
                        .sender
                        .send(Recipients::One(peer3_pk.clone()), bytes, true);
                }
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked for invalid shard crypto.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_reconstruction_recovers_after_quorum_with_one_invalid_shard() {
        // With 10 peers, minimum_shards=4.
        // Contribute exactly 4 shards first (1 leader + 3 pending), with one invalid:
        // quorum is reached, but checked_shards stays at 3 after batch validation.
        // Then send one more valid shard to meet reconstruction threshold.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();

                // Prepare one invalid shard: shard data from block2, commitment from block1.
                let peer1_index = peers[1].index.get() as u16;
                let mut invalid_shard = coded_block2.shard(peer1_index).expect("missing shard");
                invalid_shard.commitment = commitment1;

                // Announce leader and deliver receiver's leader shard.
                let leader = peers[0].public_key.clone();
                peers[receiver_idx].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let leader_shard = coded_block1
                    .shard(peers[receiver_idx].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), leader_shard, true);

                // Contribute exactly minimum_shards total:
                // - invalid shard from peer1
                // - valid shard from peer2
                // - valid shard from peer4
                peers[1].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    invalid_shard.encode(),
                    true,
                );
                for idx in [2usize, 4usize] {
                    let shard = coded_block1
                        .shard(peers[idx].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[idx]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard, true);
                }

                context.sleep(config.link.latency * 2).await;

                // Invalid shard should be blocked, and reconstruction should not happen yet.
                assert_blocked(
                    &oracle,
                    &peers[receiver_idx].public_key,
                    &peers[1].public_key,
                )
                .await;
                assert!(
                    peers[receiver_idx].mailbox.get(commitment1).await.is_none(),
                    "block should not reconstruct with only 3 checked shards"
                );

                // Send one additional valid shard; this should now satisfy checked threshold.
                let extra_shard = coded_block1
                    .shard(peers[5].index.get() as u16)
                    .expect("missing shard")
                    .encode();
                peers[5]
                    .sender
                    .send(Recipients::One(receiver_pk), extra_shard, true);

                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(commitment1)
                    .await
                    .expect("block should reconstruct after additional valid shard");
                assert_eq!(reconstructed.commitment(), commitment1);
            },
        );
    }

    #[test_traced]
    fn test_invalid_pending_shard_blocked_on_drain() {
        // Test that a shard buffered in pending shards (before checking data) is
        // blocked when batch validation runs at quorum and verification fails.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Create two different blocks.
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);
                let commitment1 = coded_block1.commitment();

                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);

                // Get peer 1's shard from block2, but wrap with block1's commitment.
                let peer1_index = peers[1].index.get() as u16;
                let mut wrong_shard = coded_block2.shard(peer1_index).expect("missing shard");
                wrong_shard.commitment = commitment1;
                let wrong_bytes = wrong_shard.encode();

                let peer3_pk = peers[3].public_key.clone();

                // Send the invalid shard BEFORE the leader shard (no checking data yet,
                // so it gets buffered in pending shards).
                peers[1]
                    .sender
                    .send(Recipients::One(peer3_pk.clone()), wrong_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet (shard is buffered).
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Send valid shards from peers 2 and 4 so the pending count
                // reaches quorum once the leader shard arrives
                // (minimum_shards = 4: 1 leader + 3 pending).
                for &idx in &[2, 4] {
                    let peer_index = peers[idx].index.get() as u16;
                    let shard = coded_block1.shard(peer_index).expect("missing shard");
                    let bytes = shard.encode();
                    peers[idx]
                        .sender
                        .send(Recipients::One(peer3_pk.clone()), bytes, true);
                }
                context.sleep(config.link.latency * 2).await;

                // No one should be blocked yet (all shards are buffered pending leader).
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty(), "no peers should be blocked yet");

                // Now inform peer 3 of the leader and send the valid leader shard.
                let leader = peers[0].public_key.clone();
                peers[3].mailbox.discovered(
                    commitment1,
                    leader,
                    Round::new(Epoch::zero(), View::new(1)),
                );
                let peer3_index = peers[3].index.get() as u16;
                let leader_shard = coded_block1.shard(peer3_index).expect("missing shard");
                let shard_bytes = leader_shard.encode();
                peers[0]
                    .sender
                    .send(Recipients::One(peer3_pk), shard_bytes, true);
                context.sleep(config.link.latency * 2).await;

                // Peer 1 should be blocked after batch validation validates and
                // rejects their invalid shard.
                assert_blocked(&oracle, &peers[3].public_key, &peers[1].public_key).await;
            },
        );
    }

    #[test_traced]
    fn test_cross_epoch_buffered_shard_not_blocked() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(2),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            // Epoch 0 participants: peers 0..4 (seeds 0..4).
            // Epoch 1 participants: peers 0..3 + peer 4 (seed 4 replaces seed 3).
            let mut epoch0_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            epoch0_keys.sort_by_key(|s| s.public_key());
            let epoch0_pks: Vec<P> = epoch0_keys.iter().map(|c| c.public_key()).collect();
            let epoch0_set: Set<P> = Set::from_iter_dedup(epoch0_pks.clone());

            let future_peer_key = PrivateKey::from_seed(4);
            let future_peer_pk = future_peer_key.public_key();
            let mut epoch1_pks: Vec<P> = epoch0_pks[..3]
                .iter()
                .cloned()
                .chain(std::iter::once(future_peer_pk.clone()))
                .collect();
            epoch1_pks.sort();
            let epoch1_set: Set<P> = Set::from_iter_dedup(epoch1_pks);

            let receiver_idx_in_epoch0 = epoch0_set
                .index(&epoch0_pks[0])
                .expect("receiver must be in epoch 0")
                .get() as usize;
            let receiver_key = epoch0_keys[receiver_idx_in_epoch0].clone();
            let receiver_pk = receiver_key.public_key();

            let receiver_control = oracle.control(receiver_pk.clone());
            let (sender_handle, receiver_handle) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let future_peer_control = oracle.control(future_peer_pk.clone());
            let (mut future_peer_sender, _future_peer_receiver) = future_peer_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(future_peer_pk.clone(), receiver_pk.clone(), DEFAULT_LINK)
                .await
                .expect("link should be added");
            oracle.manager().track(
                0,
                Set::from_iter_dedup([receiver_pk.clone(), future_peer_pk.clone()]),
            );
            context.sleep(Duration::from_millis(10)).await;

            // Set up the receiver's engine with a multi-epoch provider.
            let scheme_epoch0 =
                Scheme::signer(SCHEME_NAMESPACE, epoch0_set.clone(), receiver_key.clone())
                    .expect("signer scheme should be created");
            let scheme_epoch1 =
                Scheme::signer(SCHEME_NAMESPACE, epoch1_set.clone(), receiver_key.clone())
                    .expect("signer scheme should be created");
            let scheme_provider =
                MultiEpochProvider::single(scheme_epoch0).with_epoch(Epoch::new(1), scheme_epoch1);

            let config: Config<_, _, _, _, C, _, _, _> = Config {
                scheme_provider,
                blocker: receiver_control.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };

            let (engine, mailbox) = ShardEngine::new(context.child("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            // Build a coded block using epoch 1's participant set.
            let coding_config = coding_config_for_participants(epoch1_set.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            // The future peer creates a shard at their epoch 1 index.
            let future_peer_index = epoch1_set
                .index(&future_peer_pk)
                .expect("future peer must be in epoch 1");
            let future_shard = coded_block
                .shard(future_peer_index.get() as u16)
                .expect("missing shard");
            let shard_bytes = future_shard.encode();

            // Send the shard BEFORE external_proposed (goes to pre-leader buffer).
            future_peer_sender.send(Recipients::One(receiver_pk.clone()), shard_bytes, true);
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // No one should be blocked yet (shard is buffered, leader unknown).
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "no peers should be blocked while shard is buffered"
            );

            // Announce the leader with an epoch 1 round.
            let leader = epoch0_pks[1].clone();
            mailbox.discovered(commitment, leader, Round::new(Epoch::new(1), View::new(1)));
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // The future peer is a valid participant in epoch 1, so they must NOT
            // be blocked after their buffered shard is ingested.
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "future-epoch participant should not be blocked: {blocked:?}"
            );
        });
    }

    #[test_traced]
    fn test_shard_broadcast_survives_provider_churn() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(4),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|k| k.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

            let leader_idx = 0usize;
            let broadcaster_idx = 1usize;
            let receiver_idx = 2usize;

            let leader_pk = peer_keys[leader_idx].clone();
            let broadcaster_pk = peer_keys[broadcaster_idx].clone();
            let receiver_pk = peer_keys[receiver_idx].clone();

            let mut registrations = BTreeMap::new();
            for key in &peer_keys {
                let control = oracle.control(key.clone());
                let (sender, receiver) = control
                    .register(0, TEST_QUOTA)
                    .await
                    .expect("registration should succeed");
                registrations.insert(key.clone(), (control, sender, receiver));
            }

            for src in &peer_keys {
                for dst in &peer_keys {
                    if src == dst {
                        continue;
                    }
                    oracle
                        .add_link(src.clone(), dst.clone(), DEFAULT_LINK)
                        .await
                        .expect("link should be added");
                }
            }
            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let (_leader_control, mut leader_sender, _leader_receiver) = registrations
                .remove(&leader_pk)
                .expect("leader should be registered");
            let (broadcaster_control, broadcaster_sender, broadcaster_receiver) = registrations
                .remove(&broadcaster_pk)
                .expect("broadcaster should be registered");
            let (receiver_control, receiver_sender, receiver_receiver) = registrations
                .remove(&receiver_pk)
                .expect("receiver should be registered");

            let broadcaster_scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[broadcaster_idx].clone(),
            )
            .expect("signer scheme should be created");
            // `discovered` performs two scoped lookups (`handle_external_proposal`
            // and `ingest_buffered_shards`). Leader-shard validation is the third.
            // Any additional lookup for epoch 0 churns to `None`.
            let broadcaster_provider = ChurningProvider::new(broadcaster_scheme, 3);
            let broadcaster_config: Config<_, _, _, _, C, _, _, _> = Config {
                scheme_provider: broadcaster_provider,
                blocker: broadcaster_control.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };
            let (broadcaster_engine, broadcaster_mailbox) =
                ChurningShardEngine::new(context.child("broadcaster"), broadcaster_config);
            broadcaster_engine.start((broadcaster_sender, broadcaster_receiver));

            let receiver_scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme should be created");
            let receiver_config: Config<_, _, _, _, C, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(receiver_scheme),
                blocker: receiver_control.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };
            let (receiver_engine, receiver_mailbox) =
                ShardEngine::new(context.child("receiver"), receiver_config);
            receiver_engine.start((receiver_sender, receiver_receiver));

            let coding_config = coding_config_for_participants(peer_keys.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();
            let round = Round::new(Epoch::zero(), View::new(1));

            broadcaster_mailbox.discovered(commitment, leader_pk.clone(), round);
            receiver_mailbox.discovered(commitment, leader_pk.clone(), round);
            context.sleep(DEFAULT_LINK.latency).await;

            let broadcaster_index = participants
                .index(&broadcaster_pk)
                .expect("broadcaster must be a participant")
                .get() as u16;
            let broadcaster_shard = coded_block
                .shard(broadcaster_index)
                .expect("missing shard")
                .encode();
            leader_sender.send(Recipients::One(broadcaster_pk), broadcaster_shard, true);

            let receiver_index = participants
                .index(&receiver_pk)
                .expect("receiver must be a participant")
                .get() as u16;
            let receiver_shard = coded_block
                .shard(receiver_index)
                .expect("missing shard")
                .encode();
            leader_sender.send(Recipients::One(receiver_pk.clone()), receiver_shard, true);

            context.sleep(DEFAULT_LINK.latency * 3).await;

            let reconstructed = receiver_mailbox.get(commitment).await;
            assert!(
                reconstructed.is_some(),
                "receiver should reconstruct after broadcaster validates and broadcasts shard"
            );
        });
    }

    #[test_traced]
    fn test_failed_reconstruction_digest_mismatch_then_recovery() {
        // Byzantine scenario: all shards pass coding verification (correct root) but the
        // decoded blob has a different digest than what the commitment claims. This triggers
        // Error::DigestMismatch in try_reconstruct. Verify that:
        //   1. The failed commitment's state is cleaned up
        //   2. The exact commitment subscription closes
        //   3. The digest subscription survives the invalid candidate
        //   4. The valid commitment later reconstructs the claimed digest
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, _, coding_config| async move {
                // Block 1: the "claimed" block (its digest goes in the fake commitment).
                let inner1 = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block1 = CodedBlock::<B, C, H>::new(inner1, coding_config, &STRATEGY);

                // Block 2: the actual data behind the shards.
                let inner2 = B::new(Sha256Digest::EMPTY, Height::new(2), 200);
                let coded_block2 = CodedBlock::<B, C, H>::new(inner2, coding_config, &STRATEGY);
                let real_commitment2 = coded_block2.commitment();

                // This is an invalid claim, not a second accepted commitment for block1.
                // Build it from block1's digest and block2's coding root/context/config.
                // Shards from block2 will verify against block2's root (present in the fake
                // commitment), but try_reconstruct will decode block2 and find its digest != D1.
                let fake_commitment = Commitment::from((
                    coded_block1.digest(),
                    real_commitment2.root(),
                    real_commitment2.context(),
                    coding_config,
                ));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                // Discover the fake commitment.
                peers[receiver_idx]
                    .mailbox
                    .discovered(fake_commitment, leader.clone(), round);

                // Open a block subscription before sending shards.
                let mut block_sub = peers[receiver_idx].mailbox.subscribe(fake_commitment);
                let mut digest_sub = peers[receiver_idx]
                    .mailbox
                    .subscribe_by_digest(coded_block1.digest());

                // Send the receiver's shard (from block2, with fake commitment).
                let receiver_shard_idx = peers[receiver_idx].index.get() as u16;
                let mut leader_shard = coded_block2
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                leader_shard.commitment = fake_commitment;
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    leader_shard.encode(),
                    true,
                );

                // Send enough shards to reach minimum_shards (4 for 10 peers).
                // Need 3 more shards after the leader's shard.
                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let mut shard = coded_block2.shard(peer_shard_idx).expect("missing shard");
                    shard.commitment = fake_commitment;
                    peers[idx].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
                }

                context.sleep(config.link.latency * 2).await;

                // Reconstruction should have failed with DigestMismatch.
                // State for fake_commitment should be removed (engine.rs:792).
                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(fake_commitment)
                        .await
                        .is_none(),
                    "block should not be available after DigestMismatch"
                );

                // Commitment validity governs the exact-commitment subscription.
                // The digest subscription accepts another valid commitment.
                assert!(
                    matches!(block_sub.try_recv(), Err(TryRecvError::Closed)),
                    "subscription should close for failed reconstruction"
                );
                assert!(
                    matches!(digest_sub.try_recv(), Err(TryRecvError::Empty)),
                    "digest subscription should survive failed reconstruction"
                );
                // Now verify the engine is not stuck: send valid shards for block1's real
                // commitment and confirm reconstruction succeeds.
                let real_commitment1 = coded_block1.commitment();
                let round2 = Round::new(Epoch::zero(), View::new(2));
                peers[receiver_idx]
                    .mailbox
                    .discovered(real_commitment1, leader.clone(), round2);

                let leader_shard1 = coded_block1
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    leader_shard1.encode(),
                    true,
                );

                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let shard = coded_block1.shard(peer_shard_idx).expect("missing shard");
                    peers[idx].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
                }

                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(real_commitment1)
                    .await
                    .expect("valid block should reconstruct after prior failure");
                assert_eq!(reconstructed.commitment(), real_commitment1);
                let by_digest = digest_sub
                    .await
                    .expect("valid commitment should satisfy digest subscription");
                assert_eq!(by_digest.commitment(), real_commitment1);
            },
        );
    }

    #[test_traced]
    fn test_failed_reconstruction_context_mismatch_then_recovery() {
        // Byzantine scenario: shards decode to a block whose digest and coding root/config
        // match the commitment, but the commitment carries a mismatched context digest.
        // The engine must reject reconstruction and keep the commitment unresolved.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, _oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let real_commitment = coded_block.commitment();

                let wrong_context_digest = Sha256::hash(&[b"wrong_context"]);
                assert_ne!(
                    real_commitment.context(),
                    wrong_context_digest,
                    "test requires a distinct context digest"
                );
                let fake_commitment = Commitment::from((
                    coded_block.digest(),
                    real_commitment.root(),
                    wrong_context_digest,
                    coding_config,
                ));

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));

                peers[receiver_idx]
                    .mailbox
                    .discovered(fake_commitment, leader.clone(), round);
                let mut block_sub = peers[receiver_idx].mailbox.subscribe(fake_commitment);

                let receiver_shard_idx = peers[receiver_idx].index.get() as u16;
                let mut leader_shard = coded_block
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                leader_shard.commitment = fake_commitment;
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    leader_shard.encode(),
                    true,
                );

                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let mut shard = coded_block.shard(peer_shard_idx).expect("missing shard");
                    shard.commitment = fake_commitment;
                    peers[idx].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
                }

                context.sleep(config.link.latency * 2).await;

                assert!(
                    peers[receiver_idx]
                        .mailbox
                        .get(fake_commitment)
                        .await
                        .is_none(),
                    "block should not be available after ContextMismatch"
                );
                assert!(
                    matches!(block_sub.try_recv(), Err(TryRecvError::Closed)),
                    "subscription should close for context-mismatched commitment"
                );

                // Verify the receiver still reconstructs valid commitments afterward.
                let round2 = Round::new(Epoch::zero(), View::new(2));
                peers[receiver_idx]
                    .mailbox
                    .discovered(real_commitment, leader.clone(), round2);

                let real_leader_shard = coded_block
                    .shard(receiver_shard_idx)
                    .expect("missing shard");
                peers[0].sender.send(
                    Recipients::One(receiver_pk.clone()),
                    real_leader_shard.encode(),
                    true,
                );

                for &idx in &[1usize, 2, 4] {
                    let peer_shard_idx = peers[idx].index.get() as u16;
                    let shard = coded_block.shard(peer_shard_idx).expect("missing shard");
                    peers[idx].sender.send(
                        Recipients::One(receiver_pk.clone()),
                        shard.encode(),
                        true,
                    );
                }

                context.sleep(config.link.latency * 2).await;

                let reconstructed = peers[receiver_idx]
                    .mailbox
                    .get(real_commitment)
                    .await
                    .expect("valid block should reconstruct after prior context mismatch");
                assert_eq!(reconstructed.commitment(), real_commitment);
            },
        );
    }

    #[test_traced]
    fn test_same_round_equivocation_preserves_certifiable_recovery() {
        // Regression coverage for same-round leader equivocation:
        // - leader equivocates across two commitments in the same round
        // - we receive a shard for commitment B (the certifiable one)
        // - commitment A reconstructs first
        // - commitment B must still remain recoverable
        // - the leader must not be blocked (a leader that crashes after its
        //   broadcast but before its local persist legitimately re-proposes
        //   a different block for the same round after restart)
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let receiver_shard_idx = peers[receiver_idx].index.get() as u16;

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(7));

                // Two different commitments in the same round (equivocation scenario).
                let block_a = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 111),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_a = block_a.commitment();
                let block_b = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 222),
                    coding_config,
                    &STRATEGY,
                );
                let commitment_b = block_b.commitment();

                // Receiver learns both commitments in the same round.
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment_a, leader.clone(), round);
                peers[receiver_idx]
                    .mailbox
                    .discovered(commitment_b, leader.clone(), round);

                // Subscribe to the certifiable commitment before any reconstruction.
                let certifiable_sub = peers[receiver_idx].mailbox.subscribe(commitment_b);

                // We receive our shard for commitment B from the equivocating leader.
                let shard_b = block_b
                    .shard(receiver_shard_idx)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), shard_b, true);

                // Reconstruct conflicting commitment A first.
                let shard_a = block_a
                    .shard(receiver_shard_idx)
                    .expect("missing shard")
                    .encode();
                peers[0]
                    .sender
                    .send(Recipients::One(receiver_pk.clone()), shard_a, true);
                for i in [1usize, 2usize, 4usize] {
                    let shard_a = block_a
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard_a, true);
                }
                context.sleep(config.link.latency * 4).await;
                let reconstructed_a = peers[receiver_idx]
                    .mailbox
                    .get(commitment_a)
                    .await
                    .expect("conflicting commitment should reconstruct first");
                assert_eq!(reconstructed_a.commitment(), commitment_a);

                // Commitment B should still be recoverable after A reconstructed.
                for i in [1usize, 2usize, 4usize] {
                    let shard_b = block_b
                        .shard(peers[i].index.get() as u16)
                        .expect("missing shard")
                        .encode();
                    peers[i]
                        .sender
                        .send(Recipients::One(receiver_pk.clone()), shard_b, true);
                }

                select! {
                    result = certifiable_sub => {
                        let reconstructed_b =
                            result.expect("certifiable commitment should remain recoverable");
                        assert_eq!(reconstructed_b.commitment(), commitment_b);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("certifiable commitment was not recoverable after same-round equivocation");
                    },
                }

                // Cross-commitment equivocation within a round is tolerated,
                // so the leader must not be blocked.
                let blocked_peers = oracle.blocked().await.unwrap();
                let is_blocked = blocked_peers
                    .iter()
                    .any(|(a, b)| a == &receiver_pk && b == &leader);
                assert!(
                    !is_blocked,
                    "leader must not be blocked for same-round cross-commitment shards"
                );
            },
        );
    }

    #[test_traced]
    fn test_leader_unrelated_shard_blocks_peer() {
        // Regression test: if the leader sends an unrelated/invalid shard
        // (i.e. a shard for a different participant index), the receiver must
        // block the leader.
        let fixture: Fixture<C> = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                // Commitment being tracked by the receiver.
                let tracked_block = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(1), 100),
                    coding_config,
                    &STRATEGY,
                );
                let tracked_commitment = tracked_block.commitment();

                // Separate block used to source "unrelated" shard data.
                let unrelated_block = CodedBlock::<B, C, H>::new(
                    B::new(Sha256Digest::EMPTY, Height::new(2), 200),
                    coding_config,
                    &STRATEGY,
                );

                let receiver_idx = 3usize;
                let receiver_pk = peers[receiver_idx].public_key.clone();
                let leader_idx = 0usize;
                let leader_pk = peers[leader_idx].public_key.clone();

                // Receiver tracks the commitment with peer0 as leader.
                peers[receiver_idx].mailbox.discovered(
                    tracked_commitment,
                    leader_pk.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                );

                // Construct an unrelated shard from peer1's slot and retarget
                // its commitment to the tracked commitment so it hits active state.
                let mut unrelated_shard = unrelated_block
                    .shard(peers[1].index.get() as u16)
                    .expect("missing shard");
                unrelated_shard.commitment = tracked_commitment;

                // Leader sends this unrelated/invalid shard to receiver.
                // The shard index no longer matches sender's participant index,
                // so leader must be blocked.
                peers[leader_idx].sender.send(
                    Recipients::One(receiver_pk),
                    unrelated_shard.encode(),
                    true,
                );
                context.sleep(config.link.latency * 2).await;

                assert_blocked(&oracle, &peers[receiver_idx].public_key, &leader_pk).await;
            },
        );
    }

    #[test_traced]
    fn test_withholding_leader_victim_reconstructs_via_gossip() {
        // A Byzantine leader withholds the shard destined for one participant.
        // That participant should still reconstruct the block from shards
        // gossiped by other participants (sent via Recipients::All) without
        // any backfill mechanism.
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader = peers[0].public_key.clone();
                let victim = peers[1].public_key.clone();

                // Sever the link from leader to victim so the leader's
                // direct shard never arrives.
                oracle
                    .remove_link(leader.clone(), victim.clone())
                    .await
                    .expect("remove_link should succeed");

                // Leader proposes. The victim will not receive a direct shard
                // because the link is severed.
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform all non-leader peers of the leader so they validate
                // and re-broadcast their shards via Recipients::All.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency * 2).await;

                // The victim should reconstruct via gossiped shards from other
                // participants even though the leader withheld.
                let block_sub = peers[1].mailbox.subscribe(commitment);
                select! {
                    result = block_sub => {
                        let reconstructed = result.expect("block subscription should resolve");
                        assert_eq!(reconstructed.commitment(), commitment);
                        assert_eq!(reconstructed.height(), coded_block.height());
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("victim did not reconstruct block despite withholding leader");
                    },
                }

                // All other participants should also have reconstructed.
                for peer in peers[2..].iter_mut() {
                    let reconstructed = peer
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("block should be reconstructed");
                    assert_eq!(reconstructed.commitment(), commitment);
                }

                // No peer should be blocked — withholding is not detectable.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in withholding leader test"
                );
            },
        );
    }

    /// When the leader withholds its shard from a participant, the block
    /// can still be reconstructed from gossipped shards. However, the shard
    /// subscription must NOT resolve because the participant's own shard was
    /// never verified. Voting requires own-shard verification to ensure the
    /// participant re-broadcasts its shard and helps slower peers reach quorum.
    #[test_traced]
    fn test_shard_subscription_pending_after_reconstruction_without_leader_shard() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader = peers[0].public_key.clone();
                let victim = peers[1].public_key.clone();

                // Remove the link from leader to victim so the leader's shard
                // never reaches the victim directly.
                oracle
                    .remove_link(leader.clone(), victim.clone())
                    .await
                    .expect("remove_link should succeed");

                // Subscribe to the shard and block BEFORE any broadcasting.
                let mut shard_sub = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                let block_sub = peers[1].mailbox.subscribe(commitment);

                // Leader broadcasts.
                peers[0].mailbox.proposed(round, coded_block.clone());

                // All non-leader peers discover the leader.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }

                // Wait for gossip to propagate.
                context.sleep(config.link.latency * 4).await;

                // Block subscription should resolve (victim reconstructs from
                // gossipped shards).
                let reconstructed = block_sub.await.expect("block subscription should resolve");
                assert_eq!(reconstructed.commitment(), commitment);

                let mut late_shard_sub = peers[1]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                context.sleep(Duration::from_millis(10)).await;

                // Neither an existing nor a late shard subscription may resolve because
                // the leader never sent the victim its own shard.
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription must not resolve without own shard verification"
                );
                assert!(
                    matches!(late_shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "late shard subscription must not resolve from reconstruction alone"
                );
            },
        );
    }

    #[test_traced]
    fn test_broadcast_routes_participant_and_non_participant_shards() {
        let fixture = Fixture {
            num_secondary_peers: 1,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, non_participants, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();

                let leader = peers[0].public_key.clone();
                let round = Round::new(Epoch::zero(), View::new(1));
                peers[0].mailbox.proposed(round, coded_block.clone());

                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                for np in non_participants.iter() {
                    np.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency * 2).await;

                // Participants should receive and validate their own shards.
                for peer in peers.iter_mut() {
                    peer.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("participant shard subscription should complete");
                }

                // Non-participant should receive and validate the leader's shard.
                for np in non_participants.iter() {
                    np.mailbox
                        .subscribe_assigned_shard_verified(commitment)
                        .await
                        .expect("non-participant shard subscription should complete");
                }
                context.sleep(config.link.latency).await;

                // Non-participant should reconstruct the block from received shards.
                for np in non_participants.iter() {
                    let reconstructed = np
                        .mailbox
                        .get(commitment)
                        .await
                        .expect("non-participant should reconstruct block");
                    assert_eq!(reconstructed.commitment(), commitment);
                }

                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in participant/non-participant shard routing test"
                );
            },
        );
    }

    #[test_traced]
    fn test_non_participant_reconstructs_after_discovered() {
        let fixture = Fixture {
            num_secondary_peers: 1,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, non_participants, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader = peers[0].public_key.clone();
                peers[0].mailbox.proposed(round, coded_block.clone());

                // Inform participants of the leader so they validate and re-broadcast
                // shards.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }
                context.sleep(config.link.latency).await;

                // Non-participant discovers the leader after shards are already
                // propagating through the network.
                let np = &non_participants[0];
                let block_sub = np.mailbox.subscribe(commitment);
                np.mailbox.discovered(commitment, leader.clone(), round);

                // Wait for enough shards (leader's shard + shards from
                // participants) to arrive and reconstruct.
                select! {
                    result = block_sub => {
                        let reconstructed = result.expect("block subscription should resolve");
                        assert_eq!(reconstructed.commitment(), commitment);
                        assert_eq!(reconstructed.height(), coded_block.height());
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("non-participant block subscription did not resolve");
                    },
                }

                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in non-participant reconstruction test"
                );
            },
        );
    }

    #[test_traced]
    fn test_peer_set_update_evicts_peer_buffers() {
        // Shards buffered before leader announcement should be evicted when
        // the sender leaves latest.primary. Even if the overlap window keeps
        // the sender connected, fresh pre-leader shards from that peer must
        // not recreate the buffer.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 10usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(num_peers),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(2),
                },
            );
            network.start();

            let mut private_keys = (0..num_peers)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

            // Test from the perspective of a single receiver (peer 3).
            let receiver_idx = 3usize;
            let receiver_pk = peer_keys[receiver_idx].clone();
            let leader_pk = peer_keys[0].clone();

            let receiver_control = oracle.control(receiver_pk.clone());
            let (sender_handle, receiver_handle) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            // Register the leader so it can send shards.
            let leader_control = oracle.control(leader_pk.clone());
            let (mut leader_sender, _leader_receiver) = leader_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(leader_pk.clone(), receiver_pk.clone(), DEFAULT_LINK)
                .await
                .expect("link should be added");

            // Track the full participant set so the engine sees all peers.
            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme should be created");

            let config: Config<_, _, _, _, C, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };

            let (engine, mailbox) = ShardEngine::new(context.child("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            // Build a coded block and extract the shard destined for the receiver.
            let coding_config = coding_config_for_participants(num_peers as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let receiver_participant = participants
                .index(&receiver_pk)
                .expect("receiver must be a participant");
            let leader_shard = coded_block
                .shard(receiver_participant.get() as u16)
                .expect("missing shard");
            let shard_bytes = leader_shard.encode();

            // Send the shard BEFORE leader announcement (it gets buffered).
            leader_sender.send(
                Recipients::One(receiver_pk.clone()),
                shard_bytes.clone(),
                true,
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Now send a peer set update that excludes the leader.
            let remaining: Set<P> =
                Set::from_iter_dedup(peer_keys.iter().filter(|pk| **pk != leader_pk).cloned());
            oracle.manager().track(1, remaining);
            context.sleep(Duration::from_millis(10)).await;

            // The retained overlap window still lets the leader reach the receiver,
            // but this fresh pre-leader shard must not be buffered again.
            leader_sender.send(Recipients::One(receiver_pk.clone()), shard_bytes, true);
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Announce the leader. Buffered shards from the leader should have been
            // evicted, so the shard will NOT be ingested.
            let mut shard_sub = mailbox.subscribe_assigned_shard_verified(commitment);
            mailbox.discovered(
                commitment,
                leader_pk.clone(),
                Round::new(Epoch::zero(), View::new(1)),
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // The shard subscription should still be pending (no shard was ingested).
            assert!(
                matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                "shard subscription should not resolve after evicted leader's buffer"
            );
            assert!(
                mailbox.get(commitment).await.is_none(),
                "block should not reconstruct from evicted buffers"
            );
        });
    }

    #[test_traced]
    fn test_peer_buffer_lifetime_tracks_latest_primary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(1),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let mut private_keys = (0..4)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();
            let receiver_pk = peer_keys[0].clone();
            let sender_pk = peer_keys[1].clone();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys);

            let receiver_control = oracle.control(receiver_pk);
            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[0].clone(),
            )
            .expect("signer scheme should be created");

            let config: Config<_, _, _, _, C, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control,
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(16),
                peer_buffer_size: NZUsize!(4),
                background_channel_capacity: NZUsize!(16),
                peer_provider: oracle.manager(),
            };

            let (mut engine, _mailbox) = ShardEngine::new(context.child("engine"), config);

            // Only `sender_pk` is in `latest.primary`, so only that peer may retain a pre-leader
            // buffer row (`buffer_peer_shard` / `peer_buffers`).
            engine.update_latest_primary_peers(Set::from_iter_dedup([sender_pk.clone()]));

            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(
                inner,
                coding_config_for_participants(participants.len() as u16),
                &STRATEGY,
            );
            let shard = coded_block.shard(0).expect("missing shard");

            // Pre-leader path: buffer one shard before any leader or notarized interest arrives.
            engine.buffer_peer_shard(sender_pk.clone(), shard);
            assert_eq!(
                engine.peer_buffers.get(&sender_pk).map(VecDeque::len),
                Some(1),
                "peer buffer should contain the buffered shard"
            );

            // Empty primary: no peer may retain buffers; `update_latest_primary_peers` drops the
            // staged shard and the deque entry for `sender_pk`.
            engine.update_latest_primary_peers(Set::default());
            assert!(
                !engine.peer_buffers.contains_key(&sender_pk),
                "peer buffer should be evicted once sender leaves latest.primary"
            );
        });
    }

    #[test_traced]
    fn test_old_epoch_buffered_shards_are_dropped_after_cutover() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 6usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(num_peers - 1),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(2),
                },
            );
            network.start();

            let mut private_keys = (0..num_peers)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();

            // Epoch 0: first five peers. Epoch 1: swap out `peer_keys[0]` for `peer_keys[5]` so the
            // cutover changes who is in `latest.primary` while `tracked_peer_sets` retains overlap.
            let epoch0_set: Set<P> = Set::from_iter_dedup(peer_keys[..5].iter().cloned());
            let epoch1_set: Set<P> = Set::from_iter_dedup([
                peer_keys[1].clone(),
                peer_keys[2].clone(),
                peer_keys[3].clone(),
                peer_keys[4].clone(),
                peer_keys[5].clone(),
            ]);

            let receiver_idx = 3usize;
            let receiver_pk = peer_keys[receiver_idx].clone();
            let receiver_key = private_keys[receiver_idx].clone();
            let leader_pk = peer_keys[0].clone();

            let receiver_control = oracle.control(receiver_pk.clone());
            let (sender_handle, receiver_handle) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let leader_control = oracle.control(leader_pk.clone());
            let (mut leader_sender, _leader_receiver) = leader_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");
            oracle
                .add_link(leader_pk.clone(), receiver_pk.clone(), DEFAULT_LINK)
                .await
                .expect("link should be added");

            // Peer-set id 0: epoch 0 primaries before any cutover.
            oracle.manager().track(0, epoch0_set.clone());
            context.sleep(Duration::from_millis(10)).await;

            let scheme_epoch0 =
                Scheme::signer(SCHEME_NAMESPACE, epoch0_set.clone(), receiver_key.clone())
                    .expect("epoch 0 signer scheme should be created");
            let scheme_epoch1 =
                Scheme::signer(SCHEME_NAMESPACE, epoch1_set.clone(), receiver_key.clone())
                    .expect("epoch 1 signer scheme should be created");

            let config: Config<_, _, _, _, C, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme_epoch0)
                    .with_epoch(Epoch::new(1), scheme_epoch1),
                blocker: receiver_control.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };

            // Receiver engine: schemes for both epochs so post-cutover validation can run if needed.
            let (engine, mailbox) = ShardEngine::new(context.child("receiver"), config);
            engine.start((sender_handle, receiver_handle));

            let coding_config = coding_config_for_participants(epoch0_set.len() as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let receiver_participant = epoch0_set
                .index(&receiver_pk)
                .expect("receiver must be an epoch 0 participant");
            let leader_shard = coded_block
                .shard(receiver_participant.get() as u16)
                .expect("missing shard");

            // Inbound: epoch-0 leader shard arrives before `Discovered` (pre-leader buffer path).
            leader_sender.send(
                Recipients::One(receiver_pk.clone()),
                leader_shard.encode(),
                true,
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Cutover to epoch 1 primaries before `Discovered`: `leader_pk` (epoch-0-only) is no
            // longer in `latest.primary`, so overlap-buffered shards for that sender must not feed
            // reconstruction.
            oracle.manager().track(1, epoch1_set);
            context.sleep(Duration::from_millis(10)).await;

            // Leader announcement for the old commitment: should not complete reconstruction from
            // dropped pre-cutover buffers.
            let mut shard_sub = mailbox.subscribe_assigned_shard_verified(commitment);
            mailbox.discovered(
                commitment,
                leader_pk,
                Round::new(Epoch::zero(), View::new(1)),
            );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            assert!(
                matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                "old-epoch shard subscription should stay pending after cutover"
            );
            assert!(
                mailbox.get(commitment).await.is_none(),
                "old-epoch commitment should not reconstruct from overlap-only buffered shards"
            );
        });
    }

    /// If the evicted node leaves the
    /// [`commonware_p2p::PeerSetUpdate::latest`] primary set, it must still
    /// reconstruct once the leader is discovered, as long as enough buffered
    /// shards came from peers that remain in `latest.primary`.
    ///
    /// This does not rely on a self-buffered shard or a leader-delivered shard:
    /// reconstruction should succeed from the remaining buffered peer shards
    /// alone.
    #[test_traced]
    fn test_evicted_node_still_reconstructs_from_buffered_peer_shards() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let num_peers = 10usize;
            let (network, oracle) = simulated::Network::<deterministic::Context, P>::new(
                context.child("network"),
                simulated::Config {
                    max_size: MAX_SHARD_SIZE as u32,
                    max_peers_per_set: NZUsize!(num_peers),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(2),
                },
            );
            network.start();

            let mut private_keys = (0..num_peers)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            private_keys.sort_by_key(|s| s.public_key());
            let peer_keys: Vec<P> = private_keys.iter().map(|c| c.public_key()).collect();
            let participants: Set<P> = Set::from_iter_dedup(peer_keys.clone());

            // Receiver (`peer_keys[1]`) is evicted from `latest.primary` after shards are buffered.
            // The leader (`peer_keys[0]`) has no link to the receiver, so reconstruction cannot use a
            // leader-delivered shard or a self-buffered shard; it must use gossip from peers 2/4/5/6 only.
            let receiver_idx = 1usize;
            let receiver_pk = peer_keys[receiver_idx].clone();
            let leader_pk = peer_keys[0].clone();
            let peer2_pk = peer_keys[2].clone();
            let peer4_pk = peer_keys[4].clone();
            let peer5_pk = peer_keys[5].clone();
            let peer6_pk = peer_keys[6].clone();

            let receiver_control = oracle.control(receiver_pk.clone());
            let (evicted_sender, evicted_receiver) = receiver_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let peer2_control = oracle.control(peer2_pk.clone());
            let (mut peer2_sender, _peer2_receiver) = peer2_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let peer4_control = oracle.control(peer4_pk.clone());
            let (mut peer4_sender, _peer4_receiver) = peer4_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let peer5_control = oracle.control(peer5_pk.clone());
            let (mut peer5_sender, _peer5_receiver) = peer5_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            let peer6_control = oracle.control(peer6_pk.clone());
            let (mut peer6_sender, _peer6_receiver) = peer6_control
                .register(0, TEST_QUOTA)
                .await
                .expect("registration should succeed");

            // Only secondary peers that will forward shards are connected to the receiver (not the leader).
            for sender in [&peer2_pk, &peer4_pk, &peer5_pk, &peer6_pk] {
                oracle
                    .add_link(sender.clone(), receiver_pk.clone(), DEFAULT_LINK)
                    .await
                    .expect("link should be added");
            }

            // Start with the full committee so the receiver's signer scheme matches the coded block.
            oracle.manager().track(0, participants.clone());
            context.sleep(Duration::from_millis(10)).await;

            let scheme = Scheme::signer(
                SCHEME_NAMESPACE,
                participants.clone(),
                private_keys[receiver_idx].clone(),
            )
            .expect("signer scheme should be created");

            let config: Config<_, _, _, _, C, _, _, _> = Config {
                scheme_provider: MultiEpochProvider::single(scheme),
                blocker: receiver_control.clone(),
                shard_codec_cfg: CodecConfig {
                    maximum_shard_size: MAX_SHARD_SIZE,
                },
                block_codec_cfg: (),
                strategy: STRATEGY,
                mailbox_size: NZUsize!(1024),
                peer_buffer_size: NZUsize!(64),
                background_channel_capacity: NZUsize!(1024),
                peer_provider: oracle.manager(),
            };

            let (engine, mailbox) = ShardEngine::new(context.child("evicted"), config);
            engine.start((evicted_sender, evicted_receiver));

            let coding_config = coding_config_for_participants(num_peers as u16);
            let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
            let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
            let commitment = coded_block.commitment();

            let peer2_shard = coded_block.shard(2).expect("missing shard 2").encode();
            let peer4_shard = coded_block.shard(4).expect("missing shard 4").encode();
            let peer5_shard = coded_block.shard(5).expect("missing shard 5").encode();
            let peer6_shard = coded_block.shard(6).expect("missing shard 6").encode();

            let block_sub = mailbox.subscribe(commitment);

            // Pre-`Discovered` path: four shards from peers that will still be in `latest.primary` after
            // the receiver is evicted (indices 2, 4, 5, 6). Together they are enough to reconstruct.
            peer2_sender
                .send(
                    Recipients::One(receiver_pk.clone()),
                    peer2_shard,
                    true,
                );
            peer4_sender
                .send(
                    Recipients::One(receiver_pk.clone()),
                    peer4_shard,
                    true,
                );
            peer5_sender
                .send(
                    Recipients::One(receiver_pk.clone()),
                    peer5_shard,
                    true,
                );
            peer6_sender
                .send(
                    Recipients::One(receiver_pk.clone()),
                    peer6_shard,
                    true,
                );
            context.sleep(DEFAULT_LINK.latency * 2).await;

            // Evict the receiver from `latest.primary`: buffered shards from remaining primaries must
            // still count toward reconstruction once the leader is known.
            let latest_primary: Set<P> = Set::from_iter_dedup(
                peer_keys
                    .iter()
                    .filter(|pk| **pk != receiver_pk)
                    .cloned(),
            );
            oracle.manager().track(1, latest_primary);
            context.sleep(Duration::from_millis(10)).await;

            // Leader announcement drains overlap-buffered peer shards; the evicted receiver should
            // still reach quorum without ever receiving the leader's direct shard.
            mailbox
                .discovered(
                    commitment,
                    leader_pk.clone(),
                    Round::new(Epoch::zero(), View::new(1)),
                );

            select! {
                _ = block_sub => {},
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("block subscription did not resolve after leader discovery");
                },
            }

            context.sleep(DEFAULT_LINK.latency * 2).await;
            let block = mailbox.get(commitment).await;
            assert!(
                block.is_some(),
                "evicted node should reconstruct from buffered shards sent by remaining latest.primary peers"
            );
            assert_eq!(block.unwrap().commitment(), commitment);

            assert!(
                oracle.blocked().await.unwrap().is_empty(),
                "no peer should be blocked when overlapping shards are valid"
            );
        });
    }

    /// When peer gossip shards arrive before the leader's direct shard,
    /// the state may transition to Ready before the leader shard is
    /// processed. The late leader shard must still be accepted, verified,
    /// and broadcast so that slower peers can reach quorum.
    #[test_traced]
    fn test_late_leader_shard_accepted_after_quorum_transition() {
        let fixture = Fixture {
            num_primary_peers: 10,
            ..Default::default()
        };

        fixture.start(
            |config, context, oracle, mut peers, _, coding_config| async move {
                let inner = B::new(Sha256Digest::EMPTY, Height::new(1), 100);
                let coded_block = CodedBlock::<B, C, H>::new(inner, coding_config, &STRATEGY);
                let commitment = coded_block.commitment();
                let round = Round::new(Epoch::zero(), View::new(1));

                let leader_idx = 0usize;
                let victim_idx = 1usize;
                let leader = peers[leader_idx].public_key.clone();
                let victim = peers[victim_idx].public_key.clone();

                // Sever the link from leader to victim so the leader's
                // direct shard does not arrive initially.
                oracle
                    .remove_link(leader.clone(), victim.clone())
                    .await
                    .expect("remove_link should succeed");

                // Leader proposes. All peers except the victim get their
                // shard from the leader, verify it, and gossip it.
                peers[leader_idx]
                    .mailbox
                    .proposed(round, coded_block.clone());

                // Inform all non-leader peers of the leader.
                for peer in peers[1..].iter_mut() {
                    peer.mailbox.discovered(commitment, leader.clone(), round);
                }

                // Wait for gossip to propagate. The victim should
                // reconstruct the block from gossiped peer shards,
                // transitioning to Ready without its own shard.
                context.sleep(config.link.latency * 4).await;

                let block_sub = peers[victim_idx].mailbox.subscribe(commitment);
                select! {
                    result = block_sub => {
                        let reconstructed = result.expect("block subscription should resolve");
                        assert_eq!(reconstructed.commitment(), commitment);
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("victim did not reconstruct block from gossip");
                    },
                }

                // The shard subscription should NOT have resolved yet
                // because the victim has not verified its own shard.
                let mut shard_sub = peers[victim_idx]
                    .mailbox
                    .subscribe_assigned_shard_verified(commitment);
                assert!(
                    matches!(shard_sub.try_recv(), Err(TryRecvError::Empty)),
                    "shard subscription must not resolve before own shard is verified"
                );

                // Now restore the link so the leader's shard arrives late.
                oracle
                    .add_link(leader.clone(), victim.clone(), DEFAULT_LINK)
                    .await
                    .expect("add_link should succeed");

                // Re-send the leader's shard manually via the leader's
                // network sender (the engine already broadcast it earlier,
                // but the link was down).
                let leader_shard = coded_block
                    .shard(peers[victim_idx].index.get() as u16)
                    .expect("missing victim shard");
                peers[leader_idx].sender.send(
                    Recipients::One(victim.clone()),
                    leader_shard.encode(),
                    true,
                );
                context.sleep(config.link.latency * 2).await;

                // The shard subscription should now resolve because the
                // late leader shard was accepted and verified.
                select! {
                    _ = shard_sub => {},
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("shard subscription did not resolve after late leader shard");
                    },
                }

                // No peer should be blocked.
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "no peer should be blocked in late leader shard test"
                );

                // After both reconstruction and assigned shard readiness,
                // additional gossip shards should be silently ignored.
                let extra_sender_idx = 2usize;
                let extra_shard = coded_block
                    .shard(peers[extra_sender_idx].index.get() as u16)
                    .expect("missing shard");
                peers[extra_sender_idx].sender.send(
                    Recipients::One(victim.clone()),
                    extra_shard.encode(),
                    true,
                );
                context.sleep(config.link.latency * 2).await;

                // The gossip shard should be silently dropped (not blocked).
                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked.is_empty(),
                    "gossip shard after full reconstruction should be silently ignored"
                );
            },
        );
    }
}
