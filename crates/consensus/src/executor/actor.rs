//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.
//!
//! Beyond finalizations, the agent tracks which blocks are notarized (learned
//! from the parent contexts that consensus hands to the application on
//! propose/verify: such a parent must be notarized for the proposal to be
//! valid) and reconstructs the canonical notarized chain on top of the
//! finalized tip. It drives the execution layer's head towards the tip of
//! that notarized chain, fetching missing block bodies from the marshal
//! actor in the background. This decouples updating the execution layer from
//! the lifetime of individual consensus requests: even if simplex aborts a
//! view (and with it the application's verify/propose future), the executor
//! retains what it learned and keeps the execution layer in sync.
//!
//! Execution-layer work is prioritized by consensus latency: validating a
//! proposal, then building one, then forwarding notarized blocks, then
//! forwarding finalized blocks.
//!
//! Every forkchoice update that moves the head targets a notarized block:
//! notarized-block forwarding does so by construction, and a build request
//! does so because it canonicalizes the propose context's parent, which
//! consensus guarantees to be notarized. A head left behind by an aborted
//! request is thus always a valid — at worst stale — notarized-chain state
//! to converge from (see [`Canonicalize`] for the build-specific leak).
//!
//! The finalized tip of the *network* (reported by the marshal, possibly
//! ahead of the finalized blocks delivered so far) marks an ownership
//! boundary: blocks at or below it belong exclusively to the ordered,
//! acknowledged, fatal-on-failure finalization pipeline, and the
//! notarized-chain machinery prunes itself to strictly above it. Forwarding
//! of notarized blocks is explicitly gated on the *locally* forwarded
//! finalized tip having caught up with the network's: until then it stays
//! dormant instead of racing the finalization pipeline into syncing
//! failures.
//!
//! Validation requests are deliberately kept off that convergence machinery:
//! a block is validated with a single new-payload request, which requires the
//! execution layer to already know the block's parent. If it does not, the
//! validation fails (costing the node its vote for that view) and the gap is
//! repaired in the background instead of on the latency-critical path.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;

use alloy_rpc_types_engine::{ForkchoiceState, PayloadId};
use commonware_consensus::{
    CertifiableBlock as _, Heightable as _,
    marshal::Update,
    simplex::types::Context,
    types::{Height, Round},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{
    Clock, ContextCell, FutureExt, Handle, Metrics as RuntimeMetrics, Pacer, Spawner, spawn_cell,
};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use eyre::{Report, WrapErr as _, bail, ensure};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    future::BoxFuture,
    stream::FuturesUnordered,
};
use prometheus_client::metrics::counter::Counter;
use reth_ethereum::{chainspec::EthChainSpec, rpc::eth::primitives::BlockNumHash};
use reth_node_builder::PayloadKind;
use reth_provider::{BlockHashReader as _, BlockIdReader as _, BlockReader as _, BlockSource};
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tokio::select;
use tracing::{Level, Span, debug, error, error_span, info, info_span, instrument, warn};

use super::{
    Config,
    ingress::{CanonicalizeAndBuild, Command, Message, ValidateBlock},
};
use crate::{
    consensus::{Digest, block::Block},
    utils::OptionFuture,
};

#[cfg(test)]
mod tests;

/// A block known to the executor together with the validator set to validate
/// it against.
#[derive(Clone, Debug)]
struct BlockEntry {
    block: Arc<Block>,
    /// Set when the execution layer failed to process the block for a reason
    /// that carries no evidence of divergence (unreachable, still syncing).
    /// Forwarding skips rejected blocks instead of retrying them in a tight
    /// loop; the marker lasts until the advancing finalized tip expunges the
    /// entry (the finalization pipeline retries the block with
    /// fatal-on-failure semantics) or a re-recorded body clears it.
    rejected: bool,
}

/// Tracks notarized blocks at the tip of the chain and returns which block can
/// be forwarded to the EL next.
///
/// Notarization facts (a round and the digest notarized in it) are learned
/// from the parent contexts that simplex hands to the application on
/// propose/verify, and derived from blocks fetched along the latest
/// notarization's ancestry. Block bodies are captured from validation
/// requests or fetched from the marshal actor. Both are combined to
/// reconstruct the
/// canonical notarized chain on top of the finalized tip: the ancestry of
/// the latest notarization, because a block can only be notarized if its
/// parent is, so everything off that ancestry was forked out (its round
/// nullified).
///
/// The directory holds data strictly above the finalized *network* tip,
/// which it tracks itself: recording and pruning are guarded against it.
///
/// The directory is self-canonicalizing: it tracks how far along the
/// canonical notarized path the execution layer's head has been advanced
/// (the `notarized_cursor`) and hands out the block directly above the
/// cursor as the next to forward. Forked-out blocks are deleted as they are
/// discovered — a new latest notarization deletes everything at or above
/// its height, a fetched ancestor deletes its same-height siblings — and
/// the cursor sinks to the parent of its deleted block each time, so it
/// converges on the fork point (a block the execution layer provably has)
/// and the common trunk is never re-forwarded.
#[derive(Debug)]
struct NotarizedFactsDirectory {
    /// The latest observed finalized tip of the network: the directory's
    /// lower bound. Data at or below it is never recorded, and recorded data
    /// is pruned once the tip moves past it.
    finalized_tip: (Round, Height, Digest),
    /// The canonicalization cursor: the most recent block on the canonical
    /// notarized path that the execution layer provably has. Blocks are
    /// forwarded strictly above it.
    ///
    /// The cursor never runs ahead of the execution layer's head, but it may
    /// trail it: when the canonical path forks away, the cursor sinks to
    /// the fork point (an ancestor of the head, hence still known to the
    /// execution layer), and when the finalized tip advances past it, it is
    /// reset to that tip — which the execution layer only knows once the
    /// finalization pipeline has caught up, so the caller must gate
    /// forwarding on that (see [`Actor::next_notarized_forward`]).
    notarized_cursor: (Height, Digest),
    /// Digests known to be notarized, keyed by the round they were notarized in.
    notarized: BTreeMap<Round, Digest>,
    /// Bodies of blocks at the tip of the chain, keyed by digest.
    blocks: HashMap<Digest, BlockEntry>,
}

impl NotarizedFactsDirectory {
    fn new(finalized_tip: (Round, Height, Digest), notarized_cursor: (Height, Digest)) -> Self {
        Self {
            finalized_tip,
            notarized_cursor,
            notarized: BTreeMap::new(),
            blocks: HashMap::new(),
        }
    }

    /// Records `digest` as notarized in `round` unless it is already covered
    /// by the finalized tip.
    fn record_notarized(&mut self, round: Round, digest: Digest) {
        let (finalized_round, _, finalized_digest) = self.finalized_tip;
        if round > finalized_round && digest != finalized_digest {
            let is_latest = self
                .notarized
                .last_key_value()
                .is_none_or(|(latest, _)| round > *latest);
            self.notarized.insert(round, digest);
            // A new latest notarization proves everything at or above its
            // height forked out. Its height is only known once its body is;
            // if the body is still missing, the deletion happens when the
            // body arrives (see [`Self::record_block`]).
            if is_latest && let Some(entry) = self.blocks.get(&digest) {
                let height = entry.block.height();
                self.delete_forked_out(height, digest);
            }
        }
    }

    /// Records the body of a block unless the finalized tip covers its
    /// height. Such a stale block's notarization fact is dropped along with
    /// its body so that the body is not fetched again.
    fn record_block(&mut self, block: Arc<Block>) {
        if block.height() <= self.finalized_tip.1 {
            debug!(
                digest = %block.digest(),
                height = %block.height(),
                "block is at or below the finalized tip; dropping it from the directory",
            );
            self.remove(&block.digest());
            return;
        }
        let digest = block.digest();
        let height = block.height();
        self.blocks.insert(
            digest,
            BlockEntry {
                block,
                rejected: false,
            },
        );
        // The body may have delivered the height of the latest notarization,
        // enabling the fork-out deletion deferred by
        // [`Self::record_notarized`].
        if self
            .notarized
            .last_key_value()
            .is_some_and(|(_, latest)| *latest == digest)
        {
            self.delete_forked_out(height, digest);
        }
    }

    /// Records the body of a block fetched along the latest notarization's
    /// ancestry.
    ///
    /// Being on the ancestry proves the block notarized, so its notarization
    /// fact — at the round named by its own consensus context — is recorded
    /// alongside the body. It also proves the block canonical at its height,
    /// so any different block stored at the same height was forked out and
    /// is deleted. Bodies from validation requests carry neither proof (a
    /// stale validation of a forked-out block may arrive late) and must use
    /// [`Self::record_block`].
    fn record_fetched_block(&mut self, block: Arc<Block>) {
        let height = block.height();
        let digest = block.digest();
        let round = block.context().round;
        // Record before sweeping the siblings: the fetched block may be the
        // latest notarization itself, whose fact must survive the sweep of
        // bodiless facts.
        self.record_block(block);
        self.record_notarized(round, digest);
        self.delete_forked_out_siblings(height, digest);
    }

    /// Records the execution layer's canonical head, advancing the
    /// canonicalization cursor when the head sits on the canonical notarized
    /// path above the cursor.
    ///
    /// Anything else is ignored: the cursor must never name a block off the
    /// canonical path, and it only ever moves backwards through
    /// [`Self::sink_cursor`] or [`Self::advance_finalized`], which uphold
    /// that.
    fn record_execution_notarized(&mut self, height: Height, head: Digest) {
        if height <= self.notarized_cursor.0 || head == self.notarized_cursor.1 {
            return;
        }
        let Some((_, tip)) = self.notarized.last_key_value() else {
            return;
        };
        let mut digest = *tip;
        while digest != self.notarized_cursor.1 {
            if digest == head {
                self.notarized_cursor = (height, head);
                return;
            }
            let Some(entry) = self.blocks.get(&digest) else {
                return;
            };
            digest = entry.block.parent_digest();
        }
    }

    /// Deletes every block at or above `height` other than `canonical`,
    /// along with the facts of the deleted blocks.
    ///
    /// The caller proves that the block `canonical` at `height` is the
    /// latest notarization: everything else at or above that height was
    /// forked out (at most one block per height is ever on the canonical
    /// chain, and the newest notarization is on it).
    fn delete_forked_out(&mut self, height: Height, canonical: Digest) {
        self.sink_cursor(height, canonical);
        self.blocks
            .retain(|digest, entry| entry.block.height() < height || *digest == canonical);
        self.drop_orphaned_facts();
    }

    /// Deletes the blocks at exactly `height` other than `canonical`, along
    /// with their facts.
    ///
    /// The caller proves that the block `canonical` lies on the latest
    /// notarization's ancestry: its same-height siblings were forked out.
    /// Blocks above `height` are left alone — the ancestry continues above.
    fn delete_forked_out_siblings(&mut self, height: Height, canonical: Digest) {
        if self.notarized_cursor.0 == height {
            self.sink_cursor(height, canonical);
        }
        self.blocks
            .retain(|digest, entry| entry.block.height() != height || *digest == canonical);
        self.drop_orphaned_facts();
    }

    /// Sinks the canonicalization cursor below `height` ahead of deleting
    /// the forked-out blocks there.
    ///
    /// Each step moves the cursor to the parent of its current block — an
    /// ancestor of the execution layer's head, hence known to it. Repeated
    /// sinking converges on the fork point level by level as the forked-out
    /// blocks are discovered. If a body is missing the cursor stays put and
    /// forwarding stalls until the finalized tip catches up and resets it.
    fn sink_cursor(&mut self, height: Height, canonical: Digest) {
        while self.notarized_cursor.0 >= height && self.notarized_cursor.1 != canonical {
            let Some(entry) = self.blocks.get(&self.notarized_cursor.1) else {
                return;
            };
            let Some(parent_height) = entry.block.height().previous() else {
                return;
            };
            self.notarized_cursor = (parent_height, entry.block.parent_digest());
        }
    }

    /// Drops all facts whose block the directory does not hold.
    ///
    /// This may overprune facts whose body simply has not arrived yet, and
    /// that is fine: nothing is lost, because a fact is implied by any
    /// descendant's ancestry and the next context naming it records it
    /// again. The exception is the *latest* fact, which defines the
    /// canonical path; every deletion site guarantees its body is present
    /// by the time this sweep runs, so it always survives.
    fn drop_orphaned_facts(&mut self) {
        let blocks = &self.blocks;
        self.notarized
            .retain(|_, digest| blocks.contains_key(digest));
    }

    /// Marks the block as rejected by the execution layer, excluding it from
    /// forwarding until the entry is expunged or its body re-recorded.
    fn mark_rejected(&mut self, digest: &Digest) {
        if let Some(entry) = self.blocks.get_mut(digest) {
            entry.rejected = true;
        }
    }

    /// Removes a block from the directory.
    fn remove(&mut self, digest: &Digest) {
        self.blocks.remove(digest);
        self.notarized.retain(|_, notarized| notarized != digest);
    }

    /// Advances the finalized tip of the network and drops all data at or
    /// below its round and height, enforcing the ownership boundary with the
    /// finalization pipeline.
    ///
    /// Tips at or below the already tracked round (a tip replayed on
    /// startup) are ignored, so the boundary never regresses. The marshal
    /// actor guarantees that a newer round never finalizes a lower height.
    fn advance_finalized(&mut self, round: Round, height: Height, digest: Digest) {
        if round > self.finalized_tip.0 {
            self.finalized_tip = (round, height, digest);
            self.notarized.retain(|notarized, _| *notarized > round);
            self.blocks.retain(|_, entry| entry.block.height() > height);
            // The finalized tip overtook the canonicalization cursor; continue
            // forwarding from the tip. The execution layer only knows the tip
            // once the finalization pipeline has caught up, which the caller
            // must gate forwarding on.
            if self.notarized_cursor.0 <= height {
                self.notarized_cursor = (height, digest);
            }
        } else {
            debug!(
                %round,
                %height,
                %digest,
                "ignoring finalized tip that does not advance the tracked one",
            );
        }
    }

    /// Returns the next notarized block to forward to the execution layer,
    /// if any: the block directly above the canonicalization cursor on the
    /// canonical notarized path.
    ///
    /// Returns nothing when the path between the latest notarization and
    /// the cursor has a gap (the fetch machinery is repairing it, or the
    /// cursor is waiting to be re-rooted onto the path), when the cursor is
    /// at the latest notarization itself, or when the candidate was
    /// rejected by the execution layer (forwarding halts until the entry is
    /// expunged).
    fn next_to_forward(&self) -> Option<&BlockEntry> {
        let (_, tip) = self.notarized.last_key_value()?;
        let mut digest = *tip;
        let mut child: Option<&BlockEntry> = None;
        while digest != self.notarized_cursor.1 {
            let entry = self.blocks.get(&digest)?;
            child = Some(entry);
            digest = entry.block.parent_digest();
        }
        child.filter(|entry| !entry.rejected)
    }

    /// Returns the first missing ancestor on the latest notarization's path,
    /// together with the round it was notarized in.
    ///
    /// A notarization implies the notarization of all its ancestors up to
    /// the finalized tip, so a missing ancestor body must be fetched even if
    /// no explicit notarization fact was observed for it; its round is then
    /// derived from the consensus context of its child, which names the view
    /// the parent was constructed in. The walk stops at the network's
    /// finalized tip because it is never forwarded, so its body is not
    /// needed. This also covers the locally forwarded finalized tip, which
    /// never runs ahead of the network's.
    fn first_missing_ancestor(&self) -> Option<(Round, Digest)> {
        let (finalized_round, finalized_height, finalized_digest) = self.finalized_tip;
        let (latest_round, tip) = self.notarized.last_key_value()?;
        // The round of the latest notarization comes from its fact; further
        // down the path it is derived from the context of the child walked
        // through.
        let mut round = *latest_round;
        let mut digest = *tip;
        // The stop conditions are evaluated for every candidate digest
        // before it can be reported missing; otherwise the walk would
        // report the finalized tip itself (whose body is deliberately never
        // recorded) as a gap.
        while digest != finalized_digest && round > finalized_round {
            let Some(entry) = self.blocks.get(&digest) else {
                return Some((round, digest));
            };
            if entry.block.height() <= finalized_height {
                break;
            }
            let context = entry.block.context();
            round = Round::new(context.round.epoch(), context.parent.0);
            digest = entry.block.parent_digest();
        }
        None
    }
}

/// Tracks the latest forkchoice state accepted by the execution layer.
///
/// Also tracks the corresponding heights corresponding to
/// `forkchoice_state.head_block_hash` and
/// `forkchoice_state.finalized_block_hash`, respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LastCanonicalized {
    forkchoice: ForkchoiceState,
    head_height: Height,
    finalized_height: Height,
}

impl LastCanonicalized {
    /// Updates the finalized height and finalized block hash to `height` and `digest`.
    ///
    /// `height` must be ahead of the latest canonicalized finalized height. If
    /// it is not, then this is a no-op.
    ///
    /// Similarly, if `height` is ahead or the same as the latest canonicalized
    /// head height, it also updates the head height.
    ///
    /// This is to ensure that the finalized block hash is never ahead of the
    /// head hash.
    fn update_finalized(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized_height {
            this.finalized_height = height;
            this.forkchoice.safe_block_hash = digest.0;
            this.forkchoice.finalized_block_hash = digest.0;
        }
        if height >= this.head_height {
            this.head_height = height;
            this.forkchoice.head_block_hash = digest.0;
        }
        this
    }

    /// Updates the head height and head block hash to `height` and `digest`.
    ///
    /// If `height > self.finalized_height` or `digest` is the same as the finalized block hash,
    /// this method will return a new canonical state with `self.head_height = height` and
    /// `self.forkchoice.head = hash`.
    ///
    /// If `height <= self.finalized_height`, then this method will return
    /// `self` unchanged.
    fn update_head(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized_height || digest.0 == this.forkchoice.finalized_block_hash {
            this.head_height = height;
            this.forkchoice.head_block_hash = digest.0;
        }
        this
    }
}

pub(crate) struct Actor<TContext> {
    context: ContextCell<TContext>,

    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    execution_node: Arc<TempoFullNode>,

    /// Highest finalized height the executor should backfill to on startup so
    /// that CL and EL have a consistent view.
    finalized_floor: Height,

    /// The channel over which the agent will receive new commands from the
    /// application actor.
    mailbox: mpsc::UnboundedReceiver<Message>,

    /// The mailbox of the marshal actor. Used to backfill finalized blocks
    /// on startup and to fetch missing notarized block bodies.
    marshal: crate::alias::marshal::Mailbox,

    /// The latest state that the executor canonicalized. On startup, contains
    /// the latest execution layer state.
    last_canonicalized: LastCanonicalized,

    /// The interval at which to send a forkchoice update heartbeat to the
    /// execution layer.
    fcu_heartbeat_interval: Duration,

    /// The timer for the next FCU heartbeat.
    ///
    /// Armed only when no execution-layer work is active or queued.
    fcu_heartbeat_timer: OptionFuture<BoxFuture<'static, ()>>,

    /// Finalized blocks waiting to be forwarded to the execution layer.
    pending_finalizations: VecDeque<FinalizedBlockRequest>,

    /// The latest not-yet-started consensus request — validating a proposed
    /// block or building one — keyed by its round. The two kinds share one
    /// slot because a node either verifies or proposes in a round, never
    /// both. A request from a newer round supersedes a queued older one;
    /// requests at or below the queued round are dropped on arrival. Either
    /// way, dropping a request's response channel signals the failure to its
    /// subscriber.
    pending_consensus_request: Option<(Round, ConsensusRequest)>,

    /// The single execution-layer request currently being driven in the background.
    execution_task: OptionFuture<BoxFuture<'static, ExecutionTaskResult>>,

    /// The fetch of a notarized block body that is missing from the
    /// directory, driven concurrently with the execution task. At most one
    /// fetch runs at a time.
    pending_notarized_block: OptionFuture<PendingNotarizedBlock>,

    /// Payload build jobs currently being driven to completion.
    ///
    /// Each job resolves a payload from the execution layer's payload builder
    /// and delivers it to the subscriber that requested the build. If the
    /// subscriber dropped its receiver in the meantime, the built payload is
    /// discarded.
    payload_jobs: FuturesUnordered<BoxFuture<'static, ()>>,

    /// Tracks notarized blocks at the tip of the chain, bounded from below
    /// by the latest observed finalized tip of the network. That tip is
    /// never forwarded to the execution layer; the finalized watermark
    /// advances exclusively through delivered finalized blocks.
    notarized_facts_directory: NotarizedFactsDirectory,

    /// The node's ed25519 public key if the node is participating in
    /// consensus. Not set if not, for example for followers.
    public_key: Option<PublicKey>,

    metrics: Metrics,
}

#[derive(Clone)]
struct Metrics {
    /// Number of finalized blocks whose proposer matches this node's public key.
    finalized_blocks_proposed_by_self: commonware_runtime::telemetry::metrics::Registered<Counter>,
}

impl Metrics {
    fn init<TContext>(context: &TContext) -> Self
    where
        TContext: RuntimeMetrics,
    {
        let finalized_blocks_proposed_by_self = context.register(
            "finalized_blocks_proposed_by_self",
            "number of finalized blocks whose proposer matches this node's public key",
            Counter::default(),
        );
        Self {
            finalized_blocks_proposed_by_self,
        }
    }
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + RuntimeMetrics + Pacer + Spawner,
{
    pub(super) fn init(
        context: TContext,
        config: super::Config,
        mailbox: UnboundedReceiver<super::ingress::Message>,
    ) -> eyre::Result<Self> {
        let Config {
            execution_node,
            finalized_floor,
            finalized_tip,
            marshal,
            fcu_heartbeat_interval,
            public_key,
        } = config;
        let metrics = Metrics::init(&context);

        let canonical_state = execution_node.provider.canonical_in_memory_state();

        let head_num_hash: BlockNumHash = canonical_state.chain_info().into();
        let execution_finalized_num_hash = canonical_state
            .get_finalized_num_hash()
            .unwrap_or_else(|| BlockNumHash::new(0, execution_node.chain_spec().genesis_hash()));

        Ok(Self {
            context: ContextCell::new(context),
            execution_node,
            finalized_floor,
            mailbox,
            marshal,
            last_canonicalized: LastCanonicalized {
                forkchoice: ForkchoiceState {
                    head_block_hash: head_num_hash.hash,
                    safe_block_hash: execution_finalized_num_hash.hash,
                    finalized_block_hash: execution_finalized_num_hash.hash,
                },
                head_height: Height::new(head_num_hash.number),
                finalized_height: Height::new(execution_finalized_num_hash.number),
            },
            fcu_heartbeat_interval,
            fcu_heartbeat_timer: OptionFuture::none(),

            pending_finalizations: VecDeque::new(),
            pending_consensus_request: None,

            execution_task: OptionFuture::none(),
            pending_notarized_block: OptionFuture::none(),
            payload_jobs: FuturesUnordered::new(),

            notarized_facts_directory: NotarizedFactsDirectory::new(
                finalized_tip,
                (
                    Height::new(head_num_hash.number),
                    Digest(head_num_hash.hash),
                ),
            ),

            public_key,
            metrics,
        })
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        if let Err(error) = self.backfill_to_finalized_floor().await {
            error_span!("shutdown").in_scope(|| {
                error!(
                    %error,
                    "executor failed startup backfill",
                )
            });
            return;
        }

        info_span!("start").in_scope(|| {
            info!(
                finalized_height = %self.last_canonicalized.finalized_height,
                finalized_digest = %self.last_canonicalized.forkchoice.finalized_block_hash,
                head_height = %self.last_canonicalized.head_height,
                head_digest = %self.last_canonicalized.forkchoice.head_block_hash,
                "entering executor loop",
            );
        });

        loop {
            self.start_next_execution_task();
            self.update_notarized_block_fetch();
            self.update_fcu_heartbeat_timer();

            select! {
                biased;

                task_result = &mut self.execution_task => {
                    match task_result {
                        ExecutionTaskResult::Completed { canonicalized, payload_job } => {
                            if let Some(canonicalized) = canonicalized {
                                // There is only one execution task running at
                                // a time, and `last_canonicalized` is only
                                // mutated here to keep a consistent view.
                                self.last_canonicalized = canonicalized;
                                // Feed head movements to the directory so
                                // its canonicalization cursor tracks heads
                                // set by builds and finalizations, not just
                                // by notarized-block forwarding.
                                self.notarized_facts_directory.record_execution_notarized(
                                    canonicalized.head_height,
                                    Digest(canonicalized.forkchoice.head_block_hash),
                                );
                            }
                            if let Some(job) = payload_job {
                                self.payload_jobs.push(
                                    run_payload_job(
                                        self.context.child("payload_job"),
                                        self.execution_node.clone(),
                                        job,
                                    )
                                    .boxed(),
                                );
                            }
                        }
                        ExecutionTaskResult::NotarizedBlockRejected { digest } => {
                            // The cause is logged by the task itself. The
                            // marker keeps the block from being retried in
                            // a tight loop; the finalization pipeline
                            // remains the fatal-on-failure backstop.
                            self.notarized_facts_directory.mark_rejected(&digest);
                        }
                        ExecutionTaskResult::Fatal { error } => {
                            error_span!("shutdown").in_scope(|| error!(
                                %error,
                                "executor encountered fatal execution-layer update error; \
                                shutting down to prevent consensus-execution divergence"
                            ));
                            break;
                        }
                    }
                }

                Some(()) = self.payload_jobs.next() => {}

                (digest, round, block) = &mut self.pending_notarized_block => {
                    self.handle_fetched_notarized_block(digest, round, block);
                }

                msg = self.mailbox.next() => {
                    let Some(msg) = msg else { break; };
                    if let Err(error) = self.handle_message(msg) {
                        error_span!("shutdown").in_scope(|| error!(
                            %error,
                            "executor failed handling message; \
                            shutting down to prevent consensus-execution divergence"
                        ));
                        break;
                    }
                },

                _ = (&mut self.fcu_heartbeat_timer).fuse() => {
                    self.send_forkchoice_update_heartbeat();
                },
            }
        }
    }

    async fn backfill_to_finalized_floor(&mut self) -> eyre::Result<()> {
        let start = self.last_canonicalized.finalized_height.get() + 1;
        let end = self.finalized_floor.get();
        let heights = start..=end;
        if !heights.is_empty() {
            info!(
                start = *heights.start(),
                end = *heights.end(),
                "backfilling finalized blocks before entering executor loop"
            );
        }
        for height in heights {
            let span = info_span!("backfill_on_start", %height);
            let block = get_block(
                self.marshal.clone(),
                self.execution_node.clone(),
                Height::new(height),
            )
            .await
            .wrap_err_with(|| format!("failed backfilling block for height `{height}`"))?;

            let (ack, _wait) = Exact::handle();
            let request = FinalizedBlockRequest {
                cause: span,
                block: Arc::new(block),
                acknowledgment: ack,
            };

            if let Some(canonicalized) = forward_finalized(
                self.context.as_present(),
                self.execution_node.clone(),
                self.public_key.clone(),
                self.metrics.clone(),
                self.last_canonicalized,
                request,
            )
            .await
            .wrap_err_with(|| {
                format!(
                    "failed forwarding backfilled finalized block at height `{height}` \
                    to execution layer"
                )
            })? {
                self.last_canonicalized = canonicalized;
            }
        }

        Ok(())
    }

    fn arm_fcu_heartbeat_timer(&mut self) {
        if !self.fcu_heartbeat_timer.is_none() {
            return;
        }
        self.fcu_heartbeat_timer
            .replace(self.context.sleep(self.fcu_heartbeat_interval).boxed());
    }

    fn disarm_fcu_heartbeat_timer(&mut self) {
        self.fcu_heartbeat_timer = OptionFuture::none();
    }

    fn update_fcu_heartbeat_timer(&mut self) {
        if self.execution_task.is_none()
            && self.pending_finalizations.is_empty()
            && self.pending_consensus_request.is_none()
        {
            self.arm_fcu_heartbeat_timer();
        } else {
            self.disarm_fcu_heartbeat_timer();
        }
    }

    #[instrument(skip_all)]
    fn send_forkchoice_update_heartbeat(&mut self) {
        // The heartbeat timer is only armed while no other execution-layer
        // work is active or queued.
        if !self.execution_task.is_none() {
            return;
        }
        let task = execute_heartbeat(
            self.context.child("heartbeat"),
            self.execution_node.clone(),
            self.last_canonicalized,
            Span::current(),
        );
        self.execution_task.replace(task.boxed());
    }

    fn handle_message(&mut self, message: Message) -> eyre::Result<()> {
        let cause = message.cause;
        match message.command {
            Command::CanonicalizeAndBuild(CanonicalizeAndBuild {
                round,
                height,
                digest,
                attributes,
                response,
            }) => {
                queue_consensus_request(
                    &mut self.pending_consensus_request,
                    round,
                    ConsensusRequest::Build(Box::new(Canonicalize {
                        cause,
                        height,
                        digest,
                        build_attributes: Some((*attributes, response)),
                    })),
                );
            }
            Command::Finalize(finalized) => match *finalized {
                Update::Tip(round, height, digest) => {
                    // A now-stale in-flight body fetch is dropped by
                    // `update_notarized_block_fetch` on the next loop
                    // iteration.
                    self.notarized_facts_directory
                        .advance_finalized(round, height, digest);
                }
                Update::Block(block, acknowledgement) => {
                    self.pending_finalizations.push_back(FinalizedBlockRequest {
                        cause,
                        block,
                        acknowledgment: acknowledgement,
                    });
                }
            },
            Command::ParentNotarized(notarized) => {
                self.record_notarized_parent(notarized.context);
            }
            Command::ValidateBlock(request) => {
                let ValidateBlock {
                    round,
                    block,
                    validator_set,
                    response,
                } = *request;
                // Keep the block body around even if this request is aborted:
                // once the block is notarized, the directory needs the body to
                // forward it to the execution layer.
                self.notarized_facts_directory.record_block(block.clone());
                queue_consensus_request(
                    &mut self.pending_consensus_request,
                    round,
                    ConsensusRequest::Validate(ValidateBlockRequest {
                        cause,
                        block,
                        validator_set,
                        response,
                    }),
                );
            }
        }
        Ok(())
    }

    /// Records the context's parent as notarized.
    fn record_notarized_parent(&mut self, context: Context<Digest, PublicKey>) {
        self.notarized_facts_directory.record_notarized(
            Round::new(context.round.epoch(), context.parent.0),
            context.parent.1,
        );
    }

    /// Keeps the fetch of missing notarized block bodies pointed at the
    /// first gap on the latest notarization's ancestor path.
    ///
    /// A missing body prevents the reconstructed notarized chain from
    /// linking up with the finalized tip, stalling the convergence of the
    /// execution layer on the notarized tip until finalization catches up;
    /// fetching it lets convergence proceed. The fetch runs concurrently
    /// with the execution task so that a slow fetch never delays validations
    /// or builds.
    fn update_notarized_block_fetch(&mut self) {
        // `first_missing_ancestor` bounds its walk by the network's
        // finalized tip alone, which is only correct while the locally
        // forwarded finalized tip does not run ahead of it. The marshal
        // actor upholds this: it reports a finalized tip before delivering
        // the finalized blocks covered by it.
        debug_assert!(
            self.last_canonicalized.finalized_height
                <= self.notarized_facts_directory.finalized_tip.1,
            "the locally forwarded finalized tip must never run ahead of the \
            observed finalized tip of the network",
        );
        let next = self.notarized_facts_directory.first_missing_ancestor();

        // Drop an in-flight fetch that is no longer needed because its
        // digest was finalized or forked out: nobody is required to serve a
        // forked-out block, so the fetch might never resolve and would wedge
        // the fetch slot.
        if let Some(pending) = self.pending_notarized_block.as_ref()
            && next.map(|(_, digest)| digest) != Some(pending.digest)
        {
            self.pending_notarized_block = OptionFuture::none();
        }

        if !self.pending_notarized_block.is_none() {
            return;
        }
        let Some((round, digest)) = next else {
            return;
        };
        info!(
            %round,
            %digest,
            "body of notarized block is missing; fetching it from the marshal actor",
        );
        self.pending_notarized_block
            .replace(PendingNotarizedBlock::new(
                self.marshal.clone(),
                round,
                digest,
            ));
    }

    /// Records a fetched notarized block body in the directory.
    #[instrument(skip_all, fields(%digest, %round))]
    fn handle_fetched_notarized_block(
        &mut self,
        digest: Digest,
        round: Round,
        block: Option<Arc<Block>>,
    ) {
        match block {
            Some(fetched) => {
                self.notarized_facts_directory.record_fetched_block(fetched);
            }
            None => {
                // The block is still needed — it lies on the canonical
                // notarized ancestry — so the directory is left untouched
                // and the fetch is re-scheduled on the next loop iteration.
                warn!(
                    "marshal dropped the channel before the notarized block \
                    was delivered; the fetch will be retried",
                );
            }
        }
    }

    /// The next notarized block to forward, gated on the local finalized
    /// state having caught up with the observed finalized tip of the
    /// network: the directory's canonicalization cursor may name the network
    /// tip before the execution layer knows it (see
    /// [`NotarizedFactsDirectory::advance_finalized`]).
    fn next_notarized_forward(&self) -> Option<&BlockEntry> {
        (self.last_canonicalized.finalized_height >= self.notarized_facts_directory.finalized_tip.1)
            .then(|| self.notarized_facts_directory.next_to_forward())
            .flatten()
    }

    fn start_next_execution_task(&mut self) {
        if !self.execution_task.is_none() {
            return;
        }

        // Latency critical requests come first: consensus is waiting on
        // them to vote on or propose a block. One exception: if the next
        // notarized block to forward is a validated block's parent, the
        // validation is put back and falls through to the forwarding below,
        // after which it can pass. Any deeper gap fails the validation fast
        // and heals in the background instead.
        match self.pending_consensus_request.take() {
            Some((round, ConsensusRequest::Validate(request))) => {
                let parent_is_next_notarized = self
                    .next_notarized_forward()
                    .is_some_and(|entry| entry.block.digest() == request.block.parent_digest());
                if !parent_is_next_notarized {
                    let task = execute_validation(
                        self.context.child("validate"),
                        self.execution_node.clone(),
                        request,
                    );
                    self.execution_task.replace(task.boxed());
                    return;
                }
                self.pending_consensus_request = Some((round, ConsensusRequest::Validate(request)));
            }
            Some((_, ConsensusRequest::Build(request))) => {
                let task = execute_canonicalize(
                    self.context.child("canonicalize_and_build"),
                    self.execution_node.clone(),
                    self.last_canonicalized,
                    request,
                );
                self.execution_task.replace(task.boxed());
                return;
            }
            None => {}
        }

        // Drive the execution layer's head towards the tip of the
        // canonical notarized chain.
        if let Some(entry) = self.next_notarized_forward() {
            let task = execute_notarization(
                self.context.child("notarize"),
                self.execution_node.clone(),
                self.last_canonicalized,
                entry.block.clone(),
                None,
            );
            self.execution_task.replace(task.boxed());
            return;
        }

        // Finalizations are forwarded in order and acknowledged so that the
        // marshal actor can make progress.
        if let Some(request) = self.pending_finalizations.pop_front() {
            let task = execute_finalization(
                self.context.child("finalize"),
                self.execution_node.clone(),
                self.public_key.clone(),
                self.metrics.clone(),
                self.last_canonicalized,
                request,
            );
            self.execution_task.replace(task.boxed());
        }
    }
}

#[instrument(skip_all, fields(height), err)]
async fn get_block(
    marshal: crate::alias::marshal::Mailbox,
    execution_node: Arc<TempoFullNode>,
    height: Height,
) -> eyre::Result<Block> {
    if let Some(block) = marshal.get_block(height).await {
        return Ok(block);
    }

    warn!(
        "marshal did not have backfill block; looking up its finalized digest \
        to look for it in the execution layer"
    );
    let Some((_, digest)) = marshal.get_info(height).await else {
        bail!("marshal actor did not have finalization info at height");
    };

    info!(
        %digest,
        "found finalized digest for block height; checking execution layer",
    );
    let Some(block) = execution_node
        .provider
        .find_sealed_or_recovered_block(digest.0, BlockSource::Any)
        .wrap_err_with(|| {
            format!("failed querying execution layer for backfill block `{digest}`")
        })?
    else {
        warn!(%digest, "execution layer did not have missing backfill block");
        bail!(
            "marshal actor did not have block at height `{height}` and \
            execution layer did not have block `{digest}`"
        );
    };

    Ok(Block::from_execution_block_unchecked(block, None))
}

struct FinalizedBlockRequest {
    cause: Span,
    block: Arc<Block>,
    acknowledgment: Exact,
}

/// An in-flight fetch of a notarized block body that is missing from the
/// directory, keyed by the digest being fetched and the round it was
/// notarized in.
///
/// Resolves to the digest, the round, and the fetched block — `None` for the
/// block if the marshal actor dropped the channel before delivering it.
struct PendingNotarizedBlock {
    digest: Digest,
    round: Round,
    fetch: tokio::sync::oneshot::Receiver<Arc<Block>>,
}

impl PendingNotarizedBlock {
    fn new(marshal: crate::alias::marshal::Mailbox, round: Round, digest: Digest) -> Self {
        let fetch = marshal.subscribe_by_digest(
            digest,
            commonware_consensus::marshal::core::DigestFallback::FetchByRound { round },
        );
        Self {
            digest,
            round,
            fetch,
        }
    }
}

impl Future for PendingNotarizedBlock {
    type Output = (Digest, Round, Option<Arc<Block>>);

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let block = std::task::ready!(self.fetch.poll_unpin(cx));
        std::task::Poll::Ready((self.digest, self.round, block.ok()))
    }
}

/// A latency-critical request from a consensus round: the node is either
/// asked to validate the round's proposal or to build it.
enum ConsensusRequest {
    Validate(ValidateBlockRequest),
    Build(Box<Canonicalize>),
}

/// Queues `request` into `slot` unless the slot already holds a request from
/// the same or a newer round.
///
/// Propose and verify are mutually exclusive within a round, but the
/// application's handlers run concurrently, so a request sent by a dying
/// older-round task can arrive after a newer one; the round guard keeps it
/// from clobbering the newer request. Dropping a request — superseded or
/// stale — drops its response channel, signalling the failure to the
/// subscriber.
fn queue_consensus_request(
    slot: &mut Option<(Round, ConsensusRequest)>,
    round: Round,
    request: ConsensusRequest,
) {
    match slot {
        Some((queued, _)) if round <= *queued => {
            debug!(
                %round,
                queued_round = %queued,
                "dropping consensus request at or below the queued round",
            );
        }
        Some(_) => {
            debug!(%round, "consensus request superseded a queued one");
            *slot = Some((round, request));
        }
        None => *slot = Some((round, request)),
    }
}

/// A request to validate a block against the execution layer via a
/// new-payload request.
struct ValidateBlockRequest {
    cause: Span,
    block: Arc<Block>,
    validator_set: Option<Vec<B256>>,
    /// Delivers the validation result: `Some(duration)` when the execution
    /// layer accepted the block, `None` when it rejected it. Dropped without
    /// a value when validation was not possible or the request was
    /// superseded.
    response: oneshot::Sender<Option<Duration>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForkchoiceUpdateKind {
    Heartbeat,
    Canonicalize { head_or_finalized: HeadOrFinalized },
}

enum ExecutionTaskResult {
    Completed {
        canonicalized: Option<LastCanonicalized>,
        /// A payload build that the forkchoice update kicked off on the
        /// execution layer and that still needs to be driven to completion.
        payload_job: Option<StartPayloadJob>,
    },
    /// A notarized block could not be forwarded for a reason that carries no
    /// evidence of consensus-execution divergence, for example because the
    /// execution layer was unreachable or reported that it was still syncing.
    /// The block should be marked rejected in the directory so that it is
    /// withheld from forwarding instead of being retried in a tight loop;
    /// the finalization pipeline retries it with fatal-on-failure semantics.
    /// An outright *invalid* verdict by the execution layer is
    /// [`ExecutionTaskResult::Fatal`] right away: a quorum of validators
    /// accepted the block, so rejecting it means we diverged.
    NotarizedBlockRejected {
        digest: Digest,
    },
    Fatal {
        error: Report,
    },
}

/// A request to make `digest` the head of the canonical chain, optionally
/// registering a payload build on top of it.
///
/// The head update may outlive the build it was requested for (the Engine
/// API only registers builds via forkchoice updates, so the two cannot be
/// separated). That is safe: builds only ever target a notarized parent, so
/// a leftover head is a valid — at worst stale — notarized-chain state, and
/// the notarized block directory converges the head onwards from any
/// position. Validations are unaffected either way: a new-payload request
/// does not depend on where the head points.
struct Canonicalize {
    cause: Span,
    height: Height,
    digest: Digest,
    /// Payload attributes to register a build job with the forkchoice
    /// update, paired with the subscriber awaiting the built payload.
    build_attributes: Option<(TempoPayloadAttributes, oneshot::Sender<TempoBuiltPayload>)>,
}

/// A payload build registered on the execution layer whose result still needs
/// to be delivered to the subscriber that requested it.
struct StartPayloadJob {
    cause: Span,
    payload_id: PayloadId,
    response: oneshot::Sender<TempoBuiltPayload>,
}

async fn execute_heartbeat<TContext>(
    context: TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LastCanonicalized,
    cause: Span,
) -> ExecutionTaskResult
where
    TContext: Pacer,
{
    if let Err(error) = submit_forkchoice_update(
        &execution_node,
        &context,
        cause,
        canonicalized,
        None,
        ForkchoiceUpdateKind::Heartbeat,
    )
    .await
    {
        warn!(%error, "forkchoice update heartbeat failed");
    }
    ExecutionTaskResult::Completed {
        canonicalized: None,
        payload_job: None,
    }
}

async fn execute_canonicalize<TContext>(
    context: TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LastCanonicalized,
    request: Box<Canonicalize>,
) -> ExecutionTaskResult
where
    TContext: Pacer,
{
    let (canonicalized, payload_job) =
        run_canonicalize_task(&context, execution_node, canonicalized, *request).await;
    ExecutionTaskResult::Completed {
        canonicalized,
        payload_job,
    }
}

async fn execute_finalization<TContext>(
    context: TContext,
    execution_node: Arc<TempoFullNode>,
    public_key: Option<PublicKey>,
    metrics: Metrics,
    canonicalized: LastCanonicalized,
    request: FinalizedBlockRequest,
) -> ExecutionTaskResult
where
    TContext: Pacer,
{
    match forward_finalized(
        &context,
        execution_node,
        public_key,
        metrics,
        canonicalized,
        request,
    )
    .await
    {
        Ok(canonicalized) => ExecutionTaskResult::Completed {
            canonicalized,
            payload_job: None,
        },
        Err(error) => ExecutionTaskResult::Fatal { error },
    }
}

async fn execute_notarization<TContext>(
    context: TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LastCanonicalized,
    block: Arc<Block>,
    validator_set: Option<Vec<B256>>,
) -> ExecutionTaskResult
where
    TContext: Pacer,
{
    let digest = block.digest();
    match forward_notarized(
        &context,
        execution_node,
        canonicalized,
        block,
        validator_set,
    )
    .await
    {
        Ok(canonicalized) => ExecutionTaskResult::Completed {
            canonicalized,
            payload_job: None,
        },
        // A notarized block carries the votes of a quorum of validators, of
        // which at least f+1 honest ones validated it against their execution
        // layers before voting. Our execution layer rejecting it as invalid
        // means it has diverged from the network, whether or not the block
        // ever finalizes.
        Err(error) if error.is::<NotarizedBlockInvalid>() => ExecutionTaskResult::Fatal {
            error: error.wrap_err("execution layer rejected a notarized block"),
        },
        // Everything else (the execution layer being unreachable or still
        // syncing) carries no evidence of divergence. The cause is logged by
        // `forward_notarized`.
        Err(_logged) => ExecutionTaskResult::NotarizedBlockRejected { digest },
    }
}

/// Drives a validation request against the execution layer via a single
/// new-payload request.
///
/// The request deliberately does not repair gaps: if the execution layer does
/// not know the block's parent, validation fails (dropping the response
/// channel signals this to the subscriber) and the executor converges the
/// execution layer on the notarized chain in the background instead of on
/// this latency-critical path.
///
/// The subscriber dropping its receiver (because consensus aborted the view)
/// abandons the request; the notarized block directory retains the block body
/// recorded from the request, so the execution layer still converges on the
/// notarized tip afterwards. Validation errors are not fatal for the executor
/// because consensus treats a failed verification as a rejected proposal.
#[instrument(
    skip_all,
    parent = &request.cause,
    fields(
        block.digest = %request.block.digest(),
        block.height = %request.block.height(),
        block.parent_digest = %request.block.parent_digest(),
    ),
)]
async fn execute_validation<TContext>(
    context: TContext,
    execution_node: Arc<TempoFullNode>,
    request: ValidateBlockRequest,
) -> ExecutionTaskResult
where
    TContext: Pacer,
{
    let ValidateBlockRequest {
        cause: _,
        block,
        validator_set,
        mut response,
    } = request;

    let work = validate_block(&context, &execution_node, block, validator_set);
    futures::pin_mut!(work);

    let result = select! {
        biased;

        res = &mut work => res,

        // Stops waiting for the verdict; the execution layer may still
        // process the new-payload request. The notarized block directory
        // keeps driving the execution layer independently of this request's
        // lifetime.
        () = response.cancellation() => {
            info!(
                "verification subscriber went away before the block was \
                validated; abandoning the request"
            );
            return ExecutionTaskResult::Completed {
                canonicalized: None,
                payload_job: None,
            };
        }
    };

    match result {
        Ok(verdict) => {
            if response.send(verdict).is_err() {
                info!(
                    "verification subscriber went away before the validation \
                    result could be delivered"
                );
            }
        }
        Err(error) => {
            // Dropping the response channel signals the failure to the
            // subscriber; the cause is only logged here.
            warn!(%error, "failed validating block");
        }
    }
    ExecutionTaskResult::Completed {
        canonicalized: None,
        payload_job: None,
    }
}

/// Validates `block` against the execution layer via a new-payload request.
///
/// Returns the validation duration when the block is valid, `None` when the
/// execution layer rejected it, and an error when validation was not
/// possible.
async fn validate_block<TContext>(
    context: &TContext,
    execution_node: &Arc<TempoFullNode>,
    block: Arc<Block>,
    validator_set: Option<Vec<B256>>,
) -> eyre::Result<Option<Duration>>
where
    TContext: Pacer,
{
    use alloy_rpc_types_engine::PayloadStatusEnum;

    let (block, block_access_list) = Arc::unwrap_or_clone(block).into_parts();
    let validation_start = Instant::now();
    let payload_status = execution_node
        .add_ons_handle
        .beacon_engine_handle
        .new_payload(TempoExecutionData {
            block,
            block_access_list,
            validator_set,
        })
        .pace(context, Duration::from_millis(20))
        .await
        .wrap_err("failed sending new-payload request to execution layer to validate block")?;
    match payload_status.status {
        PayloadStatusEnum::Valid => Ok(Some(validation_start.elapsed())),
        PayloadStatusEnum::Invalid { validation_error } => {
            info!(
                validation_error,
                "execution layer returned that the block was invalid"
            );
            Ok(None)
        }
        PayloadStatusEnum::Accepted => {
            bail!(
                "failed validating block because payload was accepted, meaning \
                that it was not actually executed by the execution layer for \
                some reason"
            )
        }
        PayloadStatusEnum::Syncing => {
            bail!(
                "failed validating block because the execution layer reports \
                syncing: it does not know the block's parent; the notarized \
                chain convergence will repair the gap in the background"
            )
        }
    }
}

#[instrument(
    skip_all,
    parent = &cause,
    fields(
        %height,
        %digest,
    ),
)]
async fn run_canonicalize_task<TContext: Pacer>(
    context: &TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LastCanonicalized,
    Canonicalize {
        cause,
        height,
        digest,
        mut build_attributes,
    }: Canonicalize,
) -> (Option<LastCanonicalized>, Option<StartPayloadJob>) {
    let new_canonicalized = canonicalized.update_head(height, digest);

    if build_attributes
        .as_ref()
        .is_some_and(|(_, response)| response.is_canceled())
    {
        info!("dropping payload build request: the subscriber went away while it was queued");
        build_attributes.take();
    }

    // Only build on top of the most recent head. If the requested parent
    // could not be made the head (because a block above it was already
    // finalized), the build is stale, and submitting its attributes anyway
    // would register a build on top of the wrong block. Taking the
    // attributes drops the response channel, which signals the failure to
    // the subscriber.
    if build_attributes.is_some() && new_canonicalized.forkchoice.head_block_hash != digest.0 {
        info!("dropping payload build request: its parent cannot be made the head");
        build_attributes.take();
    }

    let (attributes, payload_response) = build_attributes.unzip();

    // The forkchoice update is submitted even if it would not change the
    // forkchoice state: the execution layer treats it as a no-op (the FCU
    // heartbeat relies on this).
    match submit_forkchoice_update(
        &execution_node,
        context,
        cause.clone(),
        new_canonicalized,
        attributes,
        ForkchoiceUpdateKind::Canonicalize {
            head_or_finalized: HeadOrFinalized::Head,
        },
    )
    .await
    {
        Ok(payload_id) => {
            let payload_job = match (payload_response, payload_id) {
                (Some(response), Some(payload_id)) => Some(StartPayloadJob {
                    cause,
                    payload_id,
                    response,
                }),
                (Some(_dropped_to_signal_failure), None) => {
                    warn!("execution layer did not return a payload id for the build request");
                    None
                }
                (None, _) => None,
            };
            (Some(new_canonicalized), payload_job)
        }
        Err(error) => {
            // Dropping the response channels signals the failure to the
            // subscribers; the cause is only logged here.
            warn!(%error, "forkchoice update failed");
            (None, None)
        }
    }
}

/// Drives a payload build on the execution layer to completion.
///
/// Resolves the payload registered under `payload_id` from the execution
/// layer's payload builder and delivers it on `response`. If the subscriber
/// goes away before the payload is resolved (for example because the
/// consensus engine cancelled the proposal request that triggered the
/// build), the in-flight resolve future is dropped, which deregisters the
/// build job from the payload builder and aborts the build.
#[instrument(
    skip_all,
    parent = &cause,
    fields(%payload_id),
)]
async fn run_payload_job<TContext: Pacer>(
    context: TContext,
    execution_node: Arc<TempoFullNode>,
    StartPayloadJob {
        cause,
        payload_id,
        mut response,
    }: StartPayloadJob,
) {
    let payload = select! {
        payload = execution_node
            .payload_builder_handle
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .pace(&context, Duration::from_millis(20))
        => payload,

        // Drops the in-flight payload-resolution, killing payload build.
        () = response.cancellation() => {
            info!("payload subscriber went away before the payload was resolved; killing the payload build");
            return;
        }
    };

    // In the failure branches, dropping the response channel signals the
    // failure to the subscriber; the cause is only logged here.
    match payload {
        Some(Ok(payload)) => {
            if response.send(payload).is_err() {
                info!(
                    "payload subscriber went away before the payload could be delivered; discarding it"
                );
            }
        }
        Some(Err(error)) => {
            warn!(
                error = %eyre::Report::new(error),
                "payload build job failed",
            );
        }
        None => {
            warn!("no payload build job found under the payload ID");
        }
    }
}

#[instrument(
    skip_all,
    parent = &cause,
    fields(
        head_block_hash = %canonicalized.forkchoice.head_block_hash,
        head_block_height = %canonicalized.head_height,
        finalized_block_hash = %canonicalized.forkchoice.finalized_block_hash,
        finalized_block_height = %canonicalized.finalized_height,
        ?kind,
    ),
)]
async fn submit_forkchoice_update<TContext: Pacer>(
    execution_node: &TempoFullNode,
    context: &TContext,
    cause: Span,
    canonicalized: LastCanonicalized,
    attrs: Option<TempoPayloadAttributes>,
    kind: ForkchoiceUpdateKind,
) -> eyre::Result<Option<PayloadId>> {
    let fcu_response = execution_node
        .add_ons_handle
        .beacon_engine_handle
        .fork_choice_updated(canonicalized.forkchoice, attrs)
        .pace(context, Duration::from_millis(20))
        .await
        .wrap_err("failed requesting execution layer to update forkchoice state")?;

    if kind == ForkchoiceUpdateKind::Heartbeat {
        if fcu_response.is_invalid() {
            warn!(
                payload_status = %fcu_response.payload_status,
                "execution layer reported FCU status",
            );
        } else {
            info!(
                payload_status = %fcu_response.payload_status,
                "execution layer reported FCU status",
            );
        }
    } else {
        debug!(
            payload_status = %fcu_response.payload_status,
            "execution layer reported FCU status",
        );
    }

    if fcu_response.is_invalid() {
        return Err(Report::msg(fcu_response.payload_status)
            .wrap_err("execution layer responded with error for forkchoice-update"));
    }

    Ok(fcu_response.payload_id)
}

#[instrument(
    skip_all,
    parent = &request.cause,
    fields(
        block.digest = %request.block.digest(),
        block.height = %request.block.height(),
    ),
    err(level = Level::WARN),
    ret,
)]
async fn forward_finalized<TContext: Pacer>(
    context: &TContext,
    execution_node: Arc<TempoFullNode>,
    public_key: Option<PublicKey>,
    metrics: Metrics,
    canonicalized: LastCanonicalized,
    request: FinalizedBlockRequest,
) -> eyre::Result<Option<LastCanonicalized>> {
    let FinalizedBlockRequest {
        cause,
        block,
        acknowledgment,
    } = request;

    // The finalized watermark reported by the execution layer is taken as
    // gospel: a finalized block at or below the watermark is never forwarded
    // (for example when consensus replays finalized blocks after restoring
    // from a snapshot whose anchor is behind the execution state), because
    // the new-payload + forkchoice-update combination would move the
    // execution layer's forkchoice backwards and trigger a reorg. Instead,
    // such a block must already be part of the execution layer's canonical
    // chain, in which case it is acknowledged and dropped.
    //
    // The watermark must be read from the provider rather than from the
    // tracked `canonicalized` state: forkchoice updates for finalized tips
    // are accepted even when the execution layer reports SYNCING, so the
    // tracked state can run ahead of what the execution layer has actually
    // persisted while it is still pipeline-syncing toward the finalized tip.
    //
    // TODO: replace this by checking the last canonicalized height once all
    // sync is forced through marshal and pipeline syncing is disabled.
    let execution_finalized = execution_node
        .provider
        .finalized_block_num_hash()
        .wrap_err("failed reading finalized block num hash from execution layer")?
        .unwrap_or_else(|| BlockNumHash::new(0, execution_node.chain_spec().genesis_hash()));

    let consensus_context = block.header().consensus_context;
    let new_canonicalized = if block.height().get() <= execution_finalized.number {
        let canonical_hash = execution_node
            .provider
            .block_hash(block.height().get())
            .wrap_err_with(|| {
                format!(
                    "failed reading canonical execution block hash at finalized \
                    block height `{}`",
                    block.height(),
                )
            })?;
        ensure!(
            canonical_hash == Some(block.digest().0),
            "finalized block with digest `{}` at height `{}` is at or below the \
            execution layer's finalized block `{}` at height `{}`, but does not \
            match the execution layer's canonical chain (canonical hash: `{:?}`)",
            block.digest(),
            block.height(),
            execution_finalized.hash,
            execution_finalized.number,
            canonical_hash,
        );
        info!(
            execution_finalized_height = execution_finalized.number,
            execution_finalized_hash = %execution_finalized.hash,
            "finalized block is already part of the execution layer's canonical \
            chain; acknowledging without forwarding",
        );
        None
    } else {
        // Rebase the tracked forkchoice state onto the watermark the execution
        // layer reported before extending it with the new block, so that the
        // forkchoice update below always finalizes the block.
        let new_canonicalized = LastCanonicalized {
            forkchoice: ForkchoiceState {
                safe_block_hash: execution_finalized.hash,
                finalized_block_hash: execution_finalized.hash,
                ..canonicalized.forkchoice
            },
            head_height: canonicalized.head_height,
            finalized_height: Height::new(execution_finalized.number),
        }
        .update_finalized(block.height(), block.digest());

        let (block, block_access_list) = Arc::unwrap_or_clone(block).into_parts();
        let payload_status = execution_node
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(TempoExecutionData {
                block,
                block_access_list,
                // can be omitted for finalized blocks
                validator_set: None,
            })
            .pace(context, Duration::from_millis(20))
            .await
            .wrap_err(
                "failed sending new-payload request to execution engine to \
                    query payload status of finalized block",
            )?;

        ensure!(
            payload_status.is_valid() || payload_status.is_syncing(),
            "this is a problem: payload status of block-to-be-finalized was \
                neither valid nor syncing: `{payload_status}`"
        );

        submit_forkchoice_update(
            &execution_node,
            context,
            cause.clone(),
            new_canonicalized,
            None,
            ForkchoiceUpdateKind::Canonicalize {
                head_or_finalized: HeadOrFinalized::Finalized,
            },
        )
        .await?;

        Some(new_canonicalized)
    };

    if let Some(public_key) = public_key.as_ref()
        && consensus_context.is_some_and(|context| context.proposer.to_inner() == *public_key)
    {
        metrics.finalized_blocks_proposed_by_self.inc();
    }

    acknowledgment.acknowledge();

    Ok(new_canonicalized)
}

/// Sentinel error signalling that the execution layer executed a notarized
/// block and rejected it as invalid, as opposed to being unable to process
/// it at all.
#[derive(Debug)]
struct NotarizedBlockInvalid {
    digest: Digest,
    height: Height,
    status: alloy_rpc_types_engine::PayloadStatus,
}

impl std::fmt::Display for NotarizedBlockInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "payload status of notarized block `{}` at height `{}` was invalid: `{}`",
            self.digest, self.height, self.status,
        )
    }
}

impl std::error::Error for NotarizedBlockInvalid {}

/// Forwards a notarized block to the execution layer and makes it the head of
/// the canonical chain.
///
/// The caller is responsible for only forwarding blocks that link to the
/// canonicalized state, so the new-payload request must come back valid;
/// anything else is an error. An outright rejection is reported as
/// [`NotarizedBlockInvalid`] so that the caller can distinguish divergence
/// from the execution layer being unable to process the block.
#[instrument(
    skip_all,
    fields(
        block.digest = %block.digest(),
        block.height = %block.height(),
    ),
    err(level = Level::WARN),
)]
async fn forward_notarized<TContext: Pacer>(
    context: &TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LastCanonicalized,
    block: Arc<Block>,
    validator_set: Option<Vec<B256>>,
) -> eyre::Result<Option<LastCanonicalized>> {
    let height = block.height();
    let digest = block.digest();

    let (block, block_access_list) = Arc::unwrap_or_clone(block).into_parts();
    let payload_status = execution_node
        .add_ons_handle
        .beacon_engine_handle
        .new_payload(TempoExecutionData {
            block,
            block_access_list,
            validator_set,
        })
        .pace(context, Duration::from_millis(20))
        .await
        .wrap_err(
            "failed sending new-payload request to execution engine to \
            forward notarized block",
        )?;
    if payload_status.is_invalid() {
        return Err(Report::new(NotarizedBlockInvalid {
            digest,
            height,
            status: payload_status,
        }));
    }
    ensure!(
        payload_status.is_valid(),
        "payload status of notarized block was neither valid nor invalid \
        (likely syncing): `{payload_status}`",
    );

    let new_canonicalized = canonicalized.update_head(height, digest);
    if new_canonicalized == canonicalized {
        return Ok(None);
    }
    submit_forkchoice_update(
        &execution_node,
        context,
        Span::current(),
        new_canonicalized,
        None,
        ForkchoiceUpdateKind::Canonicalize {
            head_or_finalized: HeadOrFinalized::Head,
        },
    )
    .await?;
    Ok(Some(new_canonicalized))
}

/// Marker to indicate whether the head hash or finalized hash should be updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadOrFinalized {
    Head,
    Finalized,
}

impl std::fmt::Display for HeadOrFinalized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Head => "head",
            Self::Finalized => "finalized",
        };
        f.write_str(msg)
    }
}
