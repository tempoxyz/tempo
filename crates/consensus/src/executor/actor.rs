//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.
//!
//! Beyond finalizations, the agent tracks the *pending head*: the parent of
//! the most recent consensus context handed to the application on
//! propose/verify. Such a parent is doubly informative - it must be
//! notarized for the proposal to be valid, and it is the block consensus
//! reports building on. The agent reconstructs the pending head's ancestry
//! on top of the finalized tip and converges the execution layer's head
//! onto it, fetching missing block bodies from the marshal actor in the
//! background. This decouples updating the execution layer from the
//! lifetime of individual consensus requests: even if simplex aborts a view
//! (and with it the application's verify/propose future), the executor
//! retains what it learned and keeps the execution layer in sync.
//!
//! Reported parents are not monotonic: after nullifications, a later view
//! may build on an *older* notarized block than its predecessor did (a
//! notarized-but-uncertified block is abandoned). Convergence therefore
//! follows the report order, and may legitimately move the execution
//! layer's head *backwards* onto the pending head.
//!
//! Execution-layer work is prioritized by consensus latency: validating a
//! proposal, then building one, then forwarding notarized blocks, then
//! forwarding finalized blocks.
//!
//! Only notarized-block forwarding and the finalization pipeline ever move
//! the execution layer's head. A build request is dispatched if and only if
//! the head already is the build's parent - its forkchoice update
//! re-affirms the head to register the build rather than moving it - and is
//! failed fast otherwise, so a build can never fight the notarized-chain
//! convergence (see [`Actor::start_next_execution_task`]).
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
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;

use alloy_rpc_types_engine::PayloadId;
use commonware_consensus::{
    Heightable as _,
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
use reth_provider::{BlockHashReader as _, BlockReader as _, BlockSource};
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tokio::select;
use tracing::{Level, Span, debug, error, error_span, info, info_span, instrument, warn};

use super::{
    Config,
    ingress::{Build, Command, Message, ValidateBlock},
};
use crate::{
    consensus::{Digest, block::Block},
    utils::OptionFuture,
};

#[cfg(test)]
mod tests;

mod notarized_tree;
use notarized_tree::{LocalState, NotarizedTree};

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

    /// The interval at which to send a forkchoice update heartbeat to the
    /// execution layer.
    fcu_heartbeat_interval: Duration,

    /// The timer for the next FCU heartbeat.
    ///
    /// Armed only when no execution-layer work is active or queued.
    fcu_heartbeat_timer: OptionFuture<BoxFuture<'static, ()>>,

    /// Finalized blocks waiting to be forwarded to the execution layer.
    pending_finalizations: VecDeque<FinalizedBlockRequest>,

    /// The latest not-yet-started consensus request - validating a proposed
    /// block or building one - keyed by its round. The two kinds share one
    /// slot because a node either verifies or proposes in a round, never
    /// both. A request from a newer round supersedes a queued older one;
    /// requests at or below the queued round are dropped on arrival. Either
    /// way, dropping a request's response channel signals the failure to its
    /// subscriber.
    pending_consensus_request: Option<(Round, ConsensusRequest)>,

    /// The single execution-layer request currently being driven in the background.
    execution_task: OptionFuture<BoxFuture<'static, ExecutionTaskResult>>,

    /// The fetch of a notarized block body that is missing from the
    /// tree, driven concurrently with the execution task. At most one
    /// fetch runs at a time.
    pending_notarized_block: OptionFuture<PendingNotarizedBlock>,

    /// Payload build jobs currently being driven to completion.
    ///
    /// Each job resolves a payload from the execution layer's payload builder
    /// and delivers it to the subscriber that requested the build. If the
    /// subscriber dropped its receiver in the meantime, the built payload is
    /// discarded. A delivered block is handed back as the job's output so
    /// that its body can be recorded in the notarized tree: the
    /// proposer is never asked to verify its own proposal, so no validation
    /// request would deliver it.
    payload_jobs: FuturesUnordered<BoxFuture<'static, Option<Arc<Block>>>>,

    /// Tracks notarized blocks at the tip of the chain, bounded from below
    /// by the latest observed finalized tip of the network. That tip is
    /// never forwarded to the execution layer; the finalized watermark
    /// advances exclusively through delivered finalized blocks.
    notarized_tree: NotarizedTree,

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

        // The forkchoice state the executor starts from: the execution
        // layer's own view of its chain.
        let local_state = LocalState {
            head: (
                Height::new(head_num_hash.number),
                Digest(head_num_hash.hash),
            ),
            finalized: (
                Height::new(execution_finalized_num_hash.number),
                Digest(execution_finalized_num_hash.hash),
            ),
        };

        Ok(Self {
            context: ContextCell::new(context),
            execution_node,
            finalized_floor,
            mailbox,
            marshal,
            fcu_heartbeat_interval,
            fcu_heartbeat_timer: OptionFuture::none(),

            pending_finalizations: VecDeque::new(),
            pending_consensus_request: None,

            execution_task: OptionFuture::none(),
            pending_notarized_block: OptionFuture::none(),
            payload_jobs: FuturesUnordered::new(),

            notarized_tree: NotarizedTree::new(finalized_tip, local_state),

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
            let canonicalized = self.notarized_tree.local_state();
            info!(
                finalized_height = %canonicalized.finalized.0,
                finalized_digest = %canonicalized.finalized.1,
                head_height = %canonicalized.head.0,
                head_digest = %canonicalized.head.1,
                "entering executor loop",
            );
        });

        loop {
            // The tree is pruned to the advancing finalized tip here,
            // before the scheduling decisions below read it. The select
            // branches only record primary state.
            self.notarized_tree.heal();

            self.start_next_execution_task();
            self.update_notarized_block_fetch();
            self.update_fcu_heartbeat_timer();

            select! {
                biased;

                task_result = &mut self.execution_task => {
                    match task_result {
                        ExecutionTaskResult::Completed { canonicalized, payload_job } => {
                            if let Some(canonicalized) = canonicalized {
                                // There is only one execution task running
                                // at a time, and the tracked state is only
                                // mutated here to keep a consistent view.
                                self.notarized_tree.set_local_state(canonicalized);
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
                            // timestamp keeps the block from being retried
                            // in a tight loop: it is withheld until the
                            // retry delay elapses; the finalization
                            // pipeline remains the fatal-on-failure
                            // backstop.
                            let now = self.context.current();
                            self.notarized_tree.mark_rejected(&digest, now);
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

                Some(delivered) = self.payload_jobs.next() => {
                    if let Some(block) = delivered {
                        // The application received the built block and may
                        // propose it; keep the body so the block can be
                        // forwarded to the execution layer once a later
                        // context proves it notarized.
                        self.notarized_tree.record_block(block);
                    }
                }

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
        let start = self.notarized_tree.local_state().finalized.0.get() + 1;
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

            let canonicalized = forward_finalized(
                self.context.as_present(),
                self.execution_node.clone(),
                self.public_key.clone(),
                self.metrics.clone(),
                self.notarized_tree.local_state(),
                request,
            )
            .await
            .wrap_err_with(|| {
                format!(
                    "failed forwarding backfilled finalized block at height `{height}` \
                    to execution layer"
                )
            })?;
            self.notarized_tree.set_local_state(canonicalized);
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

        self.start_next_execution_task();
        if !self.execution_task.is_none() {
            return;
        }

        let task = execute_heartbeat(
            self.context.child("heartbeat"),
            self.execution_node.clone(),
            self.notarized_tree.local_state(),
            Span::current(),
        );
        self.execution_task.replace(task.boxed());
    }

    fn handle_message(&mut self, message: Message) -> eyre::Result<()> {
        let cause = message.cause;
        match message.command {
            Command::Build(build) => {
                queue_consensus_request(
                    &mut self.pending_consensus_request,
                    build.round,
                    ConsensusRequest::Build { cause, build },
                );
            }
            Command::Finalize(finalized) => match *finalized {
                Update::Tip(round, height, digest) => {
                    // A now-stale in-flight body fetch is dropped by
                    // `update_notarized_block_fetch` on the next loop
                    // iteration.
                    self.notarized_tree
                        .set_network_finalized_tip(round, height, digest);
                }
                Update::Block(block, acknowledgement) => {
                    self.pending_finalizations.push_back(FinalizedBlockRequest {
                        cause,
                        block,
                        acknowledgment: acknowledgement,
                    });
                }
            },
            Command::PendingHeadReport(report) => {
                self.record_pending_head(report.context);
            }
            Command::ValidateBlock(request) => {
                let ValidateBlock {
                    round,
                    block,
                    validator_set,
                    response,
                } = *request;
                // Keep the block body around even if this request is aborted:
                // once the block is notarized, the tree needs the body to
                // forward it to the execution layer.
                self.notarized_tree.record_block(block.clone());
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

    /// Records the context's parent as the pending head that consensus
    /// reports building on.
    ///
    /// NOTE: the first proposed block of an epoch will always have a round
    /// `round = (<epoch>, <view>) = (<epoch>, 0)`. This is not a real round
    /// and hinges on the assumption that in order to verify or propose blocks
    /// for `<epoch>`, the node must have finalized the boundary block of
    /// `<epoch>`, which is exactly that parent block. In fact, a node will not
    /// start a simplex engine for `<epoch>` if it does not have this block.
    fn record_pending_head(&mut self, context: Context<Digest, PublicKey>) {
        self.notarized_tree.set_pending_head(
            context.round,
            Round::new(context.round.epoch(), context.parent.0),
            context.parent.1,
        );
    }

    /// Keeps the fetch of missing notarized block bodies pointed at the
    /// first gap on the pending head's ancestor path.
    ///
    /// A missing body prevents the reconstructed notarized chain from
    /// linking up with the finalized tip, stalling the convergence of the
    /// execution layer on the notarized tip until finalization catches up;
    /// fetching it lets convergence proceed. The fetch runs concurrently
    /// with the execution task so that a slow fetch never delays validations
    /// or builds.
    fn update_notarized_block_fetch(&mut self) {
        let next = self.notarized_tree.first_missing_ancestor();

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

    /// Records a fetched notarized block body in the tree.
    #[instrument(skip_all, fields(%digest, %round))]
    fn handle_fetched_notarized_block(
        &mut self,
        digest: Digest,
        round: Round,
        block: Option<Arc<Block>>,
    ) {
        match block {
            Some(fetched) => {
                self.notarized_tree.record_block(fetched);
            }
            None => {
                // The block is still needed - it lies on the canonical
                // notarized ancestry - so the tree is left untouched
                // and the fetch is re-scheduled on the next loop iteration.
                warn!(
                    "marshal dropped the channel before the notarized block \
                    was delivered; the fetch will be retried",
                );
            }
        }
    }

    fn start_next_execution_task(&mut self) {
        if !self.execution_task.is_none() {
            return;
        }

        // Latency critical requests come first: consensus is waiting on
        // them to vote on or propose a block. One exception: if the next
        // notarized block to forward is the request's parent, the request
        // is put back and falls through to the forwarding below, after
        // which it can pass. Any deeper gap fails the request fast and
        // heals in the background instead.
        match self.pending_consensus_request.take() {
            Some((round, ConsensusRequest::Validate(request))) => {
                let parent_is_next_notarized = self
                    .notarized_tree
                    .next_to_forward(self.context.current())
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
            Some((round, ConsensusRequest::Build { cause, build })) => {
                // A build is registered via a forkchoice update that makes
                // its parent the head, so running it with the head anywhere
                // else would fight the notarized-chain convergence. Only
                // run it when the head already is the parent (the parent's
                // pending-head report is sent ahead of the build request, so
                // convergence usually got there first) - otherwise fail
                // fast: dropping the request drops its response channel,
                // which signals the failure to the subscriber.
                if self.notarized_tree.is_execution_head(build.digest) {
                    let task = execute_build(
                        self.context.child("build"),
                        self.execution_node.clone(),
                        self.notarized_tree.local_state(),
                        cause,
                        build,
                    );
                    self.execution_task.replace(task.boxed());
                    return;
                }
                let parent_is_next_notarized = self
                    .notarized_tree
                    .next_to_forward(self.context.current())
                    .is_some_and(|entry| entry.block.digest() == build.digest);
                if parent_is_next_notarized {
                    self.pending_consensus_request =
                        Some((round, ConsensusRequest::Build { cause, build }));
                } else {
                    info!(
                        execution.head_hash = %self.notarized_tree.local_state().head.1,
                        build.parent = %build.digest,
                        "not ready to build new block, dropping it",
                    );
                }
            }
            None => {}
        }

        // Drive the execution layer's head towards the tip of the
        // canonical notarized chain.
        if let Some(entry) = self.notarized_tree.next_to_forward(self.context.current()) {
            let task = execute_notarization(
                self.context.child("notarize"),
                self.execution_node.clone(),
                self.notarized_tree.local_state(),
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
                self.notarized_tree.local_state(),
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
/// tree, keyed by the digest being fetched and the round it was
/// notarized in.
///
/// Resolves to the digest, the round, and the fetched block - `None` for the
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
    Build { cause: Span, build: Build },
}

/// Queues `request` into `slot` unless the slot already holds a request from
/// the same or a newer round.
///
/// Propose and verify are mutually exclusive within a round, but the
/// application's handlers run concurrently, so a request sent by a dying
/// older-round task can arrive after a newer one; the round guard keeps it
/// from clobbering the newer request. Dropping a request - superseded or
/// stale - drops its response channel, signalling the failure to the
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
        canonicalized: Option<LocalState>,
        /// A payload build that the forkchoice update kicked off on the
        /// execution layer and that still needs to be driven to completion.
        payload_job: Option<StartPayloadJob>,
    },
    /// A notarized block could not be forwarded for a reason that carries no
    /// evidence of consensus-execution divergence, for example because the
    /// execution layer was unreachable or reported that it was still syncing.
    ///
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
    canonicalized: LocalState,
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

async fn execute_build<TContext>(
    context: TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LocalState,
    cause: Span,
    build: Build,
) -> ExecutionTaskResult
where
    TContext: Pacer,
{
    let (canonicalized, payload_job) =
        run_build_task(&context, execution_node, canonicalized, cause, build).await;
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
    canonicalized: LocalState,
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
            canonicalized: Some(canonicalized),
            payload_job: None,
        },
        Err(error) => ExecutionTaskResult::Fatal { error },
    }
}

async fn execute_notarization<TContext>(
    context: TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LocalState,
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
            canonicalized: Some(canonicalized),
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
/// abandons the request; the notarized tree retains the block body
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
        // process the new-payload request. The notarized tree
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
            );
        }
        PayloadStatusEnum::Syncing => {
            bail!(
                "failed validating block because the execution layer reports \
                syncing: it does not know the block's parent; the notarized \
                chain convergence will repair the gap in the background"
            );
        }
    }
}

/// Registers the payload build on top of its parent (`digest`) via a
/// forkchoice update.
///
/// The caller dispatches a build only when the execution layer's head
/// already is the parent (see [`Actor::start_next_execution_task`]), so
/// the forkchoice update re-affirms the head instead of moving it; the
/// Engine API requires the update regardless, because builds can only be
/// registered through forkchoice updates. The update is still submitted
/// when the build is dropped as canceled or stale below - a no-op
/// re-affirmation, doubling as a head refresh.
#[instrument(
    skip_all,
    parent = &cause,
    fields(
        %height,
        %digest,
    ),
)]
async fn run_build_task<TContext: Pacer>(
    context: &TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LocalState,
    cause: Span,
    Build {
        round: _,
        height,
        digest,
        attributes,
        response,
    }: Build,
) -> (Option<LocalState>, Option<StartPayloadJob>) {
    let new_canonicalized = canonicalized.update_head(height, digest);

    let mut build_attributes = Some((*attributes, response));
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
    if build_attributes.is_some() && new_canonicalized.head.1 != digest {
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
) -> Option<Arc<Block>> {
    let payload = select! {
        payload = execution_node
            .payload_builder_handle
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .pace(&context, Duration::from_millis(20))
        => payload,

        // Drops the in-flight payload-resolution, killing payload build.
        () = response.cancellation() => {
            info!("payload subscriber went away before the payload was resolved; killing the payload build");
            return None;
        }
    };

    // In the failure branches, dropping the response channel signals the
    // failure to the subscriber; the cause is only logged here.
    match payload {
        Some(Ok(payload)) => {
            let retained = payload.clone();
            if response.send(payload).is_err() {
                info!(
                    "payload subscriber went away before the payload could be delivered; discarding it"
                );
                return None;
            }
            // The application received the block and may propose it; hand
            // the body to the actor loop for the notarized tree.
            let (execution_block, block_access_list, _) =
                retained.into_consensus_execution_payload();
            Some(Arc::new(Block::from_execution_block_unchecked(
                execution_block,
                block_access_list,
            )))
        }
        Some(Err(error)) => {
            warn!(
                error = %eyre::Report::new(error),
                "payload build job failed",
            );
            None
        }
        None => {
            warn!("no payload build job found under the payload ID");
            None
        }
    }
}

#[instrument(
    skip_all,
    parent = &cause,
    fields(
        head_block_hash = %canonicalized.head.1,
        head_block_height = %canonicalized.head.0,
        finalized_block_hash = %canonicalized.finalized.1,
        finalized_block_height = %canonicalized.finalized.0,
        ?kind,
    ),
)]
async fn submit_forkchoice_update<TContext: Pacer>(
    execution_node: &TempoFullNode,
    context: &TContext,
    cause: Span,
    canonicalized: LocalState,
    attrs: Option<TempoPayloadAttributes>,
    kind: ForkchoiceUpdateKind,
) -> eyre::Result<Option<PayloadId>> {
    let fcu_response = execution_node
        .add_ons_handle
        .beacon_engine_handle
        .fork_choice_updated(canonicalized.to_forkchoice_state(), attrs)
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
    canonicalized: LocalState,
    request: FinalizedBlockRequest,
) -> eyre::Result<LocalState> {
    let FinalizedBlockRequest {
        cause,
        block,
        acknowledgment,
    } = request;

    // Startup aligns consensus and execution layers. Also, all blocks
    // (finalized and notarized) arrive in the EL via the executor actor. There
    // is no pipeline sync and no other way to drive the EL forward at this
    // point.
    //
    // This means that new finalized blocks must never unwind the execution
    // layer's finalized tip and repoint to a point below it.
    //
    // Under normal operation, all block arrive in sequence. Only at startup
    // does the marshal actor forward a block at the height of the finalized
    // floor (this can include genesis).
    ensure!(
        block.height() >= canonicalized.finalized.0,
        "finalized block with digest `{}` at height `{}` is below the \
        executor's tracked finalized block `{}` at height `{}`; finalized \
        blocks must only ever be delivered at or on top of the tracked state",
        block.digest(),
        block.height(),
        canonicalized.finalized.1,
        canonicalized.finalized.0,
    );

    if block.height() == canonicalized.finalized.0 {
        ensure!(
            block.digest() == canonicalized.finalized.1,
            "finalized block with digest `{}` at height `{}` conflicts with \
            the executor's tracked finalized block `{}` at the same height; \
            two different blocks must never be finalized at the same height",
            block.digest(),
            block.height(),
            canonicalized.finalized.1,
        );
        debug!(
            "finalized block matches the tracked finalized block; \
            acknowledging re-delivery without re-execution"
        );
        acknowledgment.acknowledge();
        return Ok(canonicalized);
    }

    let consensus_context = block.header().consensus_context;
    let head_descends_from_finalized = {
        let canonical_hash = execution_node
            .provider
            .block_hash(block.height().get())
            .wrap_err_with(|| {
                format!(
                    "failed reading canonical execution block hash at \
                    finalized block height `{}`",
                    block.height(),
                )
            })?;
        canonical_hash == Some(block.digest().0)
    };

    // Ensure that the head hash is not orphaned.
    let new_canonicalized = if head_descends_from_finalized {
        canonicalized.update_finalized(block.height(), block.digest())
    } else {
        canonicalized
            .update_finalized(block.height(), block.digest())
            .update_head(block.height(), block.digest())
    };

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
        payload_status.is_valid(),
        "finalized block was not valid; this is a problem: `{payload_status}`",
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
    canonicalized: LocalState,
    block: Arc<Block>,
    validator_set: Option<Vec<B256>>,
) -> eyre::Result<LocalState> {
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
    // The forkchoice update is skipped when it would not change anything,
    // but the state is reported either way so that the tree's tracked
    // state stays consistent.
    if new_canonicalized == canonicalized {
        return Ok(new_canonicalized);
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
    Ok(new_canonicalized)
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
