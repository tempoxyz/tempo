//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent ingests (monotonically) increasing finalized blocks from the
//! marshal actor and forwards them to the execution layer as `newPayload` +
//! `forkchoiceUpdated` pairs.
//!
//! In addition, the agent:
//!
//! 1. tracks the canonical (notarized) head of the simplex engine,
//! 2. drives the execution layer toward that notarized head,
//! 3. and validates and builds blocks.
//!
//! The notarization and finalization pipelines are strictly separate:
//! the marshal actor informs the executor of the finalized network tip.
//! Notarizations then are strictly above that finalized network tip. If the
//! executor is at the finalized network tip, then the executor will forward
//! the (notarized) child to the execution layer.
//!
//! Requests to verify or build blocks work in a similar manner: a request to
//! verify or build a block on top of some `$PARENT` will only pass if the the
//! local tracked tip is at `$PARENT`.
//!
//! # Notarizations are retried, finalizations are fatal
//!
//! A notarized block rejected by the execution layer is retried while it
//! remains above the network finalized tip. Once that tip advances to or past
//! the block's height, the notarized block is ejected. In contrast, an
//! `INVALID` finalized block is a hard failure that shuts down the node.

use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;

use alloy_rpc_types_engine::{PayloadId, PayloadStatusEnum};
use commonware_consensus::{
    Heightable as _,
    marshal::Update,
    simplex::types::Context,
    types::{Height, Round},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Spawner, spawn_cell,
};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use eyre::{OptionExt as _, Report, WrapErr as _, bail, ensure, eyre};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    future::BoxFuture,
    stream::FuturesUnordered,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use tempo_node::TempoExecutionData;
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tokio::select;
use tracing::{Level, Span, debug, error, error_span, info, info_span, instrument, warn};

use super::{
    Config, ExecutionLayer, Marshal,
    ingress::{Build, Command, Message, VerifyBlock},
};
use crate::{
    consensus::{Digest, block::Block},
    utils::OptionFuture,
};

#[cfg(test)]
mod tests;

mod notarized_tree;
use notarized_tree::{LocalState, NextToForward, NotarizedTree};

/// How long a finalized block the execution layer has not accepted yet is
/// withheld before it is retried.
const FINALIZED_BLOCK_POSTPONE_DELAY: Duration = Duration::from_secs(1);

pub(crate) struct Actor<TContext, TExecutionLayer, TMarshal> {
    context: ContextCell<TContext>,

    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    execution_node: TExecutionLayer,

    /// Highest finalized height the executor should backfill to on startup so
    /// that CL and EL have a consistent view.
    finalized_floor: Height,

    /// The channel over which the agent will receive new commands from the
    /// application actor.
    mailbox: mpsc::UnboundedReceiver<Message>,

    /// The mailbox of the marshal actor. Used to backfill finalized blocks
    /// on startup and to fetch missing notarized block bodies.
    marshal: TMarshal,

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
    execution_task: OptionFuture<ExecutionTask>,

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
    /// Number of block bodies held by the notarized tree.
    notarized_tree_blocks: commonware_runtime::telemetry::metrics::Registered<Gauge>,
    /// Height distance from the locally canonicalized finalized tip up to
    /// the network's finalized tip: the undelivered finalized backlog.
    finalization_lag: commonware_runtime::telemetry::metrics::Registered<Gauge>,
    /// Height distance from the execution layer's head to the pending head:
    /// the convergence backlog. Negative when consensus re-anchored below
    /// the head; holds its last value while the pending head's height is
    /// unknown (its body has not arrived yet).
    convergence_depth: commonware_runtime::telemetry::metrics::Registered<Gauge>,
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
        let notarized_tree_blocks = context.register(
            "notarized_tree_blocks",
            "number of block bodies held by the notarized tree",
            Gauge::default(),
        );
        let finalization_lag = context.register(
            "finalization_lag",
            "height distance from the locally canonicalized finalized tip up to the \
            network's finalized tip",
            Gauge::default(),
        );
        let convergence_depth = context.register(
            "convergence_depth",
            "height distance from the execution layer's head to the pending head \
            (negative after a re-anchor below the head)",
            Gauge::default(),
        );
        Self {
            finalized_blocks_proposed_by_self,
            notarized_tree_blocks,
            finalization_lag,
            convergence_depth,
        }
    }

    /// Publishes the tree's convergence measures.
    fn observe(&self, tree: &NotarizedTree) {
        let depths = tree.depths();
        self.notarized_tree_blocks.set(depths.blocks as i64);
        self.finalization_lag.set(depths.finalization_lag as i64);
        if let Some(depth) = depths.convergence_depth {
            self.convergence_depth.set(depth);
        }
    }
}

impl<TContext, TExecutionLayer, TMarshal> Actor<TContext, TExecutionLayer, TMarshal>
where
    TContext: Clock + RuntimeMetrics + Spawner,
    TExecutionLayer: ExecutionLayer,
    TMarshal: Marshal,
{
    pub(super) fn init(
        context: TContext,
        config: super::Config<TExecutionLayer, TMarshal>,
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
        ensure!(
            finalized_tip.1 >= finalized_floor,
            "finalized tip height `{}` is below the finalized floor `{finalized_floor}`",
            finalized_tip.1,
        );
        let metrics = Metrics::init(&context);

        let execution_finalized_num_hash = execution_node.finalized_num_hash();

        // The finalized point the executor starts from. Normally this is the
        // execution layer's own finalized tip, from which the startup
        // backfill climbs to the finalized floor. The floor can also sit
        // *below* the execution layer's finality: a restored consensus
        // snapshot may anchor below the finality of the execution database
        // it is restored next to. The marshal then re-delivers finalized
        // blocks from the floor, so the tracked state must start there for
        // the re-delivery to line up; the already-finalized blocks are
        // acknowledged without involving the execution layer (see
        // [`forward_finalized`]).
        let finalized = if finalized_floor.get() < execution_finalized_num_hash.number {
            let digest = execution_node
                .canonical_block_hash(finalized_floor.get())
                .wrap_err_with(|| {
                    format!(
                        "failed reading canonical execution block hash at the \
                        finalized floor height `{finalized_floor}`"
                    )
                })?
                .ok_or_eyre(format!(
                    "no canonical execution block hash at the finalized floor \
                    height `{finalized_floor}`, even though the floor is below \
                    the execution layer's finalized height `{}`",
                    execution_finalized_num_hash.number,
                ))?;
            (finalized_floor, Digest(digest))
        } else {
            (
                Height::new(execution_finalized_num_hash.number),
                Digest(execution_finalized_num_hash.hash),
            )
        };

        // The forkchoice state the executor starts from: the startup
        // finalized point for both head and finalized - the two are not
        // differentiated at startup. The head converges onto the notarized
        // tip through normal operation.
        let local_state = LocalState {
            head: finalized,
            finalized,
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
            // branches only record primary state. Metrics observe the same
            // healed state the scheduling reads.
            self.notarized_tree.heal();
            self.metrics.observe(&self.notarized_tree);

            self.start_next_execution_task();
            self.update_notarized_block_fetch();
            self.update_fcu_heartbeat_timer();

            select! {
                biased;

                finished = &mut self.execution_task => {
                    if let Err(error) = self.handle_execution_task_finished(finished) {
                        error_span!("shutdown").in_scope(|| error!(
                            %error,
                            "executor encountered fatal execution-layer update error; \
                            shutting down to prevent consensus-execution divergence"
                        ));
                        break;
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

    #[instrument(
        skip_all,
        fields(
            task_type = task.task_type.name(),
            on_top_of.head = %task.on_top_of.head.1,
            on_top_of.finalized = %task.on_top_of.finalized.1,
        ),
    )]
    fn set_execution_task(&mut self, mut task: ExecutionTask) {
        task.span = Span::current();
        assert!(
            self.execution_task.replace(task).is_none(),
            "invariant violation: must not replace an in-flight execution task"
        );
        info!("execution task scheduled");
    }

    #[instrument(
        parent = &finished.span,
        skip_all,
        fields(
            task_type = finished.task_type.name(),
            on_top_of.head = %finished.on_top_of.head.1,
            on_top_of.finalized = %finished.on_top_of.finalized.1,
            target = ?finished.target(),
            outcome = finished.outcome.name(),
        ),
        err,
    )]
    fn handle_execution_task_finished(
        &mut self,
        finished: ExecutionTaskFinished,
    ) -> eyre::Result<()> {
        info!(
            elapsed = %tempo_telemetry_util::display_duration(finished.started_at.elapsed()),
            "execution task finished"
        );
        let ExecutionTaskFinished { outcome, .. } = finished;
        match outcome {
            ExecutionTaskOutcome::Completed {
                canonicalized,
                payload_job,
            } => {
                if let Some(canonicalized) = canonicalized {
                    // There is only one execution task running at a time,
                    // and the tracked state is only mutated here to keep a
                    // consistent view.
                    self.notarized_tree.set_local_state(canonicalized);
                }
                if let Some(job) = payload_job {
                    self.payload_jobs
                        .push(run_payload_job(self.execution_node.clone(), job).boxed());
                }
            }
            ExecutionTaskOutcome::NotarizedBlockRejected { digest, .. } => {
                // The cause is logged by the task itself. The timestamp keeps
                // the block from being retried in a tight loop: it is withheld
                // until the retry delay elapses; the finalization pipeline
                // remains the fatal-on-failure backstop.
                let now = self.context.current();
                self.notarized_tree.mark_rejected(&digest, now);
            }
            ExecutionTaskOutcome::FinalizedBlockPostponed { request } => {
                // Finalized blocks are strictly ordered: the postponed block
                // goes back to the front of the queue. The cause is logged
                // (and the retry paced) by the task itself.
                self.pending_finalizations.push_front(request);
            }
            ExecutionTaskOutcome::Fatal { error } => {
                return Err(error.wrap_err("execution task failed"));
            }
        }
        Ok(())
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
            let canonicalized = self.notarized_tree.local_state();
            let target =
                finalization_target(&self.execution_node, canonicalized, request.block.as_ref())?;

            // A postponed block is retried until the execution layer accepts
            // it; the retry pacing happens inside `forward_finalized`.
            let mut request = request;
            let canonicalized = loop {
                match forward_finalized(
                    self.context.as_present(),
                    self.execution_node.clone(),
                    self.public_key.clone(),
                    self.metrics.clone(),
                    target,
                    request,
                )
                .await
                .wrap_err_with(|| {
                    format!(
                        "failed forwarding backfilled finalized block at height `{height}` \
                        to execution layer"
                    )
                })? {
                    ForwardFinalized::Forwarded(canonicalized) => break canonicalized,
                    ForwardFinalized::Retry(postponed) => request = postponed,
                }
            };
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

        let on_top_of = self.notarized_tree.local_state();
        let fut = execute_heartbeat(self.execution_node.clone(), on_top_of, Span::current());
        self.set_execution_task(ExecutionTask::new(
            ExecutionTaskType::Heartbeat,
            on_top_of,
            fut,
        ));
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
            Command::VerifyBlock(request) => {
                let VerifyBlock {
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
                    ConsensusRequest::Verify(VerifyBlockRequest {
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
    #[instrument(
        skip_all,
        fields(digest = %context.parent.1),
    )]
    fn record_pending_head(&mut self, context: Context<Digest, PublicKey>) {
        self.notarized_tree.set_pending_head(
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
            .replace(PendingNotarizedBlock::new(&self.marshal, round, digest));
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

    /// Returns if the convergence machinery is expected to imminently make
    /// `digest` available to the execution layer.
    ///
    /// There are 2 options:
    ///
    /// 1. either the block is already queued, or
    /// 2. we expect the block to be scheduled next.
    ///
    /// Point 2 allows for marshal to deliver the next finalized block
    /// just-in-time.
    fn is_convergence_target(&self, digest: Digest) -> bool {
        self.pending_finalizations
            .iter()
            .any(|request| request.block.digest() == digest)
            || self.notarized_tree.converges_imminently(digest)
    }

    #[instrument(
        skip_all,
        fields(
            current.head_height = %self.notarized_tree.local_state().head.0,
            current.head_digest = %self.notarized_tree.local_state().head.1,
            current.finalized_height = %self.notarized_tree.local_state().finalized.0,
            current.finalized_digest = %self.notarized_tree.local_state().finalized.1,
        ),
    )]
    fn start_next_execution_task(&mut self) {
        if !self.execution_task.is_none() {
            return;
        }

        // Latency critical requests come first: consensus is waiting on
        // them to vote on or propose a block.
        //
        // Fail fast if validation or building cannot start immediately, unless
        // the parent is expected to be made available to the execution layer
        // imminently.
        match self.pending_consensus_request.take() {
            Some((round, ConsensusRequest::Verify(request))) => {
                if self
                    .notarized_tree
                    .is_local_notarized_or_finalized_tip(request.block.parent_digest())
                    || !self.is_convergence_target(request.block.parent_digest())
                {
                    let on_top_of = self.notarized_tree.local_state();
                    let fut = execute_validation(self.execution_node.clone(), request);
                    self.set_execution_task(ExecutionTask::new(
                        ExecutionTaskType::Verify,
                        on_top_of,
                        fut,
                    ));
                    return;
                }

                // Reschedules the request; the actor will not spin on
                // `start_next_execution_request` as long as it remains
                // scheduled before the select! in the select-loop (some other
                // event needs to take place first; ideally the result of the
                // convergence target we are falling through to).
                self.pending_consensus_request = Some((round, ConsensusRequest::Verify(request)));
            }
            Some((round, ConsensusRequest::Build { cause, build })) => {
                // Builds are registered via FCU setting the head hash to the
                // parent. So running it with the head anywhere else would fight
                // notarized-chain convergence.
                if self.notarized_tree.is_local_head(build.digest) {
                    let on_top_of = self.notarized_tree.local_state();
                    let fut = execute_build(self.execution_node.clone(), on_top_of, cause, build);
                    self.set_execution_task(ExecutionTask::new(
                        ExecutionTaskType::Build,
                        on_top_of,
                        fut,
                    ));
                    return;
                }
                // Reschedules the request; the actor will not spin on
                // `start_next_execution_request` as long as it remains
                // scheduled before the select! in the select-loop (some other
                // event needs to take place first; ideally the result of the
                // convergence target we are falling through to).
                if self.is_convergence_target(build.digest) {
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

        if let Some(step) = self.notarized_tree.next_to_forward(self.context.current()) {
            let on_top_of = self.notarized_tree.local_state();
            let fut = execute_notarization(self.execution_node.clone(), on_top_of, step, None);
            self.set_execution_task(ExecutionTask::new(
                ExecutionTaskType::Notarize,
                on_top_of,
                fut,
            ));
            return;
        }

        // Finalizations are forwarded in order and acknowledged so that the
        // marshal actor can make progress.
        if let Some(request) = self.pending_finalizations.pop_front() {
            let on_top_of = self.notarized_tree.local_state();
            self.set_execution_task(ExecutionTask::new(
                ExecutionTaskType::Finalize,
                on_top_of,
                execute_finalization(
                    self.context.child("finalize"),
                    self.execution_node.clone(),
                    self.public_key.clone(),
                    self.metrics.clone(),
                    on_top_of,
                    request,
                ),
            ));
        }
    }
}

#[instrument(skip_all, fields(height), err)]
async fn get_block(
    marshal: impl Marshal,
    execution_node: impl ExecutionLayer,
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
    let Some(block) = execution_node.block_by_digest(digest).wrap_err_with(|| {
        format!("failed querying execution layer for backfill block `{digest}`")
    })?
    else {
        warn!(%digest, "execution layer did not have missing backfill block");
        bail!(
            "marshal actor did not have block at height `{height}` and \
            execution layer did not have block `{digest}`"
        );
    };

    Ok(block)
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
    fn new(marshal: &impl Marshal, round: Round, digest: Digest) -> Self {
        let fetch = marshal.subscribe_by_digest(digest, round);
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
    Verify(VerifyBlockRequest),
    Build { cause: Span, build: Build },
}

/// Queues `request` into `slot` unless the slot already holds a request from
/// the same or a newer round.
///
/// Propose and verify are mutually exclusive within a round. Because Simplex
/// views are strictly monotonically increasing, a request at or below the
/// queued round cannot represent later consensus progress and must not replace
/// the request already queued. The application's handlers run concurrently,
/// so a request sent by a dying older-round task can still arrive after a newer
/// one; the round guard keeps it from clobbering the newer request. Dropping a
/// request - superseded or stale - drops its response channel, signalling the
/// failure to the subscriber.
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
struct VerifyBlockRequest {
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

#[derive(Debug, Clone, Copy)]
enum ExecutionTaskType {
    Heartbeat,
    Verify,
    Build,
    Notarize,
    Finalize,
}

impl ExecutionTaskType {
    fn name(self) -> &'static str {
        match self {
            Self::Heartbeat => "heartbeat",
            Self::Verify => "verify",
            Self::Build => "build",
            Self::Notarize => "notarize",
            Self::Finalize => "finalize",
        }
    }
}

struct ExecutionTask {
    task_type: ExecutionTaskType,
    on_top_of: LocalState,
    span: Span,
    started_at: Instant,
    fut: BoxFuture<'static, ExecutionTaskOutcome>,
}

impl ExecutionTask {
    fn new<F>(task_type: ExecutionTaskType, on_top_of: LocalState, fut: F) -> Self
    where
        F: Future<Output = ExecutionTaskOutcome> + Send + 'static,
    {
        Self {
            task_type,
            on_top_of,
            span: Span::none(),
            started_at: Instant::now(),
            fut: fut.boxed(),
        }
    }
}

struct ExecutionTaskFinished {
    task_type: ExecutionTaskType,
    on_top_of: LocalState,
    span: Span,
    started_at: Instant,
    outcome: ExecutionTaskOutcome,
}

impl ExecutionTaskFinished {
    fn target(&self) -> Option<LocalState> {
        match &self.outcome {
            ExecutionTaskOutcome::Completed { canonicalized, .. } => *canonicalized,
            ExecutionTaskOutcome::NotarizedBlockRejected { target, .. } => Some(*target),
            ExecutionTaskOutcome::FinalizedBlockPostponed { .. } => None,
            ExecutionTaskOutcome::Fatal { .. } => None,
        }
    }
}

impl Future for ExecutionTask {
    type Output = ExecutionTaskFinished;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let span = self.span.clone();
        let outcome = {
            let _entered = span.enter();
            std::task::ready!(self.fut.as_mut().poll(cx))
        };
        std::task::Poll::Ready(ExecutionTaskFinished {
            task_type: self.task_type,
            on_top_of: self.on_top_of,
            span,
            started_at: self.started_at,
            outcome,
        })
    }
}

enum ExecutionTaskOutcome {
    Completed {
        canonicalized: Option<LocalState>,
        /// A payload build that the forkchoice update kicked off on the
        /// execution layer and that still needs to be driven to completion.
        payload_job: Option<StartPayloadJob>,
    },
    /// A notarized block could not be forwarded and should be retried later.
    NotarizedBlockRejected {
        digest: Digest,
        target: LocalState,
    },
    /// A finalized block the execution layer has not accepted yet; it is
    /// put back at the front of the finalization queue for a retry.
    FinalizedBlockPostponed {
        request: FinalizedBlockRequest,
    },
    Fatal {
        error: Report,
    },
}

impl ExecutionTaskOutcome {
    fn name(&self) -> &'static str {
        match self {
            Self::Completed { .. } => "completed",
            Self::NotarizedBlockRejected { .. } => "rejected",
            Self::FinalizedBlockPostponed { .. } => "postponed",
            Self::Fatal { .. } => "fatal",
        }
    }
}

/// A payload build registered on the execution layer whose result still needs
/// to be delivered to the subscriber that requested it.
struct StartPayloadJob {
    cause: Span,
    payload_id: PayloadId,
    response: oneshot::Sender<TempoBuiltPayload>,
}

#[instrument(
    skip_all,
    parent = &cause,
    fields(
        head_block_hash = %canonicalized.head.1,
        head_block_height = %canonicalized.head.0,
        finalized_block_hash = %canonicalized.finalized.1,
        finalized_block_height = %canonicalized.finalized.0,
    ),
)]
async fn execute_heartbeat(
    execution_node: impl ExecutionLayer,
    canonicalized: LocalState,
    cause: Span,
) -> ExecutionTaskOutcome {
    if let Err(error) = submit_forkchoice_update(
        &execution_node,
        cause,
        canonicalized,
        None,
        ForkchoiceUpdateKind::Heartbeat,
    )
    .await
    {
        warn!(%error, "forkchoice update heartbeat failed");
    }
    ExecutionTaskOutcome::Completed {
        canonicalized: None,
        payload_job: None,
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
/// when the build is dropped as canceled below - a no-op re-affirmation,
/// doubling as a head refresh.
#[instrument(
    skip_all,
    parent = &cause,
    fields(%digest),
)]
async fn execute_build(
    execution_node: impl ExecutionLayer,
    canonicalized: LocalState,
    cause: Span,
    Build {
        round: _,
        digest,
        attributes,
        response,
    }: Build,
) -> ExecutionTaskOutcome {
    let mut build_attributes = Some((*attributes, response));
    if build_attributes
        .as_ref()
        .is_some_and(|(_, response)| response.is_canceled())
    {
        info!("dropping payload build request: the subscriber went away while it was queued");
        build_attributes.take();
    }

    let (attributes, payload_response) = build_attributes.unzip();

    // The forkchoice update is submitted even if it would not change the
    // forkchoice state: the execution layer treats it as a no-op (the FCU
    // heartbeat relies on this).
    match submit_forkchoice_update(
        &execution_node,
        cause.clone(),
        canonicalized,
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
            ExecutionTaskOutcome::Completed {
                canonicalized: Some(canonicalized),
                payload_job,
            }
        }
        Err(error) => {
            // Dropping the response channels signals the failure to the
            // subscribers; the cause is only logged here.
            warn!(%error, "forkchoice update failed");
            ExecutionTaskOutcome::Completed {
                canonicalized: None,
                payload_job: None,
            }
        }
    }
}

#[instrument(
    skip_all,
    parent = &request.cause,
    fields(
        block.digest = %request.block.digest(),
        block.height = %request.block.height(),
    ),
)]
async fn execute_finalization<TContext>(
    context: TContext,
    execution_node: impl ExecutionLayer,
    public_key: Option<PublicKey>,
    metrics: Metrics,
    canonicalized: LocalState,
    request: FinalizedBlockRequest,
) -> ExecutionTaskOutcome
where
    TContext: Clock,
{
    let target = match finalization_target(&execution_node, canonicalized, request.block.as_ref()) {
        Ok(target) => target,
        Err(error) => return ExecutionTaskOutcome::Fatal { error },
    };
    match forward_finalized(
        &context,
        execution_node,
        public_key,
        metrics,
        target,
        request,
    )
    .await
    {
        Ok(ForwardFinalized::Forwarded(target)) => ExecutionTaskOutcome::Completed {
            canonicalized: Some(target),
            payload_job: None,
        },
        Ok(ForwardFinalized::Retry(request)) => {
            ExecutionTaskOutcome::FinalizedBlockPostponed { request }
        }
        Err(error) => ExecutionTaskOutcome::Fatal { error },
    }
}

#[instrument(
    skip_all,
    fields(
        block.digest = %step.digest(),
        block.height = %step.height(),
    ),
)]
async fn execute_notarization(
    execution_node: impl ExecutionLayer,
    on_top_of: LocalState,
    step: NextToForward,
    validator_set: Option<Vec<B256>>,
) -> ExecutionTaskOutcome {
    let digest = step.digest();
    let is_repoint = matches!(step, NextToForward::Repoint(..));
    let target = on_top_of.update_head(step.height(), digest);
    match forward_notarized(execution_node, on_top_of, target, step, validator_set).await {
        Ok(canonicalized) => ExecutionTaskOutcome::Completed {
            canonicalized: Some(canonicalized),
            payload_job: None,
        },
        // A failed repoint is fatal: the target is expected to be an ancestor
        // of the current canonical chain. Anything but success means that CL
        // and EL disagree.
        Err(error) if is_repoint => ExecutionTaskOutcome::Fatal {
            error: error
                .wrap_err("failed repointing the execution layer's head onto the finalized tip"),
        },
        // The cause is logged by `forward_notarized`.
        Err(_logged) => ExecutionTaskOutcome::NotarizedBlockRejected { digest, target },
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
async fn execute_validation(
    execution_node: impl ExecutionLayer,
    request: VerifyBlockRequest,
) -> ExecutionTaskOutcome {
    let VerifyBlockRequest {
        cause: _,
        block,
        validator_set,
        mut response,
    } = request;

    let work = validate_block(&execution_node, block, validator_set);
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
            return ExecutionTaskOutcome::Completed {
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
    ExecutionTaskOutcome::Completed {
        canonicalized: None,
        payload_job: None,
    }
}

/// Validates `block` against the execution layer via a new-payload request.
///
/// Returns the validation duration when the block is valid, `None` when the
/// execution layer rejected it, and an error when validation was not
/// possible.
async fn validate_block(
    execution_node: &impl ExecutionLayer,
    block: Arc<Block>,
    validator_set: Option<Vec<B256>>,
) -> eyre::Result<Option<Duration>> {
    use alloy_rpc_types_engine::PayloadStatusEnum;

    let (block, block_access_list) = Arc::unwrap_or_clone(block).into_parts();
    let validation_start = Instant::now();
    let payload_status = execution_node
        .new_payload(TempoExecutionData {
            block,
            block_access_list,
            validator_set,
        })
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
async fn run_payload_job(
    execution_node: impl ExecutionLayer,
    StartPayloadJob {
        cause,
        payload_id,
        mut response,
    }: StartPayloadJob,
) -> Option<Arc<Block>> {
    let payload = select! {
        payload = execution_node
            .resolve_payload(payload_id)
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
                %error,
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
async fn submit_forkchoice_update(
    execution_node: &impl ExecutionLayer,
    cause: Span,
    canonicalized: LocalState,
    attrs: Option<TempoPayloadAttributes>,
    kind: ForkchoiceUpdateKind,
) -> eyre::Result<Option<PayloadId>> {
    // The execution layer's finalized tip only ever advances. The tracked
    // state can trail the execution layer's finality: it starts at the
    // consensus finalized floor, which can sit below the execution layer's
    // finalized tip after a snapshot restore, and only catches up as the
    // marshal re-delivers the already-finalized blocks.
    //
    // Whenever the execution layer's finality is at or ahead of the tracked
    // finalized block, that block must lie on the execution layer's
    // canonical chain - anything else means two conflicting blocks were
    // finalized. A forkchoice state whose finalized block is strictly below
    // the execution layer's own is stale in its entirety and is not
    // submitted. Callers treat the skip as a no-op; a payload-build request
    // affected by it fails through the missing payload ID.
    if let execution_finalized = execution_node.finalized_num_hash()
        && execution_finalized.number >= canonicalized.finalized.0.get()
    {
        let canonical_digest = execution_node
            .canonical_block_hash(canonicalized.finalized.0.get())
            .wrap_err_with(|| {
                format!(
                    "failed reading canonical execution block hash at the tracked \
                    finalized height `{}`",
                    canonicalized.finalized.0,
                )
            })?
            .ok_or_else(|| {
                eyre!(
                    "no canonical execution block hash at the tracked \
                    finalized height `{}`, even though it is at or below the \
                    execution layer's finalized height `{}`",
                    canonicalized.finalized.0,
                    execution_finalized.number,
                )
            })?;
        ensure!(
            canonical_digest == canonicalized.finalized.1.0,
            "tracked finalized block `{}` at height `{}` conflicts with the \
            execution layer's canonical block `{canonical_digest}` at the same \
            height, which the execution layer already considers final; two \
            different blocks must never be finalized at the same height",
            canonicalized.finalized.1,
            canonicalized.finalized.0,
        );

        if execution_finalized.number > canonicalized.finalized.0.get() {
            debug!(
                execution_finalized_height = execution_finalized.number,
                execution_finalized_hash = %execution_finalized.hash,
                "tracked finalized state is below the execution layer's \
                finalized tip; skipping the forkchoice update",
            );
            return Ok(None);
        }
    }

    let fcu_response = execution_node
        .fork_choice_updated(canonicalized.to_forkchoice_state(), attrs)
        .await
        .wrap_err("failed requesting execution layer to update forkchoice state")?;

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

    if !fcu_response.is_valid() {
        return Err(Report::msg(fcu_response.payload_status))
            .wrap_err("forkchoice-update was not valid");
    }

    Ok(fcu_response.payload_id)
}

fn finalization_target(
    execution_node: &impl ExecutionLayer,
    canonicalized: LocalState,
    block: &Block,
) -> eyre::Result<LocalState> {
    // All blocks (finalized and notarized) arrive in the EL via the executor
    // actor. There is no pipeline sync and no other way to drive the EL
    // forward at this point.
    //
    // The tracked finalized state starts at the lower of the execution
    // layer's finalized tip and the consensus finalized floor - the lowest
    // point the marshal delivers finalized blocks from. A delivery below the
    // tracked state is therefore a protocol violation.
    //
    // Under normal operation, all blocks arrive in sequence. Only at startup
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
        return Ok(canonicalized);
    }

    let canonical_hash = execution_node
        .canonical_block_hash(block.height().get())
        .wrap_err_with(|| {
            format!(
                "failed reading canonical execution block hash at finalized block height `{}`",
                block.height(),
            )
        })?;
    let head_descends_from_finalized = canonical_hash == Some(block.digest().0);

    Ok(if head_descends_from_finalized {
        canonicalized.update_finalized(block.height(), block.digest())
    } else {
        canonicalized
            .update_finalized(block.height(), block.digest())
            .update_head(block.height(), block.digest())
    })
}

#[instrument(
    skip_all,
    fields(
        block.digest = %request.block.digest(),
        block.height = %request.block.height(),
    ),
    err(level = Level::WARN),
    ret,
)]
async fn forward_finalized<TContext: Clock>(
    context: &TContext,
    execution_node: impl ExecutionLayer,
    public_key: Option<PublicKey>,
    metrics: Metrics,
    target: LocalState,
    request: FinalizedBlockRequest,
) -> eyre::Result<ForwardFinalized> {
    let FinalizedBlockRequest {
        cause,
        block,
        acknowledgment,
    } = request;

    let consensus_context = block.header().consensus_context;

    let (execution_block, block_access_list) = (*block).clone().into_parts();
    let payload_status = execution_node
        .new_payload(TempoExecutionData {
            block: execution_block,
            block_access_list,
            // can be omitted for finalized blocks
            validator_set: None,
        })
        .await
        .wrap_err(
            "failed sending new-payload request to execution engine to \
                query payload status of finalized block",
        )?;

    match &payload_status.status {
        PayloadStatusEnum::Syncing => {
            // CL enforces in-order delivery. The problem: reth can rebuild
            // indices and be temporarily unable to process blocks. This
            // requires retrying the block.
            //
            // This again causes an issue however: we can't detect genuine
            // delays from there missing a block because we violated an
            // invariant.
            warn!(
                %payload_status,
                "execution layer is not ready to accept block; postponing it",
            );
            // Intentionally stalls the execution pipeline, keeping it occupied
            // before a retry can be done.
            //
            // TODO: Would it be cleaner to do it outside the async task? That
            // would require a complex setup in the select-loop.
            context.sleep(FINALIZED_BLOCK_POSTPONE_DELAY).await;
            return Ok(ForwardFinalized::Retry(FinalizedBlockRequest {
                cause,
                block,
                acknowledgment,
            }));
        }
        PayloadStatusEnum::Valid => {}
        _ => {
            return Err(eyre!(
                "payload was not valid and not syncing: {payload_status}"
            ));
        }
    }

    submit_forkchoice_update(
        &execution_node,
        cause.clone(),
        target,
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

    Ok(ForwardFinalized::Forwarded(target))
}

/// The outcome of [`forward_finalized`].
enum ForwardFinalized {
    /// The block was forwaraded to the execution layer, which now has a new state.
    Forwarded(LocalState),
    /// The block needs to be retried because the execution layer reported
    /// SYNCING.
    Retry(FinalizedBlockRequest),
}

impl std::fmt::Debug for ForwardFinalized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forwarded(target) => f.debug_tuple("Forwarded").field(target).finish(),
            Self::Retry(request) => f
                .debug_struct("Postponed")
                .field("digest", &request.block.digest())
                .field("height", &request.block.height())
                .finish(),
        }
    }
}

/// Drives convergence of the EL to the pending notarized tip.
///
/// The caller is responsible for only forwarding blocks that link to the
/// canonicalized state, so the new-payload request must come back valid;
/// anything else is an error.
#[instrument(
    skip_all,
    fields(
        block.digest = %step.digest(),
        block.height = %step.height(),
    ),
    err(level = Level::WARN),
)]
async fn forward_notarized(
    execution_node: impl ExecutionLayer,
    on_top_of: LocalState,
    target: LocalState,
    step: NextToForward,
    validator_set: Option<Vec<B256>>,
) -> eyre::Result<LocalState> {
    if let NextToForward::Block(block) = step {
        let (block, block_access_list) = Arc::unwrap_or_clone(block).into_parts();
        let payload_status = execution_node
            .new_payload(TempoExecutionData {
                block,
                block_access_list,
                validator_set,
            })
            .await
            .wrap_err(
                "failed sending new-payload request to execution engine to \
                forward notarized block",
            )?;
        ensure!(
            payload_status.is_valid(),
            "payload status of notarized block was neither valid nor invalid \
            (likely syncing): `{payload_status}`",
        );
    }

    // The forkchoice update is skipped when it would not change anything,
    // but the state is reported either way so that the tree's tracked
    // state stays consistent.
    if target == on_top_of {
        return Ok(target);
    }
    submit_forkchoice_update(
        &execution_node,
        Span::current(),
        target,
        None,
        ForkchoiceUpdateKind::Canonicalize {
            head_or_finalized: HeadOrFinalized::Head,
        },
    )
    .await?;
    Ok(target)
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
