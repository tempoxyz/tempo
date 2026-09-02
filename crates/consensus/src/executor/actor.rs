//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent ingests (monotonically) increasing finalized blocks from the
//! marshal actor and forwards them to the execution layer.
//!
//! In addition, the agent:
//!
//! 1. tracks the canonical (notarized) head of the simplex engine,
//! 2. drives the execution layer toward that notarized head,
//! 3. and validates and builds blocks.
//!
//! # Delivery and forkchoice are separate steps
//!
//! `newPayload` delivers a block body and never moves the head; notarized
//! blocks, finalized blocks, and validation probes are all deliveries.
//! `forkchoiceUpdated` moves the head and the finalized block, on a later
//! iteration, and only ever names blocks the execution layer has answered
//! `VALID` for. One update covers everything delivered since the last one.
//! Finalized blocks are acknowledged to the marshal actor once the update
//! finalizing them is accepted, and finality work is scheduled ahead of
//! notarized convergence.
//!
//! Requests to verify or build blocks work in a similar manner: a request to
//! verify or build a block on top of some `$PARENT` will only pass if the
//! execution layer is known to have `$PARENT`.
//!
//! # Notarized deliveries are retried, everything else is fatal
//!
//! A rejected notarized delivery is retried while the block stays above the
//! finalized tip. An `INVALID` finalized block is fatal, and so is any
//! forkchoice update not answered `VALID`: the executor's view of the
//! execution layer has diverged from it.

use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;

use alloy_rpc_types_engine::{ForkchoiceUpdated, PayloadId, PayloadStatusEnum};
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
use tracing::{
    Instrument as _, Level, Span, debug, error, error_span, info, info_span, instrument, warn,
};

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
use notarized_tree::{LocalState, NotarizedTree};

/// How often to probe whether the execution layer is ready to process blocks.
const EXECUTION_LAYER_READY_POLL_INTERVAL: Duration = Duration::from_secs(1);

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

    /// Finalized blocks waiting to be delivered to the execution layer.
    pending_finalizations: VecDeque<FinalizedBlockRequest>,

    /// Finalized blocks the execution layer has accepted, waiting for the
    /// forkchoice update that finalizes them before they are acknowledged
    /// to the marshal actor. In height order.
    pending_acknowledgements: VecDeque<FinalizedBlockRequest>,

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
        // [`Self::handle_finalized_delivered`]).
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
            pending_acknowledgements: VecDeque::new(),
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
        if let Err(error) = self.wait_for_execution_layer().await {
            error_span!("shutdown").in_scope(|| {
                error!(
                    %error,
                    "failed waiting for execution layer readiness",
                )
            });
            return;
        }

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

            if let Err(error) = self.start_next_execution_task() {
                error_span!("shutdown").in_scope(|| {
                    error!(
                        %error,
                        "executor failed scheduling execution-layer work; \
                        shutting down to prevent consensus-execution divergence"
                    )
                });
                break;
            }
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
                    self.handle_message(msg);
                },

                _ = (&mut self.fcu_heartbeat_timer).fuse() => {
                    if let Err(error) = self.send_forkchoice_update_heartbeat() {
                        error_span!("shutdown").in_scope(|| error!(
                            %error,
                            "executor failed scheduling execution-layer work; \
                            shutting down to prevent consensus-execution divergence"
                        ));
                        break;
                    }
                },
            }
        }
    }

    #[instrument(
        skip_all,
        fields(
            task_type = task.task_type.name(),
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

    /// Interprets the answer of a finished execution task: this is the one
    /// place where the tracked execution-layer state is mutated and where
    /// answers are turned into decisions - what to mark delivered, what to
    /// withhold, what to acknowledge, and what is fatal.
    #[instrument(
        parent = &finished.span,
        skip_all,
        fields(
            task_type = finished.task_type.name(),
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
            ExecutionTaskOutcome::Validated { request, status } => {
                self.handle_validated(request, status)
            }
            ExecutionTaskOutcome::Delivered { digest, status } => {
                self.handle_delivered(digest, status)
            }
            ExecutionTaskOutcome::FinalizedDelivered { request, status } => {
                self.handle_finalized_delivered(request, status)?
            }
            ExecutionTaskOutcome::Forkchoice {
                target,
                build,
                response,
            } => self.handle_forkchoice_response(target, build, response)?,
        }
        Ok(())
    }

    /// Resolves a validation request from the execution layer's answer.
    /// `VALID` and `INVALID` are verdicts; `SYNCING` (unknown parent),
    /// `ACCEPTED`, and transport errors fail the request by dropping its
    /// channel. Gaps are repaired by convergence, not on this path.
    fn handle_validated(
        &mut self,
        request: Option<VerifyBlockRequest>,
        status: eyre::Result<(PayloadStatusEnum, Duration)>,
    ) {
        let Some(request) = request else {
            return;
        };
        let digest = request.block.digest();
        let now = self.context.current();
        let verdict = match status {
            Ok((PayloadStatusEnum::Valid, duration)) => {
                self.notarized_tree.mark_delivered(&digest);
                Some(duration)
            }
            Ok((PayloadStatusEnum::Invalid { validation_error }, _)) => {
                info!(
                    validation_error,
                    "execution layer returned that the block was invalid"
                );
                self.notarized_tree.mark_rejected(&digest, now);
                None
            }
            Ok((PayloadStatusEnum::Syncing, _)) => {
                warn!(
                    "failed validating block because the execution layer reports \
                    syncing: it does not know the block's parent; the notarized \
                    chain convergence will repair the gap in the background"
                );
                return;
            }
            Ok((PayloadStatusEnum::Accepted, _)) => {
                warn!(
                    "failed validating block because payload was accepted, meaning \
                    that it was not actually executed by the execution layer for \
                    some reason"
                );
                self.notarized_tree.mark_rejected(&digest, now);
                return;
            }
            Err(error) => {
                warn!(%error, "failed validating block");
                self.notarized_tree.mark_rejected(&digest, now);
                return;
            }
        };
        if request.response.send(verdict).is_err() {
            info!(
                "verification subscriber went away before the validation \
                result could be delivered"
            );
        }
    }

    /// An accepted forkchoice update becomes the tracked state (mutated only
    /// here). A rejected one is fatal: every target named is a block the
    /// execution layer accepted, so the executor's view of the execution
    /// layer has diverged from it.
    fn handle_forkchoice_response(
        &mut self,
        target: LocalState,
        build: Option<(Span, oneshot::Sender<TempoBuiltPayload>)>,
        response: eyre::Result<ForkchoiceUpdated>,
    ) -> eyre::Result<()> {
        let diverged = || {
            format!(
                "forkchoice update onto head `{}` at height `{}` and finalized block `{}` at \
                height `{}` failed; the executor's view of the execution layer has diverged \
                from the execution layer",
                target.head.1, target.head.0, target.finalized.1, target.finalized.0,
            )
        };
        let response = response.wrap_err_with(diverged)?;
        if !response.is_valid() {
            return Err(Report::msg(response.payload_status)).wrap_err_with(diverged);
        }

        self.notarized_tree.set_local_state(target);
        self.acknowledge_finalized();

        // Dropping the build's response channel signals the failure to the
        // subscriber.
        match (build, response.payload_id) {
            (Some((cause, response)), Some(payload_id)) => {
                let job = StartPayloadJob {
                    cause,
                    payload_id,
                    response,
                };
                self.payload_jobs
                    .push(run_payload_job(self.execution_node.clone(), job).boxed());
            }
            (Some(_dropped_to_signal_failure), None) => {
                warn!("execution layer did not return a payload id for the build request");
            }
            (None, _) => {}
        }
        Ok(())
    }

    /// `VALID` makes the notarized block known to the execution layer.
    /// Anything else withholds it for the retry delay so that it is not
    /// retried in a tight loop; the finalization pipeline remains the
    /// fatal-on-failure backstop.
    fn handle_delivered(&mut self, digest: Digest, status: eyre::Result<PayloadStatusEnum>) {
        match status {
            Ok(PayloadStatusEnum::Valid) => self.notarized_tree.mark_delivered(&digest),
            Ok(status) => {
                warn!(
                    %status,
                    "execution layer did not accept the notarized block; withholding it",
                );
                let now = self.context.current();
                self.notarized_tree.mark_rejected(&digest, now);
            }
            Err(error) => {
                warn!(%error, "failed delivering notarized block; withholding it");
                let now = self.context.current();
                self.notarized_tree.mark_rejected(&digest, now);
            }
        }
    }

    /// A non-`VALID` answer is fatal. Otherwise the block becomes the next
    /// finalized target and is acknowledged once the forkchoice update
    /// finalizing it lands - or right away if the execution layer already
    /// finalized it (a re-delivery). The marshal actor delivers the
    /// finalized chain in order; that order is trusted, not checked.
    fn handle_finalized_delivered(
        &mut self,
        request: FinalizedBlockRequest,
        status: eyre::Result<PayloadStatusEnum>,
    ) -> eyre::Result<()> {
        let block = request.block.as_ref();
        debug_assert!(
            block.height() >= self.notarized_tree.delivered_finalized().0,
            "finalized blocks are delivered in height order",
        );
        match status {
            Ok(PayloadStatusEnum::Valid) => {}
            Ok(status) => bail!(
                "payload status of finalized block `{}` at height `{}` was not \
                valid: {status}",
                block.digest(),
                block.height(),
            ),
            Err(error) => {
                return Err(error.wrap_err(format!(
                    "failed delivering finalized block `{}` at height `{}`",
                    block.digest(),
                    block.height(),
                )));
            }
        }

        self.notarized_tree
            .set_delivered_finalized(block.height(), block.digest());
        if block.height() <= self.notarized_tree.local_state().finalized.0 {
            self.acknowledge(request);
        } else {
            self.pending_acknowledgements.push_back(request);
        }
        Ok(())
    }

    /// Acknowledges the queued blocks the last accepted forkchoice update
    /// finalized. Deliveries are in chain order, so height identifies them.
    fn acknowledge_finalized(&mut self) {
        let finalized = self.notarized_tree.local_state().finalized.0;
        while let Some(request) = self.pending_acknowledgements.front() {
            if request.block.height() > finalized {
                break;
            }
            let Some(request) = self.pending_acknowledgements.pop_front() else {
                break;
            };
            self.acknowledge(request);
        }
    }

    /// Acknowledges a block the execution layer finalized to the marshal actor.
    fn acknowledge(&mut self, request: FinalizedBlockRequest) {
        let FinalizedBlockRequest {
            cause,
            block,
            acknowledgment,
        } = request;
        let _entered = cause.enter();
        if let Some(public_key) = self.public_key.as_ref()
            && block
                .header()
                .consensus_context
                .is_some_and(|context| context.proposer.to_inner() == *public_key)
        {
            self.metrics.finalized_blocks_proposed_by_self.inc();
        }
        info!(
            block.digest = %block.digest(),
            block.height = %block.height(),
            "finalized block is final on the execution layer; acknowledging it",
        );
        acknowledgment.acknowledge();
    }

    /// Waits until reth is ready to process blocks by repeatedly reaffirming the execution layer's
    /// own forkchoice state.
    ///
    /// Reth returns `SYNCING` for every forkchoice update while its backfill pipeline is active.
    /// Because the probe uses the execution layer's current head, safe block, and finalized block,
    /// it is non-destructive and cannot report `SYNCING` due to a detached CL-provided head. Once
    /// the probe returns `VALID`, later `SYNCING` responses while forwarding finalized blocks can
    /// be treated as invalid state.
    async fn wait_for_execution_layer(&mut self) -> eyre::Result<()> {
        for attempts in 1_u64.. {
            if self
                .execution_node
                .is_ready()
                .instrument(info_span!("check_execution_layer_readiness", attempts))
                .await?
            {
                break;
            }
            self.context
                .sleep(EXECUTION_LAYER_READY_POLL_INTERVAL)
                .await;
        }

        Ok(())
    }

    /// Climbs from the tracked finalized state to the finalized floor
    /// before entering the loop: delivers every block, then finalizes the
    /// floor with one forkchoice update. The head starts on the finalized
    /// tip and follows it.
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
        let mut floor = None;
        for height in heights {
            let span = info_span!("backfill_on_start", %height);
            let block = get_block(
                self.marshal.clone(),
                self.execution_node.clone(),
                Height::new(height),
            )
            .await
            .wrap_err_with(|| format!("failed backfilling block for height `{height}`"))?;
            let block = Arc::new(block);

            let status = deliver_block(&self.execution_node, block.clone(), None)
                .instrument(span.clone())
                .await
                .wrap_err_with(|| {
                    format!(
                        "failed forwarding backfilled finalized block at height `{height}` \
                        to execution layer"
                    )
                })?;
            ensure!(
                status == PayloadStatusEnum::Valid,
                "payload status of backfilled finalized block at height `{height}` was \
                not valid: {status}",
            );
            floor = Some((block.height(), block.digest(), span));
        }

        let Some((height, digest, span)) = floor else {
            return Ok(());
        };
        let target = self
            .notarized_tree
            .local_state()
            .update_finalized(height, digest);
        let response = submit_forkchoice_update(&self.execution_node, span, target, None)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed finalizing the backfilled finalized floor at height `{height}` \
                    on the execution layer"
                )
            })?;
        if !response.is_valid() {
            bail!(
                "forkchoice update finalizing the backfilled finalized floor at height \
                `{height}` was not valid: {}",
                response.payload_status,
            );
        }
        self.notarized_tree.set_local_state(target);
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

    /// Re-affirms the tracked forkchoice state, unless the scheduler finds
    /// real work to do first.
    #[instrument(skip_all)]
    fn send_forkchoice_update_heartbeat(&mut self) -> eyre::Result<()> {
        // The heartbeat timer is only armed while no other execution-layer
        // work is active or queued.
        if !self.execution_task.is_none() {
            return Ok(());
        }

        self.start_next_execution_task()?;
        if !self.execution_task.is_none() {
            return Ok(());
        }

        let target = self.notarized_tree.local_state();
        if self.is_stale_forkchoice(target)? {
            return Ok(());
        }
        let fut = execute_forkchoice(self.execution_node.clone(), Span::current(), target, None);
        self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Heartbeat, fut));
        Ok(())
    }

    fn handle_message(&mut self, message: Message) {
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

    /// Picks the next execution task: consensus request, finalized
    /// deliveries, the forkchoice update finalizing them, notarized
    /// deliveries, the forkchoice update moving the head. Finality goes
    /// first so a long notarized run never holds up acknowledgements;
    /// deliveries go before the update so one update covers a whole run.
    #[instrument(
        skip_all,
        fields(
            current.head_height = %self.notarized_tree.local_state().head.0,
            current.head_digest = %self.notarized_tree.local_state().head.1,
            current.finalized_height = %self.notarized_tree.local_state().finalized.0,
            current.finalized_digest = %self.notarized_tree.local_state().finalized.1,
        ),
        err,
    )]
    fn start_next_execution_task(&mut self) -> eyre::Result<()> {
        if !self.execution_task.is_none() {
            return Ok(());
        }

        // Latency critical requests come first: consensus is waiting on
        // them to vote on or propose a block.
        //
        // Fail fast if validation or building cannot start immediately, unless
        // the parent is expected to be made available to the execution layer
        // imminently.
        match self.pending_consensus_request.take() {
            Some((round, ConsensusRequest::Verify(request))) => {
                let parent = request.block.parent_digest();
                if self.notarized_tree.is_known(parent) || !self.is_convergence_target(parent) {
                    let fut = execute_validation(self.execution_node.clone(), request);
                    self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Verify, fut));
                    return Ok(());
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
                // parent, so the parent must be known to the execution
                // layer. The update moves the head onto it if it is not
                // there yet: the parent is the pending head consensus
                // reported, so there is no convergence to fight.
                match self.build_target(build.digest) {
                    BuildTarget::Ready(target) => {
                        if self.is_stale_forkchoice(target)? {
                            info!(
                                build.parent = %build.digest,
                                "tracked finality is below the execution layer's; dropping the build",
                            );
                        } else {
                            let fut = execute_forkchoice(
                                self.execution_node.clone(),
                                cause.clone(),
                                target,
                                Some((cause, build)),
                            );
                            self.set_execution_task(ExecutionTask::new(
                                ExecutionTaskType::Build,
                                fut,
                            ));
                            return Ok(());
                        }
                    }
                    BuildTarget::Stale => {
                        info!(
                            finalized = %self.notarized_tree.delivered_finalized().1,
                            build.parent = %build.digest,
                            "finality advanced past the parent to build on, dropping the build",
                        );
                    }
                    // Reschedules the request; the actor will not spin on
                    // `start_next_execution_request` as long as it remains
                    // scheduled before the select! in the select-loop (some
                    // other event needs to take place first; ideally the
                    // result of the convergence target we are falling through
                    // to).
                    BuildTarget::Unknown if self.is_convergence_target(build.digest) => {
                        self.pending_consensus_request =
                            Some((round, ConsensusRequest::Build { cause, build }));
                    }
                    BuildTarget::Unknown => {
                        info!(
                            execution.head_hash = %self.notarized_tree.local_state().head.1,
                            build.parent = %build.digest,
                            "not ready to build new block, dropping it",
                        );
                    }
                }
            }
            None => {}
        }

        // Finalizations are delivered in order and acknowledged so that the
        // marshal actor can make progress. Every finalized block is
        // delivered, whether or not the execution layer is thought to know
        // it: a known block is answered `VALID` from its caches without
        // being executed again.
        if let Some(request) = self.pending_finalizations.pop_front() {
            let fut = execute_finalization(self.execution_node.clone(), request);
            self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Finalize, fut));
            return Ok(());
        }

        // With the finalized queue drained, delivered finalized blocks that
        // await their acknowledgement are locked in before notarized
        // convergence continues. The update takes the head target that is
        // known at this point along.
        if !self.pending_acknowledgements.is_empty() && self.start_forkchoice_update()? {
            return Ok(());
        }

        if let Some(block) = self.notarized_tree.next_to_deliver(self.context.current()) {
            let fut = execute_delivery(self.execution_node.clone(), block);
            self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Deliver, fut));
            return Ok(());
        }

        self.start_forkchoice_update()?;
        Ok(())
    }

    /// Starts the forkchoice update onto the next target, if any; returns
    /// whether it did.
    fn start_forkchoice_update(&mut self) -> eyre::Result<bool> {
        let Some(target) = self.next_forkchoice_target()? else {
            return Ok(false);
        };
        if self.is_stale_forkchoice(target)? {
            // Nothing to submit: the execution layer is past this finality
            // already. The tracked state catches up to it.
            self.notarized_tree.set_local_state(target);
            self.acknowledge_finalized();
            return Ok(false);
        }
        let fut = execute_forkchoice(self.execution_node.clone(), Span::current(), target, None);
        self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Forkchoice, fut));
        Ok(true)
    }

    /// Whether `target` finalizes below the execution layer's own finality,
    /// so that submitting it would move finality backwards. The tracked
    /// state trails execution-layer finality after a snapshot restore until
    /// the marshal actor's re-deliveries catch up. A tracked finalized block
    /// the execution layer's canonical chain contradicts is fatal.
    fn is_stale_forkchoice(&self, target: LocalState) -> eyre::Result<bool> {
        let execution_finalized = self.execution_node.finalized_num_hash();
        if execution_finalized.number < target.finalized.0.get() {
            return Ok(false);
        }
        let canonical_digest = self
            .execution_node
            .canonical_block_hash(target.finalized.0.get())
            .wrap_err_with(|| {
                format!(
                    "failed reading canonical execution block hash at the tracked \
                    finalized height `{}`",
                    target.finalized.0,
                )
            })?
            .ok_or_else(|| {
                eyre!(
                    "no canonical execution block hash at the tracked finalized height \
                    `{}`, even though it is at or below the execution layer's finalized \
                    height `{}`",
                    target.finalized.0,
                    execution_finalized.number,
                )
            })?;
        ensure!(
            canonical_digest == target.finalized.1.0,
            "tracked finalized block `{}` at height `{}` conflicts with the execution \
            layer's canonical block `{canonical_digest}` at the same height, which the \
            execution layer already considers final; two different blocks must never be \
            finalized at the same height",
            target.finalized.1,
            target.finalized.0,
        );
        Ok(execution_finalized.number > target.finalized.0.get())
    }

    /// The next forkchoice state, if it differs from the tracked one: the
    /// delivered finalized block, and the highest delivered block on the
    /// pending head's ancestry. A head the tree cannot place is checked
    /// against the canonical chain and moved onto the finalized block if it
    /// does not descend from it.
    fn next_forkchoice_target(&self) -> eyre::Result<Option<LocalState>> {
        let local = self.notarized_tree.local_state();
        let (finalized_height, finalized_digest) = self.notarized_tree.delivered_finalized();
        let mut target = local.update_finalized(finalized_height, finalized_digest);
        if let Some((height, digest)) = self.notarized_tree.next_head(self.context.current()) {
            target = target.update_head(height, digest);
        }

        if target.finalized != local.finalized && target.head == local.head {
            let canonical_hash = self
                .execution_node
                .canonical_block_hash(finalized_height.get())
                .wrap_err_with(|| {
                    format!(
                        "failed reading canonical execution block hash at finalized \
                        block height `{finalized_height}`",
                    )
                })?;
            let head_descends_from_finalized = canonical_hash == Some(finalized_digest.0);
            if !head_descends_from_finalized {
                target = target.update_head(finalized_height, finalized_digest);
            }
        }

        Ok((target != local).then_some(target))
    }

    /// The forkchoice state a build on top of `parent` is registered with:
    /// the head on the parent, finality on the delivered finalized block.
    fn build_target(&self, parent: Digest) -> BuildTarget {
        let Some(height) = self.notarized_tree.known_height(parent) else {
            return BuildTarget::Unknown;
        };
        let (finalized_height, finalized_digest) = self.notarized_tree.delivered_finalized();
        let target = self
            .notarized_tree
            .local_state()
            .update_finalized(finalized_height, finalized_digest)
            .update_head(height, parent);
        if target.head.1 == parent {
            BuildTarget::Ready(target)
        } else {
            BuildTarget::Stale
        }
    }
}

/// Whether a build can be registered on its parent, see
/// [`Actor::build_target`].
enum BuildTarget {
    /// The forkchoice state to register the build with.
    Ready(LocalState),
    /// The parent is not known to the execution layer (yet).
    Unknown,
    /// Finality advanced past the parent: the build can never be
    /// registered.
    Stale,
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

#[derive(Debug, Clone, Copy)]
enum ExecutionTaskType {
    Heartbeat,
    Verify,
    Build,
    Deliver,
    Finalize,
    Forkchoice,
}

impl ExecutionTaskType {
    fn name(self) -> &'static str {
        match self {
            Self::Heartbeat => "heartbeat",
            Self::Verify => "verify",
            Self::Build => "build",
            Self::Deliver => "deliver",
            Self::Finalize => "finalize",
            Self::Forkchoice => "forkchoice",
        }
    }
}

struct ExecutionTask {
    task_type: ExecutionTaskType,
    span: Span,
    started_at: Instant,
    fut: BoxFuture<'static, ExecutionTaskOutcome>,
}

impl ExecutionTask {
    fn new<F>(task_type: ExecutionTaskType, fut: F) -> Self
    where
        F: Future<Output = ExecutionTaskOutcome> + Send + 'static,
    {
        Self {
            task_type,
            span: Span::none(),
            started_at: Instant::now(),
            fut: fut.boxed(),
        }
    }
}

struct ExecutionTaskFinished {
    task_type: ExecutionTaskType,
    span: Span,
    started_at: Instant,
    outcome: ExecutionTaskOutcome,
}

impl ExecutionTaskFinished {
    fn target(&self) -> Option<LocalState> {
        match &self.outcome {
            ExecutionTaskOutcome::Forkchoice { target, .. } => Some(*target),
            ExecutionTaskOutcome::Validated { .. }
            | ExecutionTaskOutcome::Delivered { .. }
            | ExecutionTaskOutcome::FinalizedDelivered { .. } => None,
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
            span,
            started_at: self.started_at,
            outcome,
        })
    }
}

/// What an execution task got back from its single engine call, reported
/// uninterpreted; [`Actor::handle_execution_task_finished`] decides.
enum ExecutionTaskOutcome {
    /// The request travels back for its verdict; `None` if the subscriber
    /// went away meanwhile. The status comes with the time taken.
    Validated {
        request: Option<VerifyBlockRequest>,
        status: eyre::Result<(PayloadStatusEnum, Duration)>,
    },
    /// A notarized block was delivered through a bare new-payload request.
    Delivered {
        digest: Digest,
        status: eyre::Result<PayloadStatusEnum>,
    },
    /// The request travels back for its acknowledgement.
    FinalizedDelivered {
        request: FinalizedBlockRequest,
        status: eyre::Result<PayloadStatusEnum>,
    },
    /// The raw answer to a forkchoice update, together with the build
    /// subscriber it carried.
    Forkchoice {
        target: LocalState,
        build: Option<(Span, oneshot::Sender<TempoBuiltPayload>)>,
        response: eyre::Result<ForkchoiceUpdated>,
    },
}

impl ExecutionTaskOutcome {
    fn name(&self) -> &'static str {
        match self {
            Self::Validated { .. } => "validated",
            Self::Delivered { .. } => "delivered",
            Self::FinalizedDelivered { .. } => "finalized-delivered",
            Self::Forkchoice { .. } => "forkchoice",
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

/// Submits a forkchoice update targeting `target`, with the build's payload
/// attributes if the build is still wanted. A no-op update is submitted
/// regardless (heartbeats rely on this).
#[instrument(
    skip_all,
    parent = &cause,
    fields(
        head_block_hash = %target.head.1,
        head_block_height = %target.head.0,
        finalized_block_hash = %target.finalized.1,
        finalized_block_height = %target.finalized.0,
        build = build.is_some(),
    ),
)]
async fn execute_forkchoice(
    execution_node: impl ExecutionLayer,
    cause: Span,
    target: LocalState,
    build: Option<(Span, Build)>,
) -> ExecutionTaskOutcome {
    let build = build.filter(|(_, build)| {
        if build.response.is_canceled() {
            info!("dropping payload build request: the subscriber went away while it was queued");
            return false;
        }
        true
    });
    let (build, attributes) = match build {
        Some((
            cause,
            Build {
                round: _,
                digest: _,
                attributes,
                response,
            },
        )) => (Some((cause, response)), Some(*attributes)),
        None => (None, None),
    };

    let response = submit_forkchoice_update(&execution_node, cause, target, attributes).await;
    ExecutionTaskOutcome::Forkchoice {
        target,
        build,
        response,
    }
}

/// Delivers a finalized block through a bare new-payload request.
#[instrument(
    skip_all,
    parent = &request.cause,
    fields(
        block.digest = %request.block.digest(),
        block.height = %request.block.height(),
    ),
)]
async fn execute_finalization(
    execution_node: impl ExecutionLayer,
    request: FinalizedBlockRequest,
) -> ExecutionTaskOutcome {
    // The validator set can be omitted for finalized blocks.
    let status = deliver_block(&execution_node, request.block.clone(), None).await;
    ExecutionTaskOutcome::FinalizedDelivered { request, status }
}

/// Delivers a notarized block through a bare new-payload request.
#[instrument(
    skip_all,
    fields(
        block.digest = %block.digest(),
        block.height = %block.height(),
    ),
)]
async fn execute_delivery(
    execution_node: impl ExecutionLayer,
    block: Arc<Block>,
) -> ExecutionTaskOutcome {
    let digest = block.digest();
    let status = deliver_block(&execution_node, block, None).await;
    ExecutionTaskOutcome::Delivered { digest, status }
}

/// Probes the execution layer with the block to validate and hands the
/// request back with the answer. A subscriber that went away abandons the
/// request; the recorded body still serves convergence.
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
    mut request: VerifyBlockRequest,
) -> ExecutionTaskOutcome {
    let validation_start = Instant::now();
    let work = deliver_block(
        &execution_node,
        request.block.clone(),
        request.validator_set.clone(),
    );
    futures::pin_mut!(work);

    let status = select! {
        biased;

        status = &mut work => status
            .map(|status| (status, validation_start.elapsed()))
            .wrap_err("failed sending new-payload request to execution layer to validate block"),

        // Stops waiting for the verdict; the execution layer may still
        // process the new-payload request. The notarized tree
        // keeps driving the execution layer independently of this request's
        // lifetime.
        () = request.response.cancellation() => {
            info!(
                "verification subscriber went away before the block was \
                validated; abandoning the request"
            );
            return ExecutionTaskOutcome::Validated {
                request: None,
                status: Err(eyre!("verification subscriber went away")),
            };
        }
    };

    ExecutionTaskOutcome::Validated {
        request: Some(request),
        status,
    }
}

/// Submits `block` to the execution layer through a new-payload request and
/// returns the reported payload status.
async fn deliver_block(
    execution_node: &impl ExecutionLayer,
    block: Arc<Block>,
    validator_set: Option<Vec<B256>>,
) -> eyre::Result<PayloadStatusEnum> {
    let (block, block_access_list) = Arc::unwrap_or_clone(block).into_parts();
    let payload_status = execution_node
        .new_payload(TempoExecutionData {
            block,
            block_access_list,
            validator_set,
        })
        .await
        .wrap_err("failed sending new-payload request to execution layer")?;
    if payload_status.is_valid() {
        info!(%payload_status, "execution layer reported payload status");
    } else {
        warn!(%payload_status, "execution layer reported payload status");
    }
    Ok(payload_status.status)
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

/// Submits the forkchoice update and returns the raw response. Whether to
/// submit is decided by the caller.
#[instrument(
    skip_all,
    parent = &cause,
    fields(
        head_block_hash = %canonicalized.head.1,
        head_block_height = %canonicalized.head.0,
        finalized_block_hash = %canonicalized.finalized.1,
        finalized_block_height = %canonicalized.finalized.0,
    ),
    err(level = Level::WARN),
)]
async fn submit_forkchoice_update(
    execution_node: &impl ExecutionLayer,
    cause: Span,
    canonicalized: LocalState,
    attrs: Option<TempoPayloadAttributes>,
) -> eyre::Result<ForkchoiceUpdated> {
    let fcu_response = execution_node
        .fork_choice_updated(canonicalized.to_forkchoice_state(), attrs)
        .await
        .wrap_err("failed requesting execution layer to update forkchoice state")?;
    Ok(fcu_response)
}
