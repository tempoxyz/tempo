//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent ingests (monotonically) increasing finalized blocks from the
//! marshal actor and forwards them to the execution layer.
//!
//! In addition, the agent:
//!
//! 1. tracks the parent selected by the latest consensus context,
//! 2. drives the execution layer toward that convergence target,
//! 3. and validates and builds blocks.
//!
//! # Delivery and forkchoice are separate steps
//!
//! `newPayload` delivers a block body and never moves the head; notarized
//! blocks, finalized blocks, and validation probes are all deliveries.
//! Outside builds, `forkchoiceUpdated` commits the latest delivered finalization
//! and selects the convergence target as HEAD only after its own `newPayload`
//! returned `VALID` without an intervening finalized-tip update. Otherwise HEAD
//! is the delivered finalized block. The update runs on a later iteration.
//! Finalized blocks are acknowledged to the marshal actor once the update
//! finalizing them is accepted. Finality work is scheduled ahead of builds,
//! verification, and notarized convergence.
//!
//! Verification probes the candidate first. SYNCING drives ancestor deliveries
//! backward until an engine answer or finality stops the walk, then the candidate
//! is re-probed for its verdict. Builds fetch and deliver their parent, then
//! immediately issue the forkchoice update with payload attributes on VALID,
//! using the finalized state captured when the build was scheduled.
//!
//! # Execution failures
//!
//! Failed pending-head deliveries are retried. Invalid candidates are rejected;
//! other verification and build failures end the affected request. Failed
//! finalized deliveries and failed or non-`VALID` forkchoice updates are fatal.

use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

use alloy_rpc_types_engine::{ForkchoiceState, ForkchoiceUpdated, PayloadId, PayloadStatusEnum};
use commonware_consensus::{
    CertifiableBlock as _, Heightable as _,
    marshal::Update,
    types::{Height, Round, View},
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
    future::{BoxFuture, FusedFuture as _, MaybeDone, maybe_done},
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

/// How often to probe whether the execution layer is ready to process blocks.
const EXECUTION_LAYER_READY_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Pause before restarting pending-head delivery at the finalized boundary.
const CONVERGENCE_BOUNDARY_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Back off after a rejected pending-head delivery or transport failure.
const CONVERGENCE_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Delivery count at which queued finalized blocks are committed by FCU.
/// Counts verification, convergence, finalized, and build parent deliveries.
/// Periodic FCUs let the execution layer persist and prune relative to its
/// canonical head while finalized catchup continues.
const DELIVERIES_PER_FORKCHOICE_UPDATE: usize = 8;

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
    /// Armed when no execution task or finalized delivery is pending.
    fcu_heartbeat_timer: OptionFuture<BoxFuture<'static, ()>>,

    /// Finalized blocks waiting to be delivered to the execution layer.
    pending_finalizations: VecDeque<FinalizedBlockRequest>,

    /// Finalized blocks the execution layer has accepted, waiting for the
    /// forkchoice update that finalizes them before they are acknowledged
    /// to the marshal actor. In height order.
    pending_acknowledgements: VecDeque<FinalizedBlockRequest>,

    /// New-payload requests the execution layer may have executed since the
    /// last forkchoice update, see [`DELIVERIES_PER_FORKCHOICE_UPDATE`].
    deliveries_since_forkchoice: usize,

    /// The newest round observed through build and verify contexts or
    /// finalized-tip reports. Requests can arrive out of order; an older
    /// round's parent must not supersede a newer one's. Retained independently
    /// of request cancellation and completion.
    latest_consensus_round: Round,

    /// The latest consensus request, keyed by its round. Verification stays
    /// here while its next block is fetched or executed; builds leave the slot
    /// when scheduled. A newer request replaces the slot.
    pending_consensus_request: Option<(Round, ConsensusRequest)>,

    /// Independently delivers the selected pending head through the same walk.
    convergence: Option<ConvergenceWalk>,
    convergence_retry: OptionFuture<BoxFuture<'static, ()>>,

    /// The single execution task. A build owns the slot from fetching its parent
    /// through delivery and the forkchoice update that starts the payload job.
    execution_task: OptionFuture<ExecutionTask>,

    /// The pending head's body, or an ancestor requested by its delivery walk.
    /// Verification has its own fetch so either walk can wait independently.
    pending_convergence_block: OptionFuture<PendingNotarizedBlock>,

    /// Payload build jobs currently being driven to completion.
    ///
    /// Each job resolves a payload from the execution layer's payload builder
    /// and delivers it to the subscriber that requested the build. If the
    /// subscriber dropped its receiver in the meantime, the built payload is
    /// discarded. A delivered block is handed back as the job's output so
    /// that its body can be retained for a later build: the proposer is never
    /// asked to verify its own proposal, so no validation request delivers it.
    payload_jobs: FuturesUnordered<BoxFuture<'static, Option<Arc<Block>>>>,

    /// The last accepted forkchoice and the two distinct finality watermarks.
    local_state: LocalState,
    delivered_finalized: (Height, Digest),
    network_finalized_tip: (Round, Height, Digest),

    /// The parent selected by the latest consensus context, independently of
    /// which request selected it or whether that request is still active.
    pending_head: PendingHead,

    /// Own proposals have not been delivered through verification. Retain their
    /// bodies until finality so a later build can deliver its selected parent.
    built_blocks: HashMap<Digest, Arc<Block>>,

    /// The node's ed25519 public key if the node is participating in
    /// consensus. Not set if not, for example for followers.
    public_key: Option<PublicKey>,

    metrics: Metrics,
}

#[derive(Clone)]
struct Metrics {
    /// Number of finalized blocks whose proposer matches this node's public key.
    finalized_blocks_proposed_by_self: commonware_runtime::telemetry::metrics::Registered<Counter>,
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
            finalization_lag,
            convergence_depth,
        }
    }

    fn observe(&self, local: LocalState, finalized: Height, pending_height: Option<Height>) {
        self.finalization_lag
            .set(finalized.get().saturating_sub(local.finalized.0.get()) as i64);
        if let Some(height) = pending_height {
            self.convergence_depth
                .set(height.get() as i64 - local.head.0.get() as i64);
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
        // the re-delivery to line up. Already-finalized blocks are delivered
        // again and acknowledged without waiting for another forkchoice
        // update (see [`Self::handle_finalized_delivered`]).
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
            deliveries_since_forkchoice: 0,
            latest_consensus_round: finalized_tip.0,
            pending_consensus_request: None,
            convergence: None,
            convergence_retry: OptionFuture::none(),

            execution_task: OptionFuture::none(),
            pending_convergence_block: OptionFuture::none(),
            payload_jobs: FuturesUnordered::new(),

            local_state,
            delivered_finalized: local_state.finalized,
            network_finalized_tip: finalized_tip,
            pending_head: PendingHead::finalized(finalized_tip),
            built_blocks: HashMap::new(),

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
            let canonicalized = self.local_state;
            info!(
                finalized_height = %canonicalized.finalized.0,
                finalized_digest = %canonicalized.finalized.1,
                head_height = %canonicalized.head.0,
                head_digest = %canonicalized.head.1,
                "entering executor loop",
            );
        });

        loop {
            self.prune_finalized();
            self.metrics.observe(
                self.local_state,
                self.network_finalized_tip.1,
                self.pending_head.height,
            );
            self.prepare_convergence();

            self.start_next_execution_task();
            self.update_block_fetches();
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

                canceled = async {
                    if let Some((_, ConsensusRequest::Verify(pending))) = &mut self.pending_consensus_request {
                        select! {
                            () = pending.request.cancellation() => true,
                            () = async {
                                match &mut pending.step {
                                    VerificationStep::FetchAncestor { fetch, .. }
                                        if !fetch.is_terminated() => fetch.await,
                                    _ => std::future::pending().await,
                                }
                            } => false,
                        }
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if canceled {
                        self.pending_consensus_request = None;
                    }
                }
                () = &mut self.convergence_retry => {
                    if let Some(walk) = self.convergence.as_mut() {
                        walk.reprobe();
                    }
                }

                Some(delivered) = self.payload_jobs.next() => {
                    if let Some(block) = delivered {
                        // The application received the built block and may
                        // propose it; keep the body so the block can be
                        // forwarded to the execution layer once a later
                        // context proves it notarized.
                        self.built_blocks.insert(block.digest(), block);
                    }
                }

                (digest, round, block) = &mut self.pending_convergence_block => {
                    self.handle_fetched_convergence_block(digest, round, block);
                }

                msg = self.mailbox.next() => {
                    let Some(msg) = msg else { break; };
                    self.handle_message(msg);
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

    /// Processes a finished execution task: records deliveries and forkchoice,
    /// acknowledges finalized blocks, and resolves consensus requests.
    /// Outcomes are applied before scheduling another execution task. Consensus
    /// contexts and network finality may change while a task is running.
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
            ExecutionTaskOutcome::VerificationDelivered {
                round,
                digest,
                status,
            } => {
                let _logged = self.handle_verification_delivered(round, digest, status);
            }
            ExecutionTaskOutcome::ConvergenceDelivered {
                walk,
                finalized_round,
                status,
            } => {
                // Failed convergence deliveries are logged and retried.
                let _logged = self.handle_convergence_delivered(walk, finalized_round, status);
            }
            ExecutionTaskOutcome::FinalizedDelivered { request, status } => {
                self.handle_finalized_delivered(request, status)?;
                self.retry_convergence();
            }
            ExecutionTaskOutcome::Build {
                delivery_attempted,
                finalized_round,
                result,
            } => self.handle_build(delivery_attempted, finalized_round, result)?,
            ExecutionTaskOutcome::Forkchoice(ForkchoiceOutcome {
                target,
                build,
                response,
            }) => self.handle_forkchoice_response(target, build, response)?,
        }
        Ok(())
    }

    #[instrument(skip_all, err)]
    fn handle_build(
        &mut self,
        delivery_attempted: bool,
        finalized_round: Round,
        result: eyre::Result<ForkchoiceOutcome>,
    ) -> eyre::Result<()> {
        if delivery_attempted {
            self.deliveries_since_forkchoice += 1;
        }
        match result {
            Ok(forkchoice) => {
                self.deliveries_since_forkchoice = 0;
                // A successful build delivered its exact parent with VALID.
                self.record_executed_convergence_target(forkchoice.target.head, finalized_round);
                self.handle_forkchoice_response(
                    forkchoice.target,
                    forkchoice.build,
                    forkchoice.response,
                )?;
            }
            Err(error) => warn!(%error, "build attempt failed"),
        }
        Ok(())
    }

    /// Advances only the verification that expected this execution result.
    #[instrument(skip_all, fields(%round, %digest), err(level = Level::WARN))]
    fn handle_verification_delivered(
        &mut self,
        round: Round,
        digest: Digest,
        status: eyre::Result<(PayloadStatusEnum, Duration)>,
    ) -> eyre::Result<()> {
        self.deliveries_since_forkchoice += 1;
        let Some((active_round, ConsensusRequest::Verify(pending))) =
            &mut self.pending_consensus_request
        else {
            return Ok(());
        };
        let VerificationStep::Submit {
            digest: expected,
            parent_round,
            parent_digest,
            parent_height,
        } = pending.step
        else {
            return Ok(());
        };
        if *active_round != round || expected != digest {
            return Ok(());
        }
        let (status, duration) = match status {
            Ok(result) => result,
            Err(error) => {
                self.pending_consensus_request = None;
                return Err(error.wrap_err("failed delivering verification block"));
            }
        };
        pending.duration += duration;
        let verdict = match status {
            PayloadStatusEnum::Valid => {
                if pending.is_candidate(digest) {
                    Some(pending.duration)
                } else {
                    pending.step = VerificationStep::Start;
                    return Ok(());
                }
            }
            PayloadStatusEnum::Invalid { validation_error } => {
                info!(
                    validation_error,
                    "execution layer rejected the verification block"
                );
                if pending.is_candidate(digest) {
                    None
                } else {
                    pending.step = VerificationStep::Start;
                    return Ok(());
                }
            }
            PayloadStatusEnum::Syncing => {
                if parent_height <= self.network_finalized_tip.1 {
                    if parent_digest == self.network_finalized_tip.2 {
                        if self.delivered_finalized.0 >= self.network_finalized_tip.1 {
                            pending.step = VerificationStep::Start;
                        } else {
                            pending.step = VerificationStep::WaitForFinalization {
                                height: self.network_finalized_tip.1,
                            };
                        }
                        return Ok(());
                    } else {
                        info!(
                            %parent_digest,
                            %parent_height,
                            finalized_digest = %self.network_finalized_tip.2,
                            finalized_height = %self.network_finalized_tip.1,
                            "verification ancestry does not reach the finalized tip"
                        );
                        None
                    }
                } else {
                    pending.step = VerificationStep::FetchAncestor {
                        height: parent_height,
                        fetch: maybe_done(
                            fetch_block(
                                self.execution_node.clone(),
                                self.marshal.clone(),
                                parent_digest,
                                parent_round,
                            )
                            .boxed(),
                        ),
                    };
                    return Ok(());
                }
            }
            PayloadStatusEnum::Accepted => {
                self.pending_consensus_request = None;
                bail!("payload was accepted without execution while verifying block");
            }
        };
        if pending
            .request
            .response
            .take()
            .expect("verification has a subscriber")
            .send(verdict)
            .is_err()
        {
            info!("verification subscriber went away before the verdict was delivered");
        }
        self.pending_consensus_request = None;
        Ok(())
    }

    /// Advances delivery toward the pending head, retrying rejected targets.
    #[instrument(skip_all, err(level = Level::WARN))]
    fn handle_convergence_delivered(
        &mut self,
        mut walk: ConvergenceWalk,
        finalized_round: Round,
        status: eyre::Result<PayloadStatusEnum>,
    ) -> eyre::Result<()> {
        // SYNCING blocks may execute later as their missing ancestors arrive.
        self.deliveries_since_forkchoice += 1;
        let status = match status {
            Ok(result) => result,
            Err(error) => {
                self.pause_convergence(walk);
                return Err(error.wrap_err("failed delivering convergence block"));
            }
        };
        let digest = walk.cursor.digest();
        match status {
            PayloadStatusEnum::Valid => {
                self.record_executed_convergence_target(
                    (walk.cursor.height(), digest),
                    finalized_round,
                );
                if !walk.is_target() {
                    walk.reprobe();
                    self.retain_convergence(walk);
                }
            }
            PayloadStatusEnum::Invalid { validation_error } => {
                info!(%digest, validation_error, "execution layer rejected the block");
                if walk.is_target() {
                    self.pause_convergence(walk);
                } else {
                    walk.reprobe();
                    self.retain_convergence(walk);
                }
            }
            PayloadStatusEnum::Syncing => {
                if digest == self.pending_head.digest {
                    self.pending_head.executed = None;
                }
                walk.step = ConvergenceStep::Parent;
                self.retain_convergence(walk);
            }
            PayloadStatusEnum::Accepted => {
                self.pause_convergence(walk);
                bail!("payload was accepted without execution while delivering block");
            }
        };
        Ok(())
    }

    fn retain_convergence(&mut self, walk: ConvergenceWalk) {
        if walk.target.digest() == self.pending_head.digest {
            self.convergence = Some(walk);
        }
    }

    fn pause_convergence(&mut self, mut walk: ConvergenceWalk) {
        walk.step = ConvergenceStep::Retry;
        if walk.target.digest() == self.pending_head.digest {
            self.convergence = Some(walk);
            self.convergence_retry
                .replace(self.context.sleep(CONVERGENCE_RETRY_INTERVAL).boxed());
        }
    }

    /// Only SYNCING asks for an ancestor. Finalized history is delivered by the
    /// finalization pipeline, even when its boundary advances during a fetch.
    fn prepare_convergence(&mut self) {
        if let Some(walk) = &mut self.convergence {
            if walk.step == ConvergenceStep::Parent
                && (walk.parent().1 == self.network_finalized_tip.2
                    || walk.cursor.height().get().saturating_sub(1)
                        <= self.network_finalized_tip.1.get())
            {
                walk.step = ConvergenceStep::Retry;
            }
            if walk.step == ConvergenceStep::Retry && self.convergence_retry.is_none() {
                self.convergence_retry.replace(
                    self.context
                        .sleep(CONVERGENCE_BOUNDARY_RETRY_INTERVAL)
                        .boxed(),
                );
            }
        }
    }

    fn retry_convergence(&mut self) {
        if let Some(walk) = &mut self.convergence
            && walk.step == ConvergenceStep::Retry
        {
            walk.reprobe();
            self.convergence_retry = OptionFuture::none();
        }
    }

    /// Retains only an exact-target VALID response whose delivery did not
    /// overlap a newer network finalized tip.
    fn record_executed_convergence_target(
        &mut self,
        block: (Height, Digest),
        finalized_round: Round,
    ) {
        if block.1 == self.pending_head.digest && finalized_round == self.network_finalized_tip.0 {
            self.pending_head.height = Some(block.0);
            self.pending_head.executed = Some(block);
        }
    }

    /// Finalized bodies arrive through the finalization pipeline. Other targets
    /// need their own VALID delivery before becoming HEAD.
    fn needs_head_delivery(&self) -> bool {
        self.pending_head.digest != self.network_finalized_tip.2
            && self.pending_head.executed.is_none()
    }

    fn prune_finalized(&mut self) {
        let (round, height, digest) = self.network_finalized_tip;
        debug_assert!(self.local_state.finalized.0 <= height);
        self.built_blocks.retain(|_, block| block.height() > height);
        if self.pending_head.round <= round && self.pending_head.digest != digest {
            self.pending_head = PendingHead::finalized(self.network_finalized_tip);
        }
        if self.pending_head.digest == digest {
            self.pending_head.height = Some(height);
        }
        if !self.needs_head_delivery()
            || self
                .convergence
                .as_ref()
                .is_some_and(|walk| walk.target.digest() != self.pending_head.digest)
        {
            self.convergence = None;
            self.convergence_retry = OptionFuture::none();
        }
    }

    /// An accepted forkchoice update becomes the tracked state (mutated only
    /// here), and so does a stale one that was not submitted (`None`). A
    /// rejected one is fatal: every target named is a block the execution
    /// layer accepted, so the executor's view of the execution layer has
    /// diverged from it. Finalized blocks the update covers are
    /// acknowledged; a build it carried is driven to completion.
    fn handle_forkchoice_response(
        &mut self,
        target: LocalState,
        build: Option<(Span, oneshot::Sender<TempoBuiltPayload>)>,
        response: Option<eyre::Result<ForkchoiceUpdated>>,
    ) -> eyre::Result<()> {
        let Some(response) = response else {
            // No update was submitted because the execution layer is ahead
            // of tracked finality. Advance the tracked state for replay and
            // acknowledgements; a skipped update cannot register a build.
            if build.is_some() {
                // Dropping the build's response channel signals the failure
                // to the subscriber.
                info!("tracked finality is below the execution layer's; dropping the build");
            }
            self.local_state = target;
            self.acknowledge_finalized();
            return Ok(());
        };
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

        self.local_state = target;
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

    /// A non-`VALID` answer is fatal. Otherwise the block becomes the next
    /// finalized target and is acknowledged once the forkchoice update
    /// finalizing it lands - or right away if the execution layer already
    /// finalized it (a re-delivery). The marshal actor delivers the
    /// finalized chain in order; that order is trusted, not checked.
    #[instrument(
        skip_all,
        fields(
            block.digest = %request.block.digest(),
            block.height = %request.block.height(),
        ),
        err,
    )]
    fn handle_finalized_delivered(
        &mut self,
        request: FinalizedBlockRequest,
        status: eyre::Result<PayloadStatusEnum>,
    ) -> eyre::Result<()> {
        let block = request.block.as_ref();
        debug_assert!(
            block.height() >= self.delivered_finalized.0,
            "finalized blocks are delivered in height order",
        );
        match status {
            Ok(PayloadStatusEnum::Valid) => {}
            Ok(status) => {
                bail!(
                    "payload status of finalized block `{}` at height `{}` was \
                    not valid: {status}",
                    block.digest(),
                    block.height(),
                );
            }
            Err(error) => {
                return Err(error.wrap_err(format!(
                    "failed delivering finalized block `{}` at height `{}`",
                    block.digest(),
                    block.height(),
                )));
            }
        }

        if block.height() > self.delivered_finalized.0 {
            self.delivered_finalized = (block.height(), block.digest());
        }
        self.deliveries_since_forkchoice += 1;
        if block.height() <= self.local_state.finalized.0 {
            // NOTE: this block is already final on the execution layer. This
            // can happen if marshal is anchored below the EL and delivers
            // finalized blocks the EL already knows about. In this case, it
            // makes sense to ACK immediately rather than wait for an FCU
            // sweep.
            // The execution layer confirms it is the block it finalized at
            // this height before it is acknowledged.
            let canonical = self
                .execution_node
                .canonical_block_hash(block.height().get())
                .wrap_err_with(|| {
                    format!(
                        "failed reading canonical execution block hash at finalized block \
                        height `{}`",
                        block.height(),
                    )
                })?;
            ensure!(
                canonical == Some(block.digest().0),
                "re-delivered finalized block `{}` at height `{}` conflicts with the \
                execution layer's canonical block `{canonical:?}` at the same height, which \
                the execution layer already considers final",
                block.digest(),
                block.height(),
            );
            self.acknowledge(request);
        } else {
            self.pending_acknowledgements.push_back(request);
        }
        Ok(())
    }

    /// Acknowledges the queued blocks the last accepted forkchoice update
    /// finalized. Deliveries are in chain order, so height identifies them.
    ///
    /// NOTE: the tracked state is the reference, not the execution layer's
    /// own finalized marker. An update whose head is a canonical ancestor of
    /// the execution layer's head is answered `VALID` without the marker
    /// moving, and after a restart every update is of that kind until the
    /// head catches up: waiting for the marker would never acknowledge and
    /// stall the marshal actor. The blocks are canonical and held by the
    /// execution layer either way; the marker follows with the first update
    /// that moves the head onto a new block.
    fn acknowledge_finalized(&mut self) {
        let finalized = self.local_state.finalized.0;
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
    fn acknowledge(&self, request: FinalizedBlockRequest) {
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
    /// before entering the loop, through the regular finalization tasks
    /// and their outcome handling, awaited in place. Every
    /// [`DELIVERIES_PER_FORKCHOICE_UPDATE`] delivered blocks, and at the
    /// floor, a forkchoice update finalizes them.
    #[instrument(skip_all, err)]
    async fn backfill_to_finalized_floor(&mut self) -> eyre::Result<()> {
        let start = self.local_state.finalized.0.get() + 1;
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
            let fut = execute_finalization(self.execution_node.clone(), request);
            self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Finalize, fut));
            let finished = (&mut self.execution_task).await;
            self.handle_execution_task_finished(finished)
                .wrap_err_with(|| {
                    format!(
                        "failed forwarding backfilled finalized block at height `{height}` \
                        to execution layer"
                    )
                })?;

            if (self.deliveries_since_forkchoice >= DELIVERIES_PER_FORKCHOICE_UPDATE
                || height == end)
                && self.start_forkchoice_update()
            {
                let finished = (&mut self.execution_task).await;
                self.handle_execution_task_finished(finished)
                    .wrap_err_with(|| {
                        format!(
                            "failed finalizing backfilled finalized block at height `{height}` \
                            on the execution layer"
                        )
                    })?;
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
        if self.execution_task.is_none() && self.pending_finalizations.is_empty() {
            self.arm_fcu_heartbeat_timer();
        } else {
            self.disarm_fcu_heartbeat_timer();
        }
    }

    /// Re-affirms the tracked forkchoice state, unless the scheduler finds
    /// real work to do first.
    #[instrument(skip_all)]
    fn send_forkchoice_update_heartbeat(&mut self) {
        // Give convergence priority over re-affirming the tracked state.
        if !self.execution_task.is_none() {
            return;
        }

        self.start_next_execution_task();
        if !self.execution_task.is_none() {
            return;
        }

        let target = self.local_state;
        let fut = execute_forkchoice(self.execution_node.clone(), Span::current(), target, None)
            .map(ExecutionTaskOutcome::Forkchoice);
        self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Heartbeat, fut));
    }

    fn handle_message(&mut self, message: Message) {
        let cause = message.cause;
        match message.command {
            Command::Build(build) => {
                self.record_convergence_target(build.context.round, build.context.parent);
                // Cancellation discards the build work, not its parent target.
                if build.response.is_canceled() {
                    return;
                }
                self.queue_consensus_request(
                    build.context.round,
                    ConsensusRequest::Build { cause, build },
                );
            }
            Command::Finalize(finalized) => match *finalized {
                Update::Tip(round, height, digest) => {
                    self.record_convergence_target(round, (round.view(), digest));
                    if round > self.network_finalized_tip.0 {
                        self.network_finalized_tip = (round, height, digest);
                        self.pending_head.executed = None;
                    }
                }
                Update::Block(block, acknowledgement) => {
                    self.pending_finalizations.push_back(FinalizedBlockRequest {
                        cause,
                        block,
                        acknowledgment: acknowledgement,
                    });
                }
            },
            Command::VerifyBlock(request) => {
                let VerifyBlock {
                    context,
                    block,
                    validator_set: _validator_set,
                    response,
                } = *request;
                self.record_convergence_target(context.round, context.parent);
                self.queue_consensus_request(
                    context.round,
                    ConsensusRequest::Verify(PendingVerification::new(VerificationRequest {
                        parent_round: Round::new(context.round.epoch(), context.parent.0),
                        cause,
                        block,
                        response: Some(response),
                    })),
                );
            }
        }
    }

    /// Queues a request unless the slot already holds the same or a newer
    /// round. The current execution task is allowed to finish.
    fn queue_consensus_request(&mut self, round: Round, request: ConsensusRequest) {
        match &self.pending_consensus_request {
            Some((queued, _)) if round <= *queued => {
                debug!(
                    %round,
                    queued_round = %queued,
                    "dropping consensus request at or below the queued round",
                );
            }
            Some(_) => {
                debug!(%round, "consensus request superseded a queued one");
                self.pending_consensus_request = Some((round, request));
            }
            None => self.pending_consensus_request = Some((round, request)),
        }
    }

    /// Records the newest observed consensus round and its convergence target.
    /// Build and verify requests select their parent; finalized-tip reports
    /// select the finalized block itself. A later round can select an older
    /// parent after nullifications, so the observed round orders targets.
    ///
    /// NOTE: the first proposed block of an epoch will always have a round
    /// `round = (<epoch>, <view>) = (<epoch>, 0)`. This is not a real round
    /// and hinges on the assumption that in order to verify or propose blocks
    /// for `<epoch>`, the node must have finalized the boundary block of
    /// `<epoch>`, which is exactly that parent block. In fact, a node will not
    /// start a simplex engine for `<epoch>` if it does not have this block.
    #[instrument(
        skip_all,
        fields(
            %round,
            latest_consensus_round = %self.latest_consensus_round,
            target.view = %target.0,
            target.digest = %target.1,
        ),
    )]
    fn record_convergence_target(&mut self, round: Round, target: (View, Digest)) {
        if round >= self.latest_consensus_round {
            info!("updating convergence target");
            self.latest_consensus_round = round;
            if self.pending_head.digest != target.1 {
                self.pending_head.digest = target.1;
                self.pending_head.height = None;
                self.pending_head.executed = None;
            }
            self.pending_head.round = Round::new(round.epoch(), target.0);
        }
    }

    /// Maintains the independent pending-head fetch. Verification fetches live
    /// in the consensus slot and are scheduled by their execution outcomes.
    fn update_block_fetches(&mut self) {
        let delivering = self
            .execution_task
            .as_ref()
            .is_some_and(|task| matches!(task.task_type, ExecutionTaskType::Deliver));

        // Give verification its first probe and avoid starting a second walk
        // for its candidate or parent while its ancestor fetch is pending.
        let verification_has_priority = self
            .execution_task
            .as_ref()
            .is_some_and(|task| matches!(task.task_type, ExecutionTaskType::Verify))
            || matches!(
                &self.pending_consensus_request,
                Some((_, ConsensusRequest::Verify(pending)))
                    if matches!(pending.step, VerificationStep::Start)
                        || (matches!(pending.step, VerificationStep::FetchAncestor { .. })
                            && (pending.request.block.digest() == self.pending_head.digest
                                || pending.request.block.parent_digest() == self.pending_head.digest))
            );
        let building = self
            .execution_task
            .as_ref()
            .is_some_and(|task| matches!(task.task_type, ExecutionTaskType::Build))
            || matches!(
                self.pending_consensus_request,
                Some((_, ConsensusRequest::Build { .. }))
            );
        let needs_parent = !building
            && !delivering
            && self.needs_head_delivery()
            && (!verification_has_priority || self.convergence.is_some());
        if needs_parent
            && self.convergence.is_none()
            && let Some(block) = self.built_blocks.get(&self.pending_head.digest)
        {
            self.pending_head.height = Some(block.height());
            self.convergence = Some(ConvergenceWalk::new(block.clone()));
        }
        let next = if needs_parent {
            match &self.convergence {
                Some(walk) if walk.step == ConvergenceStep::Parent => Some(walk.parent()),
                Some(_) => None,
                None => Some((self.pending_head.round, self.pending_head.digest)),
            }
        } else {
            None
        };
        update_block_fetch(
            &self.execution_node,
            &self.marshal,
            &mut self.pending_convergence_block,
            next,
        );
    }

    #[instrument(skip_all, fields(%digest, %round))]
    fn handle_fetched_parent(
        walk: &mut Option<ConvergenceWalk>,
        digest: Digest,
        round: Round,
        block: Option<Arc<Block>>,
    ) {
        if let Some(active) = walk {
            match block {
                Some(block) => {
                    active.cursor = block;
                    active.step = ConvergenceStep::Probe;
                }
                None => warn!("marshal dropped the ancestor subscription; retrying the fetch"),
            }
        }
    }

    #[instrument(skip_all, fields(%digest, %round))]
    fn handle_fetched_convergence_block(
        &mut self,
        digest: Digest,
        round: Round,
        block: Option<Arc<Block>>,
    ) {
        if self.convergence.is_some() {
            Self::handle_fetched_parent(&mut self.convergence, digest, round, block);
        } else if let Some(block) = block {
            if block.height() > self.network_finalized_tip.1 {
                self.pending_head.height = Some(block.height());
                self.convergence = Some(ConvergenceWalk::new(block));
            } else {
                self.pending_head = PendingHead::finalized(self.network_finalized_tip);
            }
        } else {
            warn!("marshal dropped the convergence target subscription; retrying the fetch");
        }
    }

    /// Schedules forkchoice updates, finalized deliveries, consensus work,
    /// then pending-head convergence. One FCU may commit several finalized
    /// deliveries.
    #[instrument(
        skip_all,
        fields(
            current.head_height = %self.local_state.head.0,
            current.head_digest = %self.local_state.head.1,
            current.finalized_height = %self.local_state.finalized.0,
            current.finalized_digest = %self.local_state.finalized.1,
        ),
    )]
    fn start_next_execution_task(&mut self) {
        if !self.execution_task.is_none() {
            return;
        }

        if self.start_forkchoice_update() {
            return;
        }

        // Deliver every finalized block in order, including blocks the EL
        // already knows. Prioritize pending finalizations so a continuous
        // stream of consensus requests cannot starve finalized catchup.
        if let Some(request) = self.pending_finalizations.pop_front() {
            let fut = execute_finalization(self.execution_node.clone(), request);
            self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Finalize, fut));
            return;
        }

        match self.pending_consensus_request.as_mut() {
            Some((round, ConsensusRequest::Verify(pending))) => {
                match pending.next_block(self.delivered_finalized.0) {
                    Poll::Ready(Some(block)) => {
                        let parent_round = if pending.is_candidate(block.digest()) {
                            pending.request.parent_round
                        } else {
                            let context = block.context();
                            Round::new(context.round.epoch(), context.parent.0)
                        };
                        pending.step = VerificationStep::Submit {
                            digest: block.digest(),
                            parent_round,
                            parent_digest: block.parent_digest(),
                            parent_height: Height::new(block.height().get().saturating_sub(1)),
                        };
                        let fut = execute_verification_delivery(
                            self.execution_node.clone(),
                            *round,
                            pending.request.cause.clone(),
                            block,
                        );
                        self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Verify, fut));
                        return;
                    }
                    Poll::Pending => {}
                    Poll::Ready(None) => {
                        warn!("verification parent fetch was dropped");
                        self.pending_consensus_request = None;
                    }
                }
            }
            Some((_, ConsensusRequest::Build { .. })) => {
                let Some((_, ConsensusRequest::Build { cause, build })) =
                    self.pending_consensus_request.take()
                else {
                    unreachable!()
                };
                let parent = build.context.parent.1;
                let parent_round = Round::new(build.context.round.epoch(), build.context.parent.0);
                let (finalized_round, _, finalized_digest) = self.network_finalized_tip;
                // A certified parent must be the finalized tip or come from
                // a later round. Decide eligibility before starting its fetch.
                if parent == finalized_digest || parent_round > finalized_round {
                    let target = self
                        .local_state
                        .update_finalized(self.delivered_finalized.0, self.delivered_finalized.1);
                    let fut = execute_build(
                        self.execution_node.clone(),
                        self.marshal.clone(),
                        cause,
                        target,
                        build,
                        self.built_blocks.get(&parent).cloned(),
                        self.network_finalized_tip.0,
                    );
                    self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Build, fut));
                    return;
                } else {
                    warn!(
                        parent: &cause,
                        %parent,
                        %parent_round,
                        %finalized_round,
                        %finalized_digest,
                        "dropping build whose parent is stale relative to finality",
                    );
                }
            }
            None => {}
        }

        if self
            .convergence
            .as_ref()
            .is_some_and(|walk| walk.step == ConvergenceStep::Probe)
        {
            let walk = self.convergence.take().expect("convergence walk is ready");
            let fut = execute_convergence_delivery(
                self.execution_node.clone(),
                walk,
                self.network_finalized_tip.0,
            );
            self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Deliver, fut));
        }
    }

    /// Starts the forkchoice update onto the next target, if any; returns
    /// whether it did.
    fn start_forkchoice_update(&mut self) -> bool {
        // Batch finalized deliveries until the queue drains or the batch
        // reaches its limit, then commit them before more consensus work.
        if !self.pending_finalizations.is_empty()
            && self.deliveries_since_forkchoice < DELIVERIES_PER_FORKCHOICE_UPDATE
        {
            return false;
        }

        // Keep counting deliveries until there is a changed forkchoice target
        // to commit.
        let Some(target) = self.next_forkchoice_target() else {
            return false;
        };
        self.deliveries_since_forkchoice = 0;
        let fut = execute_forkchoice(self.execution_node.clone(), Span::current(), target, None)
            .map(ExecutionTaskOutcome::Forkchoice);
        self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Forkchoice, fut));
        true
    }

    /// Uses the latest delivered finalized block for both fields unless the
    /// convergence target has a VALID delivery under the current network tip.
    fn next_forkchoice_target(&self) -> Option<LocalState> {
        let mut target = LocalState {
            head: self.delivered_finalized,
            finalized: self.delivered_finalized,
        };
        if let Some((height, digest)) = self.pending_head.executed {
            target = target.update_head(height, digest);
        }

        (target != self.local_state).then_some(target)
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

/// Looks up a block in the execution layer before subscribing through marshal.
#[instrument(skip_all, fields(%digest, %round))]
async fn fetch_block(
    execution_node: impl ExecutionLayer,
    marshal: impl Marshal,
    digest: Digest,
    round: Round,
) -> Option<Arc<Block>> {
    let block = match execution_node.block_by_digest(digest) {
        Ok(block) => block,
        Err(error) => {
            warn!(%error, "execution-layer block lookup failed; falling back to marshal");
            None
        }
    };
    if let Some(block) = block {
        Some(Arc::new(block))
    } else {
        marshal.subscribe_by_digest(digest, round).await.ok()
    }
}

struct FinalizedBlockRequest {
    cause: Span,
    block: Arc<Block>,
    acknowledgment: Exact,
}

/// An in-flight body fetch, keyed by digest and the round it was notarized in.
///
/// Resolves to the digest, the round, and the fetched block - `None` for the
/// block if the marshal actor dropped the channel before delivering it.
struct PendingNotarizedBlock {
    digest: Digest,
    round: Round,
    fetch: BoxFuture<'static, Option<Arc<Block>>>,
}

impl PendingNotarizedBlock {
    fn new(
        execution_node: &impl ExecutionLayer,
        marshal: &impl Marshal,
        round: Round,
        digest: Digest,
    ) -> Self {
        let fetch = fetch_block(execution_node.clone(), marshal.clone(), digest, round).boxed();
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
        std::task::Poll::Ready((self.digest, self.round, block))
    }
}

/// A request to build or verify a proposal.
enum ConsensusRequest {
    Verify(PendingVerification),
    Build { cause: Span, build: Box<Build> },
}

/// Verification stays in the consensus slot while one block is fetched or executed.
struct PendingVerification {
    /// Retains the original candidate throughout the walk.
    request: VerificationRequest,
    step: VerificationStep,
    duration: Duration,
}

enum VerificationStep {
    /// The retained candidate is ready to forward.
    Start,
    FetchAncestor {
        height: Height,
        fetch: MaybeDone<BoxFuture<'static, Option<Arc<Block>>>>,
    },
    /// Retains only metadata needed to continue after the EL response.
    Submit {
        digest: Digest,
        parent_round: Round,
        parent_digest: Digest,
        parent_height: Height,
    },
    /// Finalized history must be delivered before re-probing the candidate.
    WaitForFinalization { height: Height },
}

impl PendingVerification {
    fn new(request: VerificationRequest) -> Self {
        Self {
            request,
            step: VerificationStep::Start,
            duration: Duration::ZERO,
        }
    }

    fn is_candidate(&self, digest: Digest) -> bool {
        self.request.block.digest() == digest
    }

    /// Reconciles delivered finality and returns the next block ready to forward.
    fn next_block(&mut self, delivered_finalized: Height) -> Poll<Option<Arc<Block>>> {
        if matches!(
            self.step,
            VerificationStep::FetchAncestor { height, .. }
                | VerificationStep::WaitForFinalization { height }
                if height <= delivered_finalized
        ) {
            self.step = VerificationStep::Start;
        }
        if self
            .request
            .response
            .as_ref()
            .is_some_and(|response| response.is_canceled())
        {
            Poll::Pending
        } else {
            match &mut self.step {
                VerificationStep::Start => Poll::Ready(Some(self.request.block.clone())),
                VerificationStep::FetchAncestor { fetch, .. } => Pin::new(&mut *fetch)
                    .now_or_never()
                    .and_then(|()| Pin::new(fetch).take_output())
                    .map_or(Poll::Pending, Poll::Ready),
                VerificationStep::Submit { .. } | VerificationStep::WaitForFinalization { .. } => {
                    Poll::Pending
                }
            }
        }
    }
}

/// A consensus verification request retained throughout its ancestry walk.
struct VerificationRequest {
    parent_round: Round,
    cause: Span,
    block: Arc<Block>,
    /// Delivers the validation result: `Some(duration)` when the execution
    /// layer accepted the block, `None` when it rejected it. Dropped without
    /// a value when validation was not possible or the request was
    /// superseded.
    response: Option<oneshot::Sender<Option<Duration>>>,
}

impl VerificationRequest {
    async fn cancellation(&mut self) {
        match self.response.as_mut() {
            Some(response) => response.cancellation().await,
            None => std::future::pending().await,
        }
    }
}

/// Pending-head delivery retains its target and current cursor between engine calls.
/// Advancing drops the previous ancestor.
struct ConvergenceWalk {
    cause: Span,
    target: Arc<Block>,
    /// The target or ancestor currently being probed.
    cursor: Arc<Block>,
    step: ConvergenceStep,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConvergenceStep {
    Probe,
    Parent,
    Retry,
}

impl ConvergenceWalk {
    fn new(block: Arc<Block>) -> Self {
        Self {
            cause: Span::current(),
            target: block.clone(),
            cursor: block,
            step: ConvergenceStep::Probe,
        }
    }

    fn is_target(&self) -> bool {
        self.cursor.digest() == self.target.digest()
    }

    fn parent(&self) -> (Round, Digest) {
        let context = self.cursor.context();
        let round = Round::new(context.round.epoch(), context.parent.0);
        (round, self.cursor.parent_digest())
    }

    fn reprobe(&mut self) {
        self.cursor = self.target.clone();
        self.step = ConvergenceStep::Probe;
    }
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
            ExecutionTaskOutcome::Forkchoice(forkchoice) => Some(forkchoice.target),
            ExecutionTaskOutcome::Build { result, .. } => {
                result.as_ref().ok().map(|forkchoice| forkchoice.target)
            }
            ExecutionTaskOutcome::VerificationDelivered { .. }
            | ExecutionTaskOutcome::ConvergenceDelivered { .. }
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

/// The result of an execution task, interpreted by [`Actor::handle_execution_task_finished`].
///
/// `finalized_round` snapshots the network finalized round when the task is
/// scheduled. It travels with the result so a late `VALID` cannot restore
/// HEAD eligibility after a newer network finalized tip cleared it.
enum ExecutionTaskOutcome {
    VerificationDelivered {
        round: Round,
        digest: Digest,
        status: eyre::Result<(PayloadStatusEnum, Duration)>,
    },
    /// The convergence walk travels back with the EL's answer.
    ConvergenceDelivered {
        walk: ConvergenceWalk,
        finalized_round: Round,
        status: eyre::Result<PayloadStatusEnum>,
    },
    /// The request travels back for its acknowledgement.
    FinalizedDelivered {
        request: FinalizedBlockRequest,
        status: eyre::Result<PayloadStatusEnum>,
    },
    /// Whether parent delivery was attempted, and the build FCU if it was VALID.
    Build {
        delivery_attempted: bool,
        finalized_round: Round,
        result: eyre::Result<ForkchoiceOutcome>,
    },
    Forkchoice(ForkchoiceOutcome),
}

/// An FCU response and its build subscriber, if any. A stale update is not submitted.
struct ForkchoiceOutcome {
    target: LocalState,
    build: Option<(Span, oneshot::Sender<TempoBuiltPayload>)>,
    response: Option<eyre::Result<ForkchoiceUpdated>>,
}

impl ExecutionTaskOutcome {
    fn name(&self) -> &'static str {
        match self {
            Self::VerificationDelivered { .. } => "verification-delivered",
            Self::ConvergenceDelivered { .. } => "convergence-delivered",
            Self::FinalizedDelivered { .. } => "finalized-delivered",
            Self::Build { .. } => "build",
            Self::Forkchoice(_) => "forkchoice",
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
    build: Option<(Span, Box<Build>)>,
) -> ForkchoiceOutcome {
    let build = build.filter(|(_, build)| {
        if build.response.is_canceled() {
            info!(
                "dropping payload build request: subscriber went away while \
                awaiting execution"
            );
            return false;
        }
        true
    });
    let (build, attributes) = match build {
        Some((cause, build)) => {
            let Build {
                attributes,
                response,
                ..
            } = *build;
            (Some((cause, response)), Some(*attributes))
        }
        None => (None, None),
    };

    let response = submit_forkchoice_update(&execution_node, cause, target, attributes).await;
    ForkchoiceOutcome {
        target,
        build,
        response,
    }
}

/// Owns the execution slot while fetching and delivering the parent, then
/// immediately starts the payload build if the parent is VALID.
#[instrument(skip_all, parent = &cause, fields(
    round = %build.context.round,
    parent = %build.context.parent.1,
))]
async fn execute_build(
    execution_node: impl ExecutionLayer,
    marshal: impl Marshal,
    cause: Span,
    mut target: LocalState,
    mut build: Box<Build>,
    retained_parent: Option<Arc<Block>>,
    finalized_round: Round,
) -> ExecutionTaskOutcome {
    let mut delivery_attempted = false;
    let parent_digest = build.context.parent.1;
    let parent_round = Round::new(build.context.round.epoch(), build.context.parent.0);
    let result = async {
        let block = select! {
            biased;

            () = build.response.cancellation() => Err(eyre!("build subscriber went away")),
            block = async {
                match retained_parent {
                    Some(block) => Ok(block),
                    None => fetch_block(execution_node.clone(), marshal.clone(), parent_digest, parent_round)
                        .await.ok_or_eyre("marshal dropped the build parent subscription"),
                }
            } => block,
        }?;
        target.head = (block.height(), parent_digest);
        delivery_attempted = true;
        let status = deliver_block(&execution_node, block).await?;
        ensure!(status == PayloadStatusEnum::Valid, "build parent was not VALID: {status}");
        ensure!(!build.response.is_canceled(), "build subscriber went away");
        Ok(execute_forkchoice(execution_node, cause.clone(), target, Some((cause, build))).await)
    }.await;
    ExecutionTaskOutcome::Build {
        delivery_attempted,
        finalized_round,
        result,
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
    let status = deliver_block(&execution_node, request.block.clone()).await;
    ExecutionTaskOutcome::FinalizedDelivered { request, status }
}

#[instrument(skip_all, parent = &cause, fields(%round, digest = %block.digest()))]
async fn execute_verification_delivery(
    execution_node: impl ExecutionLayer,
    round: Round,
    cause: Span,
    block: Arc<Block>,
) -> ExecutionTaskOutcome {
    let digest = block.digest();
    let started = Instant::now();
    let status = deliver_block(&execution_node, block)
        .await
        .map(|status| (status, started.elapsed()));
    ExecutionTaskOutcome::VerificationDelivered {
        round,
        digest,
        status,
    }
}

/// Delivers one block and returns the walk with the EL's answer.
#[instrument(
    skip_all,
    parent = &walk.cause,
    fields(
        block.digest = %walk.cursor.digest(),
        block.height = %walk.cursor.height(),
        block.parent_digest = %walk.cursor.parent_digest(),
    ),
)]
async fn execute_convergence_delivery(
    execution_node: impl ExecutionLayer,
    walk: ConvergenceWalk,
    finalized_round: Round,
) -> ExecutionTaskOutcome {
    let status = deliver_block(&execution_node, walk.cursor.clone())
        .await
        .wrap_err("failed sending new-payload request for head convergence");

    ExecutionTaskOutcome::ConvergenceDelivered {
        walk,
        finalized_round,
        status,
    }
}

/// Submits `block` to the execution layer through a new-payload request and
/// returns the reported payload status.
async fn deliver_block(
    execution_node: &impl ExecutionLayer,
    block: Arc<Block>,
) -> eyre::Result<PayloadStatusEnum> {
    let (block, block_access_list) = Arc::unwrap_or_clone(block).into_parts();
    let payload_status = execution_node
        .new_payload(TempoExecutionData {
            block,
            block_access_list,
            validator_set: None,
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

/// Whether `target` finalizes below the execution layer's own finality, so
/// that submitting it would move finality backwards. The tracked state
/// trails execution-layer finality after a snapshot restore until the
/// marshal actor's re-deliveries catch up; a tracked finalized block the
/// execution layer's canonical chain contradicts is fatal.
fn is_stale_forkchoice(
    execution_node: &impl ExecutionLayer,
    target: LocalState,
) -> eyre::Result<bool> {
    let execution_finalized = execution_node.finalized_num_hash();
    if execution_finalized.number < target.finalized.0.get() {
        return Ok(false);
    }
    let canonical_digest = execution_node
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
    if execution_finalized.number > target.finalized.0.get() {
        debug!(
            execution_finalized_height = execution_finalized.number,
            execution_finalized_hash = %execution_finalized.hash,
            "tracked finalized state is below the execution layer's finalized tip; \
            skipping the forkchoice update",
        );
        return Ok(true);
    }
    Ok(false)
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
            // the body to the actor loop for a later build on this proposal.
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

/// Submits the forkchoice update unless it is stale (see
/// [`is_stale_forkchoice`]), in which case nothing is sent and `None` is
/// returned. A failing stale check is reported like a failed update; the
/// response is returned raw.
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
async fn submit_forkchoice_update(
    execution_node: &impl ExecutionLayer,
    cause: Span,
    canonicalized: LocalState,
    attrs: Option<TempoPayloadAttributes>,
) -> Option<eyre::Result<ForkchoiceUpdated>> {
    match is_stale_forkchoice(execution_node, canonicalized) {
        Ok(false) => {}
        Ok(true) => return None,
        Err(error) => return Some(Err(error)),
    }

    let fcu_response = match execution_node
        .fork_choice_updated(canonicalized.to_forkchoice_state(), attrs)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return Some(Err(error.wrap_err(
                "failed requesting execution layer to update forkchoice state",
            )));
        }
    };
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
    Some(Ok(fcu_response))
}

/// A snapshot of the execution layer's local state - its head and
/// finalized tip - for execution tasks to extend and report back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalState {
    head: (Height, Digest),
    finalized: (Height, Digest),
}

impl LocalState {
    /// Transform a [`LocalState`] to a [`ForkchoiceState`] to submit to the
    /// execution layer.
    fn to_forkchoice_state(self) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: self.head.1.0,
            safe_block_hash: self.finalized.1.0,
            finalized_block_hash: self.finalized.1.0,
        }
    }

    /// Updates the finalized tip to `digest` at `height`.
    ///
    /// `height` must be ahead of the tracked finalized height; if it is
    /// not, this is a no-op. If `height` is at or ahead of the head
    /// height, the head is moved onto the finalized tip as well, so that
    /// the finalized tip is never ahead of the head.
    fn update_finalized(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized.0 {
            this.finalized = (height, digest);
        }
        if height >= this.head.0 {
            this.head = (height, digest);
        }
        this
    }

    /// Updates the head to `digest` at `height`.
    ///
    /// The head only moves above the finalized tip (or back onto it);
    /// anything below is a no-op.
    fn update_head(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized.0 || digest == this.finalized.1 {
            this.head = (height, digest);
        }
        this
    }
}

struct PendingHead {
    round: Round,
    digest: Digest,
    height: Option<Height>,
    /// This exact target returned VALID without a newer network finalized tip.
    /// Cleared when either the selected target or network finalized tip changes.
    executed: Option<(Height, Digest)>,
}

impl PendingHead {
    fn finalized((round, height, digest): (Round, Height, Digest)) -> Self {
        Self {
            round,
            digest,
            height: Some(height),
            executed: None,
        }
    }
}

fn update_block_fetch(
    execution_node: &impl ExecutionLayer,
    marshal: &impl Marshal,
    pending: &mut OptionFuture<PendingNotarizedBlock>,
    next: Option<(Round, Digest)>,
) {
    if pending
        .as_ref()
        .is_some_and(|pending| next.map(|(_, digest)| digest) != Some(pending.digest))
    {
        *pending = OptionFuture::none();
    }
    if pending.is_none()
        && let Some((round, digest)) = next
    {
        pending.replace(PendingNotarizedBlock::new(
            execution_node,
            marshal,
            round,
            digest,
        ));
    }
}
