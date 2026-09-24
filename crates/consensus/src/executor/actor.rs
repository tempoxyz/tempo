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
//! returned `VALID` and its ancestry was walked to the current network finalized
//! tip. Otherwise HEAD is the delivered finalized block. The update runs on a
//! later iteration.
//! Finalized blocks are acknowledged to the marshal actor once the update
//! finalizing them is accepted. Finality work is scheduled ahead of builds,
//! verification, and notarized convergence.
//!
//! Builds fetch and deliver their parent, then issue the forkchoice update
//! with payload attributes on VALID, using the finalized state captured when
//! the build was scheduled. A proposal whose extra data depends on the
//! post-state of its parent, such as the DKG outcome of a boundary block,
//! first waits for that data. The build holds the slot while it waits, so no
//! other forkchoice update can move the finalized state that it captured.
//!
//! # Block verification
//!
//! A verification request carries a candidate block and wants a verdict:
//! does the execution layer accept it? The candidate is probed with
//! `newPayload` first. VALID or INVALID is the verdict. SYNCING means the
//! execution layer lacks the parent, so the walk fetches the parent and
//! probes it, one ancestor at a time down the chain, until an ancestor is
//! accepted; the candidate is then probed again for its verdict. The walk
//! stops at the finalized tip and lets the finalization pipeline deliver
//! finalized history.
//!
//! Requests from several rounds can be pending at once, one per round. They
//! share one engine slot. Whenever the slot is free it goes to the newest
//! request whose walk has a block ready to probe; a request for a round
//! finality has passed is dropped. A missing parent is first looked up
//! locally, in the execution layer and marshal storage, and the walk keeps
//! the slot for that. If neither has it, the walk subscribes for the parent
//! with the marshal actor, which fetches it from peers, and gives the slot
//! up: an abortable pool polls the subscription, while the walk retains its
//! abort handle. Parent delivery wakes the actor; queued cancellations are
//! reaped when the loop next reconciles the queue.
//! A walk waiting for finalization resumes when the finalization pipeline
//! delivers its ancestor.
//!
//! Requesters that go away are dropped without a verdict, and a request for
//! the same round replaces the pending one.
//!
//! # Execution failures
//!
//! An INVALID answer ends the walk that received it. A block that fails
//! validation is cached as invalid by the execution layer, which then answers
//! INVALID for it and for every descendant, so re-probing learns nothing.
//! For verification an INVALID is the
//! candidate's verdict, whether it was the candidate or an ancestor that was
//! rejected. Convergence stops until a newer consensus context selects the
//! same head again or a finalized block is delivered. Other verification and
//! build failures end the affected request.
//!
//! An engine call that fails outright, rather than answering with a payload
//! status, is fatal wherever it happens. The execution layer runs in this
//! process; such a failure means its engine task has died or its database is
//! failing, and no later call can succeed. A non-`VALID` forkchoice update
//! and a non-`VALID` finalized delivery are fatal as well.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, VecDeque},
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
use commonware_utils::{
    Acknowledgement,
    acknowledgement::Exact,
    futures::{AbortablePool, Aborter},
};
use eyre::{OptionExt as _, Report, WrapErr as _, bail, ensure, eyre};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    future::{BoxFuture, poll_fn},
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
    /// last successful forkchoice update, see [`DELIVERIES_PER_FORKCHOICE_UPDATE`].
    deliveries_since_forkchoice: usize,

    /// The newest round observed through build and verify contexts or
    /// finalized-tip reports. Requests can arrive out of order; an older
    /// round's parent must not supersede a newer one's. Retained independently
    /// of request cancellation and completion.
    latest_consensus_round: Round,

    /// The queued proposal build and the round it was requested for. Leaves
    /// the slot when scheduled. It stays until the next build request
    /// replaces it, its requester cancels it, or it is answered. Neither
    /// rounds nor verifications play into that: the executor serves the
    /// latest request, and whether it was sensible to make is consensus's
    /// concern.
    pending_build: Option<(Round, Span, Box<Build>)>,

    /// Verifications waiting for the slot, by round: fresh candidates, walks
    /// waiting for a subscribed ancestor or for finalization, and walks with
    /// a fetched ancestor in hand. Parent subscriptions live in the fetch
    /// pool; canceled requests are reaped when the queue is reconciled.
    /// A request stays until it has a verdict, fails, is found canceled,
    /// its round falls at or below the network finalized round, or a request
    /// for the same round replaces it.
    queued_verifications: BTreeMap<Round, Verification>,
    /// The verification holding the engine slot: the one whose cursor is in
    /// flight, about to be probed, or whose parent is being looked up
    /// locally. Handed out by [`Self::update_verifications`] to the newest
    /// verification ready to probe; a walk that has to wait for the marshal
    /// actor or for finalization goes back into the queue.
    active_verification: Option<Verification>,

    /// Parent subscriptions for verification and convergence walks. Each
    /// walk owns the abort handle for its subscription.
    parent_fetches: AbortablePool<'static, (WalkOwner, Option<Arc<Block>>)>,

    /// The walk that delivers the pending head so that a forkchoice update can
    /// select it as HEAD. Starts once the pending head's body is known and is
    /// dropped when the pending head changes or no longer needs delivery.
    convergence: Option<AncestryWalk>,
    /// Fetches the pending head's body before its walk exists.
    pending_head_fetch: OptionFuture<PendingNotarizedBlock>,

    /// The single execution task. A build owns the slot from fetching its parent
    /// through delivery and the forkchoice update that starts the payload job.
    execution_task: OptionFuture<ExecutionTask>,

    /// Payload build jobs currently being driven to completion.
    ///
    /// Each job resolves a payload from the execution layer's payload builder
    /// and delivers it to the subscriber that requested the build. If the
    /// subscriber dropped its receiver in the meantime, the built payload is
    /// discarded. A delivered block is handed back as the job's output so
    /// that its body can be retained for a later build: the proposer is never
    /// asked to verify its own proposal, so no validation request delivers it.
    payload_jobs: FuturesUnordered<BoxFuture<'static, Option<Arc<Block>>>>,

    /// The last accepted forkchoice.
    local_state: LocalState,
    /// The highest finalized block accepted by the execution layer, with its
    /// consensus round. Initialized from the local finalized state.
    delivered_finalized_tip: (Round, Height, Digest),
    /// The latest finalized tip announced by consensus, which may still
    /// need to be delivered to the execution layer.
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
        let finalized_round = if finalized.1 == finalized_tip.2 {
            finalized_tip.0
        } else if finalized.0 == Height::zero() {
            Round::zero()
        } else {
            execution_node
                .block_by_digest(finalized.1)
                .wrap_err("failed reading the local finalized block's consensus round")?
                .ok_or_eyre("local finalized block is missing from the execution layer")?
                .context()
                .round
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
            pending_build: None,
            queued_verifications: BTreeMap::new(),
            active_verification: None,
            parent_fetches: AbortablePool::default(),
            convergence: None,
            pending_head_fetch: OptionFuture::none(),

            execution_task: OptionFuture::none(),
            payload_jobs: FuturesUnordered::new(),

            local_state,
            delivered_finalized_tip: (finalized_round, finalized.0, finalized.1),
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

            self.update_verifications();
            self.start_next_execution_task();
            self.update_block_fetches();
            self.update_fcu_heartbeat_timer();

            select! {
                biased;

                finished = &mut self.execution_task => {
                    if let Err(error) = self.handle_execution_task_finished(finished) {
                        log_fatal(&error);
                        break;
                    }
                }

                (round, event) = poll_fn(|cx| match &mut self.active_verification {
                    Some(active) => active
                        .poll_event(cx)
                        .map(|event| (active.round, event)),
                    None => Poll::Pending,
                }) => {
                    self.handle_verification_event(round, event);
                }

                completion = self.parent_fetches.next_completed() => {
                    if let Ok((owner, block)) = completion {
                        self.handle_parent_fetched(owner, block);
                    }
                }

                parent = async {
                    match &mut self.convergence {
                        Some(walk) => walk.next_lookup().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.handle_parent_lookup(WalkOwner::Convergence, parent);
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

                (digest, round, block) = &mut self.pending_head_fetch => {
                    self.handle_pending_head_fetched(digest, round, block);
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
            ExecutionTaskOutcome::Delivered {
                owner,
                digest,
                status,
            } => {
                // SYNCING blocks may execute later as their missing ancestors
                // arrive, so every delivery counts toward the next update.
                self.deliveries_since_forkchoice += 1;
                // The engine call itself failing is fatal, whoever asked.
                let (status, duration) = status
                    .wrap_err_with(|| format!("failed delivering block `{digest}` for {owner}"))?;
                // An ACCEPTED answer is logged by the handlers and ends the
                // verification or stops the convergence walk.
                let _logged = match owner {
                    WalkOwner::Verification(round) => {
                        self.handle_verification_delivered(round, digest, status, duration)
                    }
                    WalkOwner::Convergence => self.handle_convergence_delivered(digest, status),
                };
            }
            ExecutionTaskOutcome::FinalizedDelivered { request, status } => {
                self.handle_finalized_delivered(request, status)?;
                self.restart_walks_covered_by_finality();
            }
            ExecutionTaskOutcome::Build(outcome) => self.handle_build(outcome)?,
            ExecutionTaskOutcome::Forkchoice(ForkchoiceOutcome {
                target,
                build,
                response,
            }) => self.handle_forkchoice_response(target, build, response)?,
        }
        Ok(())
    }

    #[instrument(skip_all, err)]
    fn handle_build(&mut self, outcome: BuildOutcome) -> eyre::Result<()> {
        match outcome {
            BuildOutcome::Aborted { delivery_attempted } => {
                if delivery_attempted {
                    self.deliveries_since_forkchoice += 1;
                }
                Ok(())
            }
            BuildOutcome::ParentDeliveryFailed(error) => {
                self.deliveries_since_forkchoice += 1;
                Err(error)
            }
            BuildOutcome::Forkchoice(outcome) => {
                self.deliveries_since_forkchoice += 1;
                let submitted = outcome.response.is_some();
                let target = outcome.target;
                self.handle_forkchoice_response(target, outcome.build, outcome.response)?;
                // A successful FCU proves that its head descends from the
                // finalized digest it named. A skipped FCU proves nothing.
                if submitted {
                    self.record_executed_convergence_target(target.head, target.finalized.1);
                }
                Ok(())
            }
        }
    }

    /// Interprets an engine answer for the active verification. Cursors
    /// overtaken by finality reprobe the target; historical targets are
    /// dropped by [`Self::prune_finalized`] before another delivery.
    #[instrument(skip_all, fields(%round, %digest), err(level = Level::WARN))]
    fn handle_verification_delivered(
        &mut self,
        round: Round,
        digest: Digest,
        status: PayloadStatusEnum,
        duration: Duration,
    ) -> eyre::Result<()> {
        let Some(active) = &mut self.active_verification else {
            return Ok(());
        };
        if active.round != round || !active.walk.awaits(digest) {
            return Ok(());
        }
        active.duration += duration;
        let walk = &mut active.walk;
        let (_, finalized_height, finalized_digest) = self.network_finalized_tip;
        if walk.conflicts_with_finality(finalized_height, finalized_digest) {
            // A finality conflict is not an execution-invalid verdict
            // that certification may cache. Close the request instead.
            self.remove_verification(round);
            return Ok(());
        }
        if walk.below_finality(finalized_height) {
            // Finality overtook this cursor without proving a conflict.
            // Reconsider the target against the new tip on the next loop.
            walk.reprobe();
            return Ok(());
        }
        let verdict = match status {
            PayloadStatusEnum::Valid if walk.at_target() => Some(active.duration),
            PayloadStatusEnum::Valid => {
                walk.reprobe();
                return Ok(());
            }
            PayloadStatusEnum::Invalid { validation_error } => {
                info!(%validation_error, "execution layer rejected the block");
                None
            }
            PayloadStatusEnum::Syncing => {
                match walk.parent_height().cmp(&finalized_height) {
                    Ordering::Greater => {
                        // Missing ancestry above finality belongs to this walk.
                        walk.look_up_parent(self.execution_node.clone(), self.marshal.clone());
                    }
                    Ordering::Equal | Ordering::Less
                        if self.delivered_finalized_tip.1 < finalized_height =>
                    {
                        // The cursor itself or its parent is the finalized
                        // tip. Let finalization supply it before retrying.
                        walk.wait_for_finalized(finalized_height);
                    }
                    Ordering::Equal | Ordering::Less => walk.reprobe(),
                }
                return Ok(());
            }
            PayloadStatusEnum::Accepted => {
                self.remove_verification(round);
                bail!("payload was accepted without execution while verifying block");
            }
        };
        self.remove_verification(round)
            .expect("the active verification was found above")
            .respond(verdict);
        Ok(())
    }

    /// Interprets an engine answer for convergence. The target must return
    /// VALID and its ancestry must reach current network finality before it
    /// becomes eligible for HEAD. Overtaken cursors reprobe the target before
    /// interpreting their status. Rejected or failed walks remain stopped
    /// until a newer consensus context or finalized delivery restarts them.
    #[instrument(skip_all, fields(%digest), err(level = Level::WARN))]
    fn handle_convergence_delivered(
        &mut self,
        digest: Digest,
        status: PayloadStatusEnum,
    ) -> eyre::Result<()> {
        let Some(walk) = &mut self.convergence else {
            return Ok(());
        };
        if !walk.awaits(digest) {
            return Ok(());
        }
        if status == PayloadStatusEnum::Syncing && digest == self.pending_head.digest {
            self.pending_head.executed = None;
        }
        let (_, finalized_height, finalized_digest) = self.network_finalized_tip;
        if walk.target.height() < finalized_height
            || walk.conflicts_with_finality(finalized_height, finalized_digest)
        {
            // A historical target cannot become HEAD below current finality,
            // even if it is canonical. A conflicting branch cannot either.
            walk.stop();
            return Ok(());
        }
        if walk.below_finality(finalized_height) {
            // Finality overtook this cursor without proving a conflict.
            // Reconsider the pending head against the new tip.
            walk.reprobe();
            return Ok(());
        }

        match status {
            PayloadStatusEnum::Valid => {
                if walk.cursor.digest() == finalized_digest
                    || walk.cursor.parent_digest() == finalized_digest
                {
                    // Every cursor belongs to the target's ancestry, so
                    // reaching finality proves the target connects to it.
                    walk.proven_finalized_tip = Some(finalized_digest);
                }

                if walk.proven_finalized_tip != Some(finalized_digest) {
                    // VALID proves execution; ancestry still needs checking.
                    walk.look_up_parent(self.execution_node.clone(), self.marshal.clone());
                } else if walk.at_target() {
                    let target = (walk.target.height(), walk.target.digest());
                    self.convergence = None;
                    self.record_executed_convergence_target(target, finalized_digest);
                } else {
                    // Keep the ancestry proof, but require the target's own VALID.
                    walk.reprobe();
                }
            }
            PayloadStatusEnum::Invalid { validation_error } => {
                info!(%validation_error, "execution layer rejected the block");
                walk.stop();
            }
            PayloadStatusEnum::Syncing => match walk.parent_height().cmp(&finalized_height) {
                Ordering::Greater => {
                    // Missing ancestry above finality belongs to this walk.
                    walk.look_up_parent(self.execution_node.clone(), self.marshal.clone());
                }
                Ordering::Equal | Ordering::Less
                    if self.delivered_finalized_tip.1 < finalized_height =>
                {
                    // The cursor itself or its parent is the finalized
                    // tip. Its execution is the finalization pipeline's job.
                    walk.wait_for_finalized(finalized_height);
                }
                Ordering::Equal | Ordering::Less => {
                    // Finalized history was already delivered. Wait for a
                    // newer context or finalized delivery before retrying.
                    walk.stop();
                }
            },
            PayloadStatusEnum::Accepted => {
                walk.stop();
                bail!("payload was accepted without execution while delivering block");
            }
        }
        Ok(())
    }

    /// Finalization delivered blocks. A walk that was about to deliver or
    /// fetch one of them restarts at its target, and so does a stopped
    /// convergence walk.
    fn restart_walks_covered_by_finality(&mut self) {
        let delivered_height = self.delivered_finalized_tip.1;
        for verification in self.verifications_mut() {
            verification.walk.on_finalized_delivered(delivered_height);
        }
        if let Some(walk) = &mut self.convergence {
            walk.on_finalized_delivered(delivered_height);
        }
    }

    /// Retains an executed target whose ancestry was proved against the
    /// current network finalized digest.
    fn record_executed_convergence_target(
        &mut self,
        block: (Height, Digest),
        finalized_digest: Digest,
    ) {
        if block.1 == self.pending_head.digest && finalized_digest == self.network_finalized_tip.2 {
            self.pending_head.height = Some(block.0);
            self.pending_head.executed = Some(block);
        }
    }

    /// Finalized bodies arrive through the finalization pipeline. Other targets
    /// need a VALID delivery and proven ancestry to network finality before
    /// becoming HEAD.
    fn needs_head_delivery(&self) -> bool {
        self.pending_head.digest != self.network_finalized_tip.2
            && self.pending_head.executed.is_none()
    }

    /// Drops obsolete requests and historical verification targets before
    /// scheduling more deliveries.
    #[instrument(skip_all)]
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
        }

        // Finalization now owns ancestry at or below the tip. Restart the
        // surviving walks before consuming any obsolete fetch completions.
        if let Some(active) = &mut self.active_verification
            && !active.retain_after_finality(round, height)
        {
            self.active_verification = None;
        }
        self.queued_verifications
            .retain(|_, verification| verification.retain_after_finality(round, height));
        if let Some(walk) = &mut self.convergence {
            walk.on_finalized_tip(round, height);
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

        self.deliveries_since_forkchoice = 0;
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
            block.height() >= self.delivered_finalized_tip.1,
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

        if block.height() > self.delivered_finalized_tip.1 {
            self.delivered_finalized_tip = (block.context().round, block.height(), block.digest());
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
            Command::PendingHead { round, parent } => {
                self.record_convergence_target(round, parent);
            }
            Command::Build(build) => {
                self.record_convergence_target(build.context.round, build.context.parent);
                // Cancellation discards the build work, not its parent target.
                if build.response.is_canceled() {
                    return;
                }
                self.queue_build(build.context.round, cause, build);
            }
            Command::Finalize(finalized) => match *finalized {
                Update::Tip(round, height, digest) => {
                    self.record_convergence_target(round, (round.view(), digest));
                    if round > self.network_finalized_tip.0 {
                        if digest != self.network_finalized_tip.2 {
                            self.pending_head.executed = None;
                        }
                        self.network_finalized_tip = (round, height, digest);
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
                    response,
                } = *request;
                self.record_convergence_target(context.round, context.parent);
                self.queue_verification(Verification::new(context.round, cause, block, response));
            }
        }
    }

    /// Queues a build, replacing any queued one. The current execution task
    /// is allowed to finish.
    fn queue_build(&mut self, round: Round, cause: Span, build: Box<Build>) {
        if let Some((queued, ..)) = self.pending_build.replace((round, cause, build)) {
            debug!(%round, queued_round = %queued, "build replaced a queued one");
        }
    }

    /// Queues a verification. Verifications from different rounds wait side
    /// by side; one for the same round replaces the pending one, whether that
    /// one is queued or active.
    fn queue_verification(&mut self, verification: Verification) {
        let round = verification.round;
        if self.remove_verification(round).is_some() {
            debug!(%round, "verification replaced a pending one for the same round");
        }
        self.queued_verifications.insert(round, verification);
    }

    /// Records the newest observed consensus round and its convergence target.
    /// Context reports, build and verify requests select their parent; finalized-tip reports
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
            } else if let Some(walk) = &mut self.convergence
                && matches!(walk.step, WalkStep::Stopped)
            {
                info!("consensus selected the head again; restarting its stopped delivery");
                walk.reprobe();
            }
            self.pending_head.round = Round::new(round.epoch(), target.0);
        }
    }

    /// Applies completed parent fetches, reconciles the queue, and hands the
    /// engine slot to the newest verification ready to probe. The holder
    /// keeps it while its cursor is in flight or its parent is being looked
    /// up locally. Otherwise it goes back into the queue, and the pick is
    /// made afresh: a walk waiting for the marshal actor or for finalization
    /// is skipped, a newer candidate goes first.
    #[instrument(
        skip_all,
        fields(
            queued = self.queued_verifications.len(),
            active = self.active_verification.as_ref().map(|active| active.round.to_string()),
        ),
    )]
    fn update_verifications(&mut self) {
        // Make every delivered parent ready before choosing the newest
        // verification to probe, regardless of pool completion order.
        //
        // Reason: the abort-pool inside the select-loop can trigger for one
        // subscription while in reality several have been resolved.
        while let Some(completion) = self.parent_fetches.next_completed().now_or_never() {
            if let Ok((owner, block)) = completion {
                self.handle_parent_fetched(owner, block);
            }
        }

        // Discard canceled requests before selecting a walk to probe.
        self.queued_verifications.retain(|round, queued| {
            let is_cancelled = queued.is_canceled();
            if is_cancelled {
                debug!(%round, "dropping verification whose requester went away");
            }
            !is_cancelled
        });
        if let Some(active) = &self.active_verification
            && !matches!(
                active.walk.step,
                WalkStep::InFlight | WalkStep::LookUpParent(_)
            )
        {
            let active = self
                .active_verification
                .take()
                .expect("the active verification was found above");
            debug!(
                round = %active.round,
                step = active.walk.step.name(),
                "active verification has to wait; back into the queue"
            );
            self.queued_verifications.insert(active.round, active);
        }
        if self.active_verification.is_none()
            && let Some(round) = self
                .queued_verifications
                .iter()
                .rev()
                .find(|(_, queued)| matches!(queued.walk.step, WalkStep::Probe))
                .map(|(round, _)| *round)
        {
            let next = self
                .queued_verifications
                .remove(&round)
                .expect("the round was found above");
            debug!(
                %round,
                target = %next.walk.target.digest(),
                cursor = %next.walk.cursor.digest(),
                "verification takes the engine slot"
            );
            self.active_verification = Some(next);
        }
    }

    /// Keeps the pending head's body fetch and convergence walk in step with
    /// the pending head. Convergence does not run while a build is queued or
    /// running: the build delivers the same parent itself. Verifications are
    /// not consulted here; they only take precedence at the engine slot, in
    /// [`Self::start_next_execution_task`], and a body both walks need is
    /// subscribed for once by the marshal actor.
    fn update_block_fetches(&mut self) {
        let building = self
            .execution_task
            .as_ref()
            .is_some_and(|task| matches!(task.task_type, ExecutionTaskType::Build))
            || self.pending_build.is_some();
        if building || !self.needs_head_delivery() {
            self.pending_head_fetch = OptionFuture::none();
            return;
        }
        if self.convergence.is_none()
            && let Some(block) = self.built_blocks.get(&self.pending_head.digest)
        {
            // The pending head is a block this node built. The execution
            // layer produced the payload and does not hold it in its block
            // tree, so the block still needs a newPayload delivery before a
            // forkchoice update can select it as HEAD. The body is retained
            // here, which saves the marshal fetch.
            //
            // Even a VALID built block needs its ancestry walked to the
            // current network finalized tip before it can become HEAD.
            self.start_convergence(block.clone());
        }
        if self.convergence.is_some() {
            self.pending_head_fetch = OptionFuture::none();
        } else {
            self.fetch_pending_head();
        }
    }

    /// Fetches the pending head's body. A fetch for a previous pending head
    /// is dropped: nobody is required to serve a forked-out block, so it
    /// might never resolve.
    fn fetch_pending_head(&mut self) {
        let (round, digest) = (self.pending_head.round, self.pending_head.digest);
        if self
            .pending_head_fetch
            .as_ref()
            .is_some_and(|fetch| fetch.digest != digest)
        {
            self.pending_head_fetch = OptionFuture::none();
        }
        if self.pending_head_fetch.is_none() {
            self.pending_head_fetch.replace(PendingNotarizedBlock::new(
                &self.execution_node,
                &self.marshal,
                round,
                digest,
            ));
        }
    }

    fn start_convergence(&mut self, block: Arc<Block>) {
        self.pending_head.height = Some(block.height());
        self.convergence = Some(AncestryWalk::new(Span::current(), block));
    }

    #[instrument(skip_all, fields(%digest, %round))]
    fn handle_pending_head_fetched(
        &mut self,
        digest: Digest,
        round: Round,
        block: Option<Arc<Block>>,
    ) {
        match block {
            Some(block) if block.height() > self.network_finalized_tip.1 => {
                self.start_convergence(block);
            }
            Some(_) => self.pending_head = PendingHead::finalized(self.network_finalized_tip),
            None => warn!("marshal dropped the pending head subscription; retrying the fetch"),
        }
    }

    /// A requester's cancellation or the active walk's local lookup woke the actor.
    #[instrument(skip_all, fields(%round))]
    fn handle_verification_event(&mut self, round: Round, event: VerificationEvent) {
        match event {
            VerificationEvent::Canceled => {
                debug!("the verification's requester went away");
                self.remove_verification(round);
            }
            VerificationEvent::ParentLookedUp(block) => {
                self.handle_parent_lookup(WalkOwner::Verification(round), block);
            }
        }
    }

    /// A local lookup either supplies the next cursor or starts a marshal
    /// subscription for the missing parent.
    fn handle_parent_lookup(&mut self, owner: WalkOwner, block: Option<Arc<Block>>) {
        let walk = match owner {
            WalkOwner::Verification(round) => match &mut self.active_verification {
                Some(active) if active.round == round => Some(&mut active.walk),
                _ => self
                    .queued_verifications
                    .get_mut(&round)
                    .map(|v| &mut v.walk),
            },
            WalkOwner::Convergence => self.convergence.as_mut(),
        };
        let Some(walk) = walk else { return };
        match block {
            Some(block) => walk.on_fetched(block),
            None => walk.fetch_parent(
                self.marshal.clone(),
                owner,
                self.network_finalized_tip.0,
                &mut self.parent_fetches,
            ),
        }
    }

    /// Applies a subscription result before the actor can replace its owner.
    /// Dropping or restarting a walk aborts its outstanding fetch, so a
    /// completion cannot be delivered to a replacement for the same owner.
    #[instrument(skip_all, fields(%owner))]
    fn handle_parent_fetched(&mut self, owner: WalkOwner, block: Option<Arc<Block>>) {
        let walk = match owner {
            WalkOwner::Verification(round) => match &mut self.active_verification {
                Some(active) if active.round == round => Some(&mut active.walk),
                _ => self
                    .queued_verifications
                    .get_mut(&round)
                    .map(|v| &mut v.walk),
            },
            WalkOwner::Convergence => self.convergence.as_mut(),
        };
        let Some(walk) = walk else {
            debug!("walk was canceled before the fetched parent could be applied");
            return;
        };
        if let Some(block) = block {
            walk.on_fetched(block);
            return;
        }
        match owner {
            WalkOwner::Verification(round) => {
                warn!(%round, "marshal gave up on the verification's ancestor; failing the request");
                self.remove_verification(round);
            }
            WalkOwner::Convergence => {
                warn!("marshal gave up on the ancestor; retrying the fetch");
                walk.look_up_parent(self.execution_node.clone(), self.marshal.clone());
            }
        }
    }

    /// Every verification, active first.
    fn verifications_mut(&mut self) -> impl Iterator<Item = &mut Verification> {
        self.active_verification
            .iter_mut()
            .chain(self.queued_verifications.values_mut())
    }

    /// Drops the verification, wherever it sits; its channel closes.
    fn remove_verification(&mut self, round: Round) -> Option<Verification> {
        match &self.active_verification {
            Some(active) if active.round == round => self.active_verification.take(),
            _ => self.queued_verifications.remove(&round),
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

        // A build proposes for its round; it goes before verifications.
        if let Some((_, cause, build)) = self.pending_build.take() {
            let parent = build.context.parent.1;
            let parent_round = Round::new(build.context.round.epoch(), build.context.parent.0);
            let (finalized_round, _, finalized_digest) = self.network_finalized_tip;
            // A certified parent must be the finalized tip or come from
            // a later round. Decide eligibility before starting its fetch.
            if parent == finalized_digest || parent_round > finalized_round {
                let target = self.local_state.update_finalized(
                    self.delivered_finalized_tip.1,
                    self.delivered_finalized_tip.2,
                );
                let fut = execute_build(
                    self.execution_node.clone(),
                    self.marshal.clone(),
                    cause,
                    target,
                    build,
                    self.built_blocks.get(&parent).cloned(),
                )
                .map(ExecutionTaskOutcome::Build);
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

        // Only the verification holding the ancestry slot probes.
        if let Some(active) = &mut self.active_verification
            && matches!(active.walk.step, WalkStep::Probe)
        {
            let block = active.walk.probe();
            let fut = execute_delivery(
                self.execution_node.clone(),
                WalkOwner::Verification(active.round),
                active.walk.cause.clone(),
                block,
            );
            self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Verify, fut));
            return;
        }

        if let Some(walk) = &mut self.convergence
            && matches!(walk.step, WalkStep::Probe)
        {
            let block = walk.probe();
            let fut = execute_delivery(
                self.execution_node.clone(),
                WalkOwner::Convergence,
                walk.cause.clone(),
                block,
            );
            self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Deliver, fut));
        }
    }

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
        let fut = execute_forkchoice(self.execution_node.clone(), Span::current(), target, None)
            .map(ExecutionTaskOutcome::Forkchoice);
        self.set_execution_task(ExecutionTask::new(ExecutionTaskType::Forkchoice, fut));
        true
    }

    /// Uses the latest delivered finalized block for both fields unless the
    /// convergence target has a VALID delivery and proven ancestry to the
    /// current network finalized tip.
    fn next_forkchoice_target(&self) -> Option<LocalState> {
        let (_, height, digest) = self.delivered_finalized_tip;
        let mut target = LocalState {
            head: (height, digest),
            finalized: (height, digest),
        };
        if let Some((height, digest)) = self.pending_head.executed {
            target = target.update_head(height, digest);
        }

        (target != self.local_state
            || self.deliveries_since_forkchoice >= DELIVERIES_PER_FORKCHOICE_UPDATE)
            .then_some(target)
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
/// Looks the block up locally, in the execution layer and then in marshal
/// storage, then subscribes for it if neither has it.
async fn fetch_block(
    execution_node: impl ExecutionLayer,
    marshal: impl Marshal,
    digest: Digest,
    round: Round,
) -> Option<Arc<Block>> {
    match look_up_block(execution_node, marshal.clone(), digest).await {
        Some(block) => Some(block),
        None => marshal.subscribe_by_digest(digest, round).await.ok(),
    }
}

/// Looks the block up locally: in the execution layer, then in marshal
/// storage, which may hold it whether or not it is finalized. Resolves
/// promptly either way.
///
/// Marshal's own lookup ends in the same reth query, restricted to canonical
/// blocks. Asking the execution layer first is still worth it: the provider
/// read is synchronous, while marshal answers through its mailbox and event
/// loop.
async fn look_up_block(
    execution_node: impl ExecutionLayer,
    marshal: impl Marshal,
    digest: Digest,
) -> Option<Arc<Block>> {
    match execution_node.block_by_digest(digest) {
        Ok(Some(block)) => return Some(Arc::new(block)),
        Ok(None) => {}
        Err(error) => {
            warn!(%error, "execution-layer block lookup failed; falling back to marshal");
        }
    }
    marshal.get_block(&digest).await.map(Arc::new)
}

/// Logs the error that shuts the executor down.
fn log_fatal(error: &Report) {
    error_span!("shutdown").in_scope(|| {
        error!(
            %error,
            "executor encountered fatal execution-layer update error; \
            shutting down to prevent consensus-execution divergence"
        )
    });
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

/// A verification request and its ancestry walk. It holds the engine slot
/// while its cursor is probed and waits in the queue otherwise, fetching
/// there if it must. The actor polls active requester cancellation, reaps
/// canceled queued requests, and pools parent subscriptions. It stays until
/// the candidate has a verdict, the request fails or is canceled, its round
/// falls at or below the network finalized round, its target falls below the
/// network finalized height, or a request for the same round replaces it.
struct Verification {
    round: Round,
    /// The walk toward the candidate, which is its target.
    walk: AncestryWalk,
    /// Delivers the verdict: `Some(duration)` when the execution layer
    /// accepted the candidate, `None` when it rejected it. Dropped without a
    /// value when verification failed or the request was replaced or dropped.
    response: oneshot::Sender<Option<Duration>>,
    /// Time spent in engine calls across the whole walk.
    duration: Duration,
}

impl Verification {
    fn new(
        round: Round,
        cause: Span,
        candidate: Arc<Block>,
        response: oneshot::Sender<Option<Duration>>,
    ) -> Self {
        Self {
            round,
            walk: AncestryWalk::new(cause, candidate),
            response,
            duration: Duration::ZERO,
        }
    }

    fn is_canceled(&self) -> bool {
        self.response.is_canceled()
    }

    /// Answers the requester and consumes the verification.
    fn respond(self, verdict: Option<Duration>) {
        if self.response.send(verdict).is_err() {
            info!("verification subscriber went away before the verdict was delivered");
        }
    }

    /// Updates the walk for finality and returns whether to retain the request.
    /// Obsolete rounds and historical targets are removed without a verdict.
    fn retain_after_finality(
        &mut self,
        network_finalized_round: Round,
        network_finalized_height: Height,
    ) -> bool {
        // A request for a round finality has passed can no longer influence consensus.
        if self.round <= network_finalized_round {
            debug!(round = %self.round, finalized_round = %network_finalized_round, "dropping verification at or below the finalized round");
            return false;
        }

        let target_height = self.walk.target.height();
        if target_height < network_finalized_height {
            debug!(round = %self.round, %target_height, %network_finalized_height, "dropping verification below the finalized height");
            return false;
        }

        self.walk
            .on_finalized_tip(network_finalized_round, network_finalized_height);
        true
    }

    /// Polls the active requester's cancellation and its local parent lookup.
    fn poll_event(&mut self, cx: &mut std::task::Context<'_>) -> Poll<VerificationEvent> {
        if self.response.poll_canceled(cx).is_ready() {
            return Poll::Ready(VerificationEvent::Canceled);
        }
        self.walk
            .poll_lookup(cx)
            .map(VerificationEvent::ParentLookedUp)
    }
}

/// What a verification woke the event loop for.
enum VerificationEvent {
    /// Its requester went away.
    Canceled,
    /// Its local parent lookup resolved.
    ParentLookedUp(Option<Arc<Block>>),
}

/// One ancestry walk, shared by verification and pending-head convergence.
///
/// The walk probes its target with a bare `newPayload`. SYNCING means the
/// execution layer lacks the parent, so the walk fetches the parent and
/// probes it next, one block at a time down the chain. The walk stops at the
/// finalized tip and lets the finalization pipeline deliver finalized history.
///
/// For verification, a VALID ancestor restarts the walk at the target: the
/// execution layer connects buffered descendants itself once the gap is closed.
/// The target must itself return VALID before verification succeeds.
/// Targets overtaken by network finality are dropped without a verdict.
///
/// Convergence walks past VALID blocks until a VALID cursor or its parent
/// is the network finalized tip. That digest proves the target's ancestry;
/// the target must then return VALID before it can become HEAD. A changed
/// finalized digest requires a new ancestry proof.
///
/// The actor interprets engine replies, decides verdicts and HEAD eligibility,
/// and schedules ancestry work. Local lookups and marshal subscriptions supply
/// the next cursor without rendering verdicts.
///
/// Only the target and the current cursor are retained. Advancing to a
/// parent drops the previous cursor.
struct AncestryWalk {
    cause: Span,
    target: Arc<Block>,
    /// The block the walk probes next, or probed last.
    cursor: Arc<Block>,
    /// The step owns the local lookup or the abort handle for a pooled
    /// parent subscription. Changing steps cancels any outstanding fetch.
    step: WalkStep,
    /// The digest of the finalized tip reached in the target's ancestry.
    /// This proof survives reprobing the target. Verification does not
    /// require it and leaves this unset.
    proven_finalized_tip: Option<Digest>,
}

enum WalkStep {
    /// The cursor is ready for `newPayload`.
    Probe,
    /// The cursor is the current execution task.
    InFlight,
    /// The parent above the finalized tip is being looked up to continue
    /// execution or prove ancestry; `None` if neither the execution layer
    /// nor marshal storage has it.
    LookUpParent(BoxFuture<'static, Option<Arc<Block>>>),
    /// The parent is not held locally and is subscribed for with the marshal
    /// actor, which may have to fetch it from peers. The receiver closes if
    /// the marshal actor gives up on it.
    FetchParent { _aborter: Aborter },
    /// Finalization must deliver `height` before the walk can proceed.
    /// Finalized history is supplied by the finalization pipeline.
    WaitForFinalized { height: Height },
    /// The owner stopped the walk after a rejected or failed delivery. It
    /// restarts at the target when the owner asks.
    Stopped,
}

impl WalkStep {
    fn name(&self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::InFlight => "in_flight",
            Self::LookUpParent(_) => "look_up_parent",
            Self::FetchParent { .. } => "fetch_parent",
            Self::WaitForFinalized { .. } => "wait_for_finalized",
            Self::Stopped => "stopped",
        }
    }
}

/// Which walk a delivery belongs to.
#[derive(Clone, Copy, Debug)]
enum WalkOwner {
    /// The verification queued under this round.
    Verification(Round),
    Convergence,
}

impl std::fmt::Display for WalkOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verification(round) => write!(f, "verification {round}"),
            Self::Convergence => f.write_str("convergence"),
        }
    }
}

impl AncestryWalk {
    fn new(cause: Span, target: Arc<Block>) -> Self {
        Self {
            cause,
            cursor: target.clone(),
            target,
            step: WalkStep::Probe,
            proven_finalized_tip: None,
        }
    }

    fn at_target(&self) -> bool {
        self.cursor.digest() == self.target.digest()
    }

    /// Whether the walk waits for the engine's answer on `digest`.
    fn awaits(&self, digest: Digest) -> bool {
        matches!(self.step, WalkStep::InFlight) && self.cursor.digest() == digest
    }

    /// The cursor's parent and the round it was notarized in, the fetch hint
    /// for the marshal actor.
    fn parent(&self) -> (Round, Digest) {
        let context = self.cursor.context();
        let round = Round::new(context.round.epoch(), context.parent.0);
        (round, self.cursor.parent_digest())
    }

    fn parent_height(&self) -> Height {
        self.cursor.height().previous().unwrap_or(Height::zero())
    }

    /// Marks the cursor as in flight and returns it for delivery.
    fn probe(&mut self) -> Arc<Block> {
        self.step = WalkStep::InFlight;
        self.cursor.clone()
    }

    fn reprobe(&mut self) {
        self.cursor = self.target.clone();
        self.step = WalkStep::Probe;
    }

    fn wait_for_finalized(&mut self, height: Height) {
        self.cursor = self.target.clone();
        self.step = WalkStep::WaitForFinalized { height };
    }

    /// Whether finality has advanced past the current cursor.
    fn below_finality(&self, finalized_height: Height) -> bool {
        self.cursor.height() < finalized_height
    }

    /// A digest mismatch proves a fork only at the finalized height.
    fn conflicts_with_finality(&self, finalized_height: Height, finalized_digest: Digest) -> bool {
        let cursor_is_not_tip =
            self.cursor.height() == finalized_height && self.cursor.digest() != finalized_digest;
        let parent_is_not_tip = self.cursor.height().previous() == Some(finalized_height)
            && self.cursor.parent_digest() != finalized_digest;

        cursor_is_not_tip || parent_is_not_tip
    }

    fn stop(&mut self) {
        self.step = WalkStep::Stopped;
    }

    /// Polls the local parent lookup. The actor applies the result before
    /// polling the walk again, advancing the cursor or starting a fetch.
    fn poll_lookup(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Option<Arc<Block>>> {
        match &mut self.step {
            WalkStep::LookUpParent(lookup) => lookup.poll_unpin(cx),
            WalkStep::Probe
            | WalkStep::InFlight
            | WalkStep::FetchParent { .. }
            | WalkStep::WaitForFinalized { .. }
            | WalkStep::Stopped => Poll::Pending,
        }
    }

    /// Drives the local lookup until it returns a parent or reports a miss.
    async fn next_lookup(&mut self) -> Option<Arc<Block>> {
        poll_fn(|cx| self.poll_lookup(cx)).await
    }

    /// Looks up the cursor's parent locally to continue the walk.
    fn look_up_parent(&mut self, execution_node: impl ExecutionLayer, marshal: impl Marshal) {
        let (_, digest) = self.parent();
        self.step = WalkStep::LookUpParent(look_up_block(execution_node, marshal, digest).boxed());
    }

    /// Subscribes for the cursor's parent with the marshal actor.
    fn fetch_parent(
        &mut self,
        marshal: impl Marshal,
        owner: WalkOwner,
        finalized_round: Round,
        fetches: &mut AbortablePool<'static, (WalkOwner, Option<Arc<Block>>)>,
    ) {
        let (round, digest) = self.parent();
        if round <= finalized_round {
            // Marshal cannot fetch below its round floor. That restriction
            // alone does not prove a digest conflict; await finalized history.
            self.wait_for_finalized(self.parent_height());
            return;
        }
        let receiver = marshal.subscribe_by_digest(digest, round);
        self.step = WalkStep::FetchParent {
            _aborter: fetches.push(async move { (owner, receiver.await.ok()) }),
        };
    }

    /// Makes the found parent the cursor.
    fn on_fetched(&mut self, block: Arc<Block>) {
        self.cursor = block;
        self.step = WalkStep::Probe;
    }

    /// Restarts ancestry work covered by the finalized height. The round
    /// floor also cancels subscriptions, but local ancestors remain usable.
    /// Reprobing finds the new finality boundary from the target.
    fn on_finalized_tip(&mut self, finalized_round: Round, finalized_height: Height) {
        let restart = match &self.step {
            WalkStep::Probe => !self.at_target() && self.cursor.height() <= finalized_height,
            WalkStep::LookUpParent(_) => self.parent_height() <= finalized_height,
            WalkStep::FetchParent { .. } => {
                self.parent_height() <= finalized_height || self.parent().0 <= finalized_round
            }
            WalkStep::InFlight | WalkStep::WaitForFinalized { .. } | WalkStep::Stopped => false,
        };
        if restart {
            debug!(parent: &self.cause, %finalized_round, %finalized_height, "finalized tip covers ancestry work; restarting at target");
            self.reprobe();
        }
    }

    /// Restarts at the target once finalization delivered the block the walk
    /// was about to deliver or fetch itself. A stopped walk restarts as well.
    fn on_finalized_delivered(&mut self, delivered_height: Height) {
        let restart = match &self.step {
            WalkStep::Probe => !self.at_target() && self.cursor.height() <= delivered_height,
            WalkStep::LookUpParent(_) | WalkStep::FetchParent { .. } => {
                self.parent_height() <= delivered_height
            }
            WalkStep::WaitForFinalized { height } => *height <= delivered_height,
            WalkStep::Stopped => true,
            WalkStep::InFlight => false,
        };
        if restart {
            self.reprobe();
        }
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
            ExecutionTaskOutcome::Forkchoice(forkchoice)
            | ExecutionTaskOutcome::Build(BuildOutcome::Forkchoice(forkchoice)) => {
                Some(forkchoice.target)
            }
            ExecutionTaskOutcome::Build(_)
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

/// The result of an execution task, interpreted by [`Actor::handle_execution_task_finished`].
enum ExecutionTaskOutcome {
    /// A walk's cursor was delivered. The status carries the time the engine
    /// call took.
    Delivered {
        owner: WalkOwner,
        digest: Digest,
        status: eyre::Result<(PayloadStatusEnum, Duration)>,
    },
    /// The request travels back for its acknowledgement.
    FinalizedDelivered {
        request: FinalizedBlockRequest,
        status: eyre::Result<PayloadStatusEnum>,
    },
    Build(BuildOutcome),
    Forkchoice(ForkchoiceOutcome),
}

/// Where a build ended: before its FCU, on a failed parent delivery, or after
/// executing the FCU. The FCU response is interpreted by the actor.
enum BuildOutcome {
    /// Cancellation, a missing parent, or a non-VALID parent ends only the build.
    Aborted { delivery_attempted: bool },
    /// The parent newPayload call failed; the actor must shut down.
    ParentDeliveryFailed(Report),
    /// The parent was VALID. The FCU may have succeeded, failed, or been skipped.
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
            Self::Delivered { .. } => "delivered",
            Self::FinalizedDelivered { .. } => "finalized-delivered",
            Self::Build(_) => "build",
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
    build: Option<(
        Span,
        oneshot::Sender<TempoBuiltPayload>,
        TempoPayloadAttributes,
    )>,
) -> ForkchoiceOutcome {
    let (build, attributes) = match build {
        Some((cause, response, attributes)) if !response.is_canceled() => {
            (Some((cause, response)), Some(attributes))
        }
        Some(_) => {
            info!(
                "dropping payload build request: subscriber went away while \
                awaiting execution"
            );
            (None, None)
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
/// starts the payload build if the parent is VALID.
///
/// A build with [`Build::deferred_extra_data`] resolves that extra data
/// between the VALID answer and the forkchoice update. The wait counts against
/// the build budget.
#[instrument(skip_all, parent = &cause, fields(
    round = %build.context.round,
    parent = %build.context.parent.1,
))]
async fn execute_build(
    execution_node: impl ExecutionLayer,
    marshal: impl Marshal,
    cause: Span,
    mut target: LocalState,
    build: Box<Build>,
    retained_parent: Option<Arc<Block>>,
) -> BuildOutcome {
    let Build {
        context,
        attributes,
        deferred_extra_data,
        mut response,
    } = *build;
    let mut attributes = *attributes;
    let parent_digest = context.parent.1;
    let parent_round = Round::new(context.round.epoch(), context.parent.0);
    let block = select! {
        biased;

        () = response.cancellation() => {
            info!("build subscriber went away");
            return BuildOutcome::Aborted { delivery_attempted: false };
        },
        block = async {
            match retained_parent {
                Some(block) => Some(block),
                None => fetch_block(execution_node.clone(), marshal.clone(), parent_digest, parent_round)
                    .await,
            }
        } => block,
    };
    let Some(block) = block else {
        warn!("marshal dropped the build parent subscription");
        return BuildOutcome::Aborted {
            delivery_attempted: false,
        };
    };
    target.head = (block.height(), parent_digest);
    let status = match deliver_block(&execution_node, Arc::clone(&block))
        .await
        .wrap_err("failed delivering build parent")
    {
        Ok(status) => status,
        Err(error) => return BuildOutcome::ParentDeliveryFailed(error),
    };
    if status != PayloadStatusEnum::Valid {
        warn!(%status, "build parent was not VALID");
        return BuildOutcome::Aborted {
            delivery_attempted: true,
        };
    }
    if response.is_canceled() {
        info!("build subscriber went away");
        return BuildOutcome::Aborted {
            delivery_attempted: true,
        };
    }
    if let Some(deferred) = deferred_extra_data {
        let wait_start = Instant::now();
        let extra_data = select! {
            biased;

            () = response.cancellation() => {
                info!("build subscriber went away while the build waited for extra data");
                return BuildOutcome::Aborted {
                    delivery_attempted: true,
                };
            },
            extra_data = deferred.resolve(block) => extra_data,
        };
        let extra_data = match extra_data {
            Ok(extra_data) => extra_data,
            Err(error) => {
                warn!(%error, "failed to get the extra data of the proposal");
                return BuildOutcome::Aborted {
                    delivery_attempted: true,
                };
            }
        };
        attributes = attributes.with_extra_data(extra_data);
        // The requester measured the budget when it sent the build, but we spent some time here
        // for waiting for the extra data to be resolved.
        if let Some(budget) = attributes.payload_build_budget() {
            attributes =
                attributes.with_payload_build_budget(budget.saturating_sub(wait_start.elapsed()));
        }
    }
    BuildOutcome::Forkchoice(
        execute_forkchoice(
            execution_node,
            cause.clone(),
            target,
            Some((cause, response, attributes)),
        )
        .await,
    )
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

/// Delivers a walk's cursor through a bare new-payload request.
#[instrument(
    skip_all,
    parent = &cause,
    fields(
        %owner,
        block.digest = %block.digest(),
        block.height = %block.height(),
        block.parent_digest = %block.parent_digest(),
    ),
)]
async fn execute_delivery(
    execution_node: impl ExecutionLayer,
    owner: WalkOwner,
    cause: Span,
    block: Arc<Block>,
) -> ExecutionTaskOutcome {
    let digest = block.digest();
    let started = Instant::now();
    let status = deliver_block(&execution_node, block)
        .await
        .map(|status| (status, started.elapsed()));
    ExecutionTaskOutcome::Delivered {
        owner,
        digest,
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
    /// This exact target executed and its ancestry reaches network finality.
    /// Cleared when the selected target or network finalized digest changes.
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
