//! Dynamic role supervision for multi-sequencer zone nodes.
//!
//! The role controller switches complete role generations — block production or import,
//! broadcast, transaction flow, settlement, and sequencer background tasks — as one fenced
//! unit, driven by the effective [`LeadershipSchedule`].
//!
//! The control rule is about the **next anchor**, never the last applied one: for the next
//! Tempo anchor `N` to be consumed, if `schedule.leader_for(N)` is this node and the zone
//! block embedding `N − 1` is locally canonical, the controller runs the leader generation
//! and the engine produces `N`; otherwise it runs the follower generation and imports. The
//! per-anchor [`ProductionPermit`] inside the engine and the
//! anchor-aware sender fence inside follower import are the protocol fences; generation
//! switching is lifecycle management.

use std::{sync::Arc, time::Duration};

use alloy_primitives::Address;
use eyre::{OptionExt as _, WrapErr as _};
use reth_chain_state::PersistedBlockSubscriptions;
use reth_node_api::ConsensusEngineHandle;
use reth_payload_builder::PayloadBuilderHandle;
use reth_primitives_traits::SealedHeader;
use reth_provider::HeaderProvider;
use reth_storage_api::{BlockNumReader, BlockReader, ReceiptProvider, StateProviderFactory};
use reth_transaction_pool::TransactionPool;
use tempo_primitives::{Block, TempoHeader};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, error, info, warn};
use zone_chainspec::ZoneChainSpec;
use zone_l1::{DepositQueue, EncryptionKeyRing, L1BlockTracker, TempoStateExt as _};
use zone_p2p::{
    BackfillCommand, BackfillRequest, BackfillResponse, LeadershipSchedule, P2pCommand, P2pEvent,
    P2pPeerId,
};
use zone_payload::ZonePayloadTypes;
use zone_sequencer::{
    SettlementManager, SettlementProver, ZoneSequencerConfig, ZoneSequencerHandle,
    ZoneSequencerProvider, resolve_portal_zone_anchor, spawn_zone_sequencer,
};
use zone_transaction_pool_alias::TempoPooledTransaction;

mod zone_transaction_pool_alias {
    pub(super) use tempo_transaction_pool::transaction::TempoPooledTransaction;
}

use crate::{
    EngineExit, ProductionPermit, ZoneEngine, ZoneSequencerAddOnsConfig,
    follower::{BlockSyncP2p, FollowerBlockSync, FollowerBlockSyncContext, PeerTipRegistry},
    replication::{
        BroadcasterShutdown, broadcast_persisted_blocks, collect_follower_settlement_signatures,
    },
    settlement_attestation::AttestationContext,
    tx_forwarding::{forward_new_transactions, insert_forwarded_transactions},
};

/// Backoff after a transient role or promotion-readiness derivation failure.
const ROLE_DECISION_RETRY_BACKOFF: Duration = Duration::from_millis(500);
/// How long a stopping generation may take before its remaining tasks are aborted.
///
/// Must cover the longest in-flight L1 confirmation (`processWithdrawals` and `submitBatch`
/// both wait up to 30s for a receipt) plus a 10s margin so demotion does not abort those waits.
const GENERATION_STOP_TIMEOUT: Duration = Duration::from_secs(40);
/// Backoff after a generation task fails unexpectedly.
const GENERATION_RESTART_BACKOFF: Duration = Duration::from_millis(500);
/// Buffer size for per-generation event channels.
const GENERATION_EVENT_BACKLOG: usize = 128;

/// Everything a role generation needs to start its tasks.
pub(crate) struct RoleControllerContext<P, Pool> {
    pub local_ed25519_public_key: P2pPeerId,
    pub schedule: LeadershipSchedule,
    pub provider: P,
    pub pool: Pool,
    pub engine_handle: ConsensusEngineHandle<ZonePayloadTypes>,
    pub payload_builder: PayloadBuilderHandle<ZonePayloadTypes>,
    pub chain_spec: Arc<ZoneChainSpec>,
    pub deposit_queue: DepositQueue,
    pub l1_block_tracker: L1BlockTracker,
    pub encryption_keys: EncryptionKeyRing,
    pub commands: mpsc::Sender<P2pCommand>,
    pub backfill_commands: mpsc::Sender<BackfillCommand>,
    pub attestation: AttestationContext,
    pub settlements: Option<SettlementManager>,
    pub portal_address: Address,
    /// Sequencer resources constructed unconditionally at startup; activation is gated by
    /// the leader generation. `None` means this node can never lead.
    pub sequencer: Option<LeaderSequencerDeps>,
    /// Tip evidence advertised by peers via backfill completions.
    pub peer_tips: PeerTipRegistry,
    /// Live role/readiness snapshot shared with the status RPC.
    pub status: SharedRoleStatus,
}

/// Live role and promotion-readiness snapshot for observability and the status RPC.
#[derive(Debug, Clone, Default)]
pub struct RoleStatus {
    /// `"leader"`, `"follower"`, or `"fenced"`.
    pub role: &'static str,
    /// Monotonic generation counter.
    pub generation: u64,
    /// Epoch of the record governing the next anchor, when known.
    pub epoch: Option<u64>,
    /// Whether the promotion barrier is currently satisfied.
    pub ready_for_promotion: bool,
    /// Unsatisfied promotion-readiness reasons (empty when ready).
    pub promotion_reasons: Vec<String>,
}

/// Shared handle to the live [`RoleStatus`].
pub type SharedRoleStatus = Arc<std::sync::Mutex<RoleStatus>>;

/// Dependencies used by leader tasks; the proof collector itself is node-owned.
pub(crate) struct LeaderSequencerDeps {
    pub config: ZoneSequencerAddOnsConfig,
    pub sequencer_config: ZoneSequencerConfig,
    /// Node-owned collector shared across all role generations.
    pub proof_collector: Option<zone_sequencer::ProofCollectorHandle>,
    pub prover: Option<SettlementProver>,
}

/// Sinks for the long-lived P2P event demultiplexer.
///
/// Role generations receive typed substreams, so dropping one generation never drops the
/// underlying network event stream.
#[derive(Clone, Default)]
pub(crate) struct EventSinks {
    inner: Arc<std::sync::Mutex<GenerationSinks>>,
}

impl EventSinks {
    fn install(
        &self,
        sync: mpsc::Sender<P2pEvent>,
        transactions: Option<mpsc::Sender<P2pEvent>>,
        backfill_responses: Option<mpsc::Sender<BackfillResponse>>,
    ) {
        let mut sinks = self.inner.lock().expect("poisoned");
        sinks.sync = Some(sync);
        sinks.transactions = transactions;
        sinks.backfill_responses = backfill_responses;
    }

    fn clear(&self) {
        let mut sinks = self.inner.lock().expect("poisoned");
        sinks.sync = None;
        sinks.transactions = None;
        sinks.backfill_responses = None;
    }

    fn sink_for(&self, event: &P2pEvent) -> Option<mpsc::Sender<P2pEvent>> {
        let sinks = self.inner.lock().expect("poisoned");
        if matches!(event, P2pEvent::TransactionReceived { .. }) {
            sinks.transactions.clone()
        } else {
            sinks.sync.clone()
        }
    }

    fn backfill_response_sink(&self) -> Option<mpsc::Sender<BackfillResponse>> {
        self.inner
            .lock()
            .expect("poisoned")
            .backfill_responses
            .clone()
    }
}

#[derive(Default)]
struct GenerationSinks {
    sync: Option<mpsc::Sender<P2pEvent>>,
    transactions: Option<mpsc::Sender<P2pEvent>>,
    backfill_responses: Option<mpsc::Sender<BackfillResponse>>,
}

/// Long-lived P2P event demultiplexer for non-backfill protocols.
///
/// It owns the generic event receiver for the process lifetime and forwards events to the active
/// generation's substream. Events arriving between generations are dropped because the successor
/// re-derives its state from the provider and schedule. Generation delivery is deliberately
/// non-blocking so a slow generation cannot block process-lifetime protocol work.
pub(crate) async fn route_events_to_generations(
    mut events: mpsc::Receiver<P2pEvent>,
    sinks: EventSinks,
) {
    while let Some(event) = events.recv().await {
        let Some(sink) = sinks.sink_for(&event) else {
            metrics::counter!("zone_leadership_events_dropped_between_generations_total")
                .increment(1);
            debug!(target: "zone::role", "Dropping P2P event with no active generation consumer");
            continue;
        };
        match sink.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Live blocks are recovered by the follower's periodic backfill probe, and
                // transaction forwarding reconciles from the pool. Keep this router non-blocking.
                metrics::counter!("zone_leadership_events_dropped_backpressure_total").increment(1);
                debug!(
                    target: "zone::role",
                    "Dropping generation event because its bounded sink is full"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The generation stopped after we snapshotted its sink; the next generation
                // installs fresh channels and re-derives its state, so late generation-specific
                // events must not leak into the successor.
                metrics::counter!("zone_leadership_events_dropped_between_generations_total")
                    .increment(1);
            }
        }
    }
    error!(target: "zone::role", "P2P event channel closed");
}

/// Routes process-lifetime backfill requests to the canonical provider server.
pub(crate) async fn route_backfill_requests(
    mut requests: mpsc::Receiver<BackfillRequest>,
    backfill: mpsc::Sender<BackfillRequest>,
) {
    while let Some(request) = requests.recv().await {
        let start = request.start;
        if let Err(err) = backfill.try_send(request) {
            metrics::counter!("zone_leadership_backfill_requests_dropped_total").increment(1);
            warn!(target: "zone::role", %err, start, "Dropped a block backfill request because the serving queue is unavailable");
        }
    }
    error!(target: "zone::role", "Typed P2P backfill request channel closed");
}

/// Routes accepted backfill responses to the currently active follower generation.
pub(crate) async fn route_backfill_responses(
    mut responses: mpsc::Receiver<BackfillResponse>,
    sinks: EventSinks,
) {
    while let Some(response) = responses.recv().await {
        let Some(sink) = sinks.backfill_response_sink() else {
            metrics::counter!("zone_leadership_events_dropped_between_generations_total")
                .increment(1);
            debug!(target: "zone::role", "Dropping backfill response with no active follower consumer");
            continue;
        };
        match sink.try_send(response) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                metrics::counter!("zone_leadership_events_dropped_backpressure_total").increment(1);
                debug!(target: "zone::role", "Dropping backfill response because the generation sink is full");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                metrics::counter!("zone_leadership_events_dropped_between_generations_total")
                    .increment(1);
            }
        }
    }
    error!(target: "zone::role", "Typed P2P backfill response channel closed");
}

/// The role a generation runs, derived from the next-anchor rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DesiredRole {
    Leader {
        epoch: u64,
        /// The next anchor, read while deriving this role decision.
        next_anchor: u64,
    },
    Follower {
        epoch: u64,
    },
    /// No retained leadership record governs the next anchor, or this node cannot lead.
    Fenced,
}

impl DesiredRole {
    /// Stable name for status, metric labels, and logs.
    const fn name(self) -> &'static str {
        match self {
            Self::Leader { .. } => "leader",
            Self::Follower { .. } => "follower",
            Self::Fenced => "fenced",
        }
    }

    /// Value for the `zone_leadership_role` gauge.
    const fn gauge(self) -> f64 {
        match self {
            Self::Leader { .. } => 2.0,
            Self::Follower { .. } => 1.0,
            Self::Fenced => 0.0,
        }
    }

    /// Epoch of the governing record, when one governs.
    const fn epoch(self) -> Option<u64> {
        match self {
            Self::Leader { epoch, .. } | Self::Follower { epoch } => Some(epoch),
            Self::Fenced => None,
        }
    }

    /// Whether two roles are the same variant, ignoring the epoch.
    ///
    /// Generations are switched per variant, not per epoch: an epoch bump that leaves this
    /// node in the same role must not tear down and rebuild its task graph.
    fn same_variant(self, other: Self) -> bool {
        std::mem::discriminant(&self) == std::mem::discriminant(&other)
    }
}

/// Outcome of one generation task, tagged for supervision decisions.
#[derive(Debug)]
enum TaskEnd {
    Engine(EngineExit),
    SequencerStopped,
    Ended(&'static str),
}

/// Whether a generation stopped with its canonical-state boundary proven.
///
/// A failed stop must fence the role controller: an aborted engine task may have an already
/// enqueued Engine API message that Reth can still apply after the task has gone away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenerationStopOutcome {
    Stopped,
    Failed,
}

/// Supervise the long-running sequencer children as one role-generation task.
///
/// An unexpected child exit must restart the whole generation immediately. During an intentional
/// generation stop, however, both children retain the graceful shutdown window needed to finish
/// in-flight L1 transactions.
async fn supervise_sequencer_tasks(
    handle: ZoneSequencerHandle,
    stop: CancellationToken,
) -> TaskEnd {
    let mut withdrawal = AbortOnDropHandle::new(handle.withdrawal_handle);
    let mut monitor = AbortOnDropHandle::new(handle.monitor_handle);

    tokio::select! {
        biased;
        () = stop.cancelled() => {
            // Both children observe the same token at their poll boundaries. Keep both handles
            // alive until they finish; the outer generation timeout will abort this supervisor
            // and AbortOnDropHandle will then abort either child that is still stuck.
            let (withdrawal_result, monitor_result) =
                tokio::join!(&mut withdrawal, &mut monitor);
            if let Err(err) = withdrawal_result {
                warn!(target: "zone::role", %err, "Withdrawal processor task failed during shutdown");
            }
            if let Err(err) = monitor_result {
                warn!(target: "zone::role", %err, "Zone monitor task failed during shutdown");
            }
            TaskEnd::SequencerStopped
        }
        result = &mut withdrawal => {
            match result {
                Ok(()) => warn!(target: "zone::role", "Withdrawal processor task stopped unexpectedly"),
                Err(err) => warn!(target: "zone::role", %err, "Withdrawal processor task failed"),
            }
            // Returning drops and aborts the monitor handle. The role controller observes
            // TaskEnd::Ended and restarts the complete generation.
            TaskEnd::Ended("withdrawal-processor")
        }
        result = &mut monitor => {
            match result {
                Ok(()) => warn!(target: "zone::role", "Zone monitor task stopped unexpectedly"),
                Err(err) => warn!(target: "zone::role", %err, "Zone monitor task failed"),
            }
            // Returning drops and aborts the withdrawal handle before the generation restarts.
            TaskEnd::Ended("zone-monitor")
        }
    }
}

/// Leader-only controls that must either both exist or both be absent.
struct LeaderShutdown {
    /// Fires when the leader engine task returns.
    engine_done: oneshot::Receiver<()>,
    /// Receives exactly one shutdown decision for the persisted-block broadcaster.
    broadcaster: oneshot::Sender<BroadcasterShutdown>,
}

struct RunningGeneration {
    id: u64,
    role: DesiredRole,
    token: CancellationToken,
    leader_shutdown: Option<LeaderShutdown>,
    tasks: JoinSet<TaskEnd>,
}

impl RunningGeneration {
    async fn stop(mut self, sinks: &EventSinks) -> GenerationStopOutcome {
        sinks.clear();
        self.token.cancel();
        let deadline = tokio::time::Instant::now() + GENERATION_STOP_TIMEOUT;

        let mut outcome = GenerationStopOutcome::Stopped;

        // Cancellation is not a block boundary: an in-flight advance still completes before the
        // engine returns, so the canonical head keeps moving after `token.cancel()`. The
        // broadcaster can only be given a drain target once the engine has actually stopped.
        let mut leader_shutdown = self.leader_shutdown.take();
        let draining = match leader_shutdown.as_mut() {
            Some(LeaderShutdown { engine_done, .. }) => {
                match tokio::time::timeout_at(deadline, engine_done).await {
                    Ok(Ok(())) => true,
                    Ok(Err(_)) => {
                        outcome = GenerationStopOutcome::Failed;
                        error!(
                            target: "zone::role",
                            generation = self.id,
                            "Engine task ended without acknowledging a clean stop; fencing role controller"
                        );
                        false
                    }
                    Err(_) => {
                        outcome = GenerationStopOutcome::Failed;
                        error!(
                            target: "zone::role",
                            generation = self.id,
                            "Engine did not stop within the timeout; fencing role controller"
                        );
                        false
                    }
                }
            }
            // Not a leader generation, so there is no canonical tail to drain.
            None => false,
        };
        if let Some(LeaderShutdown { broadcaster, .. }) = leader_shutdown {
            let command = if draining {
                BroadcasterShutdown::Drain
            } else {
                BroadcasterShutdown::Stop
            };
            if broadcaster.send(command).is_err() {
                outcome = GenerationStopOutcome::Failed;
                error!(
                    target: "zone::role",
                    generation = self.id,
                    ?command,
                    "Persisted block broadcaster exited before its shutdown could be acknowledged; fencing role controller"
                );
            }
        }
        loop {
            match tokio::time::timeout_at(deadline, self.tasks.join_next()).await {
                Ok(Some(result)) => {
                    if let Err(err) = result
                        && !err.is_cancelled()
                    {
                        warn!(target: "zone::role", generation = self.id, %err, "Generation task panicked during stop");
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    warn!(
                        target: "zone::role",
                        generation = self.id,
                        "Generation did not stop within the timeout; aborting remaining tasks"
                    );
                    outcome = GenerationStopOutcome::Failed;
                    self.tasks.abort_all();
                    while self.tasks.join_next().await.is_some() {}
                    break;
                }
            }
        }
        match outcome {
            GenerationStopOutcome::Stopped => {
                info!(target: "zone::role", generation = self.id, role = self.role.name(), "Role generation stopped");
            }
            GenerationStopOutcome::Failed => {
                error!(target: "zone::role", generation = self.id, role = self.role.name(), "Role generation teardown was not proven safe");
            }
        }
        outcome
    }
}

/// Stop the active generation and keep the controller fenced if its teardown is unproven.
///
/// Returns `false` when the controller must exit rather than allow a successor generation to
/// start after a failed teardown.
async fn stop_current_generation(
    current: &mut Option<RunningGeneration>,
    sinks: &EventSinks,
) -> bool {
    if let Some(generation) = current.take()
        && generation.stop(sinks).await == GenerationStopOutcome::Failed
    {
        error!(target: "zone::role", "Role controller exiting after an unproven generation teardown");
        return false;
    }

    true
}

/// Derive the desired role for the next anchor from local canonical state and the schedule.
///
/// `DesiredRole::Leader` carries the next anchor it was derived from, so the promotion
/// barrier never re-reads the checkpoint under a second, possibly divergent, error policy.
fn desired_role<P>(
    provider: &P,
    schedule: &LeadershipSchedule,
    local: &P2pPeerId,
    can_lead: bool,
) -> eyre::Result<DesiredRole>
where
    P: StateProviderFactory,
{
    let checkpoint = provider
        .latest()
        .map_err(eyre::Report::from)
        .and_then(|state| state.tempo_block_number().map_err(eyre::Report::from))?;
    let next_anchor = checkpoint.saturating_add(1);
    Ok(match schedule.leader_for(next_anchor) {
        None => DesiredRole::Fenced,
        Some(record) if &record.leader == local => {
            if can_lead {
                DesiredRole::Leader {
                    epoch: record.epoch,
                    next_anchor,
                }
            } else {
                error!(
                    target: "zone::role",
                    epoch = record.epoch,
                    next_anchor,
                    "This node is the scheduled leader but has no sequencer resources; fencing"
                );
                DesiredRole::Fenced
            }
        }
        Some(record) => DesiredRole::Follower {
            epoch: record.epoch,
        },
    })
}

/// Promotion-readiness verdict from the evidence required by the active transition mode.
#[derive(Debug)]
enum Readiness {
    Ready,
    Conflicted(String),
}

/// Evaluate the promotion barrier
///
/// Forced-recovery promotion requires the operator-selected block to remain in the local canonical
/// chain. The node may have advanced beyond that checkpoint before restarting, so requiring it to
/// remain the head would make every in-progress recovery restart fatal. Normal transitions need no
/// additional evidence: the next-anchor rule and production permits that stop checkpoint batches
/// at leadership boundaries ensure all earlier leaders' blocks are already local.
fn promotion_readiness<P>(
    provider: &P,
    schedule: &LeadershipSchedule,
    local: &P2pPeerId,
    next_anchor: u64,
) -> Readiness
where
    P: BlockNumReader + HeaderProvider<Header = TempoHeader>,
{
    if let Some(recovery) = schedule.forced_recovery().filter(|recovery| {
        &recovery.leader == local
            && next_anchor >= recovery.recovery_start_tempo_block
            && recovery
                .portal_activation_tempo_block
                .is_none_or(|activation| next_anchor < activation)
    }) {
        if let Err(err) = canonical_recovery_height(provider, recovery.recovery_block_hash) {
            return Readiness::Conflicted(format!(
                "forced recovery checkpoint is not canonical: {err}"
            ));
        }
        return Readiness::Ready;
    }

    Readiness::Ready
}

/// Resolve an operator-selected recovery hash to its canonical header.
///
/// The hash-to-number index can contain a known non-canonical block, so the header at the resolved
/// height is read through the canonical number index and compared again before the checkpoint is
/// trusted. This proves local ancestry only: restart safety additionally assumes that participating
/// nodes advanced on the same non-equivocating recovery-leader chain.
pub(crate) fn canonical_recovery_height<P>(
    provider: &P,
    recovery_block_hash: alloy_primitives::B256,
) -> eyre::Result<u64>
where
    P: BlockNumReader + HeaderProvider<Header = TempoHeader>,
{
    let recovery_height = provider
        .block_number(recovery_block_hash)?
        .ok_or_else(|| eyre::eyre!("recovery block {recovery_block_hash} is unknown"))?;
    let header = provider.sealed_header(recovery_height)?.ok_or_else(|| {
        eyre::eyre!("canonical header at recovery height {recovery_height} is missing")
    })?;
    eyre::ensure!(
        header.hash() == recovery_block_hash,
        "recovery block {recovery_block_hash} is not canonical at height {recovery_height}; \
         canonical hash is {}",
        header.hash(),
    );
    Ok(recovery_height)
}

/// Run the role controller until the process shuts down.
///
/// `sinks` must be the same [`EventSinks`] handed to [`route_events_to_generations`] — the
/// router is long-lived while generations come and go.
///
/// Subscribes to schedule notifications plus generation task completion, re-derives the desired
/// role by the next-anchor rule, and switches role generations.
/// Observation alone never switches roles — the trigger is consumption progress reaching
/// the boundary, which this loop tracks by re-reading the local Tempo checkpoint.
pub(crate) async fn run_role_controller<P, Pool>(
    context: RoleControllerContext<P, Pool>,
    sinks: EventSinks,
) where
    P: BlockNumReader
        + BlockReader<Block = Block>
        + HeaderProvider<Header = TempoHeader>
        + StateProviderFactory
        + ReceiptProvider
        + PersistedBlockSubscriptions
        + ZoneSequencerProvider
        + Clone
        + Send
        + Sync
        + 'static,
    Pool: TransactionPool<Transaction = TempoPooledTransaction> + Clone + 'static,
{
    let mut schedule_changes = context.schedule.subscribe();

    let mut generation_id: u64 = 0;
    let mut current: Option<RunningGeneration> = None;

    loop {
        // An rpc-only member is not registered with `ZonePortal`, so it can never be named
        // leader by a finalized transition. Fencing it explicitly means a corrupt or wrongly
        // provisioned record cannot start a producer whose blocks nobody could settle.
        let can_lead = context.sequencer.is_some()
            && context
                .schedule
                .is_quorum_member(&context.local_ed25519_public_key);
        let mut retry_decision = false;
        let mut desired = match desired_role(
            &context.provider,
            &context.schedule,
            &context.local_ed25519_public_key,
            can_lead,
        ) {
            Ok(desired) => desired,
            Err(err) => {
                error!(target: "zone::role", %err, "Failed reading the local Tempo checkpoint; fencing");
                retry_decision = true;
                DesiredRole::Fenced
            }
        };

        // Only forced recovery has an additional promotion barrier. Normal transitions are
        // complete when the local next anchor is assigned to this node.
        let mut promotion_reasons = if can_lead {
            Vec::new()
        } else {
            vec!["rpc-only nodes cannot get promoted".to_owned()]
        };
        if let DesiredRole::Leader { epoch, next_anchor } = desired
            && !current
                .as_ref()
                .is_some_and(|generation| generation.role.same_variant(desired))
        {
            match promotion_readiness(
                &context.provider,
                &context.schedule,
                &context.local_ed25519_public_key,
                next_anchor,
            ) {
                Readiness::Ready => {
                    info!(target: "zone::role", epoch, next_anchor, "Promotion barrier satisfied");
                }
                Readiness::Conflicted(detail) => {
                    error!(
                        target: "zone::role",
                        epoch,
                        %detail,
                        "Conflicting promotion evidence; fencing instead of promoting"
                    );
                    promotion_reasons = vec![detail];
                    desired = DesiredRole::Fenced;
                }
            }
        }
        if !current
            .as_ref()
            .is_some_and(|generation| generation.role.same_variant(desired))
        {
            if !stop_current_generation(&mut current, &sinks).await {
                return;
            }
            generation_id += 1;
            match start_generation(&context, &sinks, desired, generation_id).await {
                Ok(generation) => {
                    current = Some(generation);
                }
                Err(err) => {
                    // Starting a role generation is atomic: none of its task graph remains
                    // active after a startup failure. Leave the node fenced and retry the
                    // complete desired generation after the decision backoff.
                    sinks.clear();
                    retry_decision = true;
                    promotion_reasons = vec![format!(
                        "failed to start {} generation: {err:#}",
                        desired.name()
                    )];
                    error!(
                        target: "zone::role",
                        generation = generation_id,
                        role = desired.name(),
                        %err,
                        "Role generation failed to start; fencing before retry"
                    );
                }
            }

            let active_role = current
                .as_ref()
                .map(|generation| generation.role)
                .unwrap_or(DesiredRole::Fenced);
            metrics::counter!(
                "zone_leadership_transitions_total",
                "to" => active_role.name(),
            )
            .increment(1);
            metrics::gauge!("zone_leadership_role").set(active_role.gauge());
            if active_role.same_variant(desired)
                && let Some(epoch) = desired.epoch()
            {
                metrics::gauge!("zone_leadership_epoch").set(epoch as f64);
            }
        }

        let active_role = current
            .as_ref()
            .map(|generation| generation.role)
            .unwrap_or(DesiredRole::Fenced);
        // Readiness is exactly "nothing is blocking promotion", so it is derived rather than
        // tracked alongside the reasons it would have to stay consistent with.
        let ready_for_promotion = promotion_reasons.is_empty();
        {
            let mut status = context.status.lock().expect("poisoned");
            status.role = active_role.name();
            status.epoch = if active_role.same_variant(desired) {
                desired.epoch()
            } else {
                None
            };
            status.generation = generation_id;
            status.ready_for_promotion = ready_for_promotion;
            status.promotion_reasons = promotion_reasons;
        }
        metrics::gauge!("zone_leadership_ready_for_promotion").set(if ready_for_promotion {
            1.0
        } else {
            0.0
        });
        // A fenced generation has no tasks; an empty JoinSet's join_next() is immediately
        // ready with None, so polling it would spin this loop hot. Stay pending instead and
        // wake only on an explicit change or a retry for a failed/pending decision.
        let task_end = async {
            match current.as_mut() {
                Some(generation) if !generation.tasks.is_empty() => {
                    generation.tasks.join_next().await
                }
                _ => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            changed = schedule_changes.changed() => {
                if changed.is_err() {
                    error!(target: "zone::role", "Leadership schedule notifier closed");
                    return;
                }
            }
            result = task_end => {
                match result {
                    Some(Ok(TaskEnd::Engine(EngineExit::Demoted { tempo_anchor, epoch }))) => {
                        info!(
                            target: "zone::role",
                            tempo_anchor,
                            epoch,
                            "Engine halted at the activation boundary; demoting"
                        );
                        // Stop here rather than letting the next iteration notice the role
                        // change, so the broadcaster drains this leader's final blocks before
                        // the successor starts producing.
                        if !stop_current_generation(&mut current, &sinks).await {
                            return;
                        }
                        // The next loop iteration derives Follower from the same schedule.
                    }
                    Some(Ok(TaskEnd::Engine(EngineExit::Fenced { tempo_anchor }))) => {
                        error!(
                            target: "zone::role",
                            tempo_anchor,
                            "Engine fenced on an ungoverned anchor"
                        );
                        if !stop_current_generation(&mut current, &sinks).await {
                            return;
                        }
                        tokio::time::sleep(GENERATION_RESTART_BACKOFF).await;
                    }
                    Some(Ok(TaskEnd::Engine(EngineExit::Cancelled)))
                    | Some(Ok(TaskEnd::SequencerStopped)) => {}
                    Some(Ok(TaskEnd::Ended(name))) => {
                        // A generation task ended while its generation is still desired:
                        // restart the whole generation to keep the task graph coherent.
                        error!(target: "zone::role", task = name, "Generation task ended unexpectedly; restarting generation");
                        if !stop_current_generation(&mut current, &sinks).await {
                            return;
                        }
                        tokio::time::sleep(GENERATION_RESTART_BACKOFF).await;
                    }
                    Some(Err(err)) => {
                        error!(target: "zone::role", %err, "Generation task panicked; restarting generation");
                        if !stop_current_generation(&mut current, &sinks).await {
                            return;
                        }
                        tokio::time::sleep(GENERATION_RESTART_BACKOFF).await;
                    }
                    // Unreachable: join_next() is only polled while the set is non-empty.
                    None => {}
                }
            }
            _ = async {
                if retry_decision {
                    tokio::time::sleep(ROLE_DECISION_RETRY_BACKOFF).await;
                } else {
                    std::future::pending().await
                }
            } => {}
        }
    }
}

async fn start_generation<P, Pool>(
    context: &RoleControllerContext<P, Pool>,
    sinks: &EventSinks,
    desired: DesiredRole,
    id: u64,
) -> eyre::Result<RunningGeneration>
where
    P: BlockNumReader
        + BlockReader<Block = Block>
        + HeaderProvider<Header = TempoHeader>
        + StateProviderFactory
        + ReceiptProvider
        + PersistedBlockSubscriptions
        + ZoneSequencerProvider
        + Clone
        + Send
        + Sync
        + 'static,
    Pool: TransactionPool<Transaction = TempoPooledTransaction> + Clone + 'static,
{
    let token = CancellationToken::new();
    let mut leader_shutdown = None;
    let mut tasks = JoinSet::new();

    match desired {
        DesiredRole::Fenced => {
            sinks.clear();
            warn!(
                target: "zone::role",
                generation = id,
                "Leadership is uninitialized or this node cannot lead; all role tasks fenced"
            );
        }
        DesiredRole::Follower { epoch } => {
            let (sync_tx, sync_rx) = mpsc::channel(GENERATION_EVENT_BACKLOG);
            let (transactions_tx, transactions_rx) = mpsc::channel(GENERATION_EVENT_BACKLOG);
            let (backfill_tx, backfill_rx) = mpsc::channel(GENERATION_EVENT_BACKLOG);
            sinks.install(sync_tx, Some(transactions_tx), Some(backfill_tx));

            let follower_token = token.clone();
            let sync_context = FollowerBlockSyncContext {
                provider: context.provider.clone(),
                engine: context.engine_handle.clone(),
                l1_block_tracker: context.l1_block_tracker.clone(),
                deposit_queue: context.deposit_queue.clone(),
                attestation: context.attestation.clone(),
                schedule: context.schedule.clone(),
                peer_tips: context.peer_tips.clone(),
                proof_collector: context
                    .sequencer
                    .as_ref()
                    .and_then(|sequencer| sequencer.proof_collector.clone()),
            };
            let sync_p2p = BlockSyncP2p {
                events: sync_rx,
                commands: context.commands.clone(),
                backfill_responses: backfill_rx,
                backfill_commands: context.backfill_commands.clone(),
            };
            tasks.spawn(async move {
                FollowerBlockSync::new(sync_context, sync_p2p, follower_token.clone())
                    .run()
                    .await;
                if follower_token.is_cancelled() {
                    TaskEnd::Ended("follower-block-sync (cancelled)")
                } else {
                    TaskEnd::Ended("follower-block-sync")
                }
            });

            // Restarting this task performs a full txpool reconciliation on its first tick,
            // so pending transactions converge on the replacement leader.
            let pool = context.pool.clone();
            let listener = pool.new_transactions_listener();
            let commands = context.commands.clone();
            let forward_token = token.clone();
            tasks.spawn(async move {
                tokio::select! {
                    () = forward_token.cancelled() => TaskEnd::Ended("transaction-forwarding (cancelled)"),
                    () = forward_new_transactions(pool, listener, commands) => {
                        TaskEnd::Ended("transaction-forwarding")
                    }
                }
            });

            // Quorum followers retain transactions received from originating peers so a future
            // promotion cannot lose traffic submitted immediately before the handoff. RPC-only
            // followers receive no transaction events from the P2P transport.
            let pool = context.pool.clone();
            let import_token = token.clone();
            tasks.spawn(async move {
                tokio::select! {
                    () = import_token.cancelled() => TaskEnd::Ended("transaction-import (cancelled)"),
                    () = insert_forwarded_transactions(pool, transactions_rx) => {
                        TaskEnd::Ended("transaction-import")
                    }
                }
            });
            info!(target: "zone::role", generation = id, epoch, "Follower generation started");
        }
        DesiredRole::Leader { epoch, .. } => {
            let sequencer = context
                .sequencer
                .as_ref()
                .expect("leader generation requires sequencer resources");

            // Acquire every fallible prerequisite before installing sinks or spawning any
            // leader task. Otherwise a transient head-read failure could leave a partial
            // generation classified as Leader without its canonical head writer.
            let last_header = latest_sealed_header(&context.provider)?;
            let portal_anchor = resolve_portal_zone_anchor(
                &context.provider,
                context.portal_address,
                &context.attestation.l1_provider,
            )
            .await
            .wrap_err("failed to resolve portal-confirmed Zone height for leader recovery")?;

            // The outgoing leader may have one final submitBatch in flight while leadership
            // rotates. That can make this anchor one boundary stale, but rotations fence the old
            // leader before promotion, so recovery remains bounded by one configured batch
            // interval (120 Zone blocks in production) rather than replaying history from genesis.

            let portal_confirmed_height = portal_anchor.block_number;
            info!(
                target: "zone::role",
                portal_confirmed_height,
                portal_block_hash = %portal_anchor.block_hash,
                "Seeded leader settlement recovery from the portal anchor"
            );
            let settlements = context
                .settlements
                .clone()
                .ok_or_eyre("leader has no settlement manager")?;

            let (sync_tx, sync_rx) = mpsc::channel(GENERATION_EVENT_BACKLOG);
            let (transactions_tx, transactions_rx) = mpsc::channel(GENERATION_EVENT_BACKLOG);
            sinks.install(sync_tx, Some(transactions_tx), None);

            // Canonical head writer: the engine with the per-anchor production permit.
            let engine = build_engine(context, sequencer, last_header);
            let engine_token = token.clone();
            let (engine_done_tx, engine_done_rx) = oneshot::channel();
            tasks.spawn(async move {
                let exit = engine.run_until(engine_token).await;
                // Signalled before the task resolves so `stop` learns the canonical head is
                // pinned without having to drain the JoinSet first.
                let _ = engine_done_tx.send(());
                TaskEnd::Engine(exit)
            });

            // The broadcaster outlives the generation token on purpose: it must still be able to
            // publish the engine's final blocks after every other task has been cancelled.
            let (broadcaster_tx, broadcaster_rx) = oneshot::channel();
            leader_shutdown = Some(LeaderShutdown {
                engine_done: engine_done_rx,
                broadcaster: broadcaster_tx,
            });
            let provider = context.provider.clone();
            let commands = context.commands.clone();
            let broadcast_proofs = sequencer.proof_collector.clone();
            tasks.spawn(async move {
                broadcast_persisted_blocks(provider, commands, broadcaster_rx, broadcast_proofs)
                    .await;
                TaskEnd::Ended("block-broadcast")
            });

            let server_token = token.clone();
            let signature_settlements = settlements.clone();
            tasks.spawn(async move {
                collect_follower_settlement_signatures(
                    sync_rx,
                    signature_settlements,
                    server_token,
                )
                .await;
                TaskEnd::Ended("leader-settlement-signatures")
            });

            let pool = context.pool.clone();
            let import_token = token.clone();
            tasks.spawn(async move {
                tokio::select! {
                    () = import_token.cancelled() => TaskEnd::Ended("transaction-import (cancelled)"),
                    () = insert_forwarded_transactions(pool, transactions_rx) => {
                        TaskEnd::Ended("transaction-import")
                    }
                }
            });

            // Sequencer background tasks (batch submission + withdrawal processing) stop
            // gracefully: they observe the token at their poll boundaries, letting in-flight
            // L1 transactions resolve before teardown.
            let sequencer_config = sequencer.sequencer_config.clone();
            let signer = sequencer
                .config
                .l1_transaction_signer
                .clone()
                .unwrap_or_else(|| sequencer.config.sequencer_signer.clone());
            let zone_provider = context.provider.clone();
            let prover = sequencer.prover.clone();
            let sequencer_token = token.clone();
            tasks.spawn(async move {
                let handle = spawn_zone_sequencer(
                    sequencer_config,
                    signer,
                    zone_provider,
                    prover,
                    Some(settlements),
                    sequencer_token.clone(),
                )
                .await;
                supervise_sequencer_tasks(handle, sequencer_token).await
            });

            info!(target: "zone::role", generation = id, epoch, "Leader generation started");
        }
    }

    Ok(RunningGeneration {
        id,
        role: desired,
        token,
        leader_shutdown,
        tasks,
    })
}

fn latest_sealed_header<P>(provider: &P) -> eyre::Result<SealedHeader<TempoHeader>>
where
    P: BlockNumReader + HeaderProvider<Header = TempoHeader>,
{
    let number = provider.best_block_number().map_err(eyre::Report::from)?;
    provider
        .sealed_header(number)
        .map_err(eyre::Report::from)?
        .ok_or_else(|| eyre::eyre!("no latest block header"))
}

fn build_engine<P, Pool>(
    context: &RoleControllerContext<P, Pool>,
    sequencer: &LeaderSequencerDeps,
    last_header: SealedHeader<TempoHeader>,
) -> ZoneEngine
where
    P: Clone,
{
    ZoneEngine::new(
        context.chain_spec.clone(),
        context.engine_handle.clone(),
        context.payload_builder.clone(),
        context.deposit_queue.clone(),
        context.l1_block_tracker.clone(),
        last_header,
        sequencer.config.sequencer_signer.address(),
        context.encryption_keys.clone(),
        context.portal_address,
        sequencer.proof_collector.clone(),
    )
    .with_production_permit(ProductionPermit::new(
        context.schedule.clone(),
        context.local_ed25519_public_key.clone(),
    ))
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use alloy_consensus::Sealable as _;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use reth_provider::test_utils::MockEthProvider;
    use tempo_primitives::{TempoHeader, TempoPrimitives};
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::sync::CancellationToken;
    use zone_p2p::{BackfillRequest, BackfillResponse};
    use zone_sequencer::ZoneSequencerHandle;

    use super::{
        EventSinks, TaskEnd, canonical_recovery_height, latest_sealed_header,
        route_backfill_requests, route_backfill_responses, supervise_sequencer_tasks,
    };

    struct DropSignal(Option<oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }

    #[test]
    fn unavailable_canonical_head_fails_leader_prerequisite() {
        let provider = MockEthProvider::<TempoPrimitives>::new();

        assert!(
            latest_sealed_header(&provider).is_err(),
            "leader startup must fail when its canonical head cannot be read"
        );
    }

    #[test]
    fn recovery_checkpoint_may_be_a_canonical_ancestor() {
        let provider = MockEthProvider::<TempoPrimitives>::new();
        let mut recovery_header = TempoHeader::default();
        recovery_header.inner.number = 7;
        let recovery_hash = recovery_header.hash_slow();
        provider.add_header(recovery_hash, recovery_header);

        let mut head = TempoHeader::default();
        head.inner.number = 9;
        let head_hash = head.hash_slow();
        provider.add_header(head_hash, head);

        assert_eq!(
            canonical_recovery_height(&provider, recovery_hash).unwrap(),
            7
        );
    }

    #[test]
    fn recovery_checkpoint_rejects_a_known_noncanonical_hash() {
        let provider = MockEthProvider::<TempoPrimitives>::new();
        let mut header = TempoHeader::default();
        header.inner.number = 7;
        let noncanonical_hash = alloy_primitives::B256::repeat_byte(0x42);
        provider.add_header(noncanonical_hash, header);

        let error = canonical_recovery_height(&provider, noncanonical_hash).unwrap_err();
        assert!(error.to_string().contains("is not canonical at height 7"));
    }

    #[tokio::test]
    async fn sequencer_supervisor_reports_panicking_child_without_waiting_for_sibling() {
        let (monitor_started_tx, monitor_started_rx) = oneshot::channel();
        let (monitor_dropped_tx, monitor_dropped_rx) = oneshot::channel();
        let monitor_handle = tokio::spawn(async move {
            let _drop_signal = DropSignal(Some(monitor_dropped_tx));
            let _ = monitor_started_tx.send(());
            pending::<()>().await;
        });
        monitor_started_rx
            .await
            .expect("monitor task must start before the panic");

        let withdrawal_handle = tokio::spawn(async move {
            panic!("simulated withdrawal processor panic");
        });
        let handle = ZoneSequencerHandle {
            withdrawal_handle,
            monitor_handle,
        };

        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            supervise_sequencer_tasks(handle, CancellationToken::new()),
        )
        .await
        .expect("supervisor waited for the healthy long-running sibling");
        assert!(matches!(outcome, TaskEnd::Ended("withdrawal-processor")));
        tokio::time::timeout(Duration::from_secs(1), monitor_dropped_rx)
            .await
            .expect("sibling was not aborted when the supervisor returned")
            .expect("monitor drop signal was lost");
    }

    #[tokio::test]
    async fn sequencer_supervisor_waits_for_both_children_during_graceful_stop() {
        let stop = CancellationToken::new();
        let (ready_tx, mut ready_rx) = mpsc::channel(2);

        let withdrawal_stop = stop.clone();
        let withdrawal_ready = ready_tx.clone();
        let withdrawal_handle = tokio::spawn(async move {
            withdrawal_ready.send(()).await.unwrap();
            withdrawal_stop.cancelled().await;
        });

        let monitor_stop = stop.clone();
        let (monitor_stopping_tx, monitor_stopping_rx) = oneshot::channel();
        let (release_monitor_tx, release_monitor_rx) = oneshot::channel();
        let monitor_handle = tokio::spawn(async move {
            ready_tx.send(()).await.unwrap();
            monitor_stop.cancelled().await;
            let _ = monitor_stopping_tx.send(());
            let _ = release_monitor_rx.await;
        });

        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(1), ready_rx.recv())
                .await
                .expect("sequencer child did not start")
                .expect("sequencer child readiness channel closed");
        }

        let supervisor = tokio::spawn(supervise_sequencer_tasks(
            ZoneSequencerHandle {
                withdrawal_handle,
                monitor_handle,
            },
            stop.clone(),
        ));
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), monitor_stopping_rx)
            .await
            .expect("monitor did not observe graceful shutdown")
            .expect("monitor stopping signal was lost");
        tokio::task::yield_now().await;
        assert!(
            !supervisor.is_finished(),
            "supervisor aborted the slower child during graceful shutdown"
        );

        let _ = release_monitor_tx.send(());
        let outcome = tokio::time::timeout(Duration::from_secs(1), supervisor)
            .await
            .expect("supervisor did not finish after both children stopped")
            .expect("supervisor task panicked");
        assert!(matches!(outcome, TaskEnd::SequencerStopped));
    }

    /// Reproduces the startup ordering from the native stress test: the P2P router is live
    /// and receives a peer's backfill request before the role controller installs its first
    /// generation sink. The request must reach the process-lifetime backfill server anyway —
    /// losing it leaves the requester blocked behind the P2P backfill response timeout.
    #[tokio::test]
    async fn backfill_request_bypasses_generation_sinks() {
        let (network_requests, request_rx) = mpsc::channel(1);
        let (backfill_tx, mut backfill_rx) = mpsc::channel(1);
        let router = tokio::spawn(route_backfill_requests(request_rx, backfill_tx));
        let peer = PrivateKey::from_seed(1).public_key();

        network_requests
            .send(BackfillRequest {
                peer: peer.clone(),
                request_id: 7,
                start: 42,
            })
            .await
            .unwrap();

        let request = tokio::time::timeout(Duration::from_secs(1), backfill_rx.recv())
            .await
            .expect("backfill request never reached the serving channel")
            .expect("backfill serving channel closed");
        assert_eq!(request.peer, peer);
        assert_eq!(request.request_id, 7);
        assert_eq!(request.start, 42);

        drop(network_requests);
        tokio::time::timeout(Duration::from_secs(1), router)
            .await
            .expect("event router did not stop")
            .expect("event router task panicked");
    }

    #[tokio::test]
    async fn backfill_response_drops_on_generation_backpressure() {
        let sinks = EventSinks::default();
        let (generation_response_tx, mut generation_response_rx) = mpsc::channel(1);
        sinks.install(mpsc::channel(1).0, None, Some(generation_response_tx));
        let (network_responses, response_rx) = mpsc::channel(4);
        let router = tokio::spawn(route_backfill_responses(response_rx, sinks));
        let peer = PrivateKey::from_seed(1).public_key();

        network_responses
            .send(BackfillResponse::Completed {
                peer: peer.clone(),
                tip: zone_p2p::PeerTip {
                    zone_height: 1,
                    zone_hash: alloy_primitives::B256::ZERO,
                    tempo_block_number: 1,
                    tempo_block_hash: alloy_primitives::B256::ZERO,
                },
            })
            .await
            .unwrap();
        network_responses
            .send(BackfillResponse::Completed {
                peer,
                tip: zone_p2p::PeerTip {
                    zone_height: 2,
                    zone_hash: alloy_primitives::B256::ZERO,
                    tempo_block_number: 2,
                    tempo_block_hash: alloy_primitives::B256::ZERO,
                },
            })
            .await
            .unwrap();

        let forwarded = tokio::time::timeout(Duration::from_secs(1), generation_response_rx.recv())
            .await
            .expect("the first backfill response was not forwarded")
            .expect("generation response channel closed");
        assert!(
            matches!(forwarded, BackfillResponse::Completed { tip, .. } if tip.zone_height == 1)
        );

        drop(network_responses);
        tokio::time::timeout(Duration::from_secs(1), router)
            .await
            .expect("event router did not stop")
            .expect("event router task panicked");
    }
}
