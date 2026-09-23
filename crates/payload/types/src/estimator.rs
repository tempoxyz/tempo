//! Holistic proposal budget estimator shared by consensus and the payload builder.
//!
//! A block's wall-clock time is spent in four places that the proposer has to
//! reserve for before it stops adding transactions:
//!
//! 1. its own replayable build work, including the non-interruptible finish
//!    (state root, block assembly) that follows the transaction cutoff,
//! 2. persisting the encoded block through the consensus marshal, once on the
//!    proposer and once on every validator,
//! 3. the validators replaying the block through their execution layer,
//! 4. the network: shipping the proposal to a quorum and getting the next
//!    leader started on top of it.
//!
//! Each of those was previously estimated in a different place (a process-wide
//! static, a builder-local atomic, an actor-local sample window and a fixed CLI
//! constant). The [`Estimator`] owns all of them so that consensus and the
//! builder read one consistent picture, and so that the whole model can be
//! driven by a simulated block sequence in tests.
//!
//! The estimator is pure bookkeeping: callers feed observations through the
//! `on_*` hooks, passing the clock explicitly, and read decisions through
//! [`Estimator::proposal_budget`] and [`Estimator::build_plan`]. Nothing in
//! here touches wall-clock time on its own.
//!
//! # Robustness
//!
//! Every learned quantity is a percentile over a bounded window of recent
//! samples that also expire by age. A single slow observation (a persistence
//! commit landing on a block, one slow finish) therefore moves the estimate by
//! at most one window slot instead of resetting it to the outlier, while a
//! sustained change still takes over within a fraction of the window. The
//! network reservation can opt out of that damping on the way up, see
//! [`EstimatorConfig::network_reserve_fast_rise`].

use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{Duration, Instant},
};

use tracing::debug;

use crate::budget::{
    MarshalPersistEstimator, ValidationLatencyEstimate, ValidationLatencyEstimator,
    ValidationLatencyWorkload,
};

/// Target wall-clock time between blocks used when no configuration is given.
pub const DEFAULT_TARGET_BLOCK_TIME: Duration = Duration::from_millis(550);
/// Initial and minimum network reservation (proposal propagation plus votes).
pub const DEFAULT_NETWORK_BUDGET: Duration = Duration::from_millis(50);
/// Largest network reservation the estimator may learn on its own.
///
/// The cap bounds how much of the block time propagation may claim before an
/// operator has to look at the network rather than the estimator. It is
/// roughly the propagation and vote round trip measured on a 10 validator,
/// four region deployment with 2.6 MB blocks.
pub const DEFAULT_NETWORK_BUDGET_MAX: Duration = Duration::from_millis(250);
/// Percentile of recent network samples reserved when no configuration is given.
pub const DEFAULT_NETWORK_RESERVE_PERCENTILE: u8 = 75;
/// Initial estimate of total replayable build work divided by work at tx cutoff.
///
/// `1.15` means "when cutoff work is 100 ms, expect the completed replayable
/// build work to be about 115 ms". Measured finish work on a busy 10 validator
/// network is 5 to 10% of fill work; the previous default of 1.35 cost 10 to
/// 15% of every block's transactions before the first observation.
pub const DEFAULT_BUILD_TIME_MULTIPLIER: f64 = 1.15;

/// Fixed-point scale for build time multipliers.
pub const BUILD_TIME_MULTIPLIER_SCALE: u64 = 1_000_000;
/// Builder work never shrinks after the transaction cutoff.
const MIN_BUILD_TIME_MULTIPLIER_SCALED: u64 = BUILD_TIME_MULTIPLIER_SCALE;
/// Finish work larger than 70% of fill work is treated as an outlier.
const MAX_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_700_000;
/// Largest increase of the multiplier a single finished build may cause.
///
/// One slow finish, typically a state root that waited on a persistence
/// commit, used to jump the multiplier straight to its cap and cost the next
/// eight proposals 20 to 30% of their transactions. Limiting the step to 0.15
/// per observation keeps a lone outlier at a one-off cost while a sustained
/// slowdown still reaches the cap after four builds.
const BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED: u64 = 150_000;
/// Number of finished builds the multiplier is derived from.
const BUILD_TIME_SAMPLE_WINDOW: usize = 16;
/// Finished builds older than this no longer influence the multiplier.
const BUILD_TIME_SAMPLE_TTL: Duration = Duration::from_secs(60);

/// Ignore tiny blocks so fixed archive overhead does not become a large-block byte cost.
const MARSHAL_PERSIST_MIN_SAMPLE_BYTES: usize = 128 * 1024;
/// Number of persistence observations the per-byte rate is derived from.
///
/// Validators persist every verified block, so with 10 validators this covers
/// roughly the last 20 seconds of chain activity instead of the proposer's own
/// last few proposals.
const MARSHAL_PERSIST_SAMPLE_WINDOW: usize = 32;
/// Persistence observations older than this are dropped.
const MARSHAL_PERSIST_SAMPLE_TTL: Duration = Duration::from_secs(60);

/// Number of own proposals the network reservation is derived from.
const NETWORK_SAMPLE_WINDOW: usize = 16;
/// Network observations older than this are dropped.
const NETWORK_SAMPLE_TTL: Duration = Duration::from_secs(120);
/// Lowest accepted network reserve percentile: the median of the window.
const MIN_NETWORK_RESERVE_PERCENTILE: u8 = 50;
/// Highest accepted network reserve percentile: the slowest sample in the window.
const MAX_NETWORK_RESERVE_PERCENTILE: u8 = 100;
/// A proposal that has not been notarized after this long is not a usable
/// network sample; the view was most likely nullified.
const PENDING_PROPOSAL_TTL: Duration = Duration::from_secs(10);
/// Upper bound on proposals awaiting their notarization.
const MAX_PENDING_PROPOSALS: usize = 8;

/// Percentile used for the marshal persistence and build time reservations:
/// the 75th.
///
/// The median ignores too much of the tail for a reservation, the 90th
/// percentile of a 16 sample window is a single observation again. The
/// network reservation defaults to the same percentile but is configurable,
/// see [`EstimatorConfig::network_reserve_percentile`].
const RESERVE_PERCENTILE: (usize, usize) = (3, 4);

/// Identifies a proposal across epochs: `(epoch, view)`.
pub type ProposalKey = (u64, u64);

/// Network samples longer than this are discarded as clock skew or a stall
/// unrelated to propagation.
const MAX_NETWORK_SAMPLE: Duration = Duration::from_secs(5);

/// Static configuration of the [`Estimator`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EstimatorConfig {
    /// Target wall-clock time between blocks.
    pub target_block_time: Duration,
    /// Initial and minimum network reservation.
    ///
    /// Until the estimator has observed its own proposals it reserves exactly
    /// this much for propagation and votes, and it never reserves less.
    pub network_budget: Duration,
    /// Largest network reservation the estimator may learn.
    ///
    /// Setting this equal to `network_budget` disables learning and restores
    /// a fixed reservation.
    pub network_budget_max: Duration,
    /// Percentile of recent own-proposal network samples to reserve, from 50
    /// (the median) to 100 (the slowest sample in the window).
    ///
    /// A higher percentile leaves fewer proposals whose network time exceeds
    /// the reservation, at the cost of a smaller return budget and therefore
    /// smaller blocks. The reservation stays clamped between `network_budget`
    /// and `network_budget_max`.
    pub network_reserve_percentile: u8,
    /// Reserve at least the most recent network sample, not only the window
    /// percentile.
    ///
    /// The percentile over the last 16 own proposals, up to two minutes of
    /// them, lags a network that is getting slower, for example while blocks
    /// grow, so the proposals made during the rise exceed their reservation
    /// far more often than the percentile implies. With fast rise a single
    /// slow sample lifts the reservation immediately, still clamped to
    /// `network_budget_max`, and the next faster sample hands it back to the
    /// window percentile: the reservation rises instantly and decays through
    /// the window.
    pub network_reserve_fast_rise: bool,
    /// Initial ratio of total replayable build work over work at tx cutoff.
    pub build_time_multiplier: f64,
}

impl Default for EstimatorConfig {
    fn default() -> Self {
        Self {
            target_block_time: DEFAULT_TARGET_BLOCK_TIME,
            network_budget: DEFAULT_NETWORK_BUDGET,
            network_budget_max: DEFAULT_NETWORK_BUDGET_MAX,
            network_reserve_percentile: DEFAULT_NETWORK_RESERVE_PERCENTILE,
            network_reserve_fast_rise: false,
            build_time_multiplier: DEFAULT_BUILD_TIME_MULTIPLIER,
        }
    }
}

impl EstimatorConfig {
    /// Creates a configuration for the given block time and network floor,
    /// with the network cap and build multiplier at their defaults.
    pub fn new(target_block_time: Duration, network_budget: Duration) -> Self {
        Self {
            target_block_time,
            network_budget,
            ..Self::default()
        }
        .with_network_budget_max(DEFAULT_NETWORK_BUDGET_MAX.max(network_budget))
    }

    /// Creates a configuration that reproduces a fixed proposal return budget.
    ///
    /// The network reservation is pinned to `network_budget`, so the return
    /// budget is exactly `proposal_return_budget` for the lifetime of the node.
    pub fn fixed(proposal_return_budget: Duration, network_budget: Duration) -> Self {
        Self {
            target_block_time: proposal_return_budget.saturating_add(network_budget),
            network_budget,
            network_budget_max: network_budget,
            ..Self::default()
        }
    }

    /// Sets the largest learnable network reservation.
    pub fn with_network_budget_max(mut self, network_budget_max: Duration) -> Self {
        self.network_budget_max = network_budget_max;
        self
    }

    /// Sets the percentile of recent network samples to reserve.
    pub fn with_network_reserve_percentile(mut self, network_reserve_percentile: u8) -> Self {
        self.network_reserve_percentile = network_reserve_percentile;
        self
    }

    /// Sets whether the most recent network sample may lift the reservation
    /// above the window percentile.
    pub fn with_network_reserve_fast_rise(mut self, network_reserve_fast_rise: bool) -> Self {
        self.network_reserve_fast_rise = network_reserve_fast_rise;
        self
    }

    /// Sets the initial build time multiplier.
    pub fn with_build_time_multiplier(mut self, build_time_multiplier: f64) -> Self {
        self.build_time_multiplier = build_time_multiplier;
        self
    }

    /// Checks that the reservations leave room for a proposal and that the
    /// learning knobs are in range.
    pub fn validate(&self) -> Result<(), String> {
        if self.network_budget >= self.target_block_time {
            return Err(format!(
                "network budget ({:?}) must be smaller than the target block time ({:?})",
                self.network_budget, self.target_block_time
            ));
        }
        if self.network_budget_max < self.network_budget {
            return Err(format!(
                "maximum network budget ({:?}) must not be smaller than the network budget ({:?})",
                self.network_budget_max, self.network_budget
            ));
        }
        if self.network_budget_max >= self.target_block_time {
            return Err(format!(
                "maximum network budget ({:?}) must be smaller than the target block time ({:?})",
                self.network_budget_max, self.target_block_time
            ));
        }
        if !(MIN_NETWORK_RESERVE_PERCENTILE..=MAX_NETWORK_RESERVE_PERCENTILE)
            .contains(&self.network_reserve_percentile)
        {
            return Err(format!(
                "network reserve percentile ({}) must be between \
                 {MIN_NETWORK_RESERVE_PERCENTILE} and {MAX_NETWORK_RESERVE_PERCENTILE}, inclusive",
                self.network_reserve_percentile
            ));
        }
        if !(self.build_time_multiplier.is_finite() && self.build_time_multiplier >= 1.0) {
            return Err(format!(
                "build time multiplier ({}) must be finite and at least 1.0",
                self.build_time_multiplier
            ));
        }
        Ok(())
    }

    /// The proposal return budget before any network learning: the target
    /// block time minus the configured network budget.
    pub fn initial_proposal_return_budget(&self) -> Duration {
        self.target_block_time.saturating_sub(self.network_budget)
    }
}

/// Converts a human-readable build-work multiplier into the fixed-point representation.
pub fn scaled_build_time_multiplier(multiplier: f64) -> u64 {
    assert!(
        multiplier.is_finite() && multiplier >= 1.0,
        "build time multiplier must be finite and >= 1.0"
    );

    (multiplier * BUILD_TIME_MULTIPLIER_SCALE as f64).round() as u64
}

fn scaled_duration(elapsed: Duration, multiplier: u64) -> Duration {
    Duration::from_nanos(
        (elapsed.as_nanos().saturating_mul(u128::from(multiplier))
            / u128::from(BUILD_TIME_MULTIPLIER_SCALE))
        .min(u128::from(u64::MAX)) as u64,
    )
}

/// Bounded, age-limited window of samples with percentile reads.
#[derive(Clone, Debug)]
struct SampleWindow<T> {
    samples: VecDeque<(Instant, T)>,
    capacity: usize,
    ttl: Duration,
}

impl<T: Copy + Ord> SampleWindow<T> {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
            ttl,
        }
    }

    fn push(&mut self, now: Instant, value: T) {
        self.prune(now);
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back((now, value));
    }

    fn prune(&mut self, now: Instant) {
        while let Some((at, _)) = self.samples.front() {
            if now.saturating_duration_since(*at) > self.ttl {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    fn len(&self) -> usize {
        self.samples.len()
    }

    /// Returns the `numerator / denominator` percentile, rounding the rank up
    /// so that a single sample is returned as is.
    fn percentile(&self, numerator: usize, denominator: usize) -> Option<T> {
        if self.samples.is_empty() {
            return None;
        }
        let mut values: Vec<T> = self.samples.iter().map(|(_, value)| *value).collect();
        values.sort_unstable();
        let rank = (values.len() * numerator).div_ceil(denominator).max(1);
        values.get(rank - 1).copied()
    }
}

/// Learns the marshal persistence cost per encoded block byte.
#[derive(Clone, Debug)]
struct MarshalPersistTracker {
    samples: SampleWindow<u64>,
}

impl MarshalPersistTracker {
    fn new() -> Self {
        Self {
            samples: SampleWindow::new(MARSHAL_PERSIST_SAMPLE_WINDOW, MARSHAL_PERSIST_SAMPLE_TTL),
        }
    }

    fn observe(&mut self, now: Instant, block_size_bytes: usize, elapsed: Duration) -> bool {
        if block_size_bytes < MARSHAL_PERSIST_MIN_SAMPLE_BYTES || elapsed == Duration::ZERO {
            return false;
        }
        let block_size = block_size_bytes as u128;
        let ns_per_byte = elapsed
            .as_nanos()
            .saturating_add(block_size.saturating_sub(1))
            / block_size;
        self.samples
            .push(now, ns_per_byte.min(u128::from(u64::MAX)) as u64);
        true
    }

    fn estimate(&self) -> MarshalPersistEstimator {
        MarshalPersistEstimator::from_ns_per_byte(
            self.samples
                .percentile(RESERVE_PERCENTILE.0, RESERVE_PERCENTILE.1)
                .unwrap_or(0),
        )
    }
}

/// Learns how much replayable work follows the transaction cutoff.
#[derive(Clone, Debug)]
struct BuildTimeTracker {
    samples: SampleWindow<u64>,
    /// Current multiplier in fixed point.
    current: u64,
}

impl BuildTimeTracker {
    fn new(initial: f64) -> Self {
        Self {
            samples: SampleWindow::new(BUILD_TIME_SAMPLE_WINDOW, BUILD_TIME_SAMPLE_TTL),
            current: scaled_build_time_multiplier(initial).clamp(
                MIN_BUILD_TIME_MULTIPLIER_SCALED,
                MAX_BUILD_TIME_MULTIPLIER_SCALED,
            ),
        }
    }

    /// Records a finished build. Returns the observed multiplier, if usable.
    fn observe(
        &mut self,
        now: Instant,
        work_at_tx_cutoff: Duration,
        total_work: Duration,
    ) -> Option<u64> {
        if work_at_tx_cutoff == Duration::ZERO {
            return None;
        }
        let observed = (total_work
            .as_nanos()
            .saturating_mul(u128::from(BUILD_TIME_MULTIPLIER_SCALE))
            / work_at_tx_cutoff.as_nanos())
        .min(u128::from(MAX_BUILD_TIME_MULTIPLIER_SCALED)) as u64;
        let observed = observed.max(MIN_BUILD_TIME_MULTIPLIER_SCALED);
        self.samples.push(now, observed);

        let target = self
            .samples
            .percentile(RESERVE_PERCENTILE.0, RESERVE_PERCENTILE.1)
            .unwrap_or(observed);
        self.current = if target > self.current {
            target.min(
                self.current
                    .saturating_add(BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED),
            )
        } else {
            target
        };
        Some(observed)
    }

    fn scaled(&self) -> u64 {
        self.current
    }
}

/// What a proposer expects its validators to spend on a proposal.
///
/// These are subtracted from the time between returning the proposal and the
/// next leader building on it, so the network tracker only learns propagation
/// and vote time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProposalExpectation {
    /// Approximate encoded size of the proposal.
    pub block_size_bytes: usize,
    /// Expected execution-layer validation time on a validator.
    pub validator_work: Duration,
    /// Expected marshal persistence time on a validator.
    pub validator_persist: Duration,
}

#[derive(Clone, Copy, Debug)]
struct PendingProposal {
    key: ProposalKey,
    returned_at: Instant,
    /// Wall-clock time of the return, on the same clock the child block's
    /// header timestamp is taken from.
    returned_unix_ms: u64,
    expected_remote: Duration,
}

/// Learns how long the network needs between this node returning a proposal
/// and the next leader starting to build on it.
///
/// The sample is `child header timestamp - own return time - expected remote
/// work`. The child's timestamp is the next leader's build start on a
/// clock-synchronised network, and its propose path waits for the parent body,
/// so the difference is exactly the time the chain waited on propagation and
/// votes: the outbound leg to the quorum plus the vote leg to the next leader.
/// Measuring the notarization at the proposer instead would add the vote leg
/// back to the proposer, which the chain never waits for unless the proposer
/// is also the next leader; on a ten validator network with two far-away
/// proposers that over-reserved by roughly 90 ms for them.
#[derive(Clone, Debug)]
struct NetworkTracker {
    samples: SampleWindow<u64>,
    /// The most recent sample and when it was taken.
    ///
    /// The window only prunes when a sample is pushed, so every hook that
    /// carries the clock drops this one once it is older than the window's
    /// ttl.
    last: Option<(Instant, u64)>,
    pending: VecDeque<PendingProposal>,
    floor: Duration,
    cap: Duration,
    /// Percentile of the window that is reserved.
    percentile: u8,
    /// Whether the most recent sample lifts the reservation above the
    /// window percentile.
    fast_rise: bool,
}

impl NetworkTracker {
    fn new(config: &EstimatorConfig) -> Self {
        Self {
            samples: SampleWindow::new(NETWORK_SAMPLE_WINDOW, NETWORK_SAMPLE_TTL),
            last: None,
            pending: VecDeque::with_capacity(MAX_PENDING_PROPOSALS),
            floor: config.network_budget,
            cap: config.network_budget_max.max(config.network_budget),
            percentile: config.network_reserve_percentile.clamp(
                MIN_NETWORK_RESERVE_PERCENTILE,
                MAX_NETWORK_RESERVE_PERCENTILE,
            ),
            fast_rise: config.network_reserve_fast_rise,
        }
    }

    /// Forgets the most recent sample once it is older than the window's ttl.
    fn expire_last(&mut self, now: Instant) {
        if self
            .last
            .is_some_and(|(at, _)| now.saturating_duration_since(at) > self.samples.ttl)
        {
            self.last = None;
        }
    }

    fn proposal_returned(
        &mut self,
        now: Instant,
        returned_unix_ms: u64,
        key: ProposalKey,
        expectation: ProposalExpectation,
    ) {
        self.expire_last(now);
        self.pending.retain(|pending| {
            pending.key != key
                && now.saturating_duration_since(pending.returned_at) <= PENDING_PROPOSAL_TTL
        });
        if self.pending.len() == MAX_PENDING_PROPOSALS {
            self.pending.pop_front();
        }
        self.pending.push_back(PendingProposal {
            key,
            returned_at: now,
            returned_unix_ms,
            expected_remote: expectation
                .validator_work
                .saturating_add(expectation.validator_persist),
        });
    }

    /// Completes a pending proposal with the header timestamp of the block
    /// built on top of it. Returns the learned network time.
    ///
    /// A child that is not the very next view means a leader timed out in
    /// between; the chain waited on that, not on propagation, so no sample is
    /// taken.
    fn child_built(
        &mut self,
        now: Instant,
        parent: ProposalKey,
        child_view: u64,
        child_timestamp_ms: u64,
    ) -> Option<Duration> {
        self.expire_last(now);
        let index = self
            .pending
            .iter()
            .position(|pending| pending.key == parent)?;
        let pending = self.pending.remove(index)?;
        if child_view != parent.1.saturating_add(1) {
            return None;
        }
        let elapsed =
            Duration::from_millis(child_timestamp_ms.saturating_sub(pending.returned_unix_ms));
        if elapsed > MAX_NETWORK_SAMPLE {
            return None;
        }
        let network = elapsed.saturating_sub(pending.expected_remote);
        let sample = network.as_nanos().min(u128::from(u64::MAX)) as u64;
        self.samples.push(now, sample);
        self.last = Some((now, sample));
        Some(network)
    }

    fn abandoned(&mut self, key: ProposalKey) {
        self.pending.retain(|pending| pending.key != key);
    }

    /// Unclamped learned network time, if any proposal has completed.
    ///
    /// This is the configured percentile of the window, or with fast rise
    /// the most recent sample when that is higher.
    fn observed(&self) -> Option<Duration> {
        let window = self.samples.percentile(usize::from(self.percentile), 100);
        let last = self
            .last
            .filter(|_| self.fast_rise)
            .map(|(_, sample)| sample);
        // `None` orders below every sample.
        window.max(last).map(Duration::from_nanos)
    }

    /// The most recent sample, until it is older than the window's ttl.
    fn last_sample(&self) -> Option<Duration> {
        self.last.map(|(_, sample)| Duration::from_nanos(sample))
    }

    fn reserve(&self) -> Duration {
        self.observed()
            .map_or(self.floor, |observed| observed.clamp(self.floor, self.cap))
    }
}

/// Timings of a finished payload build.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FinishedBuild {
    /// Replayable work measured when pool transaction execution stopped.
    pub work_at_tx_cutoff: Duration,
    /// Replayable work measured after finalization, excluding proposer idle time.
    pub total_work: Duration,
}

/// The proposal window derived from the current network reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalBudget {
    /// Target wall-clock time between blocks.
    pub target_block_time: Duration,
    /// Time reserved for propagation and votes.
    pub network_reserve: Duration,
    /// Local proposal return budget: `target_block_time - network_reserve`.
    pub return_budget: Duration,
}

/// Point-in-time inputs for one payload build's stop decision.
///
/// The builder snapshots this once per build so the same estimates apply to
/// every decision within that build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildPlan {
    /// Remaining proposal budget handed to this build.
    pub build_budget: Duration,
    multiplier_scaled: u64,
    marshal_persist: MarshalPersistEstimator,
    validation_latency: Option<ValidationLatencyEstimate>,
}

/// Breakdown of the time a build must still reserve at a given moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadBudgetDecision {
    /// Replayable proposer work projected from the work done so far.
    pub predicted_builder_work: Duration,
    /// Validator replay work, from feedback when available.
    pub predicted_validator_work: Duration,
    /// Marshal persistence for the current block size, charged per side.
    pub marshal_persist: Duration,
    /// Everything the proposal still needs: idle, builder, validator, both persists.
    pub total_reserved: Duration,
}

impl BuildPlan {
    /// Creates a plan from explicit estimates.
    pub fn new(
        build_budget: Duration,
        build_time_multiplier: f64,
        marshal_persist: MarshalPersistEstimator,
        validation_latency: Option<ValidationLatencyEstimate>,
    ) -> Self {
        Self {
            build_budget,
            multiplier_scaled: scaled_build_time_multiplier(build_time_multiplier),
            marshal_persist,
            validation_latency,
        }
    }

    /// Overrides the validation latency estimate, for example with the
    /// snapshot consensus attached to the payload attributes.
    pub fn with_validation_latency(mut self, estimate: Option<ValidationLatencyEstimate>) -> Self {
        if estimate.is_some() {
            self.validation_latency = estimate;
        }
        self
    }

    /// The build time multiplier in use.
    pub fn build_time_multiplier(&self) -> f64 {
        self.multiplier_scaled as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64
    }

    /// The validation latency estimate in use.
    pub fn validation_latency(&self) -> Option<ValidationLatencyEstimate> {
        self.validation_latency
    }

    /// The marshal persistence rate in use.
    pub fn marshal_persist(&self) -> MarshalPersistEstimator {
        self.marshal_persist
    }

    /// Computes what the proposal still has to reserve.
    ///
    /// `elapsed` is wall-clock time spent in the builder so far. `idle_elapsed`
    /// is the proposer-only time spent waiting for more transactions, which
    /// validators do not replay and therefore counts once. Builder work is
    /// projected from the current build, validator work uses feedback from
    /// previously validated blocks capped at that projection, and marshal
    /// persistence is charged once for the proposer and once for validators
    /// because both persist before the block can progress.
    pub fn decision(
        &self,
        elapsed: Duration,
        idle_elapsed: Duration,
        block_size_bytes: usize,
        current_workload: ValidationLatencyWorkload,
    ) -> PayloadBudgetDecision {
        let work_elapsed = elapsed.saturating_sub(idle_elapsed);
        let predicted_builder_work = scaled_duration(work_elapsed, self.multiplier_scaled);
        let predicted_validator_work = self
            .validation_latency
            .and_then(|estimate| estimate.estimate(current_workload))
            .map(|estimate| estimate.min(predicted_builder_work))
            .unwrap_or(predicted_builder_work);
        let marshal_persist = self.marshal_persist.estimate(block_size_bytes);
        let total_reserved = idle_elapsed
            .saturating_add(predicted_builder_work)
            .saturating_add(predicted_validator_work)
            .saturating_add(marshal_persist)
            .saturating_add(marshal_persist);
        PayloadBudgetDecision {
            predicted_builder_work,
            predicted_validator_work,
            marshal_persist,
            total_reserved,
        }
    }

    /// Whether the build has to stop adding transactions now.
    pub fn exhausted(&self, decision: &PayloadBudgetDecision) -> bool {
        decision.total_reserved >= self.build_budget
    }
}

/// Everything the estimator currently believes, for logs and metrics.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EstimatorSnapshot {
    /// Recent P90 execution-layer validation time, if observed.
    pub validation_latency_p90: Option<Duration>,
    /// Marshal persistence cost in nanoseconds per encoded byte.
    pub marshal_persist_ns_per_byte: u64,
    /// Number of persistence observations in the window.
    pub marshal_persist_samples: usize,
    /// Build time multiplier in use.
    pub build_time_multiplier: f64,
    /// Number of finished builds in the window.
    pub build_time_samples: usize,
    /// Learned network time before clamping, if any proposal completed.
    pub network_observed: Option<Duration>,
    /// Most recent network sample, until it is older than the sample ttl.
    ///
    /// With [`EstimatorConfig::network_reserve_fast_rise`] the reservation is
    /// at least this, within its floor and cap.
    pub network_last_sample: Option<Duration>,
    /// Network reservation in use.
    pub network_reserve: Duration,
    /// Number of completed proposals in the window.
    pub network_samples: usize,
    /// Proposals still waiting for their notarization.
    pub pending_proposals: usize,
    /// Proposal return budget derived from the network reservation.
    pub proposal_return_budget: Duration,
}

#[derive(Debug)]
struct State {
    validation: ValidationLatencyEstimator,
    persist: MarshalPersistTracker,
    build_time: BuildTimeTracker,
    network: NetworkTracker,
}

/// The shared proposal budget estimator. See the [module docs](self).
#[derive(Debug)]
pub struct Estimator {
    config: EstimatorConfig,
    state: Mutex<State>,
}

impl Default for Estimator {
    fn default() -> Self {
        Self::new(EstimatorConfig::default())
    }
}

impl Estimator {
    /// Creates an estimator with no observations.
    pub fn new(config: EstimatorConfig) -> Self {
        Self {
            config,
            state: Mutex::new(State {
                validation: ValidationLatencyEstimator::default(),
                persist: MarshalPersistTracker::new(),
                build_time: BuildTimeTracker::new(config.build_time_multiplier),
                network: NetworkTracker::new(&config),
            }),
        }
    }

    /// The configuration this estimator was created with.
    pub fn config(&self) -> EstimatorConfig {
        self.config
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // The state is plain data; a poisoned lock only means another thread
        // panicked mid-update, and the samples stay usable.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // --- observations -----------------------------------------------------

    /// Records local execution-layer validation time for a block.
    ///
    /// `height` deduplicates repeated validations of the same block.
    pub fn on_block_verified(
        &self,
        height: u64,
        workload: ValidationLatencyWorkload,
        elapsed: Duration,
    ) {
        self.state().validation.observe(height, workload, elapsed);
    }

    /// Records time spent persisting an encoded block through the marshal.
    ///
    /// Both proposers (after building) and validators (after verifying)
    /// persist, so every block yields one sample per node.
    pub fn on_marshal_persist(&self, now: Instant, block_size_bytes: usize, elapsed: Duration) {
        let mut state = self.state();
        if state.persist.observe(now, block_size_bytes, elapsed) {
            debug!(
                block_size_bytes,
                ?elapsed,
                estimated_ns_per_byte = state.persist.estimate().ns_per_byte(),
                samples = state.persist.samples.len(),
                "updated marshal persistence estimate"
            );
        }
    }

    /// Records the replayable work of a finished consensus payload build.
    pub fn on_build_finished(&self, now: Instant, build: FinishedBuild) {
        let mut state = self.state();
        if let Some(observed) =
            state
                .build_time
                .observe(now, build.work_at_tx_cutoff, build.total_work)
        {
            debug!(
                observed_multiplier = observed as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64,
                build_time_multiplier =
                    state.build_time.scaled() as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64,
                samples = state.build_time.samples.len(),
                "updated build time multiplier"
            );
        }
    }

    /// Records that this node returned a proposal to consensus.
    ///
    /// `returned_unix_ms` must come from the same clock that block header
    /// timestamps use; the matching [`Self::on_child_block_built`] completes
    /// the network sample.
    pub fn on_proposal_returned(
        &self,
        now: Instant,
        returned_unix_ms: u64,
        key: ProposalKey,
        expectation: ProposalExpectation,
    ) {
        self.state()
            .network
            .proposal_returned(now, returned_unix_ms, key, expectation);
    }

    /// Records the header timestamp of a block built on top of `parent`.
    ///
    /// Only proposals this node returned itself produce a sample; other
    /// parents are ignored, so this can be fed every block the node verifies
    /// or builds.
    pub fn on_child_block_built(
        &self,
        now: Instant,
        parent: ProposalKey,
        child_view: u64,
        child_timestamp_ms: u64,
    ) {
        let mut state = self.state();
        if let Some(network) =
            state
                .network
                .child_built(now, parent, child_view, child_timestamp_ms)
        {
            debug!(
                epoch = parent.0,
                view = parent.1,
                ?network,
                network_reserve = ?state.network.reserve(),
                samples = state.network.samples.len(),
                "updated network reservation"
            );
        }
    }

    /// Expected execution-layer validation time of a block with `workload`,
    /// scaling the observed per-unit rates down as well as up.
    ///
    /// Use this to credit validators' work when measuring the network; the
    /// pacing floor from [`Self::validation_latency_estimate`] never scales
    /// down and would under-count the network for small blocks.
    pub fn expected_validation(&self, workload: ValidationLatencyWorkload) -> Option<Duration> {
        self.state().validation.workload_estimate(workload)
    }

    /// Drops a pending proposal whose view did not notarize.
    pub fn on_view_abandoned(&self, key: ProposalKey) {
        self.state().network.abandoned(key);
    }

    // --- reads ------------------------------------------------------------

    /// The proposal window for the next proposal.
    pub fn proposal_budget(&self) -> ProposalBudget {
        let network_reserve = self.state().network.reserve();
        ProposalBudget {
            target_block_time: self.config.target_block_time,
            network_reserve,
            return_budget: self
                .config
                .target_block_time
                .saturating_sub(network_reserve),
        }
    }

    /// The current validation latency estimate, if any block was validated.
    pub fn validation_latency_estimate(&self) -> Option<ValidationLatencyEstimate> {
        self.state().validation.estimate()
    }

    /// The current marshal persistence rate.
    pub fn marshal_persist(&self) -> MarshalPersistEstimator {
        self.state().persist.estimate()
    }

    /// The current build time multiplier.
    pub fn build_time_multiplier(&self) -> f64 {
        self.state().build_time.scaled() as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64
    }

    /// Snapshots the inputs for one payload build.
    pub fn build_plan(&self, build_budget: Duration) -> BuildPlan {
        let state = self.state();
        BuildPlan {
            build_budget,
            multiplier_scaled: state.build_time.scaled(),
            marshal_persist: state.persist.estimate(),
            validation_latency: state.validation.estimate(),
        }
    }

    /// Everything the estimator currently believes.
    pub fn snapshot(&self) -> EstimatorSnapshot {
        let state = self.state();
        let network_reserve = state.network.reserve();
        EstimatorSnapshot {
            validation_latency_p90: state.validation.estimate().map(|e| e.elapsed()),
            marshal_persist_ns_per_byte: state.persist.estimate().ns_per_byte(),
            marshal_persist_samples: state.persist.samples.len(),
            build_time_multiplier: state.build_time.scaled() as f64
                / BUILD_TIME_MULTIPLIER_SCALE as f64,
            build_time_samples: state.build_time.samples.len(),
            network_observed: state.network.observed(),
            network_last_sample: state.network.last_sample(),
            network_reserve,
            network_samples: state.network.samples.len(),
            pending_proposals: state.network.pending.len(),
            proposal_return_budget: self
                .config
                .target_block_time
                .saturating_sub(network_reserve),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn ms(value: u64) -> Duration {
        MS * value as u32
    }

    fn config() -> EstimatorConfig {
        EstimatorConfig::new(ms(550), ms(50))
    }

    /// Plays one own proposal in `view`, returned `view` seconds after
    /// `start`, whose child is built `network` later. Without expected
    /// validator work the whole gap is the network sample.
    fn own_proposal(estimator: &Estimator, start: Instant, view: u64, network: Duration) {
        let returned = start + Duration::from_secs(view);
        let returned_ms = 1_800_000_000_000 + view * 1000;
        estimator.on_proposal_returned(
            returned,
            returned_ms,
            (0, view),
            ProposalExpectation::default(),
        );
        estimator.on_child_block_built(
            returned + network,
            (0, view),
            view + 1,
            returned_ms + network.as_millis() as u64,
        );
    }

    fn validation_latency_estimate(
        workload: ValidationLatencyWorkload,
        elapsed: Duration,
    ) -> Option<ValidationLatencyEstimate> {
        let mut estimator = ValidationLatencyEstimator::default();
        estimator.observe(1, workload, elapsed);
        estimator.estimate()
    }

    #[test]
    fn config_validation_rejects_reservations_that_leave_no_window() {
        assert!(config().validate().is_ok());
        assert!(EstimatorConfig::new(ms(550), ms(550)).validate().is_err());
        assert!(
            config()
                .with_network_budget_max(ms(600))
                .validate()
                .is_err()
        );
        assert!(config().with_network_budget_max(ms(40)).validate().is_err());
        assert!(config().with_build_time_multiplier(0.9).validate().is_err());
        assert_eq!(config().initial_proposal_return_budget(), ms(500));
    }

    #[test]
    fn config_validation_bounds_the_network_reserve_percentile() {
        assert_eq!(config().network_reserve_percentile, 75);
        assert!(!config().network_reserve_fast_rise);
        for percentile in [50, 75, 100] {
            assert!(
                config()
                    .with_network_reserve_percentile(percentile)
                    .validate()
                    .is_ok(),
                "percentile {percentile} must be accepted"
            );
        }
        for percentile in [0, 49, 101, u8::MAX] {
            let err = config()
                .with_network_reserve_percentile(percentile)
                .validate()
                .unwrap_err();
            assert!(err.contains("network reserve percentile"), "{err}");
        }
    }

    #[test]
    fn fixed_config_pins_the_return_budget() {
        let estimator = Estimator::new(EstimatorConfig::fixed(ms(300), ms(50)));
        let now = Instant::now();
        estimator.on_proposal_returned(now, 1_000_000, (0, 1), ProposalExpectation::default());
        estimator.on_child_block_built(now + ms(400), (0, 1), 2, 1_000_400);
        assert_eq!(estimator.snapshot().network_samples, 1);
        assert_eq!(estimator.proposal_budget().return_budget, ms(300));
        assert_eq!(estimator.proposal_budget().network_reserve, ms(50));
    }

    #[test]
    fn sample_window_percentile_and_expiry() {
        let now = Instant::now();
        let mut window = SampleWindow::new(4, ms(100));
        assert_eq!(window.percentile(3, 4), None);
        for (offset, value) in [(0u64, 10u64), (10, 30), (20, 20), (30, 40)] {
            window.push(now + ms(offset), value);
        }
        assert_eq!(window.percentile(1, 2), Some(20));
        assert_eq!(window.percentile(3, 4), Some(30));
        assert_eq!(window.percentile(1, 1), Some(40));
        // Capacity evicts the oldest sample.
        window.push(now + ms(40), 50);
        assert_eq!(window.len(), 4);
        assert_eq!(window.percentile(1, 4), Some(20));
        // Age evicts everything older than the ttl: only the sample pushed
        // at +40 ms survives a push at +135 ms.
        window.push(now + ms(135), 60);
        assert_eq!(window.len(), 2);
        assert_eq!(window.percentile(1, 2), Some(50));
    }

    #[test]
    fn marshal_persist_ignores_a_single_slow_commit() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        let block = 1_000_000;
        // 10 ns per byte is a healthy 10 ms persist for a 1 MB block.
        for i in 0..24u64 {
            estimator.on_marshal_persist(now + ms(i), block, ms(10));
        }
        assert_eq!(estimator.marshal_persist().ns_per_byte(), 10);
        // One block lands on a persistence commit and takes 96 ms.
        estimator.on_marshal_persist(now + ms(30), block, ms(96));
        assert_eq!(
            estimator.marshal_persist().ns_per_byte(),
            10,
            "one outlier must not set the rate"
        );
        // A sustained slowdown takes over once it fills a quarter of the window.
        for i in 0..12u64 {
            estimator.on_marshal_persist(now + ms(40 + i), block, ms(40));
        }
        assert_eq!(estimator.marshal_persist().ns_per_byte(), 40);
        assert_eq!(estimator.marshal_persist().estimate(2 * block), ms(80));
    }

    #[test]
    fn marshal_persist_ignores_tiny_blocks_and_empty_samples() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        estimator.on_marshal_persist(now, MARSHAL_PERSIST_MIN_SAMPLE_BYTES - 1, ms(50));
        estimator.on_marshal_persist(now, 1_000_000, Duration::ZERO);
        assert_eq!(estimator.marshal_persist().ns_per_byte(), 0);
        assert_eq!(estimator.snapshot().marshal_persist_samples, 0);
    }

    #[test]
    fn build_time_multiplier_rises_in_capped_steps_and_follows_the_window_down() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        assert!((estimator.build_time_multiplier() - DEFAULT_BUILD_TIME_MULTIPLIER).abs() < 1e-9);

        // Steady builds: finish work is 5% of fill work.
        for i in 0..8u64 {
            estimator.on_build_finished(
                now + ms(i),
                FinishedBuild {
                    work_at_tx_cutoff: ms(200),
                    total_work: ms(210),
                },
            );
        }
        assert!((estimator.build_time_multiplier() - 1.05).abs() < 1e-6);

        // One finish waits 150 ms on a persistence commit: ratio 1.75, capped at 1.7.
        estimator.on_build_finished(
            now + ms(10),
            FinishedBuild {
                work_at_tx_cutoff: ms(200),
                total_work: ms(350),
            },
        );
        let after_outlier = estimator.build_time_multiplier();
        assert!(
            (after_outlier - 1.05).abs() < 1e-6,
            "p75 of the window ignores one outlier, got {after_outlier}"
        );

        // A sustained slowdown moves the multiplier by at most 0.15 per build:
        // the third slow finish flips the window's p75 to the cap, and each of
        // the two builds observed since then stepped the multiplier up once.
        for i in 0..3u64 {
            estimator.on_build_finished(
                now + ms(20 + i),
                FinishedBuild {
                    work_at_tx_cutoff: ms(200),
                    total_work: ms(350),
                },
            );
        }
        let sustained = estimator.build_time_multiplier();
        assert!(
            (sustained - 1.35).abs() < 1e-6,
            "expected two capped 0.15 steps from 1.05, got {sustained}"
        );

        // Fast finishes push the slow ones out of the window again.
        for i in 0..16u64 {
            estimator.on_build_finished(
                now + ms(40 + i),
                FinishedBuild {
                    work_at_tx_cutoff: ms(200),
                    total_work: ms(204),
                },
            );
        }
        assert!((estimator.build_time_multiplier() - 1.02).abs() < 1e-6);
    }

    #[test]
    fn build_time_multiplier_never_drops_below_one() {
        let estimator = Estimator::new(config());
        estimator.on_build_finished(
            Instant::now(),
            FinishedBuild {
                work_at_tx_cutoff: ms(200),
                total_work: ms(100),
            },
        );
        assert!((estimator.build_time_multiplier() - 1.0).abs() < 1e-9);
        // Zero cutoff work carries no information.
        estimator.on_build_finished(
            Instant::now(),
            FinishedBuild {
                work_at_tx_cutoff: Duration::ZERO,
                total_work: ms(100),
            },
        );
        assert_eq!(estimator.snapshot().build_time_samples, 1);
    }

    #[test]
    fn network_reserve_starts_at_the_floor_and_learns_from_own_proposals() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        let base_ms = 1_800_000_000_000u64;
        assert_eq!(estimator.proposal_budget().network_reserve, ms(50));
        assert_eq!(estimator.proposal_budget().return_budget, ms(500));

        // Children of other proposers' blocks are ignored.
        estimator.on_child_block_built(now, (0, 7), 8, base_ms);
        assert_eq!(estimator.snapshot().network_samples, 0);

        // Own proposals: the next leader starts building 420 ms after the
        // return, of which validators were expected to spend 225 ms
        // validating and 15 ms persisting.
        let expectation = ProposalExpectation {
            block_size_bytes: 2_600_000,
            validator_work: ms(225),
            validator_persist: ms(15),
        };
        for view in 1..=4u64 {
            let returned = now + ms(view * 1000);
            let returned_ms = base_ms + view * 1000;
            estimator.on_proposal_returned(returned, returned_ms, (0, view), expectation);
            estimator.on_child_block_built(
                returned + ms(420),
                (0, view),
                view + 1,
                returned_ms + 420,
            );
        }
        let budget = estimator.proposal_budget();
        assert_eq!(budget.network_reserve, ms(180));
        assert_eq!(budget.return_budget, ms(370));
        assert_eq!(estimator.snapshot().network_observed, Some(ms(180)));
    }

    #[test]
    fn network_reserve_is_clamped_and_pending_proposals_expire() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        let base_ms = 1_800_000_000_000u64;
        let expectation = ProposalExpectation {
            block_size_bytes: 2_600_000,
            validator_work: ms(200),
            validator_persist: Duration::ZERO,
        };
        // Faster than the floor: stays at the floor.
        estimator.on_proposal_returned(now, base_ms, (0, 1), expectation);
        estimator.on_child_block_built(now + ms(210), (0, 1), 2, base_ms + 210);
        assert_eq!(estimator.proposal_budget().network_reserve, ms(50));

        // Slower than the cap: clamped, but the observation is kept.
        for view in 2..=6u64 {
            let returned = now + ms(view * 1000);
            let returned_ms = base_ms + view * 1000;
            estimator.on_proposal_returned(returned, returned_ms, (0, view), expectation);
            estimator.on_child_block_built(
                returned + ms(700),
                (0, view),
                view + 1,
                returned_ms + 700,
            );
        }
        assert_eq!(estimator.proposal_budget().network_reserve, ms(250));
        assert_eq!(estimator.snapshot().network_observed, Some(ms(500)));

        // A nullified proposal is not a sample.
        estimator.on_proposal_returned(now + ms(10_000), base_ms + 10_000, (0, 9), expectation);
        estimator.on_view_abandoned((0, 9));
        estimator.on_child_block_built(now + ms(10_300), (0, 9), 10, base_ms + 10_300);
        assert_eq!(estimator.snapshot().network_samples, 6);

        // Neither is a child that skipped a view: the chain waited on a
        // leader timeout, not on propagation.
        estimator.on_proposal_returned(now + ms(20_000), base_ms + 20_000, (0, 10), expectation);
        estimator.on_child_block_built(now + ms(21_500), (0, 10), 12, base_ms + 21_500);
        assert_eq!(estimator.snapshot().network_samples, 6);
        assert_eq!(estimator.snapshot().pending_proposals, 0);

        // Nor an implausibly late child, which is clock skew or a stall.
        estimator.on_proposal_returned(now + ms(30_000), base_ms + 30_000, (0, 11), expectation);
        estimator.on_child_block_built(now + ms(36_000), (0, 11), 12, base_ms + 36_000);
        assert_eq!(estimator.snapshot().network_samples, 6);

        // Clock skew that puts the child before the return counts as zero
        // network time rather than being dropped.
        estimator.on_proposal_returned(now + ms(40_000), base_ms + 40_000, (0, 12), expectation);
        estimator.on_child_block_built(now + ms(40_100), (0, 12), 13, base_ms + 39_990);
        assert_eq!(estimator.snapshot().network_samples, 7);
    }

    #[test]
    fn network_samples_expire_back_to_the_floor() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        let base_ms = 1_800_000_000_000u64;
        let expectation = ProposalExpectation::default();
        estimator.on_proposal_returned(now, base_ms, (0, 1), expectation);
        estimator.on_child_block_built(now + ms(150), (0, 1), 2, base_ms + 150);
        assert_eq!(estimator.proposal_budget().network_reserve, ms(150));
        // Pushing a sample much later prunes the stale one first.
        let later = now + NETWORK_SAMPLE_TTL + ms(1000);
        let later_ms = base_ms + NETWORK_SAMPLE_TTL.as_millis() as u64 + 1000;
        estimator.on_proposal_returned(later, later_ms, (0, 2), expectation);
        estimator.on_child_block_built(later + ms(40), (0, 2), 3, later_ms + 40);
        assert_eq!(estimator.snapshot().network_samples, 1);
        assert_eq!(estimator.proposal_budget().network_reserve, ms(50));
    }

    #[test]
    fn network_reserve_uses_the_configured_percentile() {
        // Ten proposals with 100 to 190 ms of network time, out of order.
        let samples = [150, 110, 190, 130, 170, 100, 180, 120, 160, 140];
        // The rank rounds up: the 75th percentile of ten samples is the 8th
        // smallest, the 90th the 9th.
        for (percentile, expected) in [(50, 140), (75, 170), (90, 180), (100, 190)] {
            let estimator = Estimator::new(config().with_network_reserve_percentile(percentile));
            let now = Instant::now();
            for (view, network) in (1..).zip(samples) {
                own_proposal(&estimator, now, view, ms(network));
            }
            let budget = estimator.proposal_budget();
            assert_eq!(budget.network_reserve, ms(expected), "p{percentile}");
            assert_eq!(budget.return_budget, ms(550 - expected), "p{percentile}");
        }
    }

    #[test]
    fn network_reserve_fast_rise_follows_a_slow_sample_up_at_once() {
        let plain = Estimator::new(config());
        let fast = Estimator::new(config().with_network_reserve_fast_rise(true));
        let now = Instant::now();
        // Feeds the same own proposal to both estimators, returns their reserves.
        let reserves = |view, network| {
            own_proposal(&plain, now, view, network);
            own_proposal(&fast, now, view, network);
            (
                plain.proposal_budget().network_reserve,
                fast.proposal_budget().network_reserve,
            )
        };
        for view in 1..=6 {
            assert_eq!(reserves(view, ms(150)), (ms(150), ms(150)));
        }
        // One slow proposal: the window's p75 still reads 150 ms, while fast
        // rise reserves the slow sample for the very next proposal.
        assert_eq!(reserves(7, ms(240)), (ms(150), ms(240)));
        assert_eq!(fast.snapshot().network_last_sample, Some(ms(240)));
        assert_eq!(fast.proposal_budget().return_budget, ms(310));
        // The next fast proposal hands the reservation back to the window.
        assert_eq!(reserves(8, ms(150)), (ms(150), ms(150)));
        assert_eq!(fast.snapshot().network_last_sample, Some(ms(150)));
        // The last sample is reported with fast rise disabled too.
        assert_eq!(plain.snapshot().network_last_sample, Some(ms(150)));
    }

    #[test]
    fn network_reserve_fast_rise_is_capped_and_expires_with_the_window() {
        let estimator = Estimator::new(config().with_network_reserve_fast_rise(true));
        let now = Instant::now();
        for view in 1..=6 {
            own_proposal(&estimator, now, view, ms(150));
        }
        // A sample above the cap lifts the reservation only up to the cap.
        own_proposal(&estimator, now, 7, ms(400));
        let snapshot = estimator.snapshot();
        assert_eq!(snapshot.network_last_sample, Some(ms(400)));
        assert_eq!(snapshot.network_observed, Some(ms(400)));
        assert_eq!(snapshot.network_reserve, ms(250));

        // Without a newer sample the slow one still counts at exactly the
        // window's ttl, as it would in the window, and is ignored once it is
        // older. Any hook that carries the clock expires it, here blocks
        // built on other proposers' parents.
        let sampled_at = now + Duration::from_secs(7) + ms(400);
        estimator.on_child_block_built(sampled_at + NETWORK_SAMPLE_TTL, (0, 20), 21, 0);
        assert_eq!(estimator.proposal_budget().network_reserve, ms(250));
        estimator.on_child_block_built(sampled_at + NETWORK_SAMPLE_TTL + ms(1), (0, 21), 22, 0);
        let snapshot = estimator.snapshot();
        assert_eq!(snapshot.network_last_sample, None);
        assert_eq!(
            snapshot.network_reserve,
            ms(150),
            "falls back to the window percentile"
        );
    }

    #[test]
    fn build_plan_accounts_for_leader_idle_once() {
        let plan = BuildPlan::new(
            ms(500),
            1.0,
            MarshalPersistEstimator::from_ns_per_byte(0),
            None,
        );
        let decision = plan.decision(
            ms(300),
            ms(100),
            1_000_000,
            ValidationLatencyWorkload::new(1_000_000, 10),
        );
        assert_eq!(decision.predicted_builder_work, ms(200));
        assert_eq!(decision.predicted_validator_work, ms(200));
        assert_eq!(decision.total_reserved, ms(500));
        assert!(plan.exhausted(&decision));
        assert!(
            !BuildPlan::new(
                ms(501),
                1.0,
                MarshalPersistEstimator::from_ns_per_byte(0),
                None
            )
            .exhausted(&decision)
        );
    }

    #[test]
    fn build_plan_uses_validator_feedback_when_available() {
        let workload = ValidationLatencyWorkload::new(1_000_000, 10);
        let plan = BuildPlan::new(
            ms(500),
            1.0,
            MarshalPersistEstimator::from_ns_per_byte(0),
            validation_latency_estimate(workload, ms(120)),
        );
        let decision = plan.decision(ms(200), Duration::ZERO, 1_000_000, workload);
        assert_eq!(decision.predicted_builder_work, ms(200));
        assert_eq!(decision.predicted_validator_work, ms(120));
        assert_eq!(decision.total_reserved, ms(320));
    }

    #[test]
    fn build_plan_caps_scaled_validator_feedback_at_builder_projection() {
        let plan = BuildPlan::new(
            ms(500),
            1.0,
            MarshalPersistEstimator::from_ns_per_byte(0),
            validation_latency_estimate(ValidationLatencyWorkload::new(1_000_000, 10), ms(120)),
        );
        // Four times the feedback workload would scale the estimate to 480 ms,
        // which is more than the builder itself has spent.
        let decision = plan.decision(
            ms(200),
            Duration::ZERO,
            1_000_000,
            ValidationLatencyWorkload::new(4_000_000, 40),
        );
        assert_eq!(decision.predicted_validator_work, ms(200));
    }

    #[test]
    fn build_plan_accounts_for_marshal_persist_on_both_sides() {
        let plan = BuildPlan::new(
            ms(500),
            1.35,
            MarshalPersistEstimator::from_ns_per_byte(10),
            None,
        );
        let decision = plan.decision(
            ms(100),
            Duration::ZERO,
            1_000_000,
            ValidationLatencyWorkload::new(1_000_000, 10),
        );
        assert_eq!(decision.predicted_builder_work, ms(135));
        assert_eq!(decision.marshal_persist, ms(10));
        assert_eq!(decision.total_reserved, ms(135 + 135 + 10 + 10));
        assert!((plan.build_time_multiplier() - 1.35).abs() < 1e-9);
    }

    #[test]
    fn build_plan_prefers_an_explicit_validation_snapshot() {
        let estimator = Estimator::new(config());
        let workload = ValidationLatencyWorkload::new(1_000_000, 10);
        estimator.on_block_verified(1, workload, ms(200));
        let plan = estimator.build_plan(ms(400));
        assert_eq!(
            plan.validation_latency().and_then(|e| e.estimate(workload)),
            Some(ms(200))
        );
        let overridden =
            plan.with_validation_latency(validation_latency_estimate(workload, ms(50)));
        assert_eq!(
            overridden
                .validation_latency()
                .and_then(|e| e.estimate(workload)),
            Some(ms(50))
        );
        assert_eq!(plan.with_validation_latency(None), plan);
    }

    /// A ten validator network with 2.6 MB blocks, as measured on the
    /// multi-region benchmark: validators need ~225 ms to validate and ~15 ms
    /// to persist, and the next leader starts building ~210 ms of network
    /// time after that (body to the quorum plus votes to the next leader).
    struct SimulatedNetwork {
        estimator: Estimator,
        now: Instant,
        unix_ms: u64,
        validators: u64,
        block_size: usize,
        validation: Duration,
        persist: Duration,
        network: Duration,
    }

    impl SimulatedNetwork {
        fn new(estimator: Estimator) -> Self {
            Self {
                estimator,
                now: Instant::now(),
                unix_ms: 1_800_000_000_000,
                validators: 10,
                block_size: 2_600_000,
                validation: ms(225),
                persist: ms(15),
                network: ms(210),
            }
        }

        fn advance(&mut self, by: Duration) {
            self.now += by;
            self.unix_ms += by.as_millis() as u64;
        }

        /// Plays `blocks` consecutive blocks; this node proposes every
        /// `validators`th one. Returns the return budgets this node used
        /// for its own proposals.
        fn run(&mut self, blocks: u64) -> Vec<Duration> {
            let mut budgets = Vec::new();
            let workload = ValidationLatencyWorkload::new(1_000_000_000, 10_000);
            for height in 1..=blocks {
                let key = (0, height);
                let ours = height % self.validators == 0;
                if ours {
                    let budget = self.estimator.proposal_budget();
                    budgets.push(budget.return_budget);
                    let expected_persist =
                        self.estimator.marshal_persist().estimate(self.block_size);
                    let expected_work = self
                        .estimator
                        .expected_validation(workload)
                        .unwrap_or(self.validation);
                    // Build for whatever the budget leaves after the expected
                    // remote work, then persist and return.
                    self.advance(
                        budget
                            .return_budget
                            .saturating_sub(expected_work)
                            .saturating_sub(expected_persist),
                    );
                    self.estimator
                        .on_marshal_persist(self.now, self.block_size, self.persist);
                    self.estimator.on_proposal_returned(
                        self.now,
                        self.unix_ms,
                        key,
                        ProposalExpectation {
                            block_size_bytes: self.block_size,
                            validator_work: expected_work,
                            validator_persist: expected_persist,
                        },
                    );
                    // The next leader starts building once the quorum has
                    // validated and its votes reached it.
                    self.advance(self.network + self.validation + self.persist);
                    self.estimator
                        .on_child_block_built(self.now, key, height + 1, self.unix_ms);
                } else {
                    // Someone else proposed: we receive, validate and persist,
                    // and see the next block's timestamp when we verify it.
                    self.advance(ms(240) + self.network / 2);
                    self.estimator
                        .on_block_verified(height, workload, self.validation);
                    self.estimator
                        .on_marshal_persist(self.now, self.block_size, self.persist);
                    self.advance(self.network / 2);
                    self.estimator
                        .on_child_block_built(self.now, key, height + 1, self.unix_ms);
                }
            }
            budgets
        }
    }

    #[test]
    fn simulation_learns_the_network_reservation_within_a_few_proposals() {
        let mut network = SimulatedNetwork::new(Estimator::new(config()));
        let budgets = network.run(60);
        // The first own proposal still uses the configured 50 ms reservation.
        assert_eq!(budgets[0], ms(500));
        // Afterwards the reservation converges on the measured 210 ms, up to
        // the rounding of the per-byte persistence rate.
        let last = *budgets.last().unwrap();
        assert!(
            last >= ms(339) && last <= ms(341),
            "expected a return budget of about 340 ms, got {last:?}"
        );
        let snapshot = network.estimator.snapshot();
        assert!(
            snapshot.network_reserve >= ms(209) && snapshot.network_reserve <= ms(211),
            "expected a network reserve of about 210 ms, got {:?}",
            snapshot.network_reserve
        );
        assert_eq!(snapshot.validation_latency_p90, Some(ms(225)));
        assert_eq!(snapshot.marshal_persist_ns_per_byte, 6);
    }

    #[test]
    fn simulation_keeps_the_reservation_when_the_network_is_faster_than_the_floor() {
        let mut network = SimulatedNetwork::new(Estimator::new(config()));
        network.network = ms(20);
        let budgets = network.run(60);
        assert!(budgets.iter().all(|budget| *budget == ms(500)));
    }

    #[test]
    fn simulation_persistence_spike_does_not_shrink_the_next_proposals() {
        let mut network = SimulatedNetwork::new(Estimator::new(config()));
        network.run(40);
        let before = network
            .estimator
            .marshal_persist()
            .estimate(network.block_size);
        // One block hits a persistence commit and takes 10x as long to persist.
        network.persist = ms(150);
        network.run(1);
        network.persist = ms(15);
        let after = network
            .estimator
            .marshal_persist()
            .estimate(network.block_size);
        assert_eq!(
            before, after,
            "a single slow persist must not change the reservation for the next proposals"
        );
    }
}
