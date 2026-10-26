//! Proposal budget estimator shared by consensus and the payload builder.
//!
//! Before a proposer stops adding transactions it has to reserve time for
//! three things: its own replayable build work, including the finish (state
//! root, block assembly) after the transaction cutoff; the validators replaying
//! the block; and the network, from shipping the proposal to the next leader
//! starting on top of it. The [`Estimator`] owns all three estimates so that
//! consensus and the builder read one picture, and so that the whole model can
//! be driven by a simulated block sequence in tests. Marshal persistence is not
//! modelled: it runs concurrently with voting and gates finalization, not the
//! next block.
//!
//! The estimator is pure bookkeeping. Callers feed observations through the
//! `on_*` hooks and take decisions through [`Estimator::start_proposal`] and
//! [`Estimator::build_plan`], passing the clock explicitly. Starting a proposal
//! also moves the network reservation one bounded step, so it is called exactly
//! once per own proposal; [`Estimator::snapshot`] reads without moving anything.
//!
//! # Clocks
//!
//! `now: Instant` is a monotonic clock used only to age state: window samples
//! and own proposals still waiting for their child expire by it, and every read
//! drops expired samples first. The value of a network sample comes from
//! wall-clock unix milliseconds instead: when this node opened its proposal
//! window (the clock reading its header timestamp is taken from) and the header
//! timestamp the next leader set on the child. Both must come from the clock
//! header timestamps use, so a sample is only as accurate as the validators'
//! clock synchronisation.
//!
//! # Robustness
//!
//! Every learned quantity is a percentile over a bounded window of recent
//! samples, and no estimate takes its percentile as is: each follows it by at
//! most one capped step per observation, in both directions, because the
//! percentile of a sparse window is its maximum and samples aging out can leave
//! an outlier behind. One slow finish or one slow successor therefore costs the
//! next proposal one step, while a sustained change still takes over within a
//! few observations. Builds whose pool ran dry stay out of the multiplier's
//! window and teach a separate dry build finish instead, see `BuildTimeTracker`.
//!
//! The build time and network windows learn from this node's own proposals
//! only, so they are bounded by count and age: 16 samples each, with ttls long
//! enough that the count is what binds on Tempo's committee sizes. Validation
//! latency feedback learns from every verified block and is bounded by count
//! alone.

use std::{
    collections::VecDeque,
    ops::{Add, Sub},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tracing::debug;

use crate::{
    BUILD_TIME_MULTIPLIER_SCALE, BuildPlan, ProposalBudget, ValidationLatencyEstimator,
    ValidationLatencyWorkload,
};

/// Initial ratio of total replayable build work to work at transaction cutoff.
pub const DEFAULT_BUILD_TIME_MULTIPLIER: f64 = 1.15;

/// Builder work never shrinks after the transaction cutoff.
const MIN_BUILD_TIME_MULTIPLIER_SCALED: u64 = BUILD_TIME_MULTIPLIER_SCALE;
/// Finish work larger than 70% of fill work is treated as an outlier. Also the
/// largest initial multiplier a configuration may set, see
/// [`EstimatorConfig::validate`]: the multiplier is never learned above it.
const MAX_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_700_000;
/// Largest change of the multiplier, up or down, per finished build: a lone slow
/// finish costs one step, a sustained slowdown reaches the cap in four builds
/// from an empty window, and the way down from the cap takes five.
const BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED: u64 = 150_000;
/// Largest change of the dry build finish, up or down, per dry build, so that
/// one finish that waited on a persistence commit does not claim that wait for
/// the dry builds after it.
const DRY_BUILD_FINISH_MAX_STEP: Duration = Duration::from_millis(10);
const BUILD_TIME_SAMPLE_WINDOW: usize = 16;
const BUILD_TIME_SAMPLE_TTL: Duration = Duration::from_secs(5 * 60);

/// Percentile of the build time windows the multiplier and the dry build finish
/// follow. The median ignores too much of the tail; the 90th of 16 samples is a
/// single observation.
const BUILD_TIME_RESERVE_PERCENTILE: u8 = 75;

/// Target wall-clock time between blocks used when no configuration is given.
pub const DEFAULT_TARGET_BLOCK_TIME: Duration = Duration::from_millis(550);
/// Initial and minimum network reservation (proposal propagation plus votes).
pub const DEFAULT_NETWORK_BUDGET: Duration = Duration::from_millis(50);
/// Largest network reservation the estimator may learn on its own.
///
/// Bounds how much of the block time the wait after a proposal window may claim
/// before an operator has to look at the network. Validator replay beyond the
/// builder's own projected work is learned as network time, so the cap bounds
/// that as well.
pub const DEFAULT_NETWORK_BUDGET_MAX: Duration = Duration::from_millis(300);
/// Percentile of recent network samples reserved when no configuration is given.
pub const DEFAULT_NETWORK_RESERVE_PERCENTILE: u8 = 75;
/// How far a proposal may run past its return budget and still count as having
/// met it, see [`EstimatorConfig::return_budget_overrun_tolerance`].
///
/// This is the builder's pacing precision on a dry build, which idles up to its
/// budget in 1 ms steps and returns a millisecond or two late; real overruns
/// under load are tens of milliseconds.
pub const DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE: Duration = Duration::from_millis(5);

/// Number of own proposals the network reservation is derived from.
const NETWORK_SAMPLE_WINDOW: usize = 16;
/// Network samples older than this are dropped, so that a node that stopped
/// proposing does not keep stale ones. With N validators and 550 ms blocks an
/// own proposal completes every ~0.55 N s, so ten minutes hold the full 16
/// samples for committees of up to ~68 validators.
const NETWORK_SAMPLE_TTL: Duration = Duration::from_secs(10 * 60);
/// Network samples longer than this, from the window's close to the child's
/// header, are discarded as clock skew or a stall unrelated to propagation.
const MAX_NETWORK_SAMPLE: Duration = Duration::from_secs(5);
/// Largest change of the network reservation between consecutive own proposals,
/// however the window's percentile moved in between (sparse window, expiry,
/// outlier, fast rise). One bad sample costs the next proposal at most this
/// much of its window.
const NETWORK_RESERVE_MAX_STEP: Duration = Duration::from_millis(100);
/// Lowest accepted network reserve percentile: the median of the window.
const MIN_NETWORK_RESERVE_PERCENTILE: u8 = 50;
/// Highest accepted network reserve percentile: the slowest sample in the window.
const MAX_NETWORK_RESERVE_PERCENTILE: u8 = 100;
/// An own proposal whose child block has not arrived after this long is no
/// longer a usable network sample: its view was most likely nullified, or
/// the next leader built on an ancestor.
const PENDING_PROPOSAL_TTL: Duration = Duration::from_secs(10);
/// Upper bound on own proposals awaiting the block built on top of them.
const MAX_PENDING_PROPOSALS: usize = 8;

/// Identifies a proposal by its own round as `(epoch, view)`: the epoch and
/// the view in which the proposal itself was made, not those of its parent
/// or of the block built on top of it.
pub type ProposalKey = (u64, u64);

/// Static proposal budget configuration, validated at construction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EstimatorConfig {
    /// Target interval between block header timestamps.
    pub target_block_time: Duration,
    /// Initial and minimum network reservation.
    pub network_budget: Duration,
    /// Maximum network reservation; equal to the floor disables learning.
    pub network_budget_max: Duration,
    /// Reserved network percentile, from 50 to 100 inclusive.
    pub network_reserve_percentile: u8,
    /// Whether two consecutive slow samples can raise the percentile target.
    pub network_reserve_fast_rise: bool,
    /// Initial build multiplier, from 1.0 to 1.7 inclusive.
    pub build_time_multiplier: f64,
    /// Maximum accepted proposal overrun; `Duration::MAX` records all proposals.
    pub return_budget_overrun_tolerance: Duration,
}

impl Default for EstimatorConfig {
    fn default() -> Self {
        Self {
            target_block_time: DEFAULT_TARGET_BLOCK_TIME,
            network_budget: DEFAULT_NETWORK_BUDGET,
            network_budget_max: DEFAULT_NETWORK_BUDGET_MAX,
            network_reserve_percentile: DEFAULT_NETWORK_RESERVE_PERCENTILE,
            network_reserve_fast_rise: true,
            build_time_multiplier: DEFAULT_BUILD_TIME_MULTIPLIER,
            return_budget_overrun_tolerance: DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE,
        }
    }
}

impl EstimatorConfig {
    /// The network reservation cap used when none is configured: the floor plus
    /// half the initial proposal window, at most [`DEFAULT_NETWORK_BUDGET_MAX`] and
    /// never below the floor, so it stays below the target whenever the floor does.
    pub fn default_network_budget_max(
        target_block_time: Duration,
        network_budget: Duration,
    ) -> Duration {
        let initial_window = target_block_time.saturating_sub(network_budget);
        network_budget
            .saturating_add(initial_window / 2)
            .min(DEFAULT_NETWORK_BUDGET_MAX)
            .max(network_budget)
    }

    /// Creates a configuration with the network reservation pinned to
    /// `network_budget`, so the return budget is exactly `proposal_return_budget`
    /// for the lifetime of the node.
    ///
    /// Every own proposal takes a network sample, however far it overran: a pinned
    /// reservation never learns from them, so excluding overruns would only hide
    /// them from tests whose builds are slow relative to the budget.
    pub fn fixed(proposal_return_budget: Duration, network_budget: Duration) -> Self {
        Self {
            target_block_time: proposal_return_budget.saturating_add(network_budget),
            network_budget,
            network_budget_max: network_budget,
            return_budget_overrun_tolerance: Duration::MAX,
            ..Self::default()
        }
    }

    /// Sets the initial build time multiplier.
    pub fn with_build_time_multiplier(mut self, build_time_multiplier: f64) -> Self {
        self.build_time_multiplier = build_time_multiplier;
        self
    }

    /// Checks that the reservations leave room for a proposal and that the
    /// learning knobs are in range. [`Estimator::new`] rejects a
    /// configuration that fails this.
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
        // The multiplier is never learned above its cap.
        let max_build_time_multiplier =
            MAX_BUILD_TIME_MULTIPLIER_SCALED as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64;
        if self.build_time_multiplier > max_build_time_multiplier {
            return Err(format!(
                "build time multiplier ({}) must be at most {max_build_time_multiplier}, \
                 the largest multiplier the estimator learns",
                self.build_time_multiplier
            ));
        }
        Ok(())
    }
}

/// Cloneable pacing feedback shared by consensus and the payload builder.
#[derive(Clone, Debug)]
pub struct Estimator {
    inner: Arc<EstimatorInner>,
}

#[derive(Debug)]
struct EstimatorInner {
    config: EstimatorConfig,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    validation: ValidationLatencyEstimator,
    build_time: BuildTimeTracker,
    network: NetworkTracker,
}

impl Estimator {
    /// Creates empty feedback or returns why the configuration is invalid.
    pub fn new(config: EstimatorConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(EstimatorInner {
                config,
                state: Mutex::new(State {
                    validation: ValidationLatencyEstimator::default(),
                    build_time: BuildTimeTracker::new(config.build_time_multiplier),
                    network: NetworkTracker::new(&config),
                }),
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // State is plain data and remains usable after a poisoned update.
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn state_at(&self, now: Instant) -> std::sync::MutexGuard<'_, State> {
        let mut state = self.state();
        state.build_time.prune(now);
        state.network.prune(now);
        state
    }

    /// Records successful local execution-layer verification, keyed by height.
    pub fn on_block_verified(
        &self,
        height: u64,
        workload: ValidationLatencyWorkload,
        elapsed: Duration,
    ) {
        self.state().validation.observe(height, workload, elapsed);
    }

    /// Snapshots feedback once for a paced payload build, expiring stale build samples.
    pub fn build_plan(&self, now: Instant, build_budget: Duration) -> BuildPlan {
        let state = self.state_at(now);
        BuildPlan {
            build_budget,
            multiplier_scaled: state.build_time.multiplier_scaled(),
            dry_finish: state.build_time.dry_finish(),
            validation_latency: state.validation.estimate(),
        }
    }

    /// Records the replayable work of a finished consensus payload build.
    ///
    /// A build that never waited for transactions teaches the multiplier, the ratio
    /// of its total over its cutoff work. A dry build, one that waited
    /// ([`FinishedBuild::idle`] is not zero), teaches the dry build finish instead:
    /// its near-empty block's finish is mostly fixed cost that a ratio would carry
    /// over to full blocks, see [`BuildPlan::decision`].
    pub fn on_build_finished(&self, now: Instant, build: FinishedBuild) {
        let mut state = self.state();
        match state.build_time.observe(now, build) {
            Some(BuildSample::Ratio(observed)) => debug!(
                observed_multiplier = observed as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64,
                build_time_multiplier = state.build_time.multiplier_scaled() as f64
                    / BUILD_TIME_MULTIPLIER_SCALE as f64,
                samples = state.build_time.multiplier.samples.len(),
                "recorded build time multiplier sample"
            ),
            Some(BuildSample::DryFinish(finish)) => debug!(
                ?finish,
                dry_build_finish = ?state.build_time.dry_finish(),
                samples = state.build_time.dry_finish.samples.len(),
                "recorded dry build finish sample"
            ),
            None => {}
        }
    }

    /// Records that this node returned a proposal to consensus, opening the network
    /// sample that the block built on top of it completes through
    /// [`Self::on_child_block_built`].
    ///
    /// `window_opened_unix_ms` is the clock reading this node took its header
    /// timestamp from, before any clamp to the parent's, and `return_budget` the
    /// window the proposal was paced from it with. The sample is
    /// `child_timestamp_ms - window_opened_unix_ms - return_budget`: this node's
    /// own block time minus its return budget. `returned_unix_ms` is when the
    /// proposal left this node; no honest successor stamps a child before it. Both
    /// timestamps must come from the clock header timestamps use. A proposal that
    /// [overran](ProposalBudget::overran) its return budget must not be recorded.
    pub fn on_proposal_returned(
        &self,
        now: Instant,
        window_opened_unix_ms: u64,
        returned_unix_ms: u64,
        key: ProposalKey,
        return_budget: Duration,
    ) {
        self.state().network.proposal_returned(
            now,
            PendingProposal {
                key,
                returned_at: now,
                window_opened_unix_ms,
                returned_unix_ms,
                return_budget,
            },
        );
    }

    /// Records the header timestamp of a block built on top of `parent`, completing
    /// the network sample [`Self::on_proposal_returned`] opened for it.
    ///
    /// `parent` is the child's `(epoch, parent_view)` from its consensus context.
    /// Parents this node did not propose are ignored, so every finalized block can
    /// be fed, the node's own included. Feed finalized blocks only: a pending
    /// proposal completes with the first child reported for it, which must not be
    /// one that was verified but never certified. Only the timestamps decide the
    /// sample, so the finalization lag does not change it as long as it stays
    /// within the pending proposal's 10 s.
    ///
    /// No sample is taken for a child that:
    ///
    /// - builds on a pending proposal this node no longer holds: returned more than
    ///   10 s earlier or pushed out by 8 newer ones, which happens after a
    ///   nullified view or a successor building on an ancestor;
    /// - is not in the view right after its parent's: the chain waited on a leader
    ///   timeout, not on propagation;
    /// - is the first block of an epoch, which names the boundary block by its view
    ///   in the new epoch and so matches no pending proposal;
    /// - was stamped before the parent left this node, or more than 5 s after the
    ///   parent's window closed: clock skew, a backdated timestamp or a stall
    ///   unrelated to propagation.
    ///
    /// A successor chooses its header timestamp, so a byzantine one can report a
    /// faster network for the one sample it is the successor of. With fewer than a
    /// third of the validators byzantine the window's 75th percentile stays at or
    /// above about the 62nd percentile of the honest samples, and the reservation
    /// never drops below the configured floor.
    ///
    /// The sample moves the reservation's target; the reservation follows it with
    /// the next own proposal, see [`Self::start_proposal`].
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
                network_target = ?state.network.target(),
                network_reserve = ?state.network.reserve(),
                samples = state.network.samples.len(),
                "recorded network sample"
            );
        }
    }

    /// Advances the reservation once per own proposal, including failed builds.
    #[must_use]
    pub fn start_proposal(&self, now: Instant) -> ProposalBudget {
        let network_reserve = self.state().network.reserve_for_proposal(now);
        ProposalBudget::new(self.inner.config.target_block_time, network_reserve)
            .with_overrun_tolerance(self.inner.config.return_budget_overrun_tolerance)
    }

    /// The build time multiplier in use at `now`. Only finished builds move it;
    /// once every build in the window has expired it is the configured initial
    /// multiplier again.
    pub fn build_time_multiplier(&self, now: Instant) -> f64 {
        self.state_at(now).build_time.multiplier_scaled() as f64
            / BUILD_TIME_MULTIPLIER_SCALE as f64
    }

    /// Everything the estimator believes at `now`, after dropping samples
    /// older than their window's ttl.
    ///
    /// Taking a snapshot does not move the network reservation: the
    /// reservation and return budget it reports are the ones the most recent
    /// own proposal used.
    pub fn snapshot(&self, now: Instant) -> EstimatorSnapshot {
        let state = self.state_at(now);
        let budget =
            ProposalBudget::new(self.inner.config.target_block_time, state.network.reserve());
        EstimatorSnapshot {
            validation_latency_p90: state.validation.estimate().map(|e| e.elapsed()),
            build_time_multiplier: state.build_time.multiplier_scaled() as f64
                / BUILD_TIME_MULTIPLIER_SCALE as f64,
            build_time_samples: state.build_time.multiplier.samples.len(),
            dry_build_finish: state.build_time.dry_finish(),
            dry_build_samples: state.build_time.dry_finish.samples.len(),
            network_observed: state.network.observed(),
            network_last_sample: state.network.last_sample(),
            network_reserve: budget.network_reserve,
            network_samples: state.network.samples.len(),
            pending_proposals: state.network.pending.len(),
            proposal_return_budget: budget.return_budget,
        }
    }
}

/// Timings of a finished payload build.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FinishedBuild {
    /// Replayable work measured when pool transaction execution stopped.
    pub work_at_tx_cutoff: Duration,
    /// Replayable work measured after finalization, excluding proposer idle time.
    pub total_work: Duration,
    /// Time the build spent waiting for the pool to yield more transactions.
    ///
    /// Not zero for a dry build, one whose pool ran dry before its budget
    /// did: it teaches the dry build finish rather than the multiplier.
    pub idle: Duration,
}

/// Converts a human-readable build-work multiplier into the fixed-point representation.
fn scaled_build_time_multiplier(multiplier: f64) -> u64 {
    assert!(
        multiplier.is_finite() && multiplier >= 1.0,
        "build time multiplier must be finite and >= 1.0"
    );

    (multiplier * BUILD_TIME_MULTIPLIER_SCALE as f64).round() as u64
}

/// Computes the observed total-work to tx-cutoff-work multiplier.
///
/// `work_at_tx_cutoff` is measured when pool transaction execution stops.
/// `total_work` is measured after finalization finishes. Their ratio captures
/// `builder_finish` without needing a separate fixed reserve.
fn observed_build_time_multiplier(
    total_work: Duration,
    work_at_tx_cutoff: Duration,
) -> Option<u64> {
    if work_at_tx_cutoff == Duration::ZERO {
        return None;
    }

    let multiplier = total_work
        .as_nanos()
        .saturating_mul(u128::from(BUILD_TIME_MULTIPLIER_SCALE))
        / work_at_tx_cutoff.as_nanos();
    Some(
        (multiplier.min(u128::from(MAX_BUILD_TIME_MULTIPLIER_SCALED)) as u64)
            .max(MIN_BUILD_TIME_MULTIPLIER_SCALED),
    )
}

/// Bounded, age-limited window of samples with percentile reads. Samples are
/// kept in insertion order and expire by the `Instant` they were pushed with,
/// which may be slightly older than the previous one's: callers read the clock
/// before they take the estimator's lock.
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

    /// Adds a sample, evicting the oldest one at capacity. Owners prune
    /// first: expiring a build window also resets its estimate, see
    /// [`BoundedFollower::prune`].
    fn push(&mut self, now: Instant, value: T) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back((now, value));
    }

    fn prune(&mut self, now: Instant) {
        self.samples
            .retain(|(at, _)| now.saturating_duration_since(*at) <= self.ttl);
    }

    fn len(&self) -> usize {
        self.samples.len()
    }

    fn newest(&self) -> impl Iterator<Item = T> + '_ {
        self.samples.iter().rev().map(|(_, value)| *value)
    }

    fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Returns the `percent`th percentile, rounding the rank up so that a
    /// single sample is returned as is.
    fn percentile(&self, percent: u8) -> Option<T> {
        if self.samples.is_empty() {
            return None;
        }
        let mut values: Vec<T> = self.samples.iter().map(|(_, value)| *value).collect();
        values.sort_unstable();
        let rank = (values.len() * usize::from(percent)).div_ceil(100).max(1);
        values.get(rank - 1).copied()
    }
}

/// Moves `current` toward `target` by at most `max_step`, in either direction.
/// Both learned estimates follow their percentile through this because the
/// percentile can jump: that of a sparse window is its maximum, and samples
/// aging out can leave an outlier behind.
fn step_toward<T>(current: T, target: T, max_step: T) -> T
where
    T: Copy + Ord + Add<Output = T> + Sub<Output = T>,
{
    if target >= current {
        current + (target - current).min(max_step)
    } else {
        current - (current - target).min(max_step)
    }
}

/// Learns how much replayable work follows the transaction cutoff.
///
/// A build that kept adding transactions until its budget or a block limit
/// stopped it teaches the multiplier: its finish grows with the block, so its
/// ratio of total over cutoff work carries over to the next such build. A dry
/// build, one that waited for transactions, has a near-empty block whose finish
/// is mostly fixed cost; its ratio has a near-zero denominator, and a window of
/// them would hold the multiplier at its cap into the first busy builds after a
/// quiet period. So dry builds teach a separate dry build finish, which only
/// builds that waited reserve, see [`BuildPlan::decision`].
#[derive(Clone, Debug)]
struct BuildTimeTracker {
    /// Ratio of total over cutoff work in fixed point, from builds that
    /// never waited for transactions.
    multiplier: BoundedFollower,
    /// Finish duration in nanoseconds, from dry builds. Starts at zero, the
    /// reservation before any dry build finished.
    dry_finish: BoundedFollower,
}

/// What a finished build taught the [`BuildTimeTracker`].
#[derive(Clone, Copy, Debug)]
enum BuildSample {
    /// The ratio of total over cutoff work of a build that never waited, in
    /// fixed point.
    Ratio(u64),
    /// The finish duration of a dry build.
    DryFinish(Duration),
}

impl BuildTimeTracker {
    /// Starts at the configured initial multiplier and without a dry build
    /// finish.
    ///
    /// The multiplier comes from a validated configuration, so it is already
    /// within the range it is learned in.
    fn new(initial_multiplier: f64) -> Self {
        Self {
            multiplier: BoundedFollower::new(
                scaled_build_time_multiplier(initial_multiplier),
                BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED,
            ),
            dry_finish: BoundedFollower::new(0, nanos(DRY_BUILD_FINISH_MAX_STEP)),
        }
    }

    fn prune(&mut self, now: Instant) {
        self.multiplier.prune(now);
        self.dry_finish.prune(now);
    }

    /// Records a finished build. Returns what it taught, if anything.
    fn observe(&mut self, now: Instant, build: FinishedBuild) -> Option<BuildSample> {
        if !build.idle.is_zero() {
            let finish = build.total_work.saturating_sub(build.work_at_tx_cutoff);
            self.dry_finish.observe(now, nanos(finish));
            return Some(BuildSample::DryFinish(finish));
        }
        let observed = observed_build_time_multiplier(build.total_work, build.work_at_tx_cutoff)?;
        self.multiplier.observe(now, observed);
        Some(BuildSample::Ratio(observed))
    }

    fn multiplier_scaled(&self) -> u64 {
        self.multiplier.current
    }

    fn dry_finish(&self) -> Duration {
        Duration::from_nanos(self.dry_finish.current)
    }
}

fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// An estimate that follows the 75th percentile of a window of finished builds
/// by bounded steps: toward the percentile by at most `max_step` per build,
/// upward only on a build that was itself above the estimate and at most to its
/// value, see [`Self::observe`], and back to `initial` once the window is
/// empty, see [`Self::prune`].
#[derive(Clone, Debug)]
struct BoundedFollower {
    samples: SampleWindow<u64>,
    /// In use while the window is empty.
    initial: u64,
    current: u64,
    max_step: u64,
}

impl BoundedFollower {
    fn new(initial: u64, max_step: u64) -> Self {
        Self {
            samples: SampleWindow::new(BUILD_TIME_SAMPLE_WINDOW, BUILD_TIME_SAMPLE_TTL),
            initial,
            current: initial,
            max_step,
        }
    }

    /// Drops finished builds older than the window's ttl. Expired builds do not
    /// move the estimate while newer ones are left, so a read after a partial
    /// expiry cannot skip the bounded recovery; once none is left the estimate is
    /// back at its initial value, as after startup.
    fn prune(&mut self, now: Instant) {
        self.samples.prune(now);
        if self.samples.is_empty() {
            self.current = self.initial;
        }
    }

    /// Records a finished build's value and takes at most one capped step toward
    /// the window's percentile.
    ///
    /// A step up needs the build itself above the estimate and goes at most to the
    /// build's value: the percentile of a sparse window is its largest value, so
    /// without that one slow finish would raise the estimate with every build until
    /// the window held four. A step down only needs the percentile below the
    /// estimate.
    fn observe(&mut self, now: Instant, observed: u64) {
        self.prune(now);
        self.samples.push(now, observed);
        let percentile = self
            .samples
            .percentile(BUILD_TIME_RESERVE_PERCENTILE)
            .expect("the window holds the build just pushed");
        let target = if observed > self.current {
            percentile.min(observed)
        } else {
            percentile.min(self.current)
        };
        self.current = step_toward(self.current, target, self.max_step);
    }
}

/// Everything the estimator currently believes, for logs and metrics.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EstimatorSnapshot {
    /// Recent P90 execution-layer validation time, if observed.
    pub validation_latency_p90: Option<Duration>,
    /// Build time multiplier in use.
    pub build_time_multiplier: f64,
    /// Number of finished builds in the multiplier's window, which holds no
    /// dry build.
    pub build_time_samples: usize,
    /// Finish a build that waited for transactions reserves.
    pub dry_build_finish: Duration,
    /// Number of dry builds the dry build finish is derived from.
    pub dry_build_samples: usize,
    /// Learned network time before clamping, if the window holds a completed
    /// proposal: the window percentile, under fast rise lifted to the smaller of
    /// the two newest samples. Clamped, this is the reservation's target.
    pub network_observed: Option<Duration>,
    /// Newest network sample in the window.
    pub network_last_sample: Option<Duration>,
    /// Network reservation the most recent own proposal used, or the floor
    /// before the first one.
    pub network_reserve: Duration,
    /// Number of completed proposals in the window.
    pub network_samples: usize,
    /// Own proposals still waiting for the block built on top of them.
    pub pending_proposals: usize,
    /// Proposal return budget derived from the network reservation.
    pub proposal_return_budget: Duration,
}

/// Bounded network reservation learned from finalized successors.
#[derive(Clone, Debug)]
struct NetworkTracker {
    samples: SampleWindow<u64>,
    pending: VecDeque<PendingProposal>,
    floor: Duration,
    cap: Duration,
    percentile: u8,
    fast_rise: bool,
    applied: Duration,
}

impl NetworkTracker {
    fn new(config: &EstimatorConfig) -> Self {
        Self {
            samples: SampleWindow::new(NETWORK_SAMPLE_WINDOW, NETWORK_SAMPLE_TTL),
            pending: VecDeque::with_capacity(MAX_PENDING_PROPOSALS),
            floor: config.network_budget,
            cap: config.network_budget_max,
            percentile: config.network_reserve_percentile,
            fast_rise: config.network_reserve_fast_rise,
            applied: config.network_budget,
        }
    }

    fn prune(&mut self, now: Instant) {
        self.samples.prune(now);
        self.pending.retain(|pending| {
            now.saturating_duration_since(pending.returned_at) <= PENDING_PROPOSAL_TTL
        });
    }

    fn proposal_returned(&mut self, now: Instant, proposal: PendingProposal) {
        self.prune(now);
        self.pending.retain(|pending| pending.key != proposal.key);
        if self.pending.len() == MAX_PENDING_PROPOSALS {
            self.pending.pop_front();
        }
        self.pending.push_back(proposal);
    }

    fn child_built(
        &mut self,
        now: Instant,
        parent: ProposalKey,
        child_view: u64,
        child_timestamp_ms: u64,
    ) -> Option<Duration> {
        self.prune(now);
        let index = self
            .pending
            .iter()
            .position(|pending| pending.key == parent)?;
        let pending = self.pending.remove(index)?;
        if child_view != parent.1.saturating_add(1) {
            return None;
        }
        if child_timestamp_ms < pending.returned_unix_ms {
            return None;
        }
        let network =
            Duration::from_millis(child_timestamp_ms.saturating_sub(pending.window_opened_unix_ms))
                .saturating_sub(pending.return_budget);
        if network > MAX_NETWORK_SAMPLE {
            return None;
        }
        self.samples.push(now, nanos(network));
        Some(network)
    }

    fn observed(&self) -> Option<Duration> {
        let window = self.samples.percentile(self.percentile)?;
        let mut newest = self.samples.newest();
        let observed = match (newest.next(), newest.next()) {
            (Some(last), Some(previous)) if self.fast_rise => window.max(last.min(previous)),
            _ => window,
        };
        Some(Duration::from_nanos(observed))
    }

    /// The newest sample in the window.
    fn last_sample(&self) -> Option<Duration> {
        self.samples.newest().next().map(Duration::from_nanos)
    }

    fn target(&self) -> Duration {
        self.observed()
            .map_or(self.floor, |observed| observed.clamp(self.floor, self.cap))
    }

    fn reserve_for_proposal(&mut self, now: Instant) -> Duration {
        self.prune(now);
        self.applied = step_toward(self.applied, self.target(), NETWORK_RESERVE_MAX_STEP);
        self.applied
    }
    fn reserve(&self) -> Duration {
        self.applied
    }
}

/// An own proposal waiting for the block built on top of it.
#[derive(Clone, Copy, Debug)]
struct PendingProposal {
    key: ProposalKey,
    returned_at: Instant,
    window_opened_unix_ms: u64,
    returned_unix_ms: u64,
    return_budget: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_150_000;

    #[test]
    fn observed_build_multiplier_tracks_tail_cost() {
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(115), Duration::from_millis(100)),
            Some(DEFAULT_BUILD_TIME_MULTIPLIER_SCALED)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(100), Duration::from_millis(100)),
            Some(1_000_000)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(250), Duration::from_millis(100)),
            Some(MAX_BUILD_TIME_MULTIPLIER_SCALED)
        );
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(DEFAULT_BUILD_TIME_MULTIPLIER);
        let observed = tracker.observe(
            now,
            FinishedBuild {
                total_work: Duration::from_millis(250),
                work_at_tx_cutoff: Duration::from_millis(100),
                idle: Duration::ZERO,
            },
        );
        assert!(matches!(
            observed,
            Some(BuildSample::Ratio(MAX_BUILD_TIME_MULTIPLIER_SCALED))
        ));
        assert_eq!(tracker.multiplier_scaled(), 1_300_000);
    }

    #[test]
    fn build_multiplier_scales_decimal_values() {
        assert_eq!(
            scaled_build_time_multiplier(DEFAULT_BUILD_TIME_MULTIPLIER),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED
        );
    }
}
