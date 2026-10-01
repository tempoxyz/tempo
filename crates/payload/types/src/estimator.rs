//! Holistic proposal budget estimator shared by consensus and the payload builder.
//!
//! A block's wall-clock time is spent in three places that the proposer has to
//! reserve for before it stops adding transactions:
//!
//! 1. its own replayable build work, including the non-interruptible finish
//!    (state root, block assembly) that follows the transaction cutoff,
//! 2. the validators replaying the block through their execution layer,
//! 3. the network: shipping the proposal to a quorum and getting the next
//!    leader started on top of it.
//!
//! Marshal persistence is not part of the model: the marshal wrapper persists
//! a block concurrently with voting, so it gates finalization rather than the
//! next block. Each of the three was previously estimated in a different
//! place (a builder-local atomic, an actor-local sample window and a fixed CLI
//! constant). The [`Estimator`] owns all of them so that consensus and the
//! builder read one consistent picture, and so that the whole model can be
//! driven by a simulated block sequence in tests.
//!
//! The estimator is pure bookkeeping: callers feed observations through the
//! `on_*` hooks and take decisions through [`Estimator::start_proposal`] and
//! [`Estimator::build_plan`], passing the clock explicitly to both. Starting
//! a proposal also moves the network reservation one bounded step, so it is
//! called exactly once per own proposal; [`Estimator::snapshot`] reports the
//! reservation without moving it. Nothing in here touches wall-clock time on
//! its own.
//!
//! # Clocks
//!
//! The `now: Instant` arguments are a monotonic clock that is only used to
//! age state: it decides when a window sample, or an own proposal still
//! waiting for the block built on top of it, is too old to count. The reads
//! that depend on an age-limited window take it as well and drop expired
//! samples before they compute anything, so a window that stops receiving
//! samples does not keep serving old ones.
//!
//! The value of a network sample comes from a different clock: the wall-clock
//! unix milliseconds at which this node returned the proposal
//! (`returned_unix_ms`) and the header timestamp of the block built on top of
//! it (`child_timestamp_ms`), which the next leader sets. Both must be read
//! from the one clock that block header timestamps use, so a sample is only
//! as accurate as the validators' clock synchronisation; a monotonic
//! `Instant` cannot be compared across nodes.
//!
//! # Robustness
//!
//! Every learned quantity is a percentile over a bounded window of recent
//! samples. A single slow observation (a finish that waited on a persistence
//! commit, one proposal that was slow to reach the next leader) therefore
//! moves the percentile by at most one window slot instead of resetting it to
//! the outlier, while a sustained change still takes over within a fraction
//! of the window.
//!
//! The percentile itself can still jump: the 75th percentile of a window with
//! up to three samples is their maximum, and samples aging out can leave an
//! outlier behind. So neither estimate takes its percentile as is; each
//! follows it by at most one capped step at a time, in both directions. The
//! build multiplier moves by at most 0.15 per finished build and only rises
//! on a build that was itself slower than the multiplier, and then at most to
//! that build's own ratio, so a lone slow finish costs one step however long
//! it dominates a sparse window. The network reservation moves by at most
//! 100 ms per own proposal, also when fast rise lifts the target to the
//! recent samples (see [`EstimatorConfig::network_reserve_fast_rise`]), so
//! one bad sample costs the next proposal at most 100 ms of its window.
//!
//! The build time and network windows learn from this node's own proposals
//! only, which can be far apart, so they are bounded by both count and age:
//! 16 samples each, with a ttl long enough that the count is what binds on
//! the committee sizes Tempo runs with (up to ~34 validators for the build
//! time window, ~68 for the network window). The validation latency feedback
//! learns from every block this node verifies and is bounded by count alone:
//! the last 64 blocks, with no ttl, which turn over as long as the chain
//! makes progress.

use std::{
    collections::VecDeque,
    ops::{Add, Sub},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tracing::debug;

use crate::budget::{
    ValidationLatencyEstimate, ValidationLatencyEstimator, ValidationLatencyWorkload,
};

/// Target wall-clock time between blocks used when no configuration is given.
pub const DEFAULT_TARGET_BLOCK_TIME: Duration = Duration::from_millis(550);
/// Initial and minimum network reservation (proposal propagation plus votes).
pub const DEFAULT_NETWORK_BUDGET: Duration = Duration::from_millis(50);
/// Largest network reservation the estimator may learn on its own.
///
/// The cap bounds how much of the block time the chain's wait after a return
/// may claim before an operator has to look at the network rather than the
/// estimator. On the 10 validator, four region GCP benchmark with the shipped
/// sample (the unspent return budget subtracted, see the `NetworkTracker`
/// docs) the far-away (Asia) proposers settle at a reserve p50 of about 195
/// to 215 ms and touch 300 ms only on tails, so the cap leaves them their
/// learned reservation and only bounds the outliers.
///
/// The cap also bounds validator replay that the builder did not reserve
/// for: the builder caps its validator term at its own projected work, so
/// validator replay beyond the builder's work is learned as network time and
/// therefore bounded by this cap.
pub const DEFAULT_NETWORK_BUDGET_MAX: Duration = Duration::from_millis(300);
/// Percentile of recent network samples reserved when no configuration is given.
pub const DEFAULT_NETWORK_RESERVE_PERCENTILE: u8 = 75;
/// Initial estimate of total replayable build work divided by work at tx cutoff.
///
/// `1.15` means "when cutoff work is 100 ms, expect the completed replayable
/// build work to be about 115 ms". Measured finish work on a busy 10 validator
/// network is 5 to 10% of fill work; the previous default of 1.35 cost 10 to
/// 15% of every block's transactions before the first observation.
pub const DEFAULT_BUILD_TIME_MULTIPLIER: f64 = 1.15;
/// How far a proposal may run past its return budget and still count as
/// having met it, see [`ProposalBudget::unspent`].
///
/// This is the builder's pacing precision rather than a slow build: a build
/// whose pool runs dry idles until its budget in 1 ms polling steps and then
/// spends about 1 ms on an empty finish, so it returns a millisecond or two
/// after the budget. On a 10 validator benchmark 99.4% of the overruns
/// measured were at or below 5 ms, while real overruns under load were tens
/// of milliseconds.
pub const RETURN_BUDGET_OVERRUN_TOLERANCE: Duration = Duration::from_millis(5);

/// Fixed-point scale for build time multipliers.
pub const BUILD_TIME_MULTIPLIER_SCALE: u64 = 1_000_000;
/// Builder work never shrinks after the transaction cutoff.
const MIN_BUILD_TIME_MULTIPLIER_SCALED: u64 = BUILD_TIME_MULTIPLIER_SCALE;
/// Finish work larger than 70% of fill work is treated as an outlier.
///
/// This is also the largest initial multiplier a configuration may set, see
/// [`EstimatorConfig::validate`]: the multiplier is only ever learned below
/// it, so a larger initial value would not be the one in use.
const MAX_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_700_000;
/// Largest change of the multiplier, up or down, that a single finished
/// build may cause.
///
/// One slow finish, typically a state root that waited on a persistence
/// commit, used to jump the multiplier straight to its cap and cost the next
/// eight proposals 20 to 30% of their transactions. Limiting the step to 0.15
/// per observation keeps a lone outlier at a one-off cost while a sustained
/// slowdown still reaches the cap: after four builds from an empty window,
/// and after nine from a full window of fast builds, whose p75 only turns
/// with the fifth slow build. The same bound applies on the way down: when
/// the window turns from slow builds to fast ones, dropping from the cap to
/// 1.0 in one build would let the next proposal do 70% more work before its
/// cutoff while the network reservation still reflects the smaller blocks of
/// the slow period. Stepping down takes five builds from the cap instead.
const BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED: u64 = 150_000;
/// Number of finished builds the multiplier is derived from.
const BUILD_TIME_SAMPLE_WINDOW: usize = 16;
/// Finished builds older than this no longer influence the multiplier.
///
/// The arithmetic of [`NETWORK_SAMPLE_TTL`] applies with half the time: five
/// minutes hold the full 16 builds for committees of up to ~34 validators.
/// Beyond that the window holds fewer builds, which costs little, since the
/// multiplier only needs to forget builds from before a quiet period and
/// follows its window by bounded steps anyway.
const BUILD_TIME_SAMPLE_TTL: Duration = Duration::from_secs(5 * 60);

/// Number of own proposals the network reservation is derived from.
const NETWORK_SAMPLE_WINDOW: usize = 16;
/// Network observations older than this are dropped.
///
/// The ttl only exists so that a node that stopped proposing does not keep
/// stale samples. It must not be what limits the window under normal
/// operation: a percentile over a handful of samples is the worst of them.
/// With N validators and 550 ms blocks an own proposal completes every
/// ~0.55 N s, so ten minutes hold the full 16 samples for committees of up
/// to ~68 validators.
const NETWORK_SAMPLE_TTL: Duration = Duration::from_secs(10 * 60);
/// Network samples longer than this are discarded as clock skew or a stall
/// unrelated to propagation.
const MAX_NETWORK_SAMPLE: Duration = Duration::from_secs(5);
/// Largest difference between the network reservations of two consecutive
/// own proposals.
///
/// It bounds how much the reservation used for one own proposal may differ
/// from the previous one's, regardless of how the window moved in between: a
/// sparse window whose percentile is its maximum, good samples aging out, an
/// outlier, or fast rise lifting the target to the recent samples. A sample
/// carries more than propagation: the successor's clock offset and any stall
/// on the successor before it builds. Without a bound one such sample moves
/// the reservation straight to its cap and halves the next own proposal's
/// window. Measured exceedances of the reservation are small (p90 39 ms on a
/// 10 validator, four region benchmark, from a run with a 320 ms cap that
/// predates this step and the unspent-budget sample), so with 100 ms one bad
/// sample costs the next proposal at most 100 ms, while a sustained change
/// still gets through in a few proposals.
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

/// Percentile used for the build time reservation: the 75th.
///
/// The median ignores too much of the tail for a reservation, the 90th
/// percentile of a 16 sample window is a single observation again. The
/// network reservation defaults to the same percentile but is configurable,
/// see [`EstimatorConfig::network_reserve_percentile`].
const BUILD_TIME_RESERVE_PERCENTILE: u8 = 75;

/// Identifies a proposal by its own round as `(epoch, view)`: the epoch and
/// the view in which the proposal itself was made, not those of its parent
/// or of the block built on top of it.
pub type ProposalKey = (u64, u64);

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
    /// The percentile pins a statistic of this node's own block times. A
    /// sample is this node's block time minus its proposal window, so about
    /// this share of its own blocks finish at or under `target_block_time`,
    /// and their median lands below it by the window's spread from its
    /// median to this percentile: 40 to 80 ms per node on the 10 validator
    /// benchmark. A median at the target takes 50 with fast rise off.
    ///
    /// A higher percentile leaves fewer proposals whose network time exceeds
    /// the reservation, at the cost of a smaller return budget and therefore
    /// smaller blocks. The reservation stays clamped between `network_budget`
    /// and `network_budget_max`.
    pub network_reserve_percentile: u8,
    /// Let the two most recent network samples lift the reservation above
    /// the window percentile. On by default.
    ///
    /// The percentile over the last 16 own proposals lags a network that is
    /// getting slower, for example while blocks grow, so the proposals made
    /// during the rise exceed their reservation far more often than the
    /// percentile implies. Fast rise makes the smaller of the two most recent
    /// samples the reservation's target when that is above the percentile,
    /// and the very next proposal starts following it: like every change of
    /// the reservation by at most 100 ms per own proposal, and still clamped
    /// to `network_budget_max`. It takes two slow samples in a row because
    /// leaders are drawn per view: each own proposal's successor is an
    /// independent draw, so one far successor says nothing about the next,
    /// and lifting the target to a single sample chased that noise. It decays
    /// through the window: the next faster sample hands the target back to
    /// the percentile.
    ///
    /// On a 10 validator, four region benchmark lifting the target to the
    /// most recent sample alone cut the share of proposals whose network
    /// time exceeds the reservation from 43% to 37% without costing
    /// throughput. That run also raised the cap from 250 to 320 ms, and it
    /// predates both the unspent-budget sample and the per-proposal step.
    pub network_reserve_fast_rise: bool,
    /// Initial ratio of total replayable build work over work at tx cutoff.
    ///
    /// Between 1.0 and 1.7, the range the multiplier is learned in.
    pub build_time_multiplier: f64,
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
        .with_network_budget_max(Self::default_network_budget_max(
            target_block_time,
            network_budget,
        ))
    }

    /// The network reservation cap used when none is configured.
    ///
    /// The learned reservation may take at most half of the initial proposal
    /// window `target_block_time - network_budget`, never more than
    /// [`DEFAULT_NETWORK_BUDGET_MAX`], and never less than the floor: a cap
    /// equal to the floor is a fixed reservation. Rounding the half window
    /// down keeps the cap below the target whenever the floor is.
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

    /// Sets whether the two most recent network samples may lift the
    /// reservation above the window percentile.
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
        // The multiplier is never learned above its cap, so a larger initial
        // value would silently run at the cap while the configuration claims
        // otherwise.
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

    /// The proposal return budget before any network learning: the target
    /// block time minus the configured network budget.
    pub fn initial_proposal_return_budget(&self) -> Duration {
        self.target_block_time.saturating_sub(self.network_budget)
    }
}

/// The shared proposal budget estimator; the module documentation describes
/// the model.
///
/// This is a cheap handle: clones share one configuration and one set of
/// observations, so consensus and the payload builder each keep a clone and
/// read and feed the same picture.
#[derive(Clone, Debug)]
pub struct Estimator {
    inner: Arc<EstimatorInner>,
}

/// What all clones of one [`Estimator`] share.
#[derive(Debug)]
struct EstimatorInner {
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
            inner: Arc::new(EstimatorInner {
                config,
                state: Mutex::new(State {
                    validation: ValidationLatencyEstimator::default(),
                    build_time: BuildTimeTracker::new(config.build_time_multiplier),
                    network: NetworkTracker::new(&config),
                }),
            }),
        }
    }

    /// The configuration this estimator was created with.
    pub fn config(&self) -> EstimatorConfig {
        self.inner.config
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // The state is plain data; a poisoned lock only means another thread
        // panicked mid-update, and the samples stay usable.
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Locks the state for a read at `now`.
    ///
    /// The windows otherwise only drop expired samples when a hook runs, so
    /// a read after a quiet period would still see samples older than their
    /// ttl. Pruning first makes every read reflect `now`.
    fn state_at(&self, now: Instant) -> std::sync::MutexGuard<'_, State> {
        let mut state = self.state();
        state.prune(now);
        state
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

    /// Records that this node returned a proposal to consensus, opening the
    /// network sample that the block built on top of it completes through
    /// [`Self::on_child_block_built`].
    ///
    /// `unspent_return_budget` is what the proposal return budget had left
    /// at the return, which is what it reserved for the validators' replay
    /// of the block; the sample is the chain's wait beyond it. Take it from
    /// [`ProposalBudget::unspent`]: a proposal for which that returns `None`
    /// overran its return budget and must not be recorded at all, see the
    /// `NetworkTracker` docs. `returned_unix_ms` must come from the same
    /// clock that block header timestamps use.
    pub fn on_proposal_returned(
        &self,
        now: Instant,
        returned_unix_ms: u64,
        key: ProposalKey,
        unspent_return_budget: Duration,
    ) {
        self.state()
            .network
            .proposal_returned(now, returned_unix_ms, key, unspent_return_budget);
    }

    /// Records the header timestamp of a block built on top of `parent`,
    /// completing the network sample that [`Self::on_proposal_returned`]
    /// opened for it.
    ///
    /// `parent` is the child's `(epoch, parent_view)` from its consensus
    /// context. Only proposals this node returned itself produce a sample;
    /// other parents are ignored, so this can be fed every block the node
    /// verifies or builds, and it must be fed the node's own builds too,
    /// since consensus does not run `verify()` for a node's own proposal.
    /// Feed it only children that passed every check before the vote, so
    /// that an invalid child, a rejected boundary outcome or a failed build
    /// never becomes a sample. The `NetworkTracker` docs list the children
    /// that take no sample.
    ///
    /// The sample moves the target of the network reservation; the
    /// reservation itself only follows it with the next own proposal, see
    /// [`Self::start_proposal`].
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
                "updated network reservation"
            );
        }
    }

    // --- own proposals ----------------------------------------------------

    /// Starts an own proposal at `now`: moves the network reservation one
    /// bounded step toward its target and returns the proposal window.
    ///
    /// This is the one call that changes the estimator without an
    /// observation, so it must be made exactly once per own proposal: every
    /// call moves the reservation from the one the previous own proposal
    /// used toward what the window currently implies, by at most 100 ms, see
    /// the `NetworkTracker` docs. A proposal whose build fails afterwards has
    /// still taken its step. [`Self::snapshot`] reports the reservation
    /// without moving it.
    ///
    /// Network samples older than the window's ttl no longer count, also
    /// when no newer sample arrived since: a node that has not completed a
    /// proposal for that long walks its reservation back down to the
    /// configured network budget, one step per own proposal.
    #[must_use]
    pub fn start_proposal(&self, now: Instant) -> ProposalBudget {
        let network_reserve = self.state().network.reserve_for_proposal(now);
        ProposalBudget::new(self.inner.config.target_block_time, network_reserve)
    }

    // --- reads ------------------------------------------------------------

    /// The current validation latency estimate, if any block was validated.
    pub fn validation_latency_estimate(&self) -> Option<ValidationLatencyEstimate> {
        self.state().validation.estimate()
    }

    /// The build time multiplier in use at `now`.
    ///
    /// Only finished builds move it. Builds that expire while newer ones are
    /// left do not change it on their own; the next finished build steps it
    /// toward what is left. Once every finished build is older than the
    /// window's ttl, for example after a quiet period without own proposals,
    /// this is the configured initial multiplier again.
    pub fn build_time_multiplier(&self, now: Instant) -> f64 {
        self.state_at(now).build_time.scaled() as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64
    }

    /// Snapshots the inputs for one payload build that starts at `now`.
    pub fn build_plan(&self, now: Instant, build_budget: Duration) -> BuildPlan {
        let state = self.state_at(now);
        BuildPlan {
            build_budget,
            multiplier_scaled: state.build_time.scaled(),
            validation_latency: state.validation.estimate(),
        }
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
            build_time_multiplier: state.build_time.scaled() as f64
                / BUILD_TIME_MULTIPLIER_SCALE as f64,
            build_time_samples: state.build_time.samples.len(),
            network_observed: state.network.observed(),
            network_last_sample: state.network.last_sample(),
            network_reserve: budget.network_reserve,
            network_samples: state.network.samples.len(),
            pending_proposals: state.network.pending.len(),
            proposal_return_budget: budget.return_budget,
        }
    }
}

/// Converts a human-readable build-work multiplier into the fixed-point
/// representation, within the range the multiplier is learned in.
///
/// Configurations are validated before they reach this, see
/// [`EstimatorConfig::validate`], so the mapping of values outside that
/// range only guards embedders that pass an unvalidated multiplier: a
/// non-finite one maps to 1.0, and the result is clamped to 1.0 to 1.7.
pub fn scaled_build_time_multiplier(multiplier: f64) -> u64 {
    if !multiplier.is_finite() {
        return MIN_BUILD_TIME_MULTIPLIER_SCALED;
    }
    // The float to integer cast saturates, so a negative multiplier becomes
    // zero and is clamped up like any other value below 1.0.
    ((multiplier * BUILD_TIME_MULTIPLIER_SCALE as f64).round() as u64).clamp(
        MIN_BUILD_TIME_MULTIPLIER_SCALED,
        MAX_BUILD_TIME_MULTIPLIER_SCALED,
    )
}

fn scaled_duration(elapsed: Duration, multiplier: u64) -> Duration {
    Duration::from_nanos(
        (elapsed.as_nanos().saturating_mul(u128::from(multiplier))
            / u128::from(BUILD_TIME_MULTIPLIER_SCALE))
        .min(u128::from(u64::MAX)) as u64,
    )
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
    /// Time reserved for the chain's wait after the proposal is returned,
    /// beyond what the return budget leaves for the validators' replay.
    pub network_reserve: Duration,
    /// Local proposal return budget: `target_block_time - network_reserve`.
    pub return_budget: Duration,
}

impl ProposalBudget {
    /// The proposal window that `network_reserve` leaves of `target_block_time`.
    pub fn new(target_block_time: Duration, network_reserve: Duration) -> Self {
        Self {
            target_block_time,
            network_reserve,
            return_budget: target_block_time.saturating_sub(network_reserve),
        }
    }

    /// What the return budget has left for the validators' replay when the
    /// proposal returns `spent` after its start, or `None` if it overran the
    /// budget.
    ///
    /// A proposal that spent at most [`RETURN_BUDGET_OVERRUN_TOLERANCE`] more
    /// than its return budget counts as having met it, with nothing left. A
    /// proposal that spent more overran it and takes no network sample, see
    /// [`Estimator::on_proposal_returned`].
    pub fn unspent(&self, spent: Duration) -> Option<Duration> {
        let tolerated = self
            .return_budget
            .saturating_add(RETURN_BUDGET_OVERRUN_TOLERANCE);
        (spent <= tolerated).then(|| self.return_budget.saturating_sub(spent))
    }
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
    validation_latency: Option<ValidationLatencyEstimate>,
}

/// Breakdown of the time a build must still reserve at a given moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadBudgetDecision {
    /// Replayable proposer work projected from the work done so far.
    pub predicted_builder_work: Duration,
    /// Validator replay work, from feedback when available.
    pub predicted_validator_work: Duration,
    /// Everything the proposal still needs: idle, builder and validator work.
    pub total_reserved: Duration,
}

impl BuildPlan {
    /// Creates a plan from explicit estimates.
    pub fn new(
        build_budget: Duration,
        build_time_multiplier: f64,
        validation_latency: Option<ValidationLatencyEstimate>,
    ) -> Self {
        Self {
            build_budget,
            multiplier_scaled: scaled_build_time_multiplier(build_time_multiplier),
            validation_latency,
        }
    }

    /// The build time multiplier in use.
    pub fn build_time_multiplier(&self) -> f64 {
        self.multiplier_scaled as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64
    }

    /// The validation latency estimate in use.
    pub fn validation_latency(&self) -> Option<ValidationLatencyEstimate> {
        self.validation_latency
    }

    /// Computes what the proposal still has to reserve.
    ///
    /// `elapsed` is wall-clock time spent in the builder so far. `idle_elapsed`
    /// is the proposer-only time spent waiting for more transactions, which
    /// validators do not replay and therefore counts once. Builder work is
    /// projected from the current build and validator work uses feedback from
    /// previously validated blocks, capped at that projection.
    pub fn decision(
        &self,
        elapsed: Duration,
        idle_elapsed: Duration,
        current_workload: ValidationLatencyWorkload,
    ) -> PayloadBudgetDecision {
        let work_elapsed = elapsed.saturating_sub(idle_elapsed);
        let predicted_builder_work = scaled_duration(work_elapsed, self.multiplier_scaled);
        let predicted_validator_work = self
            .validation_latency
            .and_then(|estimate| estimate.estimate(current_workload))
            .map(|estimate| estimate.min(predicted_builder_work))
            .unwrap_or(predicted_builder_work);
        let total_reserved = idle_elapsed
            .saturating_add(predicted_builder_work)
            .saturating_add(predicted_validator_work);
        PayloadBudgetDecision {
            predicted_builder_work,
            predicted_validator_work,
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
    /// Build time multiplier in use.
    pub build_time_multiplier: f64,
    /// Number of finished builds in the window.
    pub build_time_samples: usize,
    /// Learned network time before clamping, if the window holds a completed
    /// proposal: the window percentile, lifted under fast rise to the smaller
    /// of the two most recent samples when that is higher.
    ///
    /// Clamped to the floor and cap, this is what the reservation moves
    /// toward with each own proposal.
    pub network_observed: Option<Duration>,
    /// Newest network sample in the window, which expires with it.
    ///
    /// With [`EstimatorConfig::network_reserve_fast_rise`] it and the sample
    /// before it may together lift the reservation, bounded by the
    /// per-proposal step and the configured cap.
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

    fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The samples' values from the most recent to the oldest.
    fn newest(&self) -> impl Iterator<Item = T> + '_ {
        self.samples.iter().rev().map(|(_, value)| *value)
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

/// Moves `current` toward `target` by at most `max_step`, in either
/// direction.
///
/// Both learned estimates follow their window's percentile through this
/// instead of taking it as is, because the percentile can jump: that of a
/// sparse window can be its maximum, and samples aging out can leave an
/// outlier behind.
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
#[derive(Clone, Debug)]
struct BuildTimeTracker {
    samples: SampleWindow<u64>,
    /// Configured initial multiplier in fixed point, in use while the window
    /// is empty.
    initial: u64,
    /// Current multiplier in fixed point.
    ///
    /// Only finished builds move it, toward the window's percentile and by
    /// at most [`BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED`] per build in either
    /// direction, and only a build that was itself slower than the
    /// multiplier may raise it, at most to that build's own ratio, see
    /// [`Self::observe`]. The one change without a build is the return to
    /// `initial` once the window is empty, see [`Self::prune`].
    current: u64,
}

impl BuildTimeTracker {
    /// Starts at the configured initial multiplier.
    ///
    /// [`scaled_build_time_multiplier`] keeps it within the range the
    /// multiplier is learned in. That is defensive:
    /// [`EstimatorConfig::validate`] rejects initial values outside it.
    fn new(initial: f64) -> Self {
        let initial = scaled_build_time_multiplier(initial);
        Self {
            samples: SampleWindow::new(BUILD_TIME_SAMPLE_WINDOW, BUILD_TIME_SAMPLE_TTL),
            initial,
            current: initial,
        }
    }

    /// Drops finished builds older than the window's ttl.
    ///
    /// Expired builds do not move the multiplier while newer ones are left:
    /// the next finished build steps it toward the percentile of what is
    /// left, one capped step at a time like any other change of the window.
    /// Lowering it here would let a read after a partial expiry skip that
    /// bounded recovery. Once no build is left, for example after a quiet
    /// period without own proposals, it is back at the configured initial
    /// value, so the first build afterwards starts from the same estimate as
    /// the first build after startup rather than from a stale one.
    fn prune(&mut self, now: Instant) {
        self.samples.prune(now);
        if self.samples.is_empty() {
            self.current = self.initial;
        }
    }

    /// The reserved percentile of the window, if it holds any build.
    fn target(&self) -> Option<u64> {
        self.samples.percentile(BUILD_TIME_RESERVE_PERCENTILE)
    }

    /// Records a finished build. Returns the observed multiplier, if usable.
    ///
    /// The multiplier then takes at most one capped step toward the window's
    /// percentile. A step up needs corroboration from the build itself: only
    /// a build whose own ratio is above the multiplier may raise it, and at
    /// most to that ratio. The percentile of a sparse window is its slowest
    /// build, so without the first condition one slow finish followed by
    /// fast ones raised the multiplier with every build until the window held
    /// four of them, instead of the one step a lone outlier is meant to cost.
    /// Without the second, a build barely slower than the multiplier still
    /// took a full step toward the outlier the percentile held on to. A step
    /// down needs no corroboration, only the percentile below the
    /// multiplier, and is bounded the same way, see
    /// [`BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED`].
    fn observe(
        &mut self,
        now: Instant,
        work_at_tx_cutoff: Duration,
        total_work: Duration,
    ) -> Option<u64> {
        self.prune(now);
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

        let percentile = self
            .target()
            .expect("the window holds the build just pushed");
        let target = if observed > self.current {
            percentile.min(observed)
        } else {
            percentile.min(self.current)
        };
        self.current = step_toward(self.current, target, BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED);
        Some(observed)
    }

    fn scaled(&self) -> u64 {
        self.current
    }
}

/// Learns how long the chain waits for a proposal after this node returned
/// it, beyond what the proposal return budget already left for the
/// validators' replay of the block.
///
/// The sample is `child header timestamp - own return - unspent return
/// budget`, where the child is the block built on top of the proposal. It is
/// an identity rather than a decomposition of the wait: this node stamps its
/// own header as it starts the proposal and returns it `spent` later, and
/// the unspent return budget is `return budget - spent`, so the sample
/// equals this node's own block time (the child's header timestamp minus its
/// own) minus its proposal window. The next own proposal's window is
/// `target - reserve`, so reserving the p-th percentile of recent samples
/// makes the p-th percentile of this node's own block times meet the target,
/// without a model of how long validation or propagation takes.
///
/// Physically, the next leader stamps its header at `build()` entry, which
/// it reaches once it has entered its view: that takes a notarization of the
/// proposal and its own certification of it. Under deferred verification the
/// peers notarize on receipt and the certification waits for the next
/// leader's own replay of the block, so the gap after the return is
/// propagation, the longer of the vote leg and that replay, and the parent
/// fetch; under inline verification it includes the peers' execution before
/// they vote. The builder caps its validator term at its own projected work,
/// so validator replay beyond the builder's work is learned here as network
/// time, and therefore bounded by the cap.
///
/// Measuring the notarization at the proposer instead would add the vote leg
/// back to the proposer, which the chain never waits for unless the proposer
/// is also the next leader; on a ten validator network with two far-away
/// proposers that over-reserved by roughly 90 ms for them.
///
/// The window gives the reservation a target: the configured percentile of
/// the window, lifted under fast rise to the smaller of the two most recent
/// samples when that is higher, and clamped between the floor and the cap;
/// an empty window's target is the floor. Fast rise takes the smaller of the
/// two because the leader after each own proposal is an independent draw:
/// one slow sample may be a single far successor, two in a row corroborate a
/// slower network. With fewer than two samples it lifts nothing, since a
/// lone sample is the percentile anyway. The reservation an own proposal
/// uses is the previous own proposal's, moved toward the target by at most
/// [`NETWORK_RESERVE_MAX_STEP`] in either direction, see
/// [`Self::reserve_for_proposal`]. So one slow sample costs the next own
/// proposal a bounded share of its window, while a sustained rise still
/// reaches the cap within a few proposals.
///
/// The step bound is also the policy for sparse windows and expiry, which
/// need no rule of their own. Above the median, the percentile of one or two
/// samples is their maximum (of up to three for the default 75th percentile),
/// and good samples aging out can leave an outlier behind, so the target may
/// jump; that is acceptable because the step, not the percentile, decides how
/// fast the reservation follows. Likewise a node that stops completing
/// proposals sees its samples expire and its target drop to the floor, and
/// walks its reservation back down one step per own proposal.
///
/// # Proposals that take no sample
///
/// - A proposal whose child never arrives: its view was nullified, or the
///   next leader held both a notarization and a nullification for the view
///   and built on an ancestor. It ages out of the pending list: the first
///   proposal recorded more than [`PENDING_PROPOSAL_TTL`] after it drops it,
///   and [`MAX_PENDING_PROPOSALS`] newer ones push it out earlier.
/// - A child whose view does not directly follow the proposal's: the chain
///   waited on a leader timeout, not on propagation.
/// - A proposal at an epoch boundary. Pending proposals are keyed by their
///   own [`ProposalKey`] and children are matched by `(epoch, parent_view)`;
///   the first block of an epoch refers to the re-proposed boundary block by
///   its view in the new epoch, so it never matches. That is intended: the
///   gap spans the epoch transition.
/// - A child more than [`MAX_NETWORK_SAMPLE`] after the return, which is
///   clock skew or a stall unrelated to propagation.
/// - A proposal that overran its return budget by more than
///   [`RETURN_BUDGET_OVERRUN_TOLERANCE`], which the caller does not record,
///   see [`ProposalBudget::unspent`]. Its gap lacks the unspent replay
///   reserve that normal samples subtract, so its sample would sit above its
///   neighbours by that reserve; the overrun is the build time multiplier's
///   to absorb. A proposal within the tolerance is recorded with nothing
///   unspent: that is the builder's pacing precision on an idle build, which
///   reserves next to nothing for replay anyway.
///
/// Consecutive own proposals under deferred verification do take a sample,
/// but their gap contains no execution (peers notarize on receipt, and the
/// parent is already executed locally), so it lands near the floor and the
/// percentile discards it.
#[derive(Clone, Debug)]
struct NetworkTracker {
    /// Completed own proposals. The newest two also drive fast rise, and
    /// they expire with the rest of the window.
    samples: SampleWindow<u64>,
    pending: VecDeque<PendingProposal>,
    floor: Duration,
    cap: Duration,
    /// Percentile of the window that is reserved.
    percentile: u8,
    /// Whether the two most recent samples lift the target above the window
    /// percentile.
    fast_rise: bool,
    /// The reservation the most recent own proposal used, the floor before
    /// the first one.
    ///
    /// Only [`Self::reserve_for_proposal`] moves it, so reads for logs and
    /// metrics report it without advancing it.
    applied: Duration,
}

impl NetworkTracker {
    fn new(config: &EstimatorConfig) -> Self {
        Self {
            samples: SampleWindow::new(NETWORK_SAMPLE_WINDOW, NETWORK_SAMPLE_TTL),
            pending: VecDeque::with_capacity(MAX_PENDING_PROPOSALS),
            floor: config.network_budget,
            cap: config.network_budget_max.max(config.network_budget),
            percentile: config.network_reserve_percentile.clamp(
                MIN_NETWORK_RESERVE_PERCENTILE,
                MAX_NETWORK_RESERVE_PERCENTILE,
            ),
            fast_rise: config.network_reserve_fast_rise,
            applied: config.network_budget,
        }
    }

    /// Drops samples older than the window's ttl, the newest ones that fast
    /// rise reads included, so that reads between samples never serve
    /// expired ones.
    ///
    /// This only changes the target; the reservation follows it with the
    /// next own proposal.
    fn prune(&mut self, now: Instant) {
        self.samples.prune(now);
        self.pending.retain(|pending| {
            now.saturating_duration_since(pending.returned_at) <= PENDING_PROPOSAL_TTL
        });
    }

    fn proposal_returned(
        &mut self,
        now: Instant,
        returned_unix_ms: u64,
        key: ProposalKey,
        unspent_return_budget: Duration,
    ) {
        self.prune(now);
        self.pending.retain(|pending| pending.key != key);
        if self.pending.len() == MAX_PENDING_PROPOSALS {
            self.pending.pop_front();
        }
        self.pending.push_back(PendingProposal {
            key,
            returned_at: now,
            returned_unix_ms,
            unspent_return_budget,
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
        self.prune(now);
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
        let network = elapsed.saturating_sub(pending.unspent_return_budget);
        self.samples
            .push(now, network.as_nanos().min(u128::from(u64::MAX)) as u64);
        Some(network)
    }

    /// Unclamped learned network time, if the window holds a completed
    /// proposal: the configured percentile of the window, lifted under fast
    /// rise to the smaller of the two most recent samples when that is
    /// higher. The lift needs no bound of its own, since the reservation
    /// follows this by at most [`NETWORK_RESERVE_MAX_STEP`] per own proposal.
    /// Callers prune first, see [`Self::prune`], so that expired samples no
    /// longer count.
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

    /// What the reservation moves toward: the observed network time clamped
    /// between the floor and the cap, or the floor while the window holds no
    /// completed proposal.
    fn target(&self) -> Duration {
        self.observed()
            .map_or(self.floor, |observed| observed.clamp(self.floor, self.cap))
    }

    /// The reservation for an own proposal made at `now`: the previous own
    /// proposal's, moved toward [`Self::target`] by at most
    /// [`NETWORK_RESERVE_MAX_STEP`].
    ///
    /// Every call takes one step, so call it once per own proposal.
    fn reserve_for_proposal(&mut self, now: Instant) -> Duration {
        self.prune(now);
        self.applied = step_toward(self.applied, self.target(), NETWORK_RESERVE_MAX_STEP);
        self.applied
    }

    /// The reservation the most recent own proposal used, without moving it.
    fn reserve(&self) -> Duration {
        self.applied
    }
}

/// An own proposal waiting for the block built on top of it.
#[derive(Clone, Copy, Debug)]
struct PendingProposal {
    key: ProposalKey,
    returned_at: Instant,
    /// Wall-clock time of the return, on the same clock the child block's
    /// header timestamp is taken from.
    returned_unix_ms: u64,
    /// What the return budget had left at the return; the chain's wait
    /// beyond it is the sample.
    unspent_return_budget: Duration,
}

#[derive(Debug)]
struct State {
    validation: ValidationLatencyEstimator,
    build_time: BuildTimeTracker,
    network: NetworkTracker,
}

impl State {
    /// Drops expired samples from every window that has a ttl. The
    /// validation latency feedback is bounded by count alone and has nothing
    /// to expire.
    fn prune(&mut self, now: Instant) {
        self.build_time.prune(now);
        self.network.prune(now);
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

    /// Starts an own proposal at `at`, once as `build()` does, and returns
    /// the network reservation it uses.
    fn reserve_at(estimator: &Estimator, at: Instant) -> Duration {
        estimator.start_proposal(at).network_reserve
    }

    /// Plays one own proposal in `view`, returned `view` seconds after
    /// `start`, whose child is built `network` later, and returns when the
    /// child was built. With no unspent return budget the whole gap is the
    /// network sample. The proposal is not started here: tests that follow
    /// the reservation start it themselves, once per own proposal, as
    /// `build()` does.
    fn own_proposal(
        estimator: &Estimator,
        start: Instant,
        view: u64,
        network: Duration,
    ) -> Instant {
        let returned = start + Duration::from_secs(view);
        let returned_ms = 1_800_000_000_000 + view * 1000;
        estimator.on_proposal_returned(returned, returned_ms, (0, view), Duration::ZERO);
        let built = returned + network;
        estimator.on_child_block_built(
            built,
            (0, view),
            view + 1,
            returned_ms + network.as_millis() as u64,
        );
        built
    }

    fn validation_latency_estimate(
        workload: ValidationLatencyWorkload,
        elapsed: Duration,
    ) -> Option<ValidationLatencyEstimate> {
        let mut estimator = ValidationLatencyEstimator::default();
        estimator.observe(1, workload, elapsed);
        estimator.estimate()
    }

    /// A multiplier in thousandths, which is exact for every value these
    /// tests produce and prints readably when a trace differs.
    fn permille(multiplier: f64) -> u64 {
        (multiplier * 1000.0).round() as u64
    }

    /// Records a finished build whose total work is `ratio_permille`
    /// thousandths of its 200 ms of work at the transaction cutoff, and
    /// returns the multiplier in use afterwards, in thousandths.
    fn finish_build(estimator: &Estimator, at: Instant, ratio_permille: u64) -> u64 {
        estimator.on_build_finished(
            at,
            FinishedBuild {
                work_at_tx_cutoff: ms(200),
                total_work: ms(200 * ratio_permille / 1000),
            },
        );
        permille(estimator.build_time_multiplier(at))
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
        // The cap defaults to 300 ms; a floor above it lifts the cap with it.
        assert_eq!(config().network_budget_max, ms(300));
        assert_eq!(
            EstimatorConfig::new(ms(550), ms(320)).network_budget_max,
            ms(320)
        );
        // A shorter target leaves the reservation half of its initial window
        // above the floor, here 50 ms + 450 ms / 2, when that is below 300 ms.
        assert_eq!(
            EstimatorConfig::new(ms(500), ms(50)).network_budget_max,
            ms(275)
        );
    }

    #[test]
    fn config_validation_bounds_the_network_reserve_percentile() {
        assert_eq!(config().network_reserve_percentile, 75);
        assert!(config().network_reserve_fast_rise);
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
    fn config_validation_bounds_the_build_time_multiplier() {
        for multiplier in [1.0, DEFAULT_BUILD_TIME_MULTIPLIER, 1.7] {
            assert!(
                config()
                    .with_build_time_multiplier(multiplier)
                    .validate()
                    .is_ok(),
                "multiplier {multiplier} must be accepted"
            );
        }
        // The multiplier is only learned up to 1.7, so a larger initial value
        // would run at 1.7 while the configuration claims otherwise.
        let too_large = config().with_build_time_multiplier(2.0);
        let err = too_large.validate().unwrap_err();
        assert!(err.contains("at most 1.7"), "{err}");
        // An estimator built from the unvalidated configuration anyway still
        // stays within the range it learns in.
        let estimator = Estimator::new(too_large);
        assert_eq!(
            permille(estimator.build_time_multiplier(Instant::now())),
            1700
        );
    }

    #[test]
    fn fixed_config_pins_the_return_budget() {
        let estimator = Estimator::new(EstimatorConfig::fixed(ms(300), ms(50)));
        let now = Instant::now();
        let built = now + ms(400);
        estimator.on_proposal_returned(now, 1_000_000, (0, 1), Duration::ZERO);
        estimator.on_child_block_built(built, (0, 1), 2, 1_000_400);
        assert_eq!(estimator.snapshot(built).network_samples, 1);
        // The next own proposal keeps the pinned window although the sample
        // is far above the floor.
        let budget = estimator.start_proposal(built);
        assert_eq!(budget.return_budget, ms(300));
        assert_eq!(budget.network_reserve, ms(50));
    }

    #[test]
    fn proposal_budget_tolerates_the_builders_pacing_precision() {
        let budget = ProposalBudget::new(ms(550), ms(150));
        assert_eq!(budget.return_budget, ms(400));
        // Inside the budget, what is left is the validators' replay reserve.
        assert_eq!(budget.unspent(ms(230)), Some(ms(170)));
        assert_eq!(budget.unspent(ms(400)), Some(Duration::ZERO));
        // An idle build that returns a few milliseconds late met its budget,
        // with nothing left.
        assert_eq!(budget.unspent(ms(402)), Some(Duration::ZERO));
        assert_eq!(
            budget.unspent(ms(400) + RETURN_BUDGET_OVERRUN_TOLERANCE),
            Some(Duration::ZERO)
        );
        // Beyond the tolerance the proposal overran its budget.
        assert_eq!(
            budget.unspent(ms(400) + RETURN_BUDGET_OVERRUN_TOLERANCE + Duration::from_micros(1)),
            None
        );
        assert_eq!(budget.unspent(ms(459)), None);
    }

    #[test]
    fn scaled_build_time_multiplier_stays_within_the_learned_range() {
        assert_eq!(scaled_build_time_multiplier(1.15), 1_150_000);
        // Configurations are validated before they get here; an embedder's
        // unvalidated value still maps into the range instead of panicking.
        for (multiplier, scaled) in [
            (f64::NAN, 1_000_000),
            (f64::INFINITY, 1_000_000),
            (f64::NEG_INFINITY, 1_000_000),
            (-1.0, 1_000_000),
            (0.5, 1_000_000),
            (2.0, 1_700_000),
        ] {
            assert_eq!(
                scaled_build_time_multiplier(multiplier),
                scaled,
                "{multiplier}"
            );
        }
    }

    #[test]
    fn sample_window_percentile_and_expiry() {
        let now = Instant::now();
        let mut window = SampleWindow::new(4, ms(100));
        assert_eq!(window.percentile(75), None);
        for (offset, value) in [(0u64, 10u64), (10, 30), (20, 20), (30, 40)] {
            window.push(now + ms(offset), value);
        }
        assert_eq!(window.percentile(50), Some(20));
        assert_eq!(window.percentile(75), Some(30));
        assert_eq!(window.percentile(100), Some(40));
        // Capacity evicts the oldest sample.
        window.push(now + ms(40), 50);
        assert_eq!(window.len(), 4);
        assert_eq!(window.percentile(25), Some(20));
        // Age evicts everything older than the ttl: only the sample pushed
        // at +40 ms survives a push at +135 ms.
        window.push(now + ms(135), 60);
        assert_eq!(window.len(), 2);
        assert_eq!(window.percentile(50), Some(50));
    }

    #[test]
    fn build_time_multiplier_rises_in_capped_steps_and_follows_the_window_down() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        assert!(
            (estimator.build_time_multiplier(now) - DEFAULT_BUILD_TIME_MULTIPLIER).abs() < 1e-9
        );

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
        assert!((estimator.build_time_multiplier(now + ms(7)) - 1.05).abs() < 1e-6);

        // One finish waits 150 ms on a persistence commit: ratio 1.75, capped at 1.7.
        estimator.on_build_finished(
            now + ms(10),
            FinishedBuild {
                work_at_tx_cutoff: ms(200),
                total_work: ms(350),
            },
        );
        let after_outlier = estimator.build_time_multiplier(now + ms(10));
        assert!(
            (after_outlier - 1.05).abs() < 1e-6,
            "p75 of the window ignores one outlier, got {after_outlier}"
        );

        // A sustained slowdown moves the multiplier by at most 0.15 per build:
        // the third slow finish flips the window's p75 to the cap, and it and
        // the fourth, each slower than the multiplier, step it up once.
        for i in 0..3u64 {
            estimator.on_build_finished(
                now + ms(20 + i),
                FinishedBuild {
                    work_at_tx_cutoff: ms(200),
                    total_work: ms(350),
                },
            );
        }
        let sustained = estimator.build_time_multiplier(now + ms(22));
        assert!(
            (sustained - 1.35).abs() < 1e-6,
            "expected two capped 0.15 steps from 1.05, got {sustained}"
        );

        // Fast finishes (ratio 1.02) push the slow ones out of the window
        // again, and the multiplier follows the window down in the same
        // capped steps: the fourth of them turns the p75 to 1.05, which the
        // multiplier reaches one build later, and the twelfth turns it to
        // 1.02.
        let trace: Vec<u64> = (0..16u64)
            .map(|i| finish_build(&estimator, now + ms(40 + i), 1020))
            .collect();
        let expected = [vec![1350; 3], vec![1200], vec![1050; 7], vec![1020; 5]].concat();
        assert_eq!(trace, expected);
    }

    #[test]
    fn build_time_multiplier_rises_only_on_a_build_slower_than_itself() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        // One slow finish (ratio 1.7) into an empty window, then fast ones
        // (ratio 1.0). The window's p75 is the slow finish until the window
        // holds four builds, but only the slow finish itself is slower than
        // the multiplier. So the outlier costs one capped step above the
        // initial 1.15 instead of one per build while it dominates a sparse
        // window, and once the p75 turns the multiplier steps back down.
        let trace: Vec<u64> = [1700, 1000, 1000, 1000, 1000]
            .into_iter()
            .map(|ratio| finish_build(&estimator, now, ratio))
            .collect();
        assert_eq!(trace, [1300, 1300, 1300, 1150, 1000]);

        // A build slower than the multiplier lifts it at most to its own
        // ratio, even while the window's p75 still holds the outlier: after
        // the outlier's one step, a build at 1.31 takes the multiplier to
        // 1.31 rather than a full step toward 1.70, and a fast build after
        // it leaves the multiplier there.
        let estimator = Estimator::new(config());
        let trace: Vec<u64> = [1700, 1000, 1310, 1000]
            .into_iter()
            .map(|ratio| finish_build(&estimator, now, ratio))
            .collect();
        assert_eq!(trace, [1300, 1300, 1310, 1310]);
    }

    #[test]
    fn build_time_multiplier_recovers_in_capped_steps() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        // Sixteen slow finishes (ratio 1.7) fill the window and take the
        // multiplier from 1.15 to its cap.
        let rise: Vec<u64> = (0..16)
            .map(|_| finish_build(&estimator, now, 1700))
            .collect();
        assert_eq!(rise, [vec![1300, 1450, 1600], vec![1700; 13]].concat());

        // Fast finishes (ratio 1.0) turn the window's p75 with the twelfth of
        // them. The multiplier then descends by at most 0.15 per build instead
        // of dropping to 1.0 at once, which would let the next proposal do 70%
        // more work before its cutoff while the network reservation still
        // reflects the smaller blocks of the slow period.
        let recovery: Vec<u64> = (0..16)
            .map(|_| finish_build(&estimator, now, 1000))
            .collect();
        assert_eq!(
            recovery,
            [vec![1700; 11], vec![1550, 1400, 1250, 1100, 1000]].concat()
        );
    }

    #[test]
    fn build_time_multiplier_never_drops_below_one() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        estimator.on_build_finished(
            now,
            FinishedBuild {
                work_at_tx_cutoff: ms(200),
                total_work: ms(100),
            },
        );
        assert!((estimator.build_time_multiplier(now) - 1.0).abs() < 1e-9);
        // Zero cutoff work carries no information.
        estimator.on_build_finished(
            now,
            FinishedBuild {
                work_at_tx_cutoff: Duration::ZERO,
                total_work: ms(100),
            },
        );
        assert_eq!(estimator.snapshot(now).build_time_samples, 1);
    }

    #[test]
    fn build_time_multiplier_returns_to_the_initial_value_without_builds() {
        let initial = 1.25;
        let estimator = Estimator::new(config().with_build_time_multiplier(initial));
        let now = Instant::now();
        // Three slow finishes (ratio 1.7) step the multiplier up to its cap.
        let trace: Vec<u64> = (0..3)
            .map(|_| finish_build(&estimator, now, 1700))
            .collect();
        assert_eq!(trace, [1400, 1550, 1700]);

        // The builds still count at exactly the ttl. After a whole ttl
        // without builds, for example a quiet period without own proposals,
        // the window is empty and the multiplier is the configured initial
        // value again, not the stale cap.
        let ttl_reached = now + BUILD_TIME_SAMPLE_TTL;
        assert_eq!(permille(estimator.build_time_multiplier(ttl_reached)), 1700);
        let quiet = ttl_reached + ms(1);
        assert_eq!(
            permille(estimator.build_time_multiplier(quiet)),
            permille(initial)
        );
        assert_eq!(estimator.snapshot(quiet).build_time_samples, 0);

        // So the first build after the quiet period steps up from the initial
        // value, as the first build after startup would.
        assert_eq!(
            finish_build(&estimator, quiet, 1700),
            permille(initial) + 150
        );
    }

    #[test]
    fn build_time_multiplier_ignores_partial_expiry_until_the_next_build() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        // Four slow finishes (ratio 1.7) take the multiplier to its cap, and
        // four fast ones (ratio 1.05) half a minute later leave the window's
        // p75 there.
        for _ in 0..4 {
            finish_build(&estimator, now, 1700);
        }
        let fast = now + Duration::from_secs(30);
        for _ in 0..4 {
            finish_build(&estimator, fast, 1050);
        }
        assert_eq!(permille(estimator.build_time_multiplier(fast)), 1700);

        // Once the slow finishes are older than the ttl only the fast ones
        // are left, yet no read moves the multiplier: dropping it to their
        // p75 would skip the capped recovery.
        let slow_expired = now + BUILD_TIME_SAMPLE_TTL + ms(1);
        let snapshot = estimator.snapshot(slow_expired);
        assert_eq!(snapshot.build_time_samples, 4);
        assert_eq!(permille(snapshot.build_time_multiplier), 1700);
        let plan = estimator.build_plan(slow_expired, ms(400));
        assert_eq!(permille(plan.build_time_multiplier()), 1700);
        assert_eq!(
            permille(estimator.build_time_multiplier(slow_expired)),
            1700
        );

        // The next finished build steps it toward the builds that are left.
        assert_eq!(finish_build(&estimator, slow_expired, 1050), 1550);

        // A window that expired completely is the one exception: the
        // multiplier is the configured initial value again.
        let quiet = slow_expired + BUILD_TIME_SAMPLE_TTL + ms(1);
        assert_eq!(estimator.snapshot(quiet).build_time_samples, 0);
        assert_eq!(
            permille(estimator.build_time_multiplier(quiet)),
            permille(DEFAULT_BUILD_TIME_MULTIPLIER)
        );
    }

    #[test]
    fn network_reserve_starts_at_the_floor_and_learns_from_own_proposals() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        let base_ms = 1_800_000_000_000u64;

        // Children of other proposers' blocks are ignored.
        estimator.on_child_block_built(now, (0, 7), 8, base_ms);
        assert_eq!(estimator.snapshot(now).network_samples, 0);

        // Own proposals, each started once as `build()` does: the next
        // leader starts building 420 ms after the return, of which the
        // return budget had already left 240 ms for the validators' replay.
        // The first one reserves the configured floor, and the reservation
        // moves from there toward the learned 180 ms by at most 100 ms per
        // proposal.
        let unspent = ms(240);
        let mut budgets = Vec::new();
        for view in 1..=4u64 {
            let returned = now + ms(view * 1000);
            let returned_ms = base_ms + view * 1000;
            budgets.push(estimator.start_proposal(returned));
            estimator.on_proposal_returned(returned, returned_ms, (0, view), unspent);
            estimator.on_child_block_built(
                returned + ms(420),
                (0, view),
                view + 1,
                returned_ms + 420,
            );
        }
        assert_eq!(budgets[0].return_budget, ms(500));
        let reserves: Vec<Duration> = budgets.iter().map(|b| b.network_reserve).collect();
        assert_eq!(reserves, [ms(50), ms(150), ms(180), ms(180)]);
        let last_built = now + ms(4_420);
        let budget = estimator.start_proposal(last_built);
        assert_eq!(budget.network_reserve, ms(180));
        assert_eq!(budget.return_budget, ms(370));
        assert_eq!(
            estimator.snapshot(last_built).network_observed,
            Some(ms(180))
        );
    }

    #[test]
    fn network_reserve_is_clamped_and_pending_proposals_expire() {
        let estimator = Estimator::new(config());
        let now = Instant::now();
        let base_ms = 1_800_000_000_000u64;
        let unspent = ms(200);
        // Faster than the floor: the next own proposal, the first of the
        // loop below, stays at the floor.
        assert_eq!(reserve_at(&estimator, now), ms(50));
        estimator.on_proposal_returned(now, base_ms, (0, 1), unspent);
        estimator.on_child_block_built(now + ms(210), (0, 1), 2, base_ms + 210);

        // Slower than the cap: the reservation climbs to the cap one step per
        // own proposal and is clamped there, but the observation is kept.
        let mut reserves = Vec::new();
        for view in 2..=6u64 {
            let returned = now + ms(view * 1000);
            let returned_ms = base_ms + view * 1000;
            reserves.push(reserve_at(&estimator, returned));
            estimator.on_proposal_returned(returned, returned_ms, (0, view), unspent);
            estimator.on_child_block_built(
                returned + ms(700),
                (0, view),
                view + 1,
                returned_ms + 700,
            );
        }
        assert_eq!(reserves, [ms(50), ms(150), ms(250), ms(300), ms(300)]);
        let last_built = now + ms(6_700);
        assert_eq!(reserve_at(&estimator, last_built), ms(300));
        assert_eq!(
            estimator.snapshot(last_built).network_observed,
            Some(ms(500))
        );

        // A proposal whose child never arrives takes no sample. Its view may
        // have been nullified, or the next leader may have held both a
        // notarization and a nullification for it and built on an ancestor,
        // as here where view 10 extends view 8.
        let orphan = now + ms(10_000);
        let orphan_ms = base_ms + 10_000;
        estimator.on_proposal_returned(orphan, orphan_ms, (0, 9), unspent);
        estimator.on_child_block_built(orphan + ms(300), (0, 8), 10, orphan_ms + 300);
        let snapshot = estimator.snapshot(orphan + ms(300));
        assert_eq!(snapshot.network_samples, 6);
        assert_eq!(snapshot.pending_proposals, 1);

        // It simply ages out: the first proposal recorded more than
        // `PENDING_PROPOSAL_TTL` later drops it.
        let next = orphan + PENDING_PROPOSAL_TTL + ms(1);
        let next_ms = orphan_ms + PENDING_PROPOSAL_TTL.as_millis() as u64 + 1;
        estimator.on_proposal_returned(next, next_ms, (0, 11), unspent);
        let snapshot = estimator.snapshot(next);
        assert_eq!(snapshot.network_samples, 6);
        assert_eq!(
            snapshot.pending_proposals, 1,
            "only the new proposal is pending"
        );

        // Neither does a proposal whose child skipped a view: the chain
        // waited on a leader timeout, not on propagation.
        let skipped = next + ms(1_500);
        estimator.on_child_block_built(skipped, (0, 11), 13, next_ms + 1_500);
        let snapshot = estimator.snapshot(skipped);
        assert_eq!(snapshot.network_samples, 6);
        assert_eq!(snapshot.pending_proposals, 0);

        // Nor an implausibly late child, which is clock skew or a stall.
        estimator.on_proposal_returned(now + ms(30_000), base_ms + 30_000, (0, 14), unspent);
        estimator.on_child_block_built(now + ms(36_000), (0, 14), 15, base_ms + 36_000);
        assert_eq!(estimator.snapshot(now + ms(36_000)).network_samples, 6);

        // Clock skew that puts the child before the return counts as zero
        // network time rather than being dropped.
        estimator.on_proposal_returned(now + ms(40_000), base_ms + 40_000, (0, 16), unspent);
        estimator.on_child_block_built(now + ms(40_100), (0, 16), 17, base_ms + 39_990);
        assert_eq!(estimator.snapshot(now + ms(40_100)).network_samples, 7);
    }

    #[test]
    fn network_samples_expire_back_to_the_floor() {
        let now = Instant::now();
        let base_ms = 1_800_000_000_000u64;
        let unspent = Duration::ZERO;
        // An estimator that learned 250 ms from one own proposal, which the
        // two own proposals after it climbed to. The network time comes from
        // the unix millisecond timestamps alone; the `Instant` only ages the
        // sample, which is taken at `now`.
        let learned = || {
            let estimator = Estimator::new(config());
            estimator.on_proposal_returned(now, base_ms, (0, 1), unspent);
            estimator.on_child_block_built(now, (0, 1), 2, base_ms + 250);
            assert_eq!(reserve_at(&estimator, now), ms(150));
            assert_eq!(reserve_at(&estimator, now), ms(250));
            estimator
        };

        // Reads expire the sample on their own: without a newer sample, the
        // target is back at the floor once the sample is older than the ttl,
        // and the reservation walks back down to it one step per own
        // proposal. A snapshot does not move the reservation.
        let estimator = learned();
        let expired = now + NETWORK_SAMPLE_TTL + ms(1);
        let snapshot = estimator.snapshot(expired);
        assert_eq!(snapshot.network_samples, 0);
        assert_eq!(snapshot.network_reserve, ms(250));
        assert_eq!(reserve_at(&estimator, expired), ms(150));
        assert_eq!(reserve_at(&estimator, expired), ms(50));

        // A proposal much later prunes the stale sample before its own
        // completes, so its faster sample alone sets the target.
        let estimator = learned();
        let later = now + NETWORK_SAMPLE_TTL + ms(1000);
        let later_ms = base_ms + NETWORK_SAMPLE_TTL.as_millis() as u64 + 1000;
        estimator.on_proposal_returned(later, later_ms, (0, 2), unspent);
        estimator.on_child_block_built(later + ms(40), (0, 2), 3, later_ms + 40);
        let snapshot = estimator.snapshot(later + ms(40));
        assert_eq!(snapshot.network_samples, 1);
        assert_eq!(snapshot.network_observed, Some(ms(40)));
        assert_eq!(reserve_at(&estimator, later + ms(40)), ms(150));
        assert_eq!(reserve_at(&estimator, later + ms(40)), ms(50));
    }

    #[test]
    fn network_reserve_uses_the_configured_percentile() {
        // Ten proposals with 100 to 190 ms of network time, out of order.
        let samples = [150, 110, 190, 130, 170, 100, 180, 120, 160, 140];
        // The rank rounds up: the 75th percentile of ten samples is the 8th
        // smallest, the 90th the 9th. Fast rise is off so that the most
        // recent samples cannot stand in for the percentile.
        for (percentile, expected) in [(50, 140), (75, 170), (90, 180), (100, 190)] {
            let estimator = Estimator::new(
                config()
                    .with_network_reserve_percentile(percentile)
                    .with_network_reserve_fast_rise(false),
            );
            let now = Instant::now();
            // Each proposal is started once, as `build()` does. All
            // percentiles of these samples lie within one step of each
            // other, so once the reservation has climbed from the floor it
            // follows the percentile exactly.
            let mut last_built = now;
            for (view, network) in (1..).zip(samples) {
                reserve_at(&estimator, now + Duration::from_secs(view));
                last_built = own_proposal(&estimator, now, view, ms(network));
            }
            let budget = estimator.start_proposal(last_built);
            assert_eq!(budget.network_reserve, ms(expected), "p{percentile}");
            assert_eq!(budget.return_budget, ms(550 - expected), "p{percentile}");
        }
    }

    #[test]
    fn network_reserve_follows_a_sparse_window_one_step_per_proposal() {
        for fast_rise in [true, false] {
            let estimator = Estimator::new(config().with_network_reserve_fast_rise(fast_rise));
            let now = Instant::now();
            // The reservation of the own proposal started `view` seconds
            // after `now`, once as `build()` does.
            let reserve = |view: u64| reserve_at(&estimator, now + Duration::from_secs(view));

            // The first own proposal after startup reserves the floor, and
            // the next leader starts building on it only 1 s after its return.
            assert_eq!(reserve(1), ms(50));
            own_proposal(&estimator, now, 1, ms(1000));
            // The percentile of a one sample window is that sample, so the
            // target is the cap at once. The reservation climbs to it one step
            // per own proposal instead of cutting the next proposal's return
            // budget from 500 to 250 ms.
            let snapshot = estimator.snapshot(now + Duration::from_secs(2));
            assert_eq!(snapshot.network_observed, Some(ms(1000)));
            assert_eq!(
                snapshot.network_reserve,
                ms(50),
                "a snapshot does not move the reservation"
            );
            assert_eq!(
                [reserve(2), reserve(3), reserve(4)],
                [ms(150), ms(250), ms(300)],
                "fast rise {fast_rise}"
            );

            // The 75th percentile of up to three samples is their maximum, so
            // the target stays at the cap through two fast proposals, and the
            // third brings it back to the floor.
            for view in 5..=7 {
                assert_eq!(reserve(view), ms(300), "fast rise {fast_rise}");
                own_proposal(&estimator, now, view, ms(50));
            }
            assert_eq!(
                estimator
                    .snapshot(now + Duration::from_secs(8))
                    .network_observed,
                Some(ms(50))
            );
            // The reservation walks back down one step per own proposal.
            assert_eq!(
                [reserve(8), reserve(9), reserve(10)],
                [ms(200), ms(100), ms(50)],
                "fast rise {fast_rise}"
            );
        }
    }

    #[test]
    fn network_reserve_climbs_one_step_per_proposal_when_good_samples_age_out() {
        for fast_rise in [true, false] {
            let estimator = Estimator::new(config().with_network_reserve_fast_rise(fast_rise));
            let now = Instant::now();
            // Sixteen own proposals at 150 ms fill the window, each started
            // once as `build()` does, and the reservation settles at 150 ms.
            for view in 1..=16 {
                reserve_at(&estimator, now + Duration::from_secs(view));
                own_proposal(&estimator, now, view, ms(150));
            }
            assert_eq!(
                estimator
                    .snapshot(now + Duration::from_secs(17))
                    .network_reserve,
                ms(150)
            );

            // Five minutes later one own proposal takes 1 s to be built on,
            // and the node proposes nothing more until its good samples are
            // older than the ttl while the outlier is not.
            let outlier_view = 300;
            let outlier_return = now + Duration::from_secs(outlier_view);
            assert_eq!(reserve_at(&estimator, outlier_return), ms(150));
            let outlier_at = own_proposal(&estimator, now, outlier_view, ms(1000));
            let good_expired = now + Duration::from_secs(16) + ms(150) + NETWORK_SAMPLE_TTL + ms(1);
            assert!(good_expired < outlier_at + NETWORK_SAMPLE_TTL);

            // The outlier is all that is left, so it is the window's
            // percentile, with fast rise or without. The reservation still
            // climbs one step per own proposal instead of jumping to the cap.
            let snapshot = estimator.snapshot(good_expired);
            assert_eq!(snapshot.network_samples, 1);
            assert_eq!(snapshot.network_observed, Some(ms(1000)));
            let reserves = [0, 1, 2]
                .map(|offset| reserve_at(&estimator, good_expired + Duration::from_secs(offset)));
            assert_eq!(
                reserves,
                [ms(250), ms(300), ms(300)],
                "fast rise {fast_rise}"
            );
        }
    }

    #[test]
    fn network_reserve_fast_rise_needs_two_slow_samples_in_a_row() {
        let plain = Estimator::new(config().with_network_reserve_fast_rise(false));
        let fast = Estimator::new(config().with_network_reserve_fast_rise(true));
        let now = Instant::now();
        // Own proposals start once each, when they return `view` seconds
        // after `now`.
        let next_return = |view| now + Duration::from_secs(view);
        // Feeds the same own proposal to both estimators, returns the
        // reserves their next proposals take.
        let reserves = |view, network| {
            own_proposal(&plain, now, view, network);
            own_proposal(&fast, now, view, network);
            (
                reserve_at(&plain, next_return(view + 1)),
                reserve_at(&fast, next_return(view + 1)),
            )
        };
        for view in 1..=12 {
            assert_eq!(reserves(view, ms(150)), (ms(150), ms(150)));
        }
        // A slow proposal between normal ones lifts nothing. The leader
        // after each own proposal is an independent draw, so one far
        // successor says nothing about the next, and the window's p75 still
        // reads 150 ms.
        assert_eq!(reserves(13, ms(240)), (ms(150), ms(150)));
        assert_eq!(reserves(14, ms(150)), (ms(150), ms(150)));
        assert_eq!(reserves(15, ms(240)), (ms(150), ms(150)));
        // A second slow proposal in a row does: fast rise makes the smaller
        // of the two the target while the window's p75 still reads 150 ms.
        // It is within one step of the previous reservation, so the very
        // next proposal reserves all of it.
        assert_eq!(reserves(16, ms(240)), (ms(150), ms(240)));
        let snapshot = fast.snapshot(next_return(17));
        assert_eq!(snapshot.network_last_sample, Some(ms(240)));
        assert_eq!(snapshot.network_observed, Some(ms(240)));
        assert_eq!(snapshot.proposal_return_budget, ms(310));
        // The next fast proposal hands the target back to the window, and the
        // reservation follows it down within one step.
        assert_eq!(reserves(17, ms(150)), (ms(150), ms(150)));
        assert_eq!(
            fast.snapshot(next_return(18)).network_last_sample,
            Some(ms(150))
        );
        // The newest sample is reported with fast rise disabled too.
        assert_eq!(
            plain.snapshot(next_return(18)).network_last_sample,
            Some(ms(150))
        );
    }

    #[test]
    fn network_reserve_fast_rise_is_step_bounded_capped_and_expires_with_the_window() {
        let estimator = Estimator::new(config().with_network_reserve_fast_rise(true));
        let now = Instant::now();
        // The reservation of the own proposal started at `at`, once as
        // `build()` does.
        let reserve = |at: Instant| reserve_at(&estimator, at);
        for view in 1..=6 {
            reserve(now + Duration::from_secs(view));
            own_proposal(&estimator, now, view, ms(150));
        }
        // Two samples in a row far above the window. The first alone lifts
        // nothing; with the second, fast rise lifts the observed network
        // time all the way to them, and the target is that clamped to the
        // cap. The reservation still moves by at most
        // `NETWORK_RESERVE_MAX_STEP` per own proposal, so stalled successors
        // cost the next proposal 100 ms of its window rather than the whole
        // range up to the cap, and the proposal after it reaches the cap.
        reserve(now + Duration::from_secs(7));
        let first_at = own_proposal(&estimator, now, 7, ms(400));
        assert_eq!(estimator.snapshot(first_at).network_observed, Some(ms(150)));
        assert_eq!(reserve(now + Duration::from_secs(8)), ms(150));
        let sampled_at = own_proposal(&estimator, now, 8, ms(400));
        let snapshot = estimator.snapshot(sampled_at);
        assert_eq!(snapshot.network_last_sample, Some(ms(400)));
        assert_eq!(snapshot.network_observed, Some(ms(400)));
        assert_eq!(snapshot.network_reserve, ms(150));
        assert_eq!(reserve(now + Duration::from_secs(9)), ms(250));
        assert_eq!(reserve(now + Duration::from_secs(10)), ms(300));
        assert_eq!(
            estimator
                .snapshot(now + Duration::from_secs(10))
                .proposal_return_budget,
            ms(250)
        );

        // The slow samples are the newest in the window, so they expire with
        // it rather than on their own. Without a newer sample the newest one
        // still counts at exactly the window's ttl, alone, so it is the
        // window's percentile and the target stays at the cap. Once it is
        // older every sample has aged out, so the target is back at the
        // floor, and the reservation walks down to it one step per own
        // proposal.
        let ttl_reached = sampled_at + NETWORK_SAMPLE_TTL;
        assert_eq!(estimator.snapshot(ttl_reached).network_samples, 1);
        assert_eq!(reserve(ttl_reached), ms(300));
        let expired = ttl_reached + ms(1);
        let snapshot = estimator.snapshot(expired);
        assert_eq!(snapshot.network_last_sample, None);
        assert_eq!(snapshot.network_samples, 0);
        assert_eq!(snapshot.network_observed, None);
        assert_eq!(snapshot.network_reserve, ms(300));
        let reserves = [0, 1, 2].map(|offset| reserve(expired + Duration::from_secs(offset)));
        assert_eq!(reserves, [ms(200), ms(100), ms(50)]);
    }

    #[test]
    fn build_plan_accounts_for_leader_idle_once() {
        let plan = BuildPlan::new(ms(500), 1.0, None);
        let decision = plan.decision(
            ms(300),
            ms(100),
            ValidationLatencyWorkload::new(1_000_000, 10),
        );
        assert_eq!(decision.predicted_builder_work, ms(200));
        assert_eq!(decision.predicted_validator_work, ms(200));
        assert_eq!(decision.total_reserved, ms(500));
        assert!(plan.exhausted(&decision));
        assert!(!BuildPlan::new(ms(501), 1.0, None).exhausted(&decision));
    }

    #[test]
    fn build_plan_uses_validator_feedback_when_available() {
        let workload = ValidationLatencyWorkload::new(1_000_000, 10);
        let plan = BuildPlan::new(ms(500), 1.0, validation_latency_estimate(workload, ms(120)));
        let decision = plan.decision(ms(200), Duration::ZERO, workload);
        assert_eq!(decision.predicted_builder_work, ms(200));
        assert_eq!(decision.predicted_validator_work, ms(120));
        assert_eq!(decision.total_reserved, ms(320));
    }

    #[test]
    fn build_plan_caps_scaled_validator_feedback_at_builder_projection() {
        let plan = BuildPlan::new(
            ms(500),
            1.0,
            validation_latency_estimate(ValidationLatencyWorkload::new(1_000_000, 10), ms(120)),
        );
        // Four times the feedback workload would scale the estimate to 480 ms,
        // which is more than the builder itself has spent.
        let decision = plan.decision(
            ms(200),
            Duration::ZERO,
            ValidationLatencyWorkload::new(4_000_000, 40),
        );
        assert_eq!(decision.predicted_validator_work, ms(200));
    }

    #[test]
    fn build_plan_scales_builder_work_by_the_multiplier() {
        let plan = BuildPlan::new(ms(500), 1.35, None);
        let decision = plan.decision(
            ms(100),
            Duration::ZERO,
            ValidationLatencyWorkload::new(1_000_000, 10),
        );
        assert_eq!(decision.predicted_builder_work, ms(135));
        assert_eq!(decision.total_reserved, ms(135 + 135));
        assert!((plan.build_time_multiplier() - 1.35).abs() < 1e-9);
    }

    #[test]
    fn build_plan_carries_the_validation_estimate() {
        let estimator = Estimator::new(config());
        let workload = ValidationLatencyWorkload::new(1_000_000, 10);
        assert_eq!(
            estimator
                .build_plan(Instant::now(), ms(400))
                .validation_latency(),
            None
        );
        estimator.on_block_verified(1, workload, ms(200));
        let plan = estimator.build_plan(Instant::now(), ms(400));
        assert_eq!(
            plan.validation_latency().and_then(|e| e.estimate(workload)),
            Some(ms(200))
        );
    }

    /// One validator of a ten validator network, modelled on the
    /// multi-region benchmark. It proposes every tenth block and paces it as
    /// `build()` and the builder do: the builder adds work 1 ms at a time
    /// until `BuildPlan::decision` tells it to stop, the finish then adds 5%
    /// to the work at the cutoff, and consensus sleeps off whatever the
    /// return budget has left beyond the validation estimate before it
    /// returns. Validators replay a block in 0.9x its builder work (171 ms
    /// against 192 ms on the benchmark), and the next leader starts building
    /// once a quorum has replayed the block and the network time to that
    /// leader has passed, as under inline verification. The network time
    /// depends on who leads next, drawn from `successors` by a fixed-seed
    /// LCG, so every run plays the same sequence. Every other leader's block
    /// takes 192 ms to build, and this node replays it, which is where its
    /// validation estimate comes from.
    struct SimulatedNetwork {
        estimator: Estimator,
        start: Instant,
        now: Instant,
        /// Network time to each validator that may lead next.
        successors: Vec<Duration>,
        /// State of the fixed-seed LCG that draws the next leader.
        lcg: u64,
    }

    /// An own proposal of the simulated node.
    struct SimulatedProposal {
        budget: ProposalBudget,
        /// From this proposal's header timestamp to its child's.
        block_time: Duration,
    }

    impl SimulatedNetwork {
        const VALIDATORS: u64 = 10;
        /// Builder work of every other leader's block.
        const OTHER_BUILD_WORK: Duration = Duration::from_millis(192);

        fn new(estimator: Estimator, successors: &[u64]) -> Self {
            let start = Instant::now();
            Self {
                estimator,
                start,
                now: start,
                successors: successors.iter().copied().map(ms).collect(),
                lcg: 1,
            }
        }

        /// The clock header timestamps use, in whole milliseconds.
        fn unix_ms(&self) -> u64 {
            1_800_000_000_000 + (self.now - self.start).as_millis() as u64
        }

        /// The network time to the next leader.
        fn next_successor(&mut self) -> Duration {
            // Knuth's MMIX LCG; its high bits are the well mixed ones.
            self.lcg = self
                .lcg
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.successors[(self.lcg >> 33) as usize % self.successors.len()]
        }

        /// Gas and transactions grow with the builder's work, so the
        /// validation estimate scales with the block.
        fn workload(work: Duration) -> ValidationLatencyWorkload {
            let millis = work.as_millis() as u64;
            ValidationLatencyWorkload::new(millis * 1_000_000, (millis * 40) as usize)
        }

        fn replay(build_work: Duration) -> Duration {
            build_work * 9 / 10
        }

        /// Plays `blocks` consecutive blocks, returns this node's own
        /// proposals.
        fn run(&mut self, blocks: u64) -> Vec<SimulatedProposal> {
            let target_block_time = self.estimator.config().target_block_time;
            let mut own = Vec::new();
            for height in 1..=blocks {
                if height % Self::VALIDATORS == 0 {
                    own.push(self.own_proposal(height));
                    continue;
                }
                // Another leader's block, which this node replays.
                let replay = Self::replay(Self::OTHER_BUILD_WORK);
                self.estimator.on_block_verified(
                    height,
                    Self::workload(Self::OTHER_BUILD_WORK),
                    replay,
                );
                self.now += target_block_time;
            }
            own
        }

        fn own_proposal(&mut self, view: u64) -> SimulatedProposal {
            let key = (0, view);
            let header_ms = self.unix_ms();
            let budget = self.estimator.start_proposal(self.now);
            // The builder's stop decision reserves the projected finish and
            // the validators' replay, the latter capped at the builder's own
            // projected work.
            let plan = self.estimator.build_plan(self.now, budget.return_budget);
            let mut cutoff = Duration::ZERO;
            while !plan.exhausted(&plan.decision(cutoff, Duration::ZERO, Self::workload(cutoff))) {
                cutoff += MS;
            }
            let build = FinishedBuild {
                work_at_tx_cutoff: cutoff,
                total_work: cutoff * 21 / 20,
            };
            self.now += build.total_work;
            self.estimator.on_build_finished(self.now, build);

            // Pace the return as `build()` does, and take the unspent budget
            // from that plan.
            let validation = plan
                .validation_latency()
                .and_then(|estimate| estimate.estimate(Self::workload(cutoff)))
                .unwrap_or(build.total_work);
            let return_delay = budget
                .return_budget
                .saturating_sub(build.total_work)
                .saturating_sub(validation);
            let unspent = budget.unspent(build.total_work + return_delay);
            self.now += return_delay;
            if let Some(unspent) = unspent {
                self.estimator
                    .on_proposal_returned(self.now, self.unix_ms(), key, unspent);
            }

            // The next leader starts building once a quorum has replayed the
            // block and the network time to it has passed.
            let network = self.next_successor();
            self.now += Self::replay(build.total_work) + network;
            let child_ms = self.unix_ms();
            self.estimator
                .on_child_block_built(self.now, key, view + 1, child_ms);
            SimulatedProposal {
                budget,
                block_time: ms(child_ms - header_ms),
            }
        }
    }

    /// The 75th percentile of the block times, rounding the rank up as the
    /// estimator's windows do.
    fn p75_block_time(proposals: &[SimulatedProposal]) -> Duration {
        let mut block_times: Vec<Duration> = proposals.iter().map(|p| p.block_time).collect();
        block_times.sort_unstable();
        block_times[(block_times.len() * 3).div_ceil(4) - 1]
    }

    #[test]
    fn simulation_meets_the_target_block_time_at_the_reserved_percentile() {
        // Network time to each validator that may lead next, as seen from a
        // proposer in one of four regions: three nearby, five in the other
        // regions close by, and two far away.
        let successors = [50, 55, 60, 90, 95, 100, 105, 110, 230, 250];
        let mut network = SimulatedNetwork::new(Estimator::new(config()), &successors);
        let own = network.run(6_000);
        assert!(
            own.iter()
                .all(|p| (ms(50)..=ms(300)).contains(&p.budget.network_reserve)),
            "the reservation stays between the floor and the cap"
        );
        // Once the window has filled and the reservation has climbed from
        // the floor, the reserved 75th percentile of the samples makes the
        // 75th percentile of this node's own block times meet the target:
        // a sample is the block time minus the proposal window. It lands a
        // little above, because a new sample is at or below the 12th
        // smallest of the 16 before it with probability 12/17 rather than
        // 3/4.
        let p75 = p75_block_time(&own[20..]);
        assert!(
            p75.abs_diff(ms(550)) <= ms(5),
            "p75 of own block times is {p75:?}"
        );
    }

    #[test]
    fn simulation_keeps_the_floor_when_the_network_is_faster_than_it() {
        // Every next leader starts building within 20 ms of the replay. The
        // chain waits less beyond the return budget than the configured
        // floor, so the reservation never leaves it, and every own block
        // finishes within the target.
        let mut network = SimulatedNetwork::new(Estimator::new(config()), &[10, 20]);
        let own = network.run(600);
        assert!(own.iter().all(|p| p.budget.network_reserve == ms(50)));
        assert!(own.iter().all(|p| p.block_time <= ms(550)));
    }
}
