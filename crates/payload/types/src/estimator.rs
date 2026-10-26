//! Shared build-time and validation feedback for paced payloads.

use std::{
    collections::VecDeque,
    ops::{Add, Sub},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{
    BUILD_TIME_MULTIPLIER_SCALE, BuildPlan, ValidationLatencyEstimator, ValidationLatencyWorkload,
};

/// Initial ratio of total replayable build work to work at transaction cutoff.
pub const DEFAULT_BUILD_TIME_MULTIPLIER: f64 = 1.15;

/// Lowest build time multiplier, configured or learned: builder work never
/// shrinks after the transaction cutoff.
const MIN_BUILD_TIME_MULTIPLIER_SCALED: u64 = BUILD_TIME_MULTIPLIER_SCALE;
/// Highest build time multiplier, configured or learned. Observed ratios above
/// it are clamped to it.
const MAX_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_700_000;
/// Largest change of the multiplier, up or down, per finished build.
const BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED: u64 = 150_000;
/// Largest change of the dry build finish, up or down, per dry build, so that
/// one finish that waited on a persistence commit does not claim that wait for
/// the dry builds after it.
const DRY_BUILD_FINISH_MAX_STEP: Duration = Duration::from_millis(10);
/// Number of most recent finished builds each learned estimate follows.
const BUILD_TIME_SAMPLE_WINDOW: usize = 16;
/// Age after which a finished build no longer counts. Once every build in a
/// window has expired, its estimate is back at its initial value.
const BUILD_TIME_SAMPLE_TTL: Duration = Duration::from_secs(5 * 60);
/// Percentile of the build time windows the multiplier and the dry build finish
/// follow.
const BUILD_TIME_RESERVE_PERCENTILE: u8 = 75;

/// Static configuration of the shared proposal budget estimator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EstimatorConfig {
    /// Ratio of total replayable build work to work at transaction cutoff that
    /// the estimator starts from, and returns to once it has seen no finished
    /// build for a while.
    pub build_time_multiplier: f64,
}

/// Why an [`EstimatorConfig`] is invalid.
#[derive(Clone, Copy, Debug, PartialEq, thiserror::Error)]
pub enum EstimatorConfigError {
    /// The build time multiplier is outside the range the estimator learns it in.
    #[error(
        "build time multiplier ({multiplier}) must be between {} and {}",
        unscaled_build_time_multiplier(MIN_BUILD_TIME_MULTIPLIER_SCALED),
        unscaled_build_time_multiplier(MAX_BUILD_TIME_MULTIPLIER_SCALED)
    )]
    BuildTimeMultiplierOutOfRange {
        /// The rejected multiplier.
        multiplier: f64,
    },
}

impl Default for EstimatorConfig {
    fn default() -> Self {
        Self {
            build_time_multiplier: DEFAULT_BUILD_TIME_MULTIPLIER,
        }
    }
}

impl EstimatorConfig {
    /// Checks that the build time multiplier is within the range the estimator
    /// learns it in, 1.0 to 1.7 inclusive. [`Estimator::new`] rejects a
    /// configuration that fails this.
    pub fn validate(&self) -> Result<(), EstimatorConfigError> {
        let range = unscaled_build_time_multiplier(MIN_BUILD_TIME_MULTIPLIER_SCALED)
            ..=unscaled_build_time_multiplier(MAX_BUILD_TIME_MULTIPLIER_SCALED);
        // `contains` is false for NaN and infinities too.
        if !range.contains(&self.build_time_multiplier) {
            return Err(EstimatorConfigError::BuildTimeMultiplierOutOfRange {
                multiplier: self.build_time_multiplier,
            });
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
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    validation: ValidationLatencyEstimator,
    build_time: BuildTimeTracker,
}

impl Estimator {
    /// Creates empty feedback, or returns why the configuration is invalid.
    pub fn new(config: EstimatorConfig) -> Result<Self, EstimatorConfigError> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(EstimatorInner {
                state: Mutex::new(State {
                    validation: ValidationLatencyEstimator::default(),
                    build_time: BuildTimeTracker::new(config.build_time_multiplier),
                }),
            }),
        })
    }

    /// Locks the shared state, blocking while another clone holds it.
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // State is plain data and remains usable after a poisoned update.
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

    /// Snapshots the current feedback for one paced payload build.
    ///
    /// `now` is the current monotonic time. Finished builds older than five
    /// minutes at `now` are forgotten for every clone of this estimator; with
    /// none left, the plan uses the configured multiplier and no dry build
    /// finish, as after startup.
    pub fn build_plan(&self, now: Instant, build_budget: Duration) -> BuildPlan {
        let mut state = self.state();
        state.build_time.prune(now);
        BuildPlan::new(
            build_budget,
            state.build_time.multiplier_scaled(),
            state.build_time.dry_finish(),
            state.validation.estimate(),
        )
    }

    /// Records the timings of a payload build that finished at `now`, the
    /// current monotonic time, for the plans of later builds.
    pub fn on_build_finished(&self, now: Instant, build: FinishedBuild) {
        self.state().build_time.observe(now, build);
    }
}

/// Timings of a finished payload build.
///
/// Both work durations exclude [`Self::idle`], and `total_work` is at least
/// `work_at_tx_cutoff`.
#[derive(Clone, Copy, Debug)]
pub struct FinishedBuild {
    /// Replayable work measured when pool transaction execution stopped.
    pub work_at_tx_cutoff: Duration,
    /// Replayable work measured after finalization.
    pub total_work: Duration,
    /// Time the build spent waiting for the pool to yield more transactions.
    ///
    /// Zero for a busy build, one that kept executing transactions until its
    /// budget or a block limit stopped it. Not zero for a dry build, one whose
    /// pool ran dry before its budget did.
    pub idle: Duration,
}

/// Converts a human-readable build-work multiplier into the fixed-point representation.
fn scaled_build_time_multiplier(multiplier: f64) -> u64 {
    let scaled = (multiplier * BUILD_TIME_MULTIPLIER_SCALE as f64).round() as u64;
    debug_assert!(
        (MIN_BUILD_TIME_MULTIPLIER_SCALED..=MAX_BUILD_TIME_MULTIPLIER_SCALED).contains(&scaled),
        "build time multiplier {multiplier} is outside the learned range"
    );
    scaled
}

/// Converts a fixed-point build-work multiplier into the human-readable representation.
fn unscaled_build_time_multiplier(scaled: u64) -> f64 {
    scaled as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64
}

/// Computes the observed total-work to tx-cutoff-work multiplier of a busy
/// build, clamped to the learned range, or `None` without cutoff work.
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
/// which may be slightly older than the previous sample's.
#[derive(Debug)]
struct SampleWindow<TSample> {
    samples: VecDeque<(Instant, TSample)>,
    capacity: usize,
    ttl: Duration,
}

impl<TSample: Copy + Ord> SampleWindow<TSample> {
    fn new(capacity: usize, ttl: Duration) -> Self {
        debug_assert!(capacity > 0, "a sample window holds at least one sample");
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
            ttl,
        }
    }

    /// Adds a sample, evicting the oldest one at capacity. Expired samples are
    /// kept until [`Self::prune`].
    fn push(&mut self, now: Instant, value: TSample) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back((now, value));
    }

    /// Drops samples older than the window's ttl at `now`.
    fn prune(&mut self, now: Instant) {
        self.samples
            .retain(|(at, _)| now.saturating_duration_since(*at) <= self.ttl);
    }

    fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Returns the `percentile`th percentile, rounding the rank up so that a
    /// single sample is returned as is, or `None` for an empty window.
    fn percentile(&self, percentile: u8) -> Option<TSample> {
        if self.samples.is_empty() {
            return None;
        }
        let mut values: Vec<TSample> = self.samples.iter().map(|(_, value)| *value).collect();
        values.sort_unstable();
        let rank = (values.len() * usize::from(percentile))
            .div_ceil(100)
            .max(1);
        values.get(rank - 1).copied()
    }
}

/// Moves `current` toward `target` by at most `max_step`, in either direction.
fn step_toward<TValue>(current: TValue, target: TValue, max_step: TValue) -> TValue
where
    TValue: Copy + Ord + Add<Output = TValue> + Sub<Output = TValue>,
{
    if target >= current {
        current + (target - current).min(max_step)
    } else {
        current - (current - target).min(max_step)
    }
}

/// Learns how much replayable work follows the transaction cutoff.
///
/// Busy builds teach the multiplier, the ratio of total over cutoff work. Dry
/// builds teach the dry build finish, the work after their cutoff, which
/// [`BuildPlan::decision`] reserves for builds that waited for transactions.
/// A dry build's near-empty block has a near-zero cutoff, so its ratio says
/// nothing about the next busy build.
#[derive(Debug)]
struct BuildTimeTracker {
    /// Ratio of total over cutoff work in fixed point, from busy builds.
    multiplier: BoundedFollower,
    /// Finish duration in nanoseconds, from dry builds. Starts at zero, the
    /// reservation before any dry build finished.
    dry_finish: BoundedFollower,
}

impl BuildTimeTracker {
    /// Starts at `initial_multiplier`, which must be within the learned range,
    /// and without a dry build finish.
    fn new(initial_multiplier: f64) -> Self {
        Self {
            multiplier: BoundedFollower::new(
                scaled_build_time_multiplier(initial_multiplier),
                BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED,
            ),
            dry_finish: BoundedFollower::new(0, saturating_nanos(DRY_BUILD_FINISH_MAX_STEP)),
        }
    }

    fn prune(&mut self, now: Instant) {
        self.multiplier.prune(now);
        self.dry_finish.prune(now);
    }

    /// Records a finished build in the estimate it teaches.
    fn observe(&mut self, now: Instant, build: FinishedBuild) {
        if !build.idle.is_zero() {
            let finish = build.total_work.saturating_sub(build.work_at_tx_cutoff);
            self.dry_finish.observe(now, saturating_nanos(finish));
            return;
        }
        // A busy build without cutoff work has no ratio to learn from.
        let Some(observed) =
            observed_build_time_multiplier(build.total_work, build.work_at_tx_cutoff)
        else {
            return;
        };
        self.multiplier.observe(now, observed);
    }

    /// The learned multiplier, in [`BUILD_TIME_MULTIPLIER_SCALE`] units per 1.0.
    fn multiplier_scaled(&self) -> u64 {
        self.multiplier.current
    }

    /// The learned dry build finish.
    fn dry_finish(&self) -> Duration {
        Duration::from_nanos(self.dry_finish.current)
    }
}

/// Converts `duration` to nanoseconds, saturating at `u64::MAX`.
fn saturating_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// An estimate that follows the [`BUILD_TIME_RESERVE_PERCENTILE`] of a window
/// of finished builds by bounded steps, and is back at its initial value once
/// every build in the window has expired.
#[derive(Debug)]
struct BoundedFollower {
    samples: SampleWindow<u64>,
    /// In use while the window is empty.
    initial: u64,
    /// The estimate, in the same unit as the samples.
    current: u64,
    /// Largest change of `current` per observed build.
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
    /// back at its initial value.
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
    /// without that one slow finish would raise the estimate with every build
    /// until the window filled. A step down only needs the percentile below the
    /// estimate.
    fn observe(&mut self, now: Instant, observed: u64) {
        self.prune(now);
        self.samples.push(now, observed);
        let percentile = self
            .samples
            .percentile(BUILD_TIME_RESERVE_PERCENTILE)
            .expect("the window holds the build just pushed");
        let target = percentile.min(observed.max(self.current));
        self.current = step_toward(self.current, target, self.max_step);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_150_000;

    fn busy(total_ms: u64, cutoff_ms: u64) -> FinishedBuild {
        FinishedBuild {
            work_at_tx_cutoff: Duration::from_millis(cutoff_ms),
            total_work: Duration::from_millis(total_ms),
            idle: Duration::ZERO,
        }
    }

    fn dry(total_ms: u64, cutoff_ms: u64) -> FinishedBuild {
        FinishedBuild {
            idle: Duration::from_millis(1),
            ..busy(total_ms, cutoff_ms)
        }
    }

    #[test]
    fn observed_build_time_multiplier_is_clamped_to_learned_range() {
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(115), Duration::from_millis(100)),
            Some(DEFAULT_BUILD_TIME_MULTIPLIER_SCALED)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(100), Duration::from_millis(100)),
            Some(MIN_BUILD_TIME_MULTIPLIER_SCALED)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(250), Duration::from_millis(100)),
            Some(MAX_BUILD_TIME_MULTIPLIER_SCALED)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(100), Duration::ZERO),
            None
        );
    }

    #[test]
    fn build_time_multiplier_scales_decimal_values() {
        assert_eq!(
            scaled_build_time_multiplier(DEFAULT_BUILD_TIME_MULTIPLIER),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED
        );
        assert_eq!(
            unscaled_build_time_multiplier(DEFAULT_BUILD_TIME_MULTIPLIER_SCALED),
            DEFAULT_BUILD_TIME_MULTIPLIER
        );
    }

    #[test]
    fn config_accepts_learned_range_inclusive() {
        for multiplier in [1.0, DEFAULT_BUILD_TIME_MULTIPLIER, 1.7] {
            let config = EstimatorConfig {
                build_time_multiplier: multiplier,
            };
            assert_eq!(config.validate(), Ok(()));
            assert!(Estimator::new(config).is_ok());
        }
    }

    #[test]
    fn config_rejects_multiplier_outside_learned_range() {
        for multiplier in [0.99, 1.71, f64::INFINITY, f64::NEG_INFINITY] {
            let config = EstimatorConfig {
                build_time_multiplier: multiplier,
            };
            let expected = EstimatorConfigError::BuildTimeMultiplierOutOfRange { multiplier };
            assert_eq!(config.validate(), Err(expected));
            assert_eq!(Estimator::new(config).unwrap_err(), expected);
        }
        let nan = EstimatorConfig {
            build_time_multiplier: f64::NAN,
        };
        assert!(matches!(
            nan.validate(),
            Err(EstimatorConfigError::BuildTimeMultiplierOutOfRange { multiplier }) if multiplier.is_nan()
        ));
        assert_eq!(
            EstimatorConfigError::BuildTimeMultiplierOutOfRange { multiplier: 2.0 }.to_string(),
            "build time multiplier (2) must be between 1 and 1.7"
        );
    }

    #[test]
    fn slow_busy_build_raises_multiplier_by_one_step() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(DEFAULT_BUILD_TIME_MULTIPLIER);
        tracker.observe(now, busy(250, 100));
        assert_eq!(
            tracker.multiplier_scaled(),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED + BUILD_TIME_MULTIPLIER_MAX_STEP_SCALED
        );
    }

    #[test]
    fn multiplier_rises_at_most_to_the_observed_build() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(DEFAULT_BUILD_TIME_MULTIPLIER);
        tracker.observe(now, busy(120, 100));
        assert_eq!(tracker.multiplier_scaled(), 1_200_000);
    }

    #[test]
    fn faster_build_does_not_raise_multiplier_toward_slow_percentile() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(DEFAULT_BUILD_TIME_MULTIPLIER);
        tracker.observe(now, busy(250, 100));
        let after_slow = tracker.multiplier_scaled();
        // The window's percentile is still the slow build, but this build was
        // below the estimate, so the estimate does not rise.
        tracker.observe(now, busy(110, 100));
        assert_eq!(tracker.multiplier_scaled(), after_slow);
    }

    #[test]
    fn multiplier_falls_by_bounded_steps_toward_percentile() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(1.7);
        for expected in [
            1_550_000, 1_400_000, 1_250_000, 1_100_000, 1_000_000, 1_000_000,
        ] {
            tracker.observe(now, busy(100, 100));
            assert_eq!(tracker.multiplier_scaled(), expected);
        }
    }

    #[test]
    fn busy_build_without_cutoff_work_teaches_nothing() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(DEFAULT_BUILD_TIME_MULTIPLIER);
        tracker.observe(now, busy(50, 0));
        assert_eq!(
            tracker.multiplier_scaled(),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED
        );
        assert_eq!(tracker.dry_finish(), Duration::ZERO);
    }

    #[test]
    fn dry_build_teaches_dry_finish_not_multiplier() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(DEFAULT_BUILD_TIME_MULTIPLIER);
        tracker.observe(now, dry(30, 1));
        assert_eq!(
            tracker.multiplier_scaled(),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED
        );
        assert_eq!(tracker.dry_finish(), DRY_BUILD_FINISH_MAX_STEP);
        tracker.observe(now, dry(30, 1));
        tracker.observe(now, dry(30, 1));
        assert_eq!(tracker.dry_finish(), Duration::from_millis(29));
    }

    #[test]
    fn expired_builds_reset_estimates_to_initial_values() {
        let start = Instant::now();
        let estimator = Estimator::new(EstimatorConfig::default()).unwrap();
        estimator.on_build_finished(start, busy(250, 100));
        estimator.on_build_finished(start, dry(30, 1));

        let plan = estimator.build_plan(start + BUILD_TIME_SAMPLE_TTL, Duration::MAX);
        assert_eq!(plan.build_time_multiplier(), 1.3);
        assert_eq!(plan.dry_finish(), DRY_BUILD_FINISH_MAX_STEP);

        let plan = estimator.build_plan(
            start + BUILD_TIME_SAMPLE_TTL + Duration::from_nanos(1),
            Duration::MAX,
        );
        assert_eq!(plan.build_time_multiplier(), DEFAULT_BUILD_TIME_MULTIPLIER);
        assert_eq!(plan.dry_finish(), Duration::ZERO);
    }

    #[test]
    fn partial_expiry_keeps_estimate() {
        let start = Instant::now();
        let mut follower = BoundedFollower::new(0, 10);
        follower.observe(start, 100);
        follower.observe(start + Duration::from_secs(60), 100);
        assert_eq!(follower.current, 20);
        follower.prune(start + BUILD_TIME_SAMPLE_TTL + Duration::from_secs(1));
        assert_eq!(follower.current, 20);
    }

    #[test]
    fn sample_window_evicts_oldest_at_capacity() {
        let now = Instant::now();
        let mut window = SampleWindow::new(2, BUILD_TIME_SAMPLE_TTL);
        assert_eq!(window.percentile(BUILD_TIME_RESERVE_PERCENTILE), None);
        window.push(now, 30);
        window.push(now, 10);
        window.push(now, 20);
        assert_eq!(window.percentile(50), Some(10));
        assert_eq!(window.percentile(100), Some(20));
    }
}
