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

/// Static configuration of the shared proposal budget estimator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EstimatorConfig {
    /// Initial ratio of total replayable build work to work at transaction cutoff.
    pub build_time_multiplier: f64,
}

impl Default for EstimatorConfig {
    fn default() -> Self {
        Self {
            build_time_multiplier: DEFAULT_BUILD_TIME_MULTIPLIER,
        }
    }
}

impl EstimatorConfig {
    /// Sets the initial build multiplier, validated when an estimator is constructed.
    pub fn with_build_time_multiplier(mut self, multiplier: f64) -> Self {
        self.build_time_multiplier = multiplier;
        self
    }

    /// Rejects multipliers outside the learned range, from 1.0 to 1.7 inclusive.
    pub fn validate(&self) -> Result<(), String> {
        if !self.build_time_multiplier.is_finite()
            || !(1.0..=1.7).contains(&self.build_time_multiplier)
        {
            return Err(format!(
                "build time multiplier ({}) must be finite and between 1.0 and 1.7",
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
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    validation: ValidationLatencyEstimator,
    build_time: BuildTimeTracker,
}

impl Estimator {
    /// Creates empty feedback or returns why the configuration is invalid.
    pub fn new(config: EstimatorConfig) -> Result<Self, String> {
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

    /// Snapshots feedback once for a paced payload build, expiring stale build samples.
    pub fn build_plan(&self, now: Instant, build_budget: Duration) -> BuildPlan {
        let mut state = self.state();
        state.build_time.prune(now);
        BuildPlan {
            build_budget,
            multiplier_scaled: state.build_time.multiplier_scaled(),
            dry_finish: state.build_time.dry_finish(),
            validation_latency: state.validation.estimate(),
        }
    }

    /// Records completed build work, separating dry finishes from busy-build ratios.
    pub fn on_build_finished(&self, now: Instant, build: FinishedBuild) {
        self.state().build_time.observe(now, build);
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
    fn observe(&mut self, now: Instant, build: FinishedBuild) {
        if !build.idle.is_zero() {
            let finish = build.total_work.saturating_sub(build.work_at_tx_cutoff);
            self.dry_finish.observe(now, nanos(finish));
            return;
        }
        let Some(observed) =
            observed_build_time_multiplier(build.total_work, build.work_at_tx_cutoff)
        else {
            return;
        };
        self.multiplier.observe(now, observed);
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
        tracker.observe(
            now,
            FinishedBuild {
                total_work: Duration::from_millis(250),
                work_at_tx_cutoff: Duration::from_millis(100),
                idle: Duration::ZERO,
            },
        );
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
