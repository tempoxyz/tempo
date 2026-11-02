//! Learning of the replayable work that follows a payload build's transaction cutoff.

use std::{
    collections::VecDeque,
    ops::{Add, Sub},
    time::{Duration, Instant},
};

use super::{BuildTimeMultiplier, FinishedBuild};

/// Largest change of the multiplier, up or down, per busy build, in
/// [`BuildTimeMultiplier`] fixed-point units.
const MULTIPLIER_MAX_STEP_SCALED: u64 = 150_000;
/// Largest change of the dry build finish, up or down, per dry build, so that
/// one finish that waited on a persistence commit does not claim that wait for
/// the dry builds after it.
pub(super) const DRY_FINISH_MAX_STEP: Duration = Duration::from_millis(10);
/// Number of most recent finished builds each estimate follows.
const SAMPLE_WINDOW: usize = 16;
/// Age after which a finished build no longer counts. Once every build behind
/// an estimate has expired, the estimate is back at its initial value.
pub(super) const SAMPLE_TTL: Duration = Duration::from_secs(5 * 60);
/// Percentile of its window of finished builds each estimate follows.
const RESERVE_PERCENTILE: usize = 75;

/// Learns how much replayable work follows the transaction cutoff.
///
/// Busy builds teach the multiplier, the ratio of total over cutoff work. Dry
/// builds teach the dry build finish, the work after their cutoff, which
/// [`super::BuildPlan::decision`] reserves for builds that waited for
/// transactions. A dry build's near-empty block has a near-zero cutoff, so its
/// ratio says nothing about the next busy build.
#[derive(Debug)]
pub(super) struct BuildTimeTracker {
    /// In [`BuildTimeMultiplier`] fixed-point units, from busy builds.
    multiplier_scaled: WindowedEstimate<u64>,
    /// From dry builds; zero before any dry build finished.
    dry_finish: WindowedEstimate<Duration>,
}

impl BuildTimeTracker {
    /// Starts at `initial_multiplier` and without a dry build finish.
    pub(super) fn new(initial_multiplier: BuildTimeMultiplier) -> Self {
        Self {
            multiplier_scaled: WindowedEstimate::new(
                initial_multiplier.scaled,
                MULTIPLIER_MAX_STEP_SCALED,
            ),
            dry_finish: WindowedEstimate::new(Duration::ZERO, DRY_FINISH_MAX_STEP),
        }
    }

    /// Records a finished build in the estimate it teaches.
    pub(super) fn observe(&mut self, now: Instant, finished_build: FinishedBuild) {
        let FinishedBuild {
            validation_work_at_tx_cutoff,
            validation_work,
            idle_elapsed,
        } = finished_build;
        if !idle_elapsed.is_zero() {
            self.dry_finish.observe(
                now,
                validation_work.saturating_sub(validation_work_at_tx_cutoff),
            );
            return;
        }
        // A busy build without cutoff work has no ratio to learn from.
        if validation_work_at_tx_cutoff.is_zero() {
            return;
        }
        let ratio_scaled = validation_work
            .as_nanos()
            .saturating_mul(u128::from(BuildTimeMultiplier::SCALE))
            / validation_work_at_tx_cutoff.as_nanos();
        let observed = BuildTimeMultiplier::from_scaled_clamped(
            u64::try_from(ratio_scaled).unwrap_or(u64::MAX),
        );
        self.multiplier_scaled.observe(now, observed.scaled);
    }

    /// The learned multiplier at `now`.
    pub(super) fn multiplier(&self, now: Instant) -> BuildTimeMultiplier {
        // Only ever set from valid multipliers and steps between them.
        BuildTimeMultiplier {
            scaled: self.multiplier_scaled.get(now),
        }
    }

    /// The learned dry build finish at `now`.
    pub(super) fn dry_finish(&self, now: Instant) -> Duration {
        self.dry_finish.get(now)
    }
}

/// An estimate that follows the [`RESERVE_PERCENTILE`] of a window of recent
/// finished builds by bounded steps, and is back at its initial value once
/// every build in the window has expired.
#[derive(Debug)]
struct WindowedEstimate<TValue> {
    /// Recent builds' values, oldest first, with when they finished.
    samples: VecDeque<(Instant, TValue)>,
    /// In use while no sample is live.
    initial: TValue,
    /// The estimate while a sample is live.
    current: TValue,
    /// Largest change of `current` per observed build.
    max_step: TValue,
}

impl<TValue> WindowedEstimate<TValue>
where
    TValue: Copy + Ord + Add<Output = TValue> + Sub<Output = TValue>,
{
    fn new(initial: TValue, max_step: TValue) -> Self {
        Self {
            samples: VecDeque::with_capacity(SAMPLE_WINDOW),
            initial,
            current: initial,
            max_step,
        }
    }

    /// The estimate at `now`.
    fn get(&self, now: Instant) -> TValue {
        // Samples finish in order, so the newest expires last.
        match self.samples.back() {
            Some((at, _)) if !is_expired(*at, now) => self.current,
            _ => self.initial,
        }
    }

    /// Records a finished build's value and takes at most one step of
    /// `max_step` toward the window's percentile.
    ///
    /// A step up needs the build itself above the estimate and goes at most to
    /// the build's value: the percentile of a sparse window is its largest
    /// value, so without that one slow finish would raise the estimate with
    /// every build until the window filled. A step down only needs the
    /// percentile below the estimate. Expired builds leave the window without
    /// moving the estimate while newer ones are left.
    fn observe(&mut self, now: Instant, observed: TValue) {
        self.current = self.get(now);
        self.samples.retain(|(at, _)| !is_expired(*at, now));
        if self.samples.len() == SAMPLE_WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back((now, observed));

        let mut values: Vec<TValue> = self.samples.iter().map(|(_, value)| *value).collect();
        values.sort_unstable();
        // Rounding the rank up returns a lone sample as is.
        let percentile = values[(values.len() * RESERVE_PERCENTILE).div_ceil(100) - 1];

        let target = percentile.min(observed.max(self.current));
        self.current = if target >= self.current {
            self.current + (target - self.current).min(self.max_step)
        } else {
            self.current - (self.current - target).min(self.max_step)
        };
    }
}

/// Whether a build that finished `at` no longer counts at `now`. `at` may be
/// slightly after `now` when callers read the clock before taking the lock.
fn is_expired(at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(at) > SAMPLE_TTL
}

#[cfg(test)]
mod tests {
    use super::*;

    fn busy(validation_work_ms: u64, at_tx_cutoff_ms: u64) -> FinishedBuild {
        FinishedBuild::new(
            Duration::from_millis(at_tx_cutoff_ms),
            Duration::from_millis(validation_work_ms),
            Duration::ZERO,
        )
    }

    fn dry(validation_work_ms: u64, at_tx_cutoff_ms: u64) -> FinishedBuild {
        FinishedBuild::new(
            Duration::from_millis(at_tx_cutoff_ms),
            Duration::from_millis(validation_work_ms),
            Duration::from_millis(1),
        )
    }

    fn multiplier(value: f64) -> BuildTimeMultiplier {
        BuildTimeMultiplier::new(value).unwrap()
    }

    #[test]
    fn slow_busy_build_raises_multiplier_by_one_step() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(BuildTimeMultiplier::default());
        tracker.observe(now, busy(250, 100));
        assert_eq!(tracker.multiplier(now), multiplier(1.3));
    }

    #[test]
    fn multiplier_rises_at_most_to_the_observed_build() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(BuildTimeMultiplier::default());
        tracker.observe(now, busy(120, 100));
        assert_eq!(tracker.multiplier(now), multiplier(1.2));
    }

    #[test]
    fn faster_build_does_not_raise_multiplier_toward_slow_percentile() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(BuildTimeMultiplier::default());
        tracker.observe(now, busy(250, 100));
        // The window's percentile is still the slow build, but this build was
        // below the estimate, so the estimate does not rise.
        tracker.observe(now, busy(110, 100));
        assert_eq!(tracker.multiplier(now), multiplier(1.3));
    }

    #[test]
    fn multiplier_falls_by_bounded_steps_and_stays_in_range() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(BuildTimeMultiplier::MAX);
        for expected in [1.55, 1.4, 1.25, 1.1, 1.0, 1.0] {
            tracker.observe(now, busy(100, 100));
            assert_eq!(tracker.multiplier(now), multiplier(expected));
        }
        let mut tracker = BuildTimeTracker::new(BuildTimeMultiplier::MAX);
        tracker.observe(now, busy(1_000, 100));
        assert_eq!(tracker.multiplier(now), BuildTimeMultiplier::MAX);
    }

    #[test]
    fn busy_build_without_cutoff_work_teaches_nothing() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(BuildTimeMultiplier::default());
        tracker.observe(now, busy(50, 0));
        assert_eq!(tracker.multiplier(now), BuildTimeMultiplier::default());
        assert_eq!(tracker.dry_finish(now), Duration::ZERO);
    }

    #[test]
    fn dry_build_teaches_dry_finish_not_multiplier() {
        let now = Instant::now();
        let mut tracker = BuildTimeTracker::new(BuildTimeMultiplier::default());
        tracker.observe(now, dry(30, 1));
        assert_eq!(tracker.multiplier(now), BuildTimeMultiplier::default());
        assert_eq!(tracker.dry_finish(now), DRY_FINISH_MAX_STEP);
        tracker.observe(now, dry(30, 1));
        tracker.observe(now, dry(30, 1));
        assert_eq!(tracker.dry_finish(now), Duration::from_millis(29));
    }

    #[test]
    fn partial_expiry_keeps_estimate() {
        let start = Instant::now();
        let mut estimate = WindowedEstimate::new(0u64, 10);
        estimate.observe(start, 100);
        estimate.observe(start + Duration::from_secs(60), 100);
        assert_eq!(estimate.current, 20);
        let later = start + SAMPLE_TTL + Duration::from_secs(1);
        assert_eq!(estimate.get(later), 20);
        estimate.observe(later, 0);
        assert_eq!(estimate.samples.len(), 2);
        assert_eq!(estimate.current, 20);
    }

    #[test]
    fn full_expiry_restarts_from_initial() {
        let start = Instant::now();
        let mut estimate = WindowedEstimate::new(0u64, 10);
        estimate.observe(start, 100);
        let later = start + SAMPLE_TTL + Duration::from_secs(1);
        assert_eq!(estimate.get(later), 0);
        estimate.observe(later, 100);
        assert_eq!(estimate.samples.len(), 1);
        assert_eq!(estimate.current, 10);
    }

    #[test]
    fn window_evicts_oldest_at_capacity() {
        let now = Instant::now();
        let mut estimate = WindowedEstimate::new(0u64, u64::MAX);
        for value in 1..=SAMPLE_WINDOW as u64 + 4 {
            estimate.observe(now, value);
        }
        assert_eq!(estimate.samples.len(), SAMPLE_WINDOW);
        assert_eq!(estimate.samples.front().unwrap().1, 5);
    }
}
