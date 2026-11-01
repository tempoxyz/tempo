//! Shared build-time and validation feedback for paced payloads.

mod build_plan;
mod build_time;

pub use build_plan::{BuildPlan, PayloadBudgetDecision};

use std::{
    fmt,
    num::ParseFloatError,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use crate::{ValidationLatencyEstimator, ValidationLatencyWorkload};
use build_time::BuildTimeTracker;

/// Static configuration of the shared proposal budget estimator.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Build time multiplier the estimator starts from, and returns to once it
    /// has seen no finished build for a while.
    pub build_time_multiplier: BuildTimeMultiplier,
}

/// Cloneable pacing feedback shared by consensus and the payload builder.
///
/// Clones share state: feedback recorded on one is seen by every other.
#[derive(Clone, Debug)]
pub struct Estimator {
    state: Arc<Mutex<EstimatorState>>,
}

impl Estimator {
    /// Creates an estimator without any feedback yet.
    pub fn new(config: Config) -> Self {
        Self {
            state: Arc::new(Mutex::new(EstimatorState {
                validation: ValidationLatencyEstimator::default(),
                build_time: BuildTimeTracker::new(config.build_time_multiplier),
            })),
        }
    }

    /// Records successful local execution-layer verification, keyed by height.
    pub fn on_block_verified(
        &self,
        height: u64,
        workload: ValidationLatencyWorkload,
        elapsed: Duration,
    ) {
        self.lock_state()
            .validation
            .observe(height, workload, elapsed);
    }

    /// Snapshots the current feedback for one paced payload build.
    ///
    /// `now` is the current monotonic time. Finished builds older than five
    /// minutes at `now` no longer count; with none left, the plan uses the
    /// configured multiplier and no dry build finish, as after startup.
    pub fn build_plan(&self, now: Instant, build_budget: Duration) -> BuildPlan {
        let state = self.lock_state();
        BuildPlan::new(
            build_budget,
            state.build_time.multiplier(now),
            state.build_time.dry_finish(now),
            state.validation.estimate(),
        )
    }

    /// Records a payload build that finished at `now`, the current monotonic
    /// time, for the plans of later builds.
    pub fn on_build_finished(&self, now: Instant, finished_build: FinishedBuild) {
        self.lock_state().build_time.observe(now, finished_build);
    }

    /// Locks the shared state, blocking while another clone holds it.
    fn lock_state(&self) -> MutexGuard<'_, EstimatorState> {
        // The state is plain data and remains usable after a poisoned update.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Ratio of a payload build's total replayable work to its work at the
/// transaction cutoff, from 1.0 to 1.7 inclusive.
///
/// Parses from and displays as a decimal number such as `1.15`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BuildTimeMultiplier {
    /// Fixed point, [`Self::SCALE`] units per 1.0, within [`Self::MIN`] to [`Self::MAX`].
    scaled: u64,
}

impl BuildTimeMultiplier {
    const SCALE: u64 = 1_000_000;
    /// Builder work never shrinks after the transaction cutoff.
    const MIN: Self = Self {
        scaled: Self::SCALE,
    };
    /// Observed ratios above it are learned as it.
    const MAX: Self = Self { scaled: 1_700_000 };
    const DEFAULT: Self = Self { scaled: 1_150_000 };

    /// Creates a multiplier, or returns why `multiplier` is outside 1.0 to 1.7.
    pub fn new(multiplier: f64) -> Result<Self, Error> {
        // `contains` is false for NaN and infinities too.
        if !(Self::MIN.get()..=Self::MAX.get()).contains(&multiplier) {
            return Err(Error::OutOfRange { multiplier });
        }
        Ok(Self {
            scaled: (multiplier * Self::SCALE as f64).round() as u64,
        })
    }

    /// The multiplier as a decimal number.
    pub fn get(self) -> f64 {
        self.scaled as f64 / Self::SCALE as f64
    }

    /// Creates a multiplier from fixed-point units, clamped to the valid range.
    fn from_scaled_clamped(scaled: u64) -> Self {
        Self {
            scaled: scaled.clamp(Self::MIN.scaled, Self::MAX.scaled),
        }
    }

    /// Multiplies `duration`, saturating at the largest `Duration` in nanoseconds.
    fn apply(self, duration: Duration) -> Duration {
        let nanos =
            duration.as_nanos().saturating_mul(u128::from(self.scaled)) / u128::from(Self::SCALE);
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

impl Default for BuildTimeMultiplier {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for BuildTimeMultiplier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

impl FromStr for BuildTimeMultiplier {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value.parse()?)
    }
}

/// Why a [`BuildTimeMultiplier`] could not be created.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum Error {
    /// The text is not a decimal number.
    #[error("build time multiplier is not a number")]
    Parse(#[from] ParseFloatError),
    /// The multiplier is outside 1.0 to 1.7.
    #[error("build time multiplier ({multiplier}) must be between 1 and 1.7")]
    OutOfRange {
        /// The rejected multiplier.
        multiplier: f64,
    },
}

/// Timings of a finished payload build.
#[derive(Clone, Copy, Debug)]
pub struct FinishedBuild {
    validation_work_at_tx_cutoff: Duration,
    validation_work: Duration,
    idle_elapsed: Duration,
}

impl FinishedBuild {
    /// Creates the timings of a finished build.
    ///
    /// `validation_work_at_tx_cutoff` is the replayable work done when pool
    /// transaction execution stopped, `validation_work` the replayable work
    /// done once the payload was finalized, so at least the former; neither
    /// includes `idle_elapsed`, the time spent waiting for the pool to yield
    /// more transactions. `idle_elapsed` is zero for a busy build, one that kept
    /// executing transactions until its budget or a block limit stopped it, and
    /// not zero for a dry build, one whose pool ran dry before its budget did.
    pub fn new(
        validation_work_at_tx_cutoff: Duration,
        validation_work: Duration,
        idle_elapsed: Duration,
    ) -> Self {
        debug_assert!(
            validation_work >= validation_work_at_tx_cutoff,
            "validation work shrank after the transaction cutoff"
        );
        Self {
            validation_work_at_tx_cutoff,
            validation_work,
            idle_elapsed,
        }
    }
}

#[derive(Debug)]
struct EstimatorState {
    validation: ValidationLatencyEstimator,
    build_time: BuildTimeTracker,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_time_multiplier_accepts_valid_range_inclusive() {
        for multiplier in [1.0, 1.15, 1.7] {
            assert_eq!(
                BuildTimeMultiplier::new(multiplier).unwrap().get(),
                multiplier
            );
        }
        assert_eq!(BuildTimeMultiplier::default().get(), 1.15);
        assert_eq!("1.35".parse::<BuildTimeMultiplier>().unwrap().get(), 1.35);
        assert_eq!(BuildTimeMultiplier::default().to_string(), "1.15");
    }

    #[test]
    fn build_time_multiplier_rejects_values_outside_valid_range() {
        for multiplier in [0.99, 1.71, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                BuildTimeMultiplier::new(multiplier),
                Err(Error::OutOfRange { multiplier })
            );
        }
        assert!(matches!(
            BuildTimeMultiplier::new(f64::NAN),
            Err(Error::OutOfRange { multiplier }) if multiplier.is_nan()
        ));
        assert!(matches!(
            "fast".parse::<BuildTimeMultiplier>(),
            Err(Error::Parse(_))
        ));
        assert_eq!(
            Error::OutOfRange { multiplier: 2.0 }.to_string(),
            "build time multiplier (2) must be between 1 and 1.7"
        );
    }

    #[test]
    fn build_time_multiplier_applies_and_clamps_fixed_point() {
        let multiplier = BuildTimeMultiplier::new(1.35).unwrap();
        assert_eq!(
            multiplier.apply(Duration::from_millis(100)),
            Duration::from_millis(135)
        );
        assert_eq!(
            BuildTimeMultiplier::from_scaled_clamped(0),
            BuildTimeMultiplier::MIN
        );
        assert_eq!(
            BuildTimeMultiplier::from_scaled_clamped(u64::MAX),
            BuildTimeMultiplier::MAX
        );
    }

    #[test]
    fn expired_builds_reset_plan_to_configured_values() {
        let start = Instant::now();
        let estimator = Estimator::new(Config::default());
        estimator.on_build_finished(
            start,
            FinishedBuild::new(
                Duration::from_millis(100),
                Duration::from_millis(250),
                Duration::ZERO,
            ),
        );
        estimator.on_build_finished(
            start,
            FinishedBuild::new(
                Duration::from_millis(1),
                Duration::from_millis(30),
                Duration::from_millis(1),
            ),
        );

        let plan = estimator.build_plan(start + build_time::SAMPLE_TTL, Duration::MAX);
        assert_eq!(plan.build_time_multiplier().get(), 1.3);
        assert_eq!(plan.dry_finish(), build_time::DRY_FINISH_MAX_STEP);

        let plan = estimator.build_plan(
            start + build_time::SAMPLE_TTL + Duration::from_nanos(1),
            Duration::MAX,
        );
        assert_eq!(plan.build_time_multiplier(), BuildTimeMultiplier::default());
        assert_eq!(plan.dry_finish(), Duration::ZERO);
    }
}
