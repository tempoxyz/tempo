//! Shared build-time and validation feedback for paced payloads.

mod build_plan;
mod build_time;
mod network;

pub use build_plan::{BuildPlan, PayloadBudgetDecision};

use std::{
    fmt,
    num::ParseFloatError,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use crate::{ProposalBudget, ValidationLatencyEstimator, ValidationLatencyWorkload};
use build_time::BuildTimeTracker;
use network::{NetworkTracker, PendingProposal};

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
/// met it, see [`Config::return_budget_overrun_tolerance`].
///
/// This is the builder's pacing precision on a dry build, which idles up to its
/// budget in 1 ms steps and returns a millisecond or two late; real overruns
/// under load are tens of milliseconds.
pub const DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE: Duration = Duration::from_millis(5);

/// Lowest accepted network reserve percentile: the median of the window.
const MIN_NETWORK_RESERVE_PERCENTILE: u8 = 50;
/// Highest accepted network reserve percentile: the slowest sample in the window.
const MAX_NETWORK_RESERVE_PERCENTILE: u8 = 100;

/// Identifies a proposal by its own round as `(epoch, view)`: the epoch and
/// the view in which the proposal itself was made, not those of its parent
/// or of the block built on top of it.
pub type ProposalKey = (u64, u64);

/// Static proposal budget configuration, validated at construction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Config {
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
    pub build_time_multiplier: BuildTimeMultiplier,
    /// Maximum accepted proposal overrun; `Duration::MAX` records all proposals.
    pub return_budget_overrun_tolerance: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target_block_time: DEFAULT_TARGET_BLOCK_TIME,
            network_budget: DEFAULT_NETWORK_BUDGET,
            network_budget_max: DEFAULT_NETWORK_BUDGET_MAX,
            network_reserve_percentile: DEFAULT_NETWORK_RESERVE_PERCENTILE,
            network_reserve_fast_rise: true,
            build_time_multiplier: BuildTimeMultiplier::default(),
            return_budget_overrun_tolerance: DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE,
        }
    }
}

impl Config {
    /// Creates a configuration for the given block time and network floor,
    /// with the network cap and build multiplier at their defaults.
    pub fn new(target_block_time: Duration, network_budget: Duration) -> Self {
        Self {
            target_block_time,
            network_budget,
            network_budget_max: Self::default_network_budget_max(target_block_time, network_budget),
            ..Self::default()
        }
    }

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
    pub fn with_build_time_multiplier(
        mut self,
        build_time_multiplier: BuildTimeMultiplier,
    ) -> Self {
        self.build_time_multiplier = build_time_multiplier;
        self
    }

    /// Checks that the reservations leave room for a proposal and that the
    /// learning knobs are in range. [`Estimator::new`] rejects a
    /// configuration that fails this.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.network_budget >= self.target_block_time {
            return Err(ConfigError::NetworkBudget {
                network_budget: self.network_budget,
                target_block_time: self.target_block_time,
            });
        }
        if self.network_budget_max < self.network_budget {
            return Err(ConfigError::NetworkBudgetMaxBelowFloor {
                network_budget_max: self.network_budget_max,
                network_budget: self.network_budget,
            });
        }
        if self.network_budget_max >= self.target_block_time {
            return Err(ConfigError::NetworkBudgetMax {
                network_budget_max: self.network_budget_max,
                target_block_time: self.target_block_time,
            });
        }
        if !(MIN_NETWORK_RESERVE_PERCENTILE..=MAX_NETWORK_RESERVE_PERCENTILE)
            .contains(&self.network_reserve_percentile)
        {
            return Err(ConfigError::NetworkReservePercentile {
                percentile: self.network_reserve_percentile,
            });
        }
        Ok(())
    }
}

/// Why a proposal budget configuration is invalid.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The network floor leaves no time for a proposal.
    #[error(
        "network budget ({network_budget:?}) must be smaller than the target block time ({target_block_time:?})"
    )]
    NetworkBudget {
        /// The configured floor.
        network_budget: Duration,
        /// The configured block interval.
        target_block_time: Duration,
    },
    /// The network cap is below the floor.
    #[error(
        "maximum network budget ({network_budget_max:?}) must not be smaller than the network budget ({network_budget:?})"
    )]
    NetworkBudgetMaxBelowFloor {
        /// The configured cap.
        network_budget_max: Duration,
        /// The configured floor.
        network_budget: Duration,
    },
    /// The network cap leaves no time for a proposal.
    #[error(
        "maximum network budget ({network_budget_max:?}) must be smaller than the target block time ({target_block_time:?})"
    )]
    NetworkBudgetMax {
        /// The configured cap.
        network_budget_max: Duration,
        /// The configured block interval.
        target_block_time: Duration,
    },
    /// The percentile is outside the median-to-maximum range.
    #[error("network reserve percentile ({percentile}) must be between 50 and 100, inclusive")]
    NetworkReservePercentile {
        /// The rejected percentile.
        percentile: u8,
    },
}

/// Cloneable pacing feedback shared by consensus and the payload builder.
///
/// Clones share state: feedback recorded on one is seen by every other.
#[derive(Clone, Debug)]
pub struct Estimator {
    config: Config,
    state: Arc<Mutex<EstimatorState>>,
}

impl Estimator {
    /// Creates an estimator without feedback, or rejects an invalid configuration.
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            state: Arc::new(Mutex::new(EstimatorState {
                validation: ValidationLatencyEstimator::default(),
                build_time: BuildTimeTracker::new(config.build_time_multiplier),
                network: NetworkTracker::new(&config),
            })),
        })
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

    /// Records a proposal that met its budget; clocks use header timestamp milliseconds.
    pub fn on_proposal_returned(
        &self,
        now: Instant,
        window_opened_unix_ms: u64,
        returned_unix_ms: u64,
        key: ProposalKey,
        return_budget: Duration,
    ) {
        self.lock_state().network.proposal_returned(
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

    /// Completes pending samples from finalized children only.
    pub fn on_child_block_built(
        &self,
        now: Instant,
        parent: ProposalKey,
        child_view: u64,
        child_timestamp_ms: u64,
    ) {
        self.lock_state()
            .network
            .child_built(now, parent, child_view, child_timestamp_ms);
    }

    /// Advances the reservation once per own proposal, including failed builds.
    #[must_use]
    pub fn start_proposal(&self, now: Instant) -> ProposalBudget {
        let network_reserve = self.lock_state().network.reserve_for_proposal(now);
        ProposalBudget::new(self.config.target_block_time, network_reserve)
            .with_overrun_tolerance(self.config.return_budget_overrun_tolerance)
    }

    /// Counts completed samples after expiring stale network observations.
    pub fn snapshot(&self, now: Instant) -> EstimatorSnapshot {
        let mut state = self.lock_state();
        state.network.prune(now);
        EstimatorSnapshot {
            network_samples: state.network.sample_count(),
        }
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
    network: NetworkTracker,
}

/// Completed network observations, exposed for deterministic e2e checks.
#[derive(Clone, Copy, Debug)]
pub struct EstimatorSnapshot {
    /// Number of retained finalized-child network samples.
    pub network_samples: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_reservations_that_leave_no_proposal_window() {
        let config = Config {
            network_budget: Config::default().target_block_time,
            ..Config::default()
        };
        assert_eq!(
            config.validate(),
            Err(ConfigError::NetworkBudget {
                network_budget: config.network_budget,
                target_block_time: config.target_block_time,
            })
        );
        let config = Config {
            network_budget_max: Duration::ZERO,
            ..Config::default()
        };
        assert_eq!(
            config.validate(),
            Err(ConfigError::NetworkBudgetMaxBelowFloor {
                network_budget: config.network_budget,
                network_budget_max: Duration::ZERO,
            })
        );
        let config = Config {
            network_budget_max: Config::default().target_block_time,
            ..Config::default()
        };
        assert_eq!(
            config.validate(),
            Err(ConfigError::NetworkBudgetMax {
                network_budget_max: config.network_budget_max,
                target_block_time: config.target_block_time,
            })
        );
        for percentile in [49, 101] {
            assert_eq!(
                Config {
                    network_reserve_percentile: percentile,
                    ..Config::default()
                }
                .validate(),
                Err(ConfigError::NetworkReservePercentile { percentile })
            );
        }
    }

    #[test]
    fn cloned_estimator_shares_network_learning_and_fixed_budget_stays_pinned() {
        let now = Instant::now();
        let estimator = Estimator::new(Config::default()).unwrap();
        let clone = estimator.clone();
        estimator.on_proposal_returned(now, 1_000, 1_500, (1, 1), Duration::from_millis(500));
        clone.on_child_block_built(now, (1, 1), 2, 1_700);
        assert_eq!(estimator.snapshot(now).network_samples, 1);
        assert_eq!(
            estimator.start_proposal(now).network_reserve,
            Duration::from_millis(150)
        );

        let fixed = Estimator::new(Config::fixed(
            Duration::from_millis(500),
            Duration::from_millis(50),
        ))
        .unwrap();
        fixed.on_proposal_returned(now, 1_000, 1_800, (1, 1), Duration::from_millis(500));
        fixed.on_child_block_built(now, (1, 1), 2, 1_900);
        assert_eq!(fixed.snapshot(now).network_samples, 1);
        assert_eq!(
            fixed.start_proposal(now).return_budget,
            Duration::from_millis(500)
        );
    }

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
        let estimator = Estimator::new(Config::default()).unwrap();
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
