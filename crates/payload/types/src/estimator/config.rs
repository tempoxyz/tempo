//! Inputs and validation for the shared estimator.

use super::BuildTimeMultiplier;
use std::time::Duration;

/// Target interval used when no timing configuration is supplied.
pub const DEFAULT_TARGET_BLOCK_TIME: Duration = Duration::from_millis(550);
/// Initial and minimum time from a proposal window's close to its successor header.
pub const DEFAULT_NETWORK_BUDGET: Duration = Duration::from_millis(50);

/// Largest default learned network reservation.
const DEFAULT_NETWORK_BUDGET_MAX: Duration = Duration::from_millis(300);
/// Percentile followed by network reservation estimates.
pub const DEFAULT_NETWORK_RESERVE_PERCENTILE: u8 = 75;
/// Accepted replay-adjusted overrun when recording returned proposals.
const DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE: Duration = Duration::from_millis(5);

/// How proposal time is reserved for the network.
#[derive(Clone, Copy, Debug)]
pub enum NetworkReservation {
    /// Learn from finalized successors using the configured percentile and fast-rise policy.
    Adaptive,
    /// Keep the configured reservation unchanged and allow overrun observations.
    Fixed,
}

/// Unvalidated estimator inputs. Validation occurs when constructing an estimator.
#[derive(Clone, Copy, Debug)]
pub struct EstimatorConfig {
    /// Target interval between block header timestamps.
    pub target_block_time: Duration,
    /// Initial and minimum network reservation, including propagation, voting,
    /// unprojected validation and the next proposal's preparation.
    pub network_budget: Duration,
    /// Maximum learned network reservation; equal to the floor disables learning.
    pub network_budget_max: Duration,
    /// Reserved network percentile, from 50 to 100 inclusive.
    pub network_reserve_percentile: u8,
    /// Whether two consecutive slow samples can raise the percentile target.
    pub network_reserve_fast_rise: bool,
    /// Maximum accepted proposal overrun; `Duration::MAX` records every proposal.
    pub return_budget_overrun_tolerance: Duration,
    /// Initial build multiplier, also used after five minutes without finished builds.
    pub build_time_multiplier: BuildTimeMultiplier,
    /// Whether the network reservation adapts or stays fixed.
    pub network_reservation_policy: NetworkReservation,
}

impl EstimatorConfig {
    /// Creates unvalidated timing inputs with adaptive network learning and
    /// the default build multiplier. The learned cap is the floor plus half
    /// the initial proposal allowance, capped at 300 ms but never below the floor.
    pub fn new(target_block_time: Duration, network_budget: Duration) -> Self {
        Self {
            target_block_time,
            network_budget,
            network_budget_max: network_budget
                .saturating_add(target_block_time.saturating_sub(network_budget) / 2)
                .min(DEFAULT_NETWORK_BUDGET_MAX)
                .max(network_budget),
            network_reserve_percentile: DEFAULT_NETWORK_RESERVE_PERCENTILE,
            network_reserve_fast_rise: true,
            return_budget_overrun_tolerance: DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE,
            build_time_multiplier: BuildTimeMultiplier::default(),
            network_reservation_policy: NetworkReservation::Adaptive,
        }
    }

    /// Checks that the floor leaves a positive proposal allowance, the adaptive
    /// cap is between the floor (inclusive) and target (exclusive), and the
    /// network percentile is from 50 to 100 inclusive. Fixed reservations ignore
    /// the adaptive cap. Returns an error describing an invalid setting.
    /// Call before constructing an estimator to handle invalid inputs without panicking.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.network_budget >= self.target_block_time {
            return Err(ConfigError(ConfigErrorKind::NetworkBudget {
                network_budget: self.network_budget,
                target_block_time: self.target_block_time,
            }));
        }
        if matches!(
            self.network_reservation_policy,
            NetworkReservation::Adaptive
        ) && (self.network_budget_max < self.network_budget
            || self.network_budget_max >= self.target_block_time)
        {
            return Err(ConfigError(ConfigErrorKind::NetworkBudgetMax {
                network_budget_max: self.network_budget_max,
                network_budget: self.network_budget,
                target_block_time: self.target_block_time,
            }));
        }
        if !(50..=100).contains(&self.network_reserve_percentile) {
            return Err(ConfigError(ConfigErrorKind::NetworkPercentile {
                percentile: self.network_reserve_percentile,
            }));
        }
        Ok(())
    }
}

impl Default for EstimatorConfig {
    fn default() -> Self {
        Self::new(DEFAULT_TARGET_BLOCK_TIME, DEFAULT_NETWORK_BUDGET)
    }
}

/// An invalid estimator configuration, with a human-readable explanation.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ConfigError(ConfigErrorKind);

#[derive(Debug, thiserror::Error)]
enum ConfigErrorKind {
    /// The floor leaves no proposal allowance.
    #[error(
        "network budget ({network_budget:?}) must be smaller than the target block time ({target_block_time:?})"
    )]
    NetworkBudget {
        /// Configured floor.
        network_budget: Duration,
        /// Configured target.
        target_block_time: Duration,
    },
    /// The cap is below the floor or leaves no proposal allowance.
    #[error(
        "maximum network budget ({network_budget_max:?}) must be at least the network budget ({network_budget:?}) and smaller than the target block time ({target_block_time:?})"
    )]
    NetworkBudgetMax {
        /// Configured cap.
        network_budget_max: Duration,
        /// Configured floor.
        network_budget: Duration,
        /// Configured target.
        target_block_time: Duration,
    },
    /// The percentile falls outside the supported range.
    #[error("network reserve percentile ({percentile}) must be between 50 and 100, inclusive")]
    NetworkPercentile {
        /// Configured percentile.
        percentile: u8,
    },
}
