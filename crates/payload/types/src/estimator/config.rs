//! Inputs and validation for the shared estimator.

use super::BuildTimeMultiplier;
use std::time::Duration;

/// Target interval used when no timing configuration is supplied.
pub const DEFAULT_TARGET_BLOCK_TIME: Duration = Duration::from_millis(550);
/// Initial and minimum time from a proposal window's close to its successor header.
pub const DEFAULT_NETWORK_BUDGET: Duration = Duration::from_millis(50);

/// Largest default learned network reservation.
pub const DEFAULT_NETWORK_BUDGET_MAX: Duration = Duration::from_millis(300);
/// Percentile followed by network reservation estimates.
pub const DEFAULT_NETWORK_RESERVE_PERCENTILE: u8 = 75;
/// Accepted timer overshoot when recording returned proposals.
pub const DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE: Duration = Duration::from_millis(5);

/// How proposal time is reserved for the network.
#[derive(Clone, Copy, Debug)]
pub enum NetworkReservation {
    /// Learn from finalized successors, using p75 and corroborated fast rises.
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
            network_budget_max: Self::default_network_budget_max(target_block_time, network_budget),
            network_reserve_percentile: DEFAULT_NETWORK_RESERVE_PERCENTILE,
            network_reserve_fast_rise: true,
            return_budget_overrun_tolerance: DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE,
            build_time_multiplier: BuildTimeMultiplier::default(),
            network_reservation_policy: NetworkReservation::Adaptive,
        }
    }

    /// Default learned cap: the floor plus half the initial proposal allowance,
    /// at most 300 ms and never below the floor.
    pub fn default_network_budget_max(
        target_block_time: Duration,
        network_budget: Duration,
    ) -> Duration {
        network_budget
            .saturating_add(target_block_time.saturating_sub(network_budget) / 2)
            .min(DEFAULT_NETWORK_BUDGET_MAX)
            .max(network_budget)
    }

    /// Rejects a network reservation that leaves no positive proposal allowance.
    /// Call before constructing an estimator to return an error instead of panicking.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.network_budget >= self.target_block_time {
            return Err(ConfigError::NetworkBudget {
                network_budget: self.network_budget,
                target_block_time: self.target_block_time,
            });
        }
        if matches!(
            self.network_reservation_policy,
            NetworkReservation::Adaptive
        ) && (self.network_budget_max < self.network_budget
            || self.network_budget_max >= self.target_block_time)
        {
            return Err(ConfigError::NetworkBudgetMax {
                network_budget_max: self.network_budget_max,
                network_budget: self.network_budget,
                target_block_time: self.target_block_time,
            });
        }
        if !(50..=100).contains(&self.network_reserve_percentile) {
            return Err(ConfigError::NetworkPercentile {
                percentile: self.network_reserve_percentile,
            });
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
pub enum ConfigError {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_learning_controls() {
        let mut config = EstimatorConfig::default();
        for cap in [Duration::ZERO, config.target_block_time] {
            config.network_budget_max = cap;
            assert!(matches!(
                config.validate(),
                Err(ConfigError::NetworkBudgetMax { .. })
            ));
        }
        config.network_budget_max = DEFAULT_NETWORK_BUDGET_MAX;
        for percentile in [49, 101] {
            config.network_reserve_percentile = percentile;
            assert!(
                matches!(config.validate(), Err(ConfigError::NetworkPercentile { percentile: actual }) if actual == percentile)
            );
        }
        for percentile in [50, 100] {
            config.network_reserve_percentile = percentile;
            assert!(config.validate().is_ok());
        }
    }

    #[test]
    fn fixed_policy_does_not_validate_unused_cap() {
        let config = EstimatorConfig {
            target_block_time: Duration::from_millis(100),
            network_reservation_policy: NetworkReservation::Fixed,
            ..EstimatorConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn derived_cap_leaves_proposal_allowance() {
        for (target, floor, cap) in [(550, 50, 300), (100, 50, 75), (1000, 400, 400)] {
            let config =
                EstimatorConfig::new(Duration::from_millis(target), Duration::from_millis(floor));
            assert_eq!(config.network_budget_max, Duration::from_millis(cap));
            assert!(config.validate().is_ok());
        }
    }
}
