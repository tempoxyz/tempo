//! Inputs and validation for the shared estimator.

use super::BuildTimeMultiplier;
use std::time::Duration;

/// Target interval used when no timing configuration is supplied.
pub const DEFAULT_TARGET_BLOCK_TIME: Duration = Duration::from_millis(550);
/// Initial and minimum time from a proposal window's close to its successor header.
pub const DEFAULT_NETWORK_BUDGET: Duration = Duration::from_millis(50);

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
            build_time_multiplier: BuildTimeMultiplier::default(),
            network_reservation_policy: NetworkReservation::Adaptive,
        }
    }

    /// Rejects a network reservation that leaves no positive proposal allowance.
    /// Call before constructing an estimator to return an error instead of panicking.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.network_budget >= self.target_block_time {
            return Err(ConfigError {
                network_budget: self.network_budget,
                target_block_time: self.target_block_time,
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
#[error(
    "network budget ({network_budget:?}) must be smaller than the target block time ({target_block_time:?})"
)]
pub struct ConfigError {
    network_budget: Duration,
    target_block_time: Duration,
}
