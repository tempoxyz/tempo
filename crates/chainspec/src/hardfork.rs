//! Tempo-specific hardfork definitions and traits.
//!
//! This module provides the infrastructure for managing hardfork transitions in Tempo.
//!
//! ## Usage
//!
//! When a new hardfork is needed:
//! 1. Add a new variant to `TempoHardfork` (e.g., `Allegro`, `Vivace`)
//! 2. Add the activation condition to `TempoChainHardforks`
//! 3. Add a convenience method to `TempoHardforks` trait (optional, for ergonomics)
//! 4. Update genesis files with the activation timestamp/block
//! 5. Use hardfork checks in the EVM handler and precompiles to gate new features
//!
//! ## Current State
//!
//! The `Adagio` variant is a placeholder representing the pre-hardfork baseline.

use alloy_hardforks::hardfork;
use reth_chainspec::{EthereumHardforks, ForkCondition};

hardfork!(
    /// Tempo-specific hardforks for network upgrades.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    TempoHardfork {
        /// Placeholder representing the baseline (pre-hardfork) state.
        Adagio,
    }
);

/// Trait for querying Tempo-specific hardfork activations.
pub trait TempoHardforks: EthereumHardforks {
    /// Retrieves activation condition for a Tempo-specific hardfork
    fn tempo_fork_activation(&self, fork: TempoHardfork) -> ForkCondition;

    /// Convenience method to check if Adagio hardfork is active at a given timestamp
    fn is_adagio_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::Adagio)
            .active_at_timestamp(timestamp)
    }
}

/// Configuration for Tempo-specific hardfork activations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempoChainHardforks {
    /// Activation condition for Adagio hardfork
    pub adagio: ForkCondition,
}

impl TempoChainHardforks {
    /// Creates hardforks with Adagio active at genesis (timestamp 0)
    pub fn adagio_at_genesis() -> Self {
        Self {
            adagio: ForkCondition::Timestamp(0),
        }
    }

    /// Retrieves activation condition for a Tempo-specific hardfork
    pub fn tempo_fork_activation(&self, fork: TempoHardfork) -> ForkCondition {
        match fork {
            TempoHardfork::Adagio => self.adagio,
        }
    }

    /// Convenience method to check if Adagio hardfork is active at a given timestamp
    pub fn is_adagio_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::Adagio)
            .active_at_timestamp(timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::Hardfork;

    #[test]
    fn test_adagio_hardfork_name() {
        let fork = TempoHardfork::Adagio;
        assert_eq!(fork.name(), "Adagio");
    }

    #[test]
    fn test_hardfork_trait_implementation() {
        let fork = TempoHardfork::Adagio;
        // Should implement Hardfork trait
        let _name: &str = Hardfork::name(&fork);
    }

    #[test]
    fn test_tempo_chain_hardforks_at_genesis() {
        use reth_chainspec::ForkCondition;

        let hardforks = TempoChainHardforks::adagio_at_genesis();
        assert_eq!(hardforks.adagio, ForkCondition::Timestamp(0));
    }

    #[test]
    fn test_tempo_hardforks_trait_activation_query() {
        use reth_chainspec::ForkCondition;

        let hardforks = TempoChainHardforks::adagio_at_genesis();

        // Should be able to query Adagio fork activation
        let activation = hardforks.tempo_fork_activation(TempoHardfork::Adagio);
        assert_eq!(activation, ForkCondition::Timestamp(0));
    }

    #[test]
    fn test_is_adagio_active_at_timestamp() {
        let hardforks = TempoChainHardforks::adagio_at_genesis();

        // Adagio is active at timestamp 0
        assert!(hardforks.is_adagio_active_at_timestamp(0));

        // Adagio is active at any timestamp >= 0
        assert!(hardforks.is_adagio_active_at_timestamp(1000));
        assert!(hardforks.is_adagio_active_at_timestamp(u64::MAX));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_tempo_hardfork_serde() {
        let fork = TempoHardfork::Adagio;

        // Serialize to JSON
        let json = serde_json::to_string(&fork).unwrap();
        assert_eq!(json, "\"Adagio\"");

        // Deserialize from JSON
        let deserialized: TempoHardfork = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, fork);
    }
}
