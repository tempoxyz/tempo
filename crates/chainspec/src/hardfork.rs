//! Tempo-specific hardfork definitions and traits.
//!
//! This module provides the infrastructure for managing hardfork transitions in Tempo.
//!
//! ## Usage
//!
//! When a new hardfork is needed:
//! 1. Add a new variant to `TempoHardfork` (e.g., `Allegro`, `Vivace`)
//! 2. Add a field to `TempoGenesisInfo` in `spec.rs` (e.g., `allegro_time: Option<u64>`)
//! 3. Add the hardfork to the `tempo_hardfork_opts` array in `TempoChainSpec::from_genesis`
//! 4. Add a convenience method to `TempoHardforks` trait (optional, for ergonomics)
//! 5. Update genesis files with the activation timestamp (e.g., `"allegroTime": 1234567890`)
//! 6. Use hardfork checks in the EVM handler and precompiles to gate new features
//!
//! ## Current State
//!
//! The `Adagio` variant is a placeholder representing the pre-hardfork baseline.

use alloy_hardforks::hardfork;
use reth_chainspec::{EthereumHardforks, ForkCondition};
use reth_ethereum::evm::revm::primitives::hardfork::SpecId;

hardfork!(
    /// Tempo-specific hardforks for network upgrades.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Default)]
    TempoHardfork {
        /// Placeholder representing the baseline (pre-hardfork) state.
        #[default]
        Adagio,
        /// Testnet hardfork for Andantino. To be removed before mainnet launch.
        Moderato,
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

    /// Convenience method to check if Andantino hardfork is active at a given timestamp
    fn is_moderato_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::Moderato)
            .active_at_timestamp(timestamp)
    }

    /// Retrieves the latest Tempo hardfork active at a given timestamp.
    fn tempo_hardfork_at(&self, timestamp: u64) -> TempoHardfork {
        if self.is_moderato_active_at_timestamp(timestamp) {
            TempoHardfork::Moderato
        } else {
            TempoHardfork::Adagio
        }
    }
}

impl From<TempoHardfork> for SpecId {
    fn from(value: TempoHardfork) -> Self {
        match value {
            TempoHardfork::Adagio => Self::OSAKA,
            TempoHardfork::Moderato => Self::OSAKA,
        }
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
