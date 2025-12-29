//! Tempo-specific hardfork definitions and traits.
//!
//! This module provides the infrastructure for managing hardfork transitions in Tempo.

use alloy_evm::revm::primitives::hardfork::SpecId;
use alloy_hardforks::hardfork;
use reth_chainspec::{EthereumHardforks, ForkCondition};

hardfork!(
    /// Tempo-specific hardforks for network upgrades.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Default)]
    TempoHardfork {
        /// The current Tempo hardfork (genesis).
        #[default]
        Genesis,
    }
);

/// Trait for querying Tempo-specific hardfork activations.
pub trait TempoHardforks: EthereumHardforks {
    /// Retrieves activation condition for a Tempo-specific hardfork
    fn tempo_fork_activation(&self, fork: TempoHardfork) -> ForkCondition;

    /// Retrieves the Tempo hardfork active at a given timestamp.
    fn tempo_hardfork_at(&self, _timestamp: u64) -> TempoHardfork {
        TempoHardfork::Genesis
    }
}

impl From<TempoHardfork> for SpecId {
    fn from(_value: TempoHardfork) -> Self {
        Self::OSAKA
    }
}

impl From<SpecId> for TempoHardfork {
    fn from(_spec: SpecId) -> Self {
        Self::Genesis
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::Hardfork;

    #[test]
    fn test_genesis_hardfork_name() {
        let fork = TempoHardfork::Genesis;
        assert_eq!(fork.name(), "Genesis");
    }

    #[test]
    fn test_hardfork_trait_implementation() {
        let fork = TempoHardfork::Genesis;
        // Should implement Hardfork trait
        let _name: &str = Hardfork::name(&fork);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_tempo_hardfork_serde() {
        let fork = TempoHardfork::Genesis;

        // Serialize to JSON
        let json = serde_json::to_string(&fork).unwrap();
        assert_eq!(json, "\"Genesis\"");

        // Deserialize from JSON
        let deserialized: TempoHardfork = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, fork);
    }
}
