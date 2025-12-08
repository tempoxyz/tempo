//! Tempo-specific hardfork definitions and traits.
//!
//! This module provides the infrastructure for managing hardfork transitions in Tempo.
//!
//! ## Adding a New Hardfork
//!
//! When a new hardfork is needed (e.g., `Vivace`):
//!
//! ### In `hardfork.rs`:
//! 1. Add a new variant to `TempoHardfork` enum
//! 2. Add `is_vivace()` method to `TempoHardfork` impl
//! 3. Add `is_vivace_active_at_timestamp()` to `TempoHardforks` trait
//! 4. Update `tempo_hardfork_at()` to check for the new hardfork first (latest hardfork is checked first)
//! 5. Add `TempoHardfork::Vivace => Self::OSAKA` (or appropriate SpecId) in `From<TempoHardfork> for SpecId`
//! 6. Update `From<SpecId> for TempoHardfork` to check for the new hardfork first
//! 7. Add test `test_is_vivace` and update existing `is_*` tests to include the new variant
//!
//! ### In `spec.rs`:
//! 8. Add `vivace_time: Option<u64>` field to `TempoGenesisInfo`
//! 9. Extract `vivace_time` in `TempoChainSpec::from_genesis`
//! 10. Add `(TempoHardfork::Vivace, vivace_time)` to `tempo_forks` vec
//! 11. Update tests to include `"vivaceTime": <timestamp>` in genesis JSON
//!
//! ### In genesis files and generator:
//! 12. Add `"vivaceTime": 0` to `genesis/dev.json`
//! 13. Add `vivace_time: Option<u64>` arg to `xtask/src/genesis_args.rs`
//! 14. Add insertion of `"vivaceTime"` to chain_config.extra_fields
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
        Adagio,
        /// Testnet hardforks for Andantino. To be removed before mainnet launch.
        Moderato,
        /// Allegretto hardfork.
        #[default]
        Allegretto,
        /// Allegro-Moderato hardfork.
        AllegroModerato,
    }
);

impl TempoHardfork {
    /// Returns `true` if this hardfork is Moderato or later.
    #[inline]
    pub fn is_moderato(self) -> bool {
        self >= Self::Moderato
    }

    /// Returns `true` if this hardfork is Allegretto or later.
    pub fn is_allegretto(self) -> bool {
        self >= Self::Allegretto
    }

    /// Returns `true` if this hardfork is Allegro-Moderato or later.
    pub fn is_allegro_moderato(self) -> bool {
        self >= Self::AllegroModerato
    }
}

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

    /// Convenience method to check if Allegretto hardfork is active at a given timestamp
    fn is_allegretto_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::Allegretto)
            .active_at_timestamp(timestamp)
    }

    /// Convenience method to check if Allegro-Moderato hardfork is active at a given timestamp
    fn is_allegro_moderato_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::AllegroModerato)
            .active_at_timestamp(timestamp)
    }

    /// Retrieves the latest Tempo hardfork active at a given timestamp.
    fn tempo_hardfork_at(&self, timestamp: u64) -> TempoHardfork {
        if self.is_allegro_moderato_active_at_timestamp(timestamp) {
            TempoHardfork::AllegroModerato
        } else if self.is_allegretto_active_at_timestamp(timestamp) {
            TempoHardfork::Allegretto
        } else if self.is_moderato_active_at_timestamp(timestamp) {
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
            TempoHardfork::Allegretto => Self::OSAKA,
            TempoHardfork::AllegroModerato => Self::OSAKA,
        }
    }
}

impl From<SpecId> for TempoHardfork {
    /// Maps a [`SpecId`] to the *latest compatible* [`TempoHardfork`].
    ///
    /// Note: this is intentionally not a strict inverse of
    /// `From<TempoHardfork> for SpecId`, because multiple Tempo
    /// hardforks may share the same underlying EVM spec.
    fn from(spec: SpecId) -> Self {
        if spec.is_enabled_in(SpecId::from(Self::AllegroModerato)) {
            Self::AllegroModerato
        } else if spec.is_enabled_in(SpecId::from(Self::Allegretto)) {
            Self::Allegretto
        } else if spec.is_enabled_in(SpecId::from(Self::Moderato)) {
            Self::Moderato
        } else {
            Self::Adagio
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

    #[test]
    fn test_is_moderato() {
        assert!(!TempoHardfork::Adagio.is_moderato());
        assert!(TempoHardfork::Moderato.is_moderato());
        assert!(TempoHardfork::Allegretto.is_moderato());
        assert!(TempoHardfork::AllegroModerato.is_moderato());
    }

    #[test]
    fn test_is_allegretto() {
        assert!(!TempoHardfork::Adagio.is_allegretto());
        assert!(!TempoHardfork::Moderato.is_allegretto());

        assert!(TempoHardfork::Allegretto.is_allegretto());
        assert!(TempoHardfork::AllegroModerato.is_allegretto());

        assert!(TempoHardfork::Allegretto.is_moderato());
    }

    #[test]
    fn test_is_allegro_moderato() {
        assert!(!TempoHardfork::Adagio.is_allegro_moderato());
        assert!(!TempoHardfork::Moderato.is_allegro_moderato());
        assert!(!TempoHardfork::Allegretto.is_allegro_moderato());

        assert!(TempoHardfork::AllegroModerato.is_allegro_moderato());

        assert!(TempoHardfork::AllegroModerato.is_allegretto());
        assert!(TempoHardfork::AllegroModerato.is_moderato());
    }
}
