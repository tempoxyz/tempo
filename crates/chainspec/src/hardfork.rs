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
//! 5. Update `From<TempoHardfork> for SpecId` if the new hardfork requires a different Ethereum SpecId
//! 6. Add test `test_is_vivace` and update existing `is_*` tests to include the new variant
//!
//! ### In `spec.rs`:
//! 7. Add `vivace_time: Option<u64>` field to `TempoGenesisInfo`
//! 8. Extract `vivace_time` in `TempoChainSpec::from_genesis`
//! 9. Add `(TempoHardfork::Vivace, vivace_time)` to `tempo_forks` vec
//! 10. Update tests to include `"vivaceTime": <timestamp>` in genesis JSON
//!
//! ### In genesis files and generator:
//! 11. Add `"vivaceTime": 0` to `genesis/dev.json`
//! 12. Add `vivace_time: Option<u64>` arg to `xtask/src/genesis_args.rs`
//! 13. Add insertion of `"vivaceTime"` to chain_config.extra_fields
//!
//! ## Current State
//!
//! The `Genesis` variant is a placeholder representing the pre-hardfork baseline.

use alloy_evm::revm::primitives::hardfork::SpecId;
use alloy_hardforks::hardfork;
use reth_chainspec::{EthereumHardforks, ForkCondition};

hardfork!(
    /// Tempo-specific hardforks for network upgrades.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Default)]
    TempoHardfork {
        /// Genesis hardfork
        Genesis,
        #[default]
        /// T0 hardfork (default until T1 activates on mainnet)
        T0,
        /// T1 hardfork - adds expiring nonce transactions
        T1,
        /// T2 hardfork - adds compound transfer policies (TIP-1015)
        T2,
    }
);

impl TempoHardfork {
    /// Returns true if this hardfork is T0 or later.
    pub fn is_t0(&self) -> bool {
        *self >= Self::T0
    }

    /// Returns true if this hardfork is T1 or later.
    pub fn is_t1(&self) -> bool {
        *self >= Self::T1
    }

    /// Returns true if this hardfork is T2 or later.
    pub fn is_t2(&self) -> bool {
        *self >= Self::T2
    }

    /// Returns the base fee for this hardfork.
    /// - Pre-T1: 10 gwei
    /// - T1+: 20 gwei (targets ~0.1 cent per TIP-20 transfer)
    pub const fn base_fee(&self) -> u64 {
        match self {
            Self::T1 | Self::T2 => crate::spec::TEMPO_T1_BASE_FEE,
            Self::T0 | Self::Genesis => crate::spec::TEMPO_T0_BASE_FEE,
        }
    }

    /// Returns the fixed general gas limit for T1+, or None for pre-T1.
    /// - Pre-T1: None
    /// - T1+: 30M gas (fixed)
    pub const fn general_gas_limit(&self) -> Option<u64> {
        match self {
            Self::T1 | Self::T2 => Some(crate::spec::TEMPO_T1_GENERAL_GAS_LIMIT),
            Self::T0 | Self::Genesis => None,
        }
    }

    /// Returns the per-transaction gas limit cap, or None if uncapped.
    /// - Pre-T1: None (no per-tx cap)
    /// - T1+: 30M gas (allows maximum-sized contract deployments under TIP-1000 state creation)
    pub const fn tx_gas_limit_cap(&self) -> Option<u64> {
        match self {
            Self::T1 | Self::T2 => Some(crate::spec::TEMPO_T1_TX_GAS_LIMIT_CAP),
            Self::T0 | Self::Genesis => None,
        }
    }

    /// Gas cost for using an existing 2D nonce key
    pub const fn gas_existing_nonce_key(&self) -> u64 {
        match self {
            Self::Genesis => 0,
            Self::T0 | Self::T1 => crate::spec::TEMPO_T1_EXISTING_NONCE_KEY_GAS,
            Self::T2 => crate::spec::TEMPO_T2_EXISTING_NONCE_KEY_GAS,
        }
    }

    /// Gas cost for using a new 2D nonce key
    pub const fn gas_new_nonce_key(&self) -> u64 {
        match self {
            Self::Genesis => 0,
            Self::T0 | Self::T1 => crate::spec::TEMPO_T1_NEW_NONCE_KEY_GAS,
            Self::T2 => crate::spec::TEMPO_T2_NEW_NONCE_KEY_GAS,
        }
    }
}

/// Trait for querying Tempo-specific hardfork activations.
pub trait TempoHardforks: EthereumHardforks {
    /// Retrieves activation condition for a Tempo-specific hardfork
    fn tempo_fork_activation(&self, fork: TempoHardfork) -> ForkCondition;

    /// Retrieves the Tempo hardfork active at a given timestamp.
    fn tempo_hardfork_at(&self, timestamp: u64) -> TempoHardfork {
        if self.is_t2_active_at_timestamp(timestamp) {
            return TempoHardfork::T2;
        }
        if self.is_t1_active_at_timestamp(timestamp) {
            return TempoHardfork::T1;
        }
        if self.is_t0_active_at_timestamp(timestamp) {
            return TempoHardfork::T0;
        }
        TempoHardfork::Genesis
    }

    /// Returns true if T0 is active at the given timestamp.
    fn is_t0_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T0)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T1 is active at the given timestamp.
    fn is_t1_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T1)
            .active_at_timestamp(timestamp)
    }

    /// Returns true if T2 is active at the given timestamp.
    fn is_t2_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T2)
            .active_at_timestamp(timestamp)
    }

    /// Returns the general (non-payment) gas limit for the given timestamp and block parameters.
    /// - T1+: fixed at 30M gas
    /// - Pre-T1: calculated as (gas_limit - shared_gas_limit) / 2
    fn general_gas_limit_at(&self, timestamp: u64, gas_limit: u64, shared_gas_limit: u64) -> u64 {
        self.tempo_hardfork_at(timestamp)
            .general_gas_limit()
            .unwrap_or_else(|| (gas_limit - shared_gas_limit) / 2)
    }
}

impl From<TempoHardfork> for SpecId {
    fn from(_value: TempoHardfork) -> Self {
        Self::OSAKA
    }
}

impl From<&TempoHardfork> for SpecId {
    fn from(value: &TempoHardfork) -> Self {
        Self::from(*value)
    }
}

impl From<SpecId> for TempoHardfork {
    fn from(_spec: SpecId) -> Self {
        // All Tempo hardforks map to SpecId::OSAKA, so we cannot derive the hardfork from SpecId.
        // Default to the default hardfork when converting from SpecId.
        // The actual hardfork should be passed explicitly where needed.
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::Hardfork;

    #[test]
    fn test_hardfork_name() {
        assert_eq!(TempoHardfork::Genesis.name(), "Genesis");
        assert_eq!(TempoHardfork::T0.name(), "T0");
        assert_eq!(TempoHardfork::T1.name(), "T1");
        assert_eq!(TempoHardfork::T2.name(), "T2");
    }

    #[test]
    fn test_is_t0() {
        assert!(!TempoHardfork::Genesis.is_t0());
        assert!(TempoHardfork::T0.is_t0());
        assert!(TempoHardfork::T1.is_t0());
        assert!(TempoHardfork::T2.is_t0());
    }

    #[test]
    fn test_is_t1() {
        assert!(!TempoHardfork::Genesis.is_t1());
        assert!(!TempoHardfork::T0.is_t1());
        assert!(TempoHardfork::T1.is_t1());
        assert!(TempoHardfork::T2.is_t1());
    }

    #[test]
    fn test_is_t2() {
        assert!(!TempoHardfork::Genesis.is_t2());
        assert!(!TempoHardfork::T0.is_t2());
        assert!(!TempoHardfork::T1.is_t2());
        assert!(TempoHardfork::T2.is_t2());
    }

    #[test]
    fn test_t1_hardfork_name() {
        let fork = TempoHardfork::T1;
        assert_eq!(fork.name(), "T1");
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
