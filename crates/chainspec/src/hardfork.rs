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

use alloy_eips::eip7825::MAX_TX_GAS_LIMIT_OSAKA;
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
        /// T1A hardfork - removes EIP-7825 per-transaction gas limit
        T1A,
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

    /// Returns true if this hardfork is T1A or later.
    pub fn is_t1a(&self) -> bool {
        *self >= Self::T1A
    }

    /// Returns true if this hardfork is T2 or later.
    pub fn is_t2(&self) -> bool {
        *self >= Self::T2
    }

    /// Returns the base fee for this hardfork in attodollars.
    ///
    /// Attodollars are the atomic gas accounting units at 10^-18 USD precision. Individual attodollars are not representable onchain (since TIP-20 tokens only have 6 decimals), but the unit is used for gas accounting.
    /// - Pre-T1: 10 billion attodollars per gas
    /// - T1+: 20 billion attodollars per gas (targets ~0.1 cent per TIP-20 transfer)
    ///
    /// Economic conversion: ceil(basefee × gas_used / 10^12) = cost in microdollars (TIP-20 tokens)
    pub const fn base_fee(&self) -> u64 {
        match self {
            Self::T1 | Self::T1A | Self::T2 => crate::spec::TEMPO_T1_BASE_FEE,
            Self::T0 | Self::Genesis => crate::spec::TEMPO_T0_BASE_FEE,
        }
    }

    /// Returns the fixed general gas limit for T1+, or None for pre-T1.
    /// - Pre-T1: None
    /// - T1+: 30M gas (fixed)
    pub const fn general_gas_limit(&self) -> Option<u64> {
        match self {
            Self::T1 | Self::T1A | Self::T2 => Some(crate::spec::TEMPO_T1_GENERAL_GAS_LIMIT),
            Self::T0 | Self::Genesis => None,
        }
    }

    /// Returns the per-transaction gas limit cap.
    /// - Pre-T1A: EIP-7825 Osaka limit (16,777,216 gas)
    /// - T1A+: 30M gas (allows maximum-sized contract deployments under TIP-1000 state creation)
    pub const fn tx_gas_limit_cap(&self) -> Option<u64> {
        match self {
            Self::T1A | Self::T2 => Some(crate::spec::TEMPO_T1_TX_GAS_LIMIT_CAP),
            Self::T0 | Self::Genesis | Self::T1 => Some(MAX_TX_GAS_LIMIT_OSAKA),
        }
    }

    /// Gas cost for using an existing 2D nonce key
    pub const fn gas_existing_nonce_key(&self) -> u64 {
        match self {
            Self::Genesis | Self::T0 | Self::T1 | Self::T1A => {
                crate::spec::TEMPO_T1_EXISTING_NONCE_KEY_GAS
            }
            Self::T2 => crate::spec::TEMPO_T2_EXISTING_NONCE_KEY_GAS,
        }
    }

    /// Gas cost for using a new 2D nonce key
    pub const fn gas_new_nonce_key(&self) -> u64 {
        match self {
            Self::Genesis | Self::T0 | Self::T1 | Self::T1A => {
                crate::spec::TEMPO_T1_NEW_NONCE_KEY_GAS
            }
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
        if self.is_t1a_active_at_timestamp(timestamp) {
            return TempoHardfork::T1A;
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

    /// Returns true if T1A is active at the given timestamp.
    fn is_t1a_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.tempo_fork_activation(TempoHardfork::T1A)
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
        assert_eq!(TempoHardfork::T1A.name(), "T1A");
        assert_eq!(TempoHardfork::T2.name(), "T2");
    }

    #[test]
    fn test_is_t0() {
        assert!(!TempoHardfork::Genesis.is_t0());
        assert!(TempoHardfork::T0.is_t0());
        assert!(TempoHardfork::T1.is_t0());
        assert!(TempoHardfork::T1A.is_t0());
        assert!(TempoHardfork::T2.is_t0());
    }

    #[test]
    fn test_is_t1() {
        assert!(!TempoHardfork::Genesis.is_t1());
        assert!(!TempoHardfork::T0.is_t1());
        assert!(TempoHardfork::T1.is_t1());
        assert!(TempoHardfork::T1A.is_t1());
        assert!(TempoHardfork::T2.is_t1());
    }

    #[test]
    fn test_is_t1a() {
        assert!(!TempoHardfork::Genesis.is_t1a());
        assert!(!TempoHardfork::T0.is_t1a());
        assert!(!TempoHardfork::T1.is_t1a());
        assert!(TempoHardfork::T1A.is_t1a());
        assert!(TempoHardfork::T2.is_t1a());
    }

    #[test]
    fn test_is_t2() {
        assert!(!TempoHardfork::Genesis.is_t2());
        assert!(!TempoHardfork::T0.is_t2());
        assert!(!TempoHardfork::T1.is_t2());
        assert!(!TempoHardfork::T1A.is_t2());
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

    #[test]
    fn test_base_fee_values() {
        // Pre-T1 variants use T0 base fee (10 billion)
        assert_eq!(TempoHardfork::Genesis.base_fee(), 10_000_000_000);
        assert_eq!(TempoHardfork::T0.base_fee(), 10_000_000_000);
        // T1+ variants use T1 base fee (20 billion)
        assert_eq!(TempoHardfork::T1.base_fee(), 20_000_000_000);
        assert_eq!(TempoHardfork::T1A.base_fee(), 20_000_000_000);
        assert_eq!(TempoHardfork::T2.base_fee(), 20_000_000_000);
        // Ensure no variant returns 0 or 1
        for fork in [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T1A,
            TempoHardfork::T2,
        ] {
            assert!(fork.base_fee() > 1, "base_fee must not be 0 or 1");
        }
    }

    #[test]
    fn test_general_gas_limit_values() {
        // Pre-T1 returns None
        assert_eq!(TempoHardfork::Genesis.general_gas_limit(), None);
        assert_eq!(TempoHardfork::T0.general_gas_limit(), None);
        // T1+ returns Some(30_000_000)
        assert_eq!(TempoHardfork::T1.general_gas_limit(), Some(30_000_000));
        assert_eq!(TempoHardfork::T1A.general_gas_limit(), Some(30_000_000));
        assert_eq!(TempoHardfork::T2.general_gas_limit(), Some(30_000_000));
        // Ensure T1+ values are not 0 or 1
        assert_ne!(TempoHardfork::T1.general_gas_limit(), Some(0));
        assert_ne!(TempoHardfork::T1.general_gas_limit(), Some(1));
    }

    #[test]
    fn test_tx_gas_limit_cap_values() {
        // Pre-T1A returns EIP-7825 Osaka limit (16,777,216)
        assert_eq!(
            TempoHardfork::Genesis.tx_gas_limit_cap(),
            Some(MAX_TX_GAS_LIMIT_OSAKA)
        );
        assert_eq!(
            TempoHardfork::T0.tx_gas_limit_cap(),
            Some(MAX_TX_GAS_LIMIT_OSAKA)
        );
        assert_eq!(
            TempoHardfork::T1.tx_gas_limit_cap(),
            Some(MAX_TX_GAS_LIMIT_OSAKA)
        );
        // T1A+ returns Some(30_000_000)
        assert_eq!(TempoHardfork::T1A.tx_gas_limit_cap(), Some(30_000_000));
        assert_eq!(TempoHardfork::T2.tx_gas_limit_cap(), Some(30_000_000));
        // All variants return Some (never None)
        for fork in [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T1A,
            TempoHardfork::T2,
        ] {
            assert!(fork.tx_gas_limit_cap().is_some());
            assert_ne!(fork.tx_gas_limit_cap(), Some(0));
            assert_ne!(fork.tx_gas_limit_cap(), Some(1));
        }
    }

    #[test]
    fn test_gas_existing_nonce_key_values() {
        // COLD_SLOAD(2100) + WARM_SSTORE_RESET(2900) = 5000
        assert_eq!(TempoHardfork::Genesis.gas_existing_nonce_key(), 5000);
        assert_eq!(TempoHardfork::T0.gas_existing_nonce_key(), 5000);
        assert_eq!(TempoHardfork::T1.gas_existing_nonce_key(), 5000);
        assert_eq!(TempoHardfork::T1A.gas_existing_nonce_key(), 5000);
        // T2: 5000 + 2*WARM_SLOAD(100) = 5200
        assert_eq!(TempoHardfork::T2.gas_existing_nonce_key(), 5200);
        // Ensure no variant returns 0 or 1
        for fork in [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T1A,
            TempoHardfork::T2,
        ] {
            assert!(fork.gas_existing_nonce_key() > 1);
        }
    }

    #[test]
    fn test_gas_new_nonce_key_values() {
        // COLD_SLOAD(2100) + SSTORE_SET(20000) = 22100
        assert_eq!(TempoHardfork::Genesis.gas_new_nonce_key(), 22100);
        assert_eq!(TempoHardfork::T0.gas_new_nonce_key(), 22100);
        assert_eq!(TempoHardfork::T1.gas_new_nonce_key(), 22100);
        assert_eq!(TempoHardfork::T1A.gas_new_nonce_key(), 22100);
        // T2: 22100 + 2*WARM_SLOAD(100) = 22300
        assert_eq!(TempoHardfork::T2.gas_new_nonce_key(), 22300);
        // Ensure no variant returns 0 or 1
        for fork in [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T1A,
            TempoHardfork::T2,
        ] {
            assert!(fork.gas_new_nonce_key() > 1);
        }
    }

    #[test]
    fn test_from_tempo_hardfork_for_spec_id() {
        // All TempoHardfork variants map to SpecId::OSAKA
        assert_eq!(SpecId::from(TempoHardfork::Genesis), SpecId::OSAKA);
        assert_eq!(SpecId::from(TempoHardfork::T0), SpecId::OSAKA);
        assert_eq!(SpecId::from(TempoHardfork::T1), SpecId::OSAKA);
        assert_eq!(SpecId::from(TempoHardfork::T1A), SpecId::OSAKA);
        assert_eq!(SpecId::from(TempoHardfork::T2), SpecId::OSAKA);
        // Ensure it doesn't return default (which would be FRONTIER = 0)
        assert_ne!(SpecId::from(TempoHardfork::Genesis), SpecId::default());
    }

    #[test]
    fn test_general_gas_limit_at_arithmetic() {
        use crate::spec::TempoChainSpec;

        // Build a chain spec with T1 active at timestamp 100
        let genesis: alloy_genesis::Genesis = serde_json::from_str(
            r#"{
                "config": { "chainId": 9999, "t0Time": 0, "t1Time": 100 },
                "alloc": {}
            }"#,
        )
        .unwrap();
        let cs = TempoChainSpec::from_genesis(genesis);

        // At T1 (timestamp >= 100), general_gas_limit_at returns the fixed value
        assert_eq!(
            cs.general_gas_limit_at(100, 60_000_000, 10_000_000),
            30_000_000
        );
        assert_eq!(cs.general_gas_limit_at(200, 100_000_000, 0), 30_000_000);

        // Pre-T1 (timestamp < 100), formula: (gas_limit - shared_gas_limit) / 2
        // (60_000_000 - 10_000_000) / 2 = 25_000_000
        assert_eq!(
            cs.general_gas_limit_at(50, 60_000_000, 10_000_000),
            25_000_000
        );
        // (100_000_000 - 0) / 2 = 50_000_000
        assert_eq!(cs.general_gas_limit_at(0, 100_000_000, 0), 50_000_000);
        // (1000 - 0) / 2 = 500 (detects / vs %, / vs *, - vs +, - vs /)
        assert_eq!(cs.general_gas_limit_at(0, 1000, 0), 500);
        // (100 - 50) / 2 = 25
        assert_eq!(cs.general_gas_limit_at(0, 100, 50), 25);
    }
}
