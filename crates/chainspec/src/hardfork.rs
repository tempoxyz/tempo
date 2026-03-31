//! Tempo-specific hardfork definitions and traits.
//!
//! This module provides the infrastructure for managing hardfork transitions in Tempo.
//!
//! ## Adding a New Hardfork
//!
//! When a new hardfork is needed (e.g., `Vivace`):
//!
//! ### In `hardfork.rs`:
//! 1. Append a `Vivace` variant to `tempo_hardfork!` — automatically:
//!    * defines the enum variant via [`hardfork!`]
//!    * implements trait `TempoHardforks` by adding `is_vivace()`, `is_vivace_active_at_timestamp()`,
//!      and updating `tempo_hardfork_at()`
//!    * adds tests for each of the `TempoHardfork` methods
//! 2. Update `From<TempoHardfork> for SpecId` if the hardfork requires a different Ethereum `SpecId`
//!
//! ### In `spec.rs`:
//! 3. Add `vivace_time: Option<u64>` field to `TempoGenesisInfo`
//! 4. Add `TempoHardfork::Vivace => self.vivace_time` arm to `TempoGenesisInfo::fork_time()`
//!
//! ### In genesis files and generator:
//! 5. Add `"vivaceTime": 0` to `genesis/dev.json`
//! 6. Add `vivace_time: Option<u64>` arg to `xtask/src/genesis_args.rs`
//! 7. Add insertion of `"vivaceTime"` to chain_config.extra_fields

use alloy_eips::eip7825::MAX_TX_GAS_LIMIT_OSAKA;
use alloy_evm::revm::primitives::hardfork::SpecId;
use alloy_hardforks::hardfork;
use reth_chainspec::{EthereumHardforks, ForkCondition};

/// Single-source hardfork definition macro. Append a new variant and everything else is generated:
///
/// * Defines the `TempoHardfork` enum via [`hardfork!`] (including `Display`, `FromStr`,
///   `Hardfork` trait impl, and `VARIANTS` const)
/// * Generates `is_<fork>()` inherent methods on `TempoHardfork` — returns `true` when
///   `*self >= Self::<Fork>`
/// * Generates the `TempoHardforks` trait with:
///   - `tempo_fork_activation()` (required — the only method implementors provide)
///   - `tempo_hardfork_at()` — walks `VARIANTS` in reverse to find the latest active fork
///   - `is_<fork>_active_at_timestamp()` — per-fork convenience helpers
///   - `general_gas_limit_at()` — gas limit lookup by timestamp
/// * Generates a `#[cfg(test)] mod tests` with activation, naming, trait, and serde tests
///
/// `Genesis` (first variant) is treated as the baseline and does not get `is_*()` methods.
///  All subsequent variants are considered post-Genesis hardforks.
macro_rules! tempo_hardfork {
    (
        $(#[$enum_meta:meta])*
        TempoHardfork {
            $(#[$genesis_meta:meta])* Genesis,
            $( $(#[$meta:meta])* $variant:ident ),* $(,)?
        }
    ) => {

        // delegate to alloy's `hardfork!` macro
        hardfork!(
            $(#[$enum_meta])*
            TempoHardfork {
                $(#[$genesis_meta])* Genesis,
                $( $(#[$meta])* $variant ),*
            }
        );

        impl TempoHardfork {
            paste::paste! {
                $(
                    #[doc = concat!("Returns true if this hardfork is ", stringify!($variant), " or later.")]
                    pub const fn [<is_ $variant:lower>](&self) -> bool {
                        *self as u64 >= Self::$variant as u64
                    }
                )*
            }
        }

        /// Trait for querying Tempo-specific hardfork activations.
        pub trait TempoHardforks: EthereumHardforks {
            /// Retrieves activation condition for a Tempo-specific hardfork.
            fn tempo_fork_activation(&self, fork: TempoHardfork) -> ForkCondition;

            /// Retrieves the Tempo hardfork active at a given timestamp.
            fn tempo_hardfork_at(&self, timestamp: u64) -> TempoHardfork {
                for &fork in TempoHardfork::VARIANTS.iter().rev() {
                    if self.tempo_fork_activation(fork).active_at_timestamp(timestamp) {
                        return fork;
                    }
                }
                TempoHardfork::Genesis
            }

            paste::paste! {
                $(
                    #[doc = concat!("Returns true if ", stringify!($variant), " is active at the given timestamp.")]
                    fn [<is_ $variant:lower _active_at_timestamp>](&self, timestamp: u64) -> bool {
                        self.tempo_fork_activation(TempoHardfork::$variant)
                            .active_at_timestamp(timestamp)
                    }
                )*
            }

            /// Returns the general (non-payment) gas limit for the given timestamp and block.
            /// - T1+: fixed at 30M gas
            /// - Pre-T1: calculated as (gas_limit - shared_gas_limit) / 2
            fn general_gas_limit_at(&self, timestamp: u64, gas_limit: u64, shared_gas_limit: u64) -> u64 {
                self.tempo_hardfork_at(timestamp)
                    .general_gas_limit()
                    .unwrap_or_else(|| (gas_limit - shared_gas_limit) / 2)
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use TempoHardfork::*;
            use reth_chainspec::Hardfork;

            #[test]
            fn test_hardfork_name() {
                assert_eq!(Genesis.name(), "Genesis");
                $(assert_eq!($variant.name(), stringify!($variant));)*
            }

            #[test]
            fn test_hardfork_trait_implementation() {
                for fork in TempoHardfork::VARIANTS {
                    let _name: &str = Hardfork::name(fork);
                }
            }

            #[test]
            #[cfg(feature = "serde")]
            fn test_tempo_hardfork_serde() {
                for fork in TempoHardfork::VARIANTS {
                    let json = serde_json::to_string(fork).expect("serialize");
                    let deserialized: TempoHardfork = serde_json::from_str(&json).expect("deserialize");
                    assert_eq!(deserialized, *fork);
                }
            }

            paste::paste! {
                $(
                    #[test]
                    fn [<test_is_ $variant:lower>]() {
                        let idx = TempoHardfork::VARIANTS.iter().position(|v| *v == $variant)
                            .expect(concat!(stringify!($variant), " missing from VARIANTS"));
                        for (i, fork) in TempoHardfork::VARIANTS.iter().enumerate() {
                            let active = TempoHardfork::[<is_ $variant:lower>](fork);
                            if i >= idx {
                                assert!(active, "{fork:?} should satisfy is_{}", stringify!([<$variant:lower>]));
                            } else {
                                assert!(!active, "{fork:?} should not satisfy is_{}", stringify!([<$variant:lower>]));
                            }
                        }
                    }
                )*
            }
        }
    };
}

// -------------------------------------------------------------------------------------
// Tempo hardfork definitions — append new variants here.
// -------------------------------------------------------------------------------------
tempo_hardfork! (
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
        /// T1.A hardfork - removes EIP-7825 per-transaction gas limit
        T1A,
        /// T1.B hardfork
        T1B,
        /// T1.C hardfork
        T1C,
        /// T2 hardfork - adds compound transfer policies ([TIP-1015])
        ///
        /// [TIP-1015]: <https://docs.tempo.xyz/protocol/tips/tip-1015>
        T2,
        /// T3 hardfork
        T3,
    }
);

impl TempoHardfork {
    /// Returns the base fee for this hardfork in attodollars.
    ///
    /// Attodollars are the atomic gas accounting units at 10^-18 USD precision. Individual attodollars are not representable onchain (since TIP-20 tokens only have 6 decimals), but the unit is used for gas accounting.
    /// - Pre-T1: 10 billion attodollars per gas
    /// - T1+: 20 billion attodollars per gas (targets ~0.1 cent per TIP-20 transfer)
    ///
    /// Economic conversion: ceil(basefee × gas_used / 10^12) = cost in microdollars (TIP-20 tokens)
    pub const fn base_fee(&self) -> u64 {
        if self.is_t1() {
            return crate::spec::TEMPO_T1_BASE_FEE;
        }
        crate::spec::TEMPO_T0_BASE_FEE
    }

    /// Returns the fixed general gas limit for T1+, or None for pre-T1.
    /// - Pre-T1: None
    /// - T1+: 30M gas (fixed)
    pub const fn general_gas_limit(&self) -> Option<u64> {
        if self.is_t1() {
            return Some(crate::spec::TEMPO_T1_GENERAL_GAS_LIMIT);
        }
        None
    }

    /// Returns the per-transaction gas limit cap.
    /// - Pre-T1A: EIP-7825 Osaka limit (16,777,216 gas)
    /// - T1A+: 30M gas (allows maximum-sized contract deployments under [TIP-1000] state creation)
    ///
    /// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
    pub const fn tx_gas_limit_cap(&self) -> Option<u64> {
        if self.is_t1a() {
            return Some(crate::spec::TEMPO_T1_TX_GAS_LIMIT_CAP);
        }
        Some(MAX_TX_GAS_LIMIT_OSAKA)
    }

    /// Gas cost for using an existing 2D nonce key
    pub const fn gas_existing_nonce_key(&self) -> u64 {
        if self.is_t2() {
            return crate::spec::TEMPO_T2_EXISTING_NONCE_KEY_GAS;
        }
        crate::spec::TEMPO_T1_EXISTING_NONCE_KEY_GAS
    }

    /// Gas cost for using a new 2D nonce key
    pub const fn gas_new_nonce_key(&self) -> u64 {
        if self.is_t2() {
            return crate::spec::TEMPO_T2_NEW_NONCE_KEY_GAS;
        }
        crate::spec::TEMPO_T1_NEW_NONCE_KEY_GAS
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
