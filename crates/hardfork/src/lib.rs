//! Tempo chain identity, activation metadata, and current protocol constants.
//!
//! Historical identifiers and timestamps are retained to preserve genesis hashes,
//! networking fork IDs, and RPC schedule responses. They do not select execution
//! rules. This source tree executes only [TempoHardfork::CURRENT]; the released
//! v1 binary serves older blocks through tempo-multiplex.
//!
//! A protocol upgrade requires another versioned execution binary, not another
//! timestamp-dependent branch in the EVM or precompiles. The metadata enum can
//! describe a scheduled upgrade without enabling its execution in this binary.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod constants;

use crate::constants::gas;
#[cfg(feature = "evm")]
use alloy_evm::revm::primitives::hardfork::SpecId;
use alloy_hardforks::hardfork;

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

        /// Invokes the given macro with all post-Genesis Tempo hardfork variants.
        ///
        /// This lets downstream crates generate per-hardfork APIs from the same variant list as
        /// [`TempoHardfork`] without depending on Tempo's chainspec implementation.
        #[macro_export]
        macro_rules! tempo_post_genesis_hardforks {
            ($callback:ident) => {
                $callback! { $($variant),* }
            };
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use TempoHardfork::*;
            use alloy_hardforks::Hardfork;

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
            fn test_variant_index_roundtrip() {
                for fork in TempoHardfork::VARIANTS {
                    assert_eq!(
                        TempoHardfork::from_variant_index(fork.variant_index()),
                        Some(*fork)
                    );
                }
                assert_eq!(
                    TempoHardfork::from_variant_index(TempoHardfork::VARIANTS.len() as u8),
                    None
                );
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
                            let active_index = i;
                            if active_index >= idx {
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
tempo_hardfork!(
    /// Tempo-specific hardforks for network upgrades.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Default)]
    TempoHardfork {
        /// Genesis hardfork.
        Genesis,
        /// T0 hardfork.
        T0,
        /// T1 hardfork.
        T1,
        /// T1.A hardfork.
        T1A,
        /// T1.B hardfork.
        T1B,
        /// T1.C hardfork.
        T1C,
        /// T2 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t2>.
        T2,
        /// T3 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t3>.
        T3,
        /// T4 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t4>.
        T4,
        /// T5 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t5>.
        T5,
        /// T6 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t6>.
        T6,
        /// T7 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t7>.
        T7,
        /// T8 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t8>.
        T8,
        /// T9 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t9>.
        T9,
        /// T10 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t10>.
        T10,
        /// T11 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t11>.
        #[default]
        T11,
        /// T12 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t12>.
        T12,
        /// T13 hardfork.
        ///
        /// See <https://docs.tempo.xyz/docs/protocol/upgrades/t13>.
        T13,
    }
);

impl TempoHardfork {
    /// The only protocol executed by the v2 binary.
    pub const CURRENT: Self = Self::T11;

    /// Whether this build excludes historical execution rules.
    pub const FIXED_EXECUTION: bool = true;

    /// Returns the position of this hardfork in [`Self::VARIANTS`].
    ///
    /// Useful for storing the hardfork in an atomic, see [`Self::from_variant_index`].
    pub const fn variant_index(&self) -> u8 {
        *self as u8
    }

    /// Returns the latest defined Tempo hardfork.
    pub const fn latest() -> Self {
        Self::VARIANTS[Self::VARIANTS.len() - 1]
    }

    /// Returns the hardfork at the given [`Self::VARIANTS`] position, see
    /// [`Self::variant_index`].
    ///
    /// Returns `None` if the index is out of bounds.
    pub const fn from_variant_index(index: u8) -> Option<Self> {
        if (index as usize) < Self::VARIANTS.len() {
            Some(Self::VARIANTS[index as usize])
        } else {
            None
        }
    }

    /// Current execution rules use a fixed 30M general gas limit.
    pub const fn general_gas_limit(&self) -> Option<u64> {
        Some(gas::TEMPO_T1_GENERAL_GAS_LIMIT)
    }

    /// Current execution rules have no shared gas lane.
    pub const fn shared_gas_limit(&self, _block_gas_limit: u64) -> u64 {
        0
    }

    /// Returns the 30M per-transaction gas limit cap for [TIP-1000] state creation.
    ///
    /// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
    pub const fn tx_gas_limit_cap(&self) -> Option<u64> {
        Some(gas::TEMPO_T1_TX_GAS_LIMIT_CAP)
    }

    /// Gas cost for using an existing 2D nonce key
    pub const fn gas_existing_nonce_key(&self) -> u64 {
        gas::TEMPO_T2_EXISTING_NONCE_KEY_GAS
    }

    /// Gas cost for using a new 2D nonce key
    pub const fn gas_new_nonce_key(&self) -> u64 {
        gas::TEMPO_T2_NEW_NONCE_KEY_GAS
    }

    /// Returns the expiring nonce replay-protection capacity.
    pub const fn expiring_nonce_set_capacity(&self) -> u32 {
        3_000_000
    }

    /// Returns the maximum expiring nonce validity window in seconds.
    pub const fn expiring_nonce_max_expiry_secs(&self) -> u64 {
        300
    }

    /// Returns the active hardfork at the given timestamp for the specified chain.
    ///
    /// Returns `None` if the chain ID is not a known Tempo chain.
    pub const fn from_chain_and_timestamp(chain_id: u64, timestamp: u64) -> Option<Self> {
        // Walk variants in reverse to find the latest active fork, mirroring
        // `TempoHardforks::tempo_hardfork_at` but without needing a chainspec instance.
        let variants = Self::VARIANTS;
        let mut i = variants.len();
        while i > 0 {
            i -= 1;
            let activation = match chain_id {
                4217 => variants[i].mainnet_activation_timestamp(),
                42431 => variants[i].moderato_activation_timestamp(),
                _ => return None,
            };
            if let Some(ts) = activation
                && timestamp >= ts
            {
                return Some(variants[i]);
            }
        }
        Some(Self::Genesis)
    }

    /// Retrieves the activation block for this hardfork on mainnet.
    pub const fn mainnet_activation_block(&self) -> Option<u64> {
        use crate::constants::mainnet::*;
        match self {
            Self::Genesis => Some(MAINNET_GENESIS_BLOCK),
            Self::T0 => Some(MAINNET_T0_BLOCK),
            Self::T1 => Some(MAINNET_T1_BLOCK),
            Self::T1A => Some(MAINNET_T1A_BLOCK),
            Self::T1B => Some(MAINNET_T1B_BLOCK),
            Self::T1C => Some(MAINNET_T1C_BLOCK),
            Self::T2 => Some(MAINNET_T2_BLOCK),
            Self::T3 => None, // not yet known
            Self::T4 => None,
            Self::T5 => None,
            Self::T6 => None,
            Self::T7 => None,
            Self::T8 => None,
            Self::T9 => None,
            Self::T10 => None,
            Self::T11 => None,
            Self::T12 => None,
            Self::T13 => None,
        }
    }

    /// Retrieves the activation timestamp for this hardfork on mainnet.
    pub const fn mainnet_activation_timestamp(&self) -> Option<u64> {
        use crate::constants::mainnet::*;
        match self {
            Self::Genesis => Some(MAINNET_GENESIS_TIMESTAMP),
            Self::T0 => Some(MAINNET_T0_TIMESTAMP),
            Self::T1 => Some(MAINNET_T1_TIMESTAMP),
            Self::T1A => Some(MAINNET_T1A_TIMESTAMP),
            Self::T1B => Some(MAINNET_T1B_TIMESTAMP),
            Self::T1C => Some(MAINNET_T1C_TIMESTAMP),
            Self::T2 => Some(MAINNET_T2_TIMESTAMP),
            Self::T3 => Some(MAINNET_T3_TIMESTAMP),
            Self::T4 => Some(MAINNET_T4_TIMESTAMP),
            Self::T5 => Some(MAINNET_T5_TIMESTAMP),
            Self::T6 => Some(MAINNET_T6_TIMESTAMP),
            Self::T7 => Some(MAINNET_T7_TIMESTAMP),
            Self::T8 => Some(MAINNET_T8_TIMESTAMP),
            Self::T9 => Some(MAINNET_T9_TIMESTAMP),
            Self::T10 => Some(MAINNET_T10_TIMESTAMP),
            Self::T11 => Some(MAINNET_T11_TIMESTAMP),
            Self::T12 => None,
            Self::T13 => None,
        }
    }

    /// Retrieves the activation block for this hardfork on moderato testnet.
    pub const fn moderato_activation_block(&self) -> Option<u64> {
        use crate::constants::moderato::*;
        match self {
            Self::Genesis => Some(MODERATO_GENESIS_BLOCK),
            Self::T0 => Some(MODERATO_T0_BLOCK),
            Self::T1 => Some(MODERATO_T1_BLOCK),
            Self::T1A => Some(MODERATO_T1A_BLOCK),
            Self::T1B => Some(MODERATO_T1B_BLOCK),
            Self::T1C => Some(MODERATO_T1C_BLOCK),
            Self::T2 => Some(MODERATO_T2_BLOCK),
            Self::T3 => None, // not yet known
            Self::T4 => None,
            Self::T5 => None,
            Self::T6 => None,
            Self::T7 => None,
            Self::T8 => None,
            Self::T9 => None,
            Self::T10 => None,
            Self::T11 => None,
            Self::T12 => None,
            Self::T13 => None,
        }
    }

    /// Retrieves the activation timestamp for this hardfork on moderato testnet.
    pub const fn moderato_activation_timestamp(&self) -> Option<u64> {
        use crate::constants::moderato::*;
        match self {
            Self::Genesis => Some(MODERATO_GENESIS_TIMESTAMP),
            Self::T0 => Some(MODERATO_T0_TIMESTAMP),
            Self::T1 => Some(MODERATO_T1_TIMESTAMP),
            Self::T1A => Some(MODERATO_T1A_TIMESTAMP),
            Self::T1B => Some(MODERATO_T1B_TIMESTAMP),
            Self::T1C => Some(MODERATO_T1C_TIMESTAMP),
            Self::T2 => Some(MODERATO_T2_TIMESTAMP),
            Self::T3 => Some(MODERATO_T3_TIMESTAMP),
            Self::T4 => Some(MODERATO_T4_TIMESTAMP),
            Self::T5 => Some(MODERATO_T5_TIMESTAMP),
            Self::T6 => Some(MODERATO_T6_TIMESTAMP),
            Self::T7 => Some(MODERATO_T7_TIMESTAMP),
            Self::T8 => Some(MODERATO_T8_TIMESTAMP),
            Self::T9 => Some(MODERATO_T9_TIMESTAMP),
            Self::T10 => Some(MODERATO_T10_TIMESTAMP),
            Self::T11 => Some(MODERATO_T11_TIMESTAMP),
            Self::T12 => None,
            Self::T13 => None,
        }
    }
}

#[cfg(test)]
mod fixed_execution_tests {
    use super::TempoHardfork;

    #[test]
    fn protocol_constants_cannot_select_historical_or_future_execution() {
        assert_eq!(TempoHardfork::default(), TempoHardfork::CURRENT);
        for metadata in TempoHardfork::VARIANTS {
            assert_eq!(metadata.general_gas_limit(), Some(30_000_000));
            assert_eq!(metadata.shared_gas_limit(500_000_000), 0);
            assert_eq!(metadata.tx_gas_limit_cap(), Some(30_000_000));
            assert_eq!(metadata.expiring_nonce_set_capacity(), 3_000_000);
            assert_eq!(metadata.expiring_nonce_max_expiry_secs(), 300);
            assert_eq!(
                metadata.gas_existing_nonce_key(),
                TempoHardfork::CURRENT.gas_existing_nonce_key()
            );
            assert_eq!(
                metadata.gas_new_nonce_key(),
                TempoHardfork::CURRENT.gas_new_nonce_key()
            );
        }
    }
}

#[cfg(feature = "evm")]
impl From<TempoHardfork> for SpecId {
    fn from(_value: TempoHardfork) -> Self {
        Self::OSAKA
    }
}

#[cfg(feature = "evm")]
impl From<&TempoHardfork> for SpecId {
    fn from(value: &TempoHardfork) -> Self {
        Self::from(*value)
    }
}

#[cfg(feature = "evm")]
impl From<SpecId> for TempoHardfork {
    fn from(_spec: SpecId) -> Self {
        // All Tempo hardforks map to SpecId::OSAKA, so we cannot derive the hardfork from SpecId.
        // Default to the default hardfork when converting from SpecId.
        // The actual hardfork should be passed explicitly where needed.
        Self::default()
    }
}
