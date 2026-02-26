//! Independent feature flags for Tempo protocol upgrades.
//!
//! Unlike the linear `TempoHardfork` enum (where T2 implies T1), features can be
//! activated independently as long as their dependency requirements are met.
//!
//! ## Adding a new feature
//!
//! 1. Add a new constant to [`TempoFeatures`]
//! 2. Add a `requires()` entry if it depends on other features
//! 3. Map it from the appropriate `TempoHardfork` in [`TempoFeatures::from_hardfork`]
//! 4. Use `features.contains(TempoFeatures::MY_FEATURE)` in gating logic
//!
//! ## Relationship to hardforks
//!
//! Existing hardforks (T0–T2) are mapped to feature sets for backward compatibility.
//! New protocol changes should be defined as features directly, not as hardfork variants.

use crate::hardfork::TempoHardfork;

bitflags::bitflags! {
    /// Bitfield of independently-activatable Tempo protocol features.
    ///
    /// Each bit represents a single protocol change that can be gated in consensus,
    /// EVM execution, transaction validation, and precompile dispatch.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TempoFeatures: u128 {
        // ── Features introduced in T1 ──────────────────────────────────
        /// Expiring nonce transactions (TIP-1005)
        const EXPIRING_NONCES       = 1 << 0;
        /// Updated base fee (20B attodollars) and fixed 30M general gas limit
        const T1_GAS_PARAMS         = 1 << 1;
        /// Keychain signature validation in EVM handler
        const KEYCHAIN_VALIDATION   = 1 << 2;

        // ── Features introduced in T1A ─────────────────────────────────
        /// Remove EIP-7825 per-transaction gas limit, allow 30M
        const REMOVE_TX_GAS_LIMIT   = 1 << 3;

        // ── Features introduced in T1B ─────────────────────────────────
        /// Replay hash v2 (includes chain_id + nonce_key)
        const REPLAY_HASH_V2        = 1 << 4;

        // ── Features introduced in T1C ─────────────────────────────────
        /// Osaka EVM precompiles (vs Prague)
        const OSAKA_PRECOMPILES     = 1 << 5;

        // ── Features introduced in T2 ──────────────────────────────────
        /// Compound transfer policies (TIP-1015)
        const COMPOUND_TRANSFERS    = 1 << 6;
        /// TIP-20 permit/nonces/DOMAIN_SEPARATOR
        const TIP20_PERMIT          = 1 << 7;
        /// ValidatorConfigV2 precompile
        const VALIDATOR_CONFIG_V2   = 1 << 8;
        /// TIP-403 compound policies & directional auth
        const TIP403_COMPOUND       = 1 << 9;
        /// Fee token query (getFeeToken) in TipFeeManager
        const FEE_TOKEN_QUERY       = 1 << 10;
        /// Updated 2D nonce key gas costs (adds 2 warm SLOADs)
        const T2_NONCE_GAS          = 1 << 11;
    }
}

/// Error returned when a feature's dependencies are not satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingDependencies {
    /// The feature that cannot be activated.
    pub feature: TempoFeatures,
    /// The unsatisfied dependencies.
    pub missing: TempoFeatures,
}

impl std::fmt::Display for MissingDependencies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cannot activate {:?}: missing dependencies {:?}",
            self.feature, self.missing
        )
    }
}

impl std::error::Error for MissingDependencies {}

impl TempoFeatures {
    /// Returns the set of features that must already be active before `self` can activate.
    ///
    /// This defines the feature dependency DAG. A feature with empty requirements can
    /// activate independently.
    pub const fn requires(self) -> Self {
        // For single-bit features, define explicit dependencies.
        // For multi-bit sets (unions), return empty — callers should check individual features.
        match self {
            // T1A features require T1 features
            f if f.bits() == Self::REMOVE_TX_GAS_LIMIT.bits() => Self::T1_GAS_PARAMS,

            // T1B features require T1A
            f if f.bits() == Self::REPLAY_HASH_V2.bits() => Self::EXPIRING_NONCES,

            // T1C features require T1B
            f if f.bits() == Self::OSAKA_PRECOMPILES.bits() => Self::REPLAY_HASH_V2,

            // T2 features require T1 features
            f if f.bits() == Self::COMPOUND_TRANSFERS.bits() => Self::EXPIRING_NONCES,
            f if f.bits() == Self::TIP20_PERMIT.bits() => Self::EXPIRING_NONCES,
            f if f.bits() == Self::VALIDATOR_CONFIG_V2.bits() => Self::EXPIRING_NONCES,
            f if f.bits() == Self::TIP403_COMPOUND.bits() => Self::COMPOUND_TRANSFERS,
            f if f.bits() == Self::FEE_TOKEN_QUERY.bits() => Self::EXPIRING_NONCES,
            f if f.bits() == Self::T2_NONCE_GAS.bits() => Self::EXPIRING_NONCES,

            _ => Self::empty(),
        }
    }

    /// Returns `Ok(())` if all dependencies for `self` are satisfied by `active`,
    /// or `Err` with the missing dependencies.
    pub const fn can_activate(self, active: Self) -> Result<(), MissingDependencies> {
        let required = self.requires();
        let missing_bits = required.bits() & !active.bits();
        if missing_bits == 0 {
            Ok(())
        } else {
            Err(MissingDependencies {
                feature: self,
                missing: Self::from_bits_retain(missing_bits),
            })
        }
    }

    /// Construct the feature set implied by a legacy `TempoHardfork`.
    ///
    /// This provides backward compatibility: existing hardfork-gated code can be
    /// migrated incrementally to feature checks.
    pub const fn from_hardfork(hf: TempoHardfork) -> Self {
        match hf {
            TempoHardfork::Genesis => Self::empty(),
            TempoHardfork::T0 => Self::empty(),
            TempoHardfork::T1 => Self::T1_GAS_PARAMS
                .union(Self::EXPIRING_NONCES)
                .union(Self::KEYCHAIN_VALIDATION),
            TempoHardfork::T1A => {
                Self::from_hardfork(TempoHardfork::T1).union(Self::REMOVE_TX_GAS_LIMIT)
            }
            TempoHardfork::T1B => {
                Self::from_hardfork(TempoHardfork::T1A).union(Self::REPLAY_HASH_V2)
            }
            TempoHardfork::T1C => {
                Self::from_hardfork(TempoHardfork::T1B).union(Self::OSAKA_PRECOMPILES)
            }
            TempoHardfork::T2 => Self::from_hardfork(TempoHardfork::T1C)
                .union(Self::COMPOUND_TRANSFERS)
                .union(Self::TIP20_PERMIT)
                .union(Self::VALIDATOR_CONFIG_V2)
                .union(Self::TIP403_COMPOUND)
                .union(Self::FEE_TOKEN_QUERY)
                .union(Self::T2_NONCE_GAS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_hardfork_is_cumulative() {
        let t1 = TempoFeatures::from_hardfork(TempoHardfork::T1);
        let t1a = TempoFeatures::from_hardfork(TempoHardfork::T1A);
        let t1b = TempoFeatures::from_hardfork(TempoHardfork::T1B);
        let t1c = TempoFeatures::from_hardfork(TempoHardfork::T1C);
        let t2 = TempoFeatures::from_hardfork(TempoHardfork::T2);

        // Each hardfork's features are a superset of the previous
        assert!(t1a.contains(t1));
        assert!(t1b.contains(t1a));
        assert!(t1c.contains(t1b));
        assert!(t2.contains(t1c));
    }

    #[test]
    fn test_genesis_and_t0_are_empty() {
        assert!(TempoFeatures::from_hardfork(TempoHardfork::Genesis).is_empty());
        assert!(TempoFeatures::from_hardfork(TempoHardfork::T0).is_empty());
    }

    #[test]
    fn test_t1_features() {
        let t1 = TempoFeatures::from_hardfork(TempoHardfork::T1);
        assert!(t1.contains(TempoFeatures::EXPIRING_NONCES));
        assert!(t1.contains(TempoFeatures::T1_GAS_PARAMS));
        assert!(t1.contains(TempoFeatures::KEYCHAIN_VALIDATION));
        assert!(!t1.contains(TempoFeatures::REMOVE_TX_GAS_LIMIT));
    }

    #[test]
    fn test_t2_has_all_features() {
        let t2 = TempoFeatures::from_hardfork(TempoHardfork::T2);
        assert!(t2.contains(TempoFeatures::COMPOUND_TRANSFERS));
        assert!(t2.contains(TempoFeatures::TIP20_PERMIT));
        assert!(t2.contains(TempoFeatures::VALIDATOR_CONFIG_V2));
        assert!(t2.contains(TempoFeatures::TIP403_COMPOUND));
        assert!(t2.contains(TempoFeatures::FEE_TOKEN_QUERY));
        assert!(t2.contains(TempoFeatures::T2_NONCE_GAS));
    }

    #[test]
    fn test_dependency_satisfied() {
        let active = TempoFeatures::from_hardfork(TempoHardfork::T1);
        assert!(
            TempoFeatures::REMOVE_TX_GAS_LIMIT
                .can_activate(active)
                .is_ok()
        );
    }

    #[test]
    fn test_dependency_missing() {
        let active = TempoFeatures::empty();
        let result = TempoFeatures::REMOVE_TX_GAS_LIMIT.can_activate(active);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.missing.contains(TempoFeatures::T1_GAS_PARAMS));
    }

    #[test]
    fn test_compound_requires_chain() {
        // TIP403_COMPOUND requires COMPOUND_TRANSFERS which requires EXPIRING_NONCES
        let empty = TempoFeatures::empty();
        assert!(TempoFeatures::TIP403_COMPOUND.can_activate(empty).is_err());

        let with_expiring = TempoFeatures::EXPIRING_NONCES;
        // Still fails — TIP403_COMPOUND directly requires COMPOUND_TRANSFERS
        assert!(
            TempoFeatures::TIP403_COMPOUND
                .can_activate(with_expiring)
                .is_err()
        );

        let with_compound = TempoFeatures::EXPIRING_NONCES | TempoFeatures::COMPOUND_TRANSFERS;
        assert!(
            TempoFeatures::TIP403_COMPOUND
                .can_activate(with_compound)
                .is_ok()
        );
    }

    #[test]
    fn test_no_self_dependency() {
        for bit in 0..128u32 {
            let feature = TempoFeatures::from_bits_retain(1u128 << bit);
            let deps = feature.requires();
            assert!(!deps.contains(feature), "{feature:?} depends on itself");
        }
    }

    #[test]
    fn test_feature_independence() {
        // TIP20_PERMIT and VALIDATOR_CONFIG_V2 share the same dependency (EXPIRING_NONCES)
        // but are independent of each other
        let active = TempoFeatures::EXPIRING_NONCES;
        assert!(TempoFeatures::TIP20_PERMIT.can_activate(active).is_ok());
        assert!(
            TempoFeatures::VALIDATOR_CONFIG_V2
                .can_activate(active)
                .is_ok()
        );
    }

    #[test]
    fn test_128_bits_available() {
        // Verify we can use high bits without overflow
        let high = TempoFeatures::from_bits_retain(1u128 << 127);
        assert!(!high.is_empty());
        assert_eq!(high.bits().count_ones(), 1);

        let all_bits = TempoFeatures::from_bits_retain(u128::MAX);
        assert_eq!(all_bits.bits(), u128::MAX);
    }

    #[test]
    fn test_no_dependency_cycles() {
        // Walk the dependency chain for every defined feature and ensure
        // we never revisit a feature (no cycles in the DAG).
        let all_features: Vec<TempoFeatures> = (0..12)
            .map(|bit| TempoFeatures::from_bits_retain(1u128 << bit))
            .collect();

        for &feature in &all_features {
            let mut visited = TempoFeatures::empty();
            let mut current = feature;
            loop {
                let deps = current.requires();
                if deps.is_empty() {
                    break;
                }
                assert!(
                    !visited.contains(deps),
                    "cycle detected: {feature:?} -> ... -> {deps:?}"
                );
                visited = visited.union(current);
                current = deps;
            }
        }
    }

    #[test]
    fn test_hardfork_features_satisfy_all_dependencies() {
        // Every feature set produced by from_hardfork() must have all
        // internal dependencies satisfied.
        let hardforks = [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T1A,
            TempoHardfork::T1B,
            TempoHardfork::T1C,
            TempoHardfork::T2,
        ];

        for hf in hardforks {
            let features = TempoFeatures::from_hardfork(hf);
            // Check each active feature's deps are also in the set
            for bit in 0..12 {
                let flag = TempoFeatures::from_bits_retain(1u128 << bit);
                if features.contains(flag) {
                    let deps = flag.requires();
                    assert!(
                        features.contains(deps),
                        "{hf:?} includes {flag:?} but is missing its deps {deps:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_missing_dependencies_display() {
        let err = TempoFeatures::REMOVE_TX_GAS_LIMIT
            .can_activate(TempoFeatures::empty())
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot activate"));
        assert!(msg.contains("missing dependencies"));
    }

    #[test]
    fn test_empty_features_can_always_activate() {
        // Empty set has no requirements
        assert!(
            TempoFeatures::empty()
                .can_activate(TempoFeatures::empty())
                .is_ok()
        );
    }

    #[test]
    fn test_base_features_have_no_dependencies() {
        // T1 base features should be activatable from nothing
        assert!(TempoFeatures::EXPIRING_NONCES.requires().is_empty());
        assert!(TempoFeatures::T1_GAS_PARAMS.requires().is_empty());
        assert!(TempoFeatures::KEYCHAIN_VALIDATION.requires().is_empty());
    }

    #[test]
    fn test_each_hardfork_adds_features() {
        // Each successive hardfork strictly adds features (never removes)
        let pairs = [
            (TempoHardfork::Genesis, TempoHardfork::T0),
            (TempoHardfork::T0, TempoHardfork::T1),
            (TempoHardfork::T1, TempoHardfork::T1A),
            (TempoHardfork::T1A, TempoHardfork::T1B),
            (TempoHardfork::T1B, TempoHardfork::T1C),
            (TempoHardfork::T1C, TempoHardfork::T2),
        ];
        for (prev, next) in pairs {
            let prev_f = TempoFeatures::from_hardfork(prev);
            let next_f = TempoFeatures::from_hardfork(next);
            assert!(
                next_f.contains(prev_f),
                "{next:?} should be a superset of {prev:?}"
            );
        }
    }

    #[test]
    fn test_t2_feature_count() {
        let t2 = TempoFeatures::from_hardfork(TempoHardfork::T2);
        assert_eq!(
            t2.bits().count_ones(),
            12,
            "T2 should activate all 12 defined features"
        );
    }
}
