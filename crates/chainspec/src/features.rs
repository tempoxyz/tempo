//! Independent feature flags for Tempo protocol upgrades.
//!
//! Unlike the linear `TempoHardfork` enum (where T2 implies T1), features can be
//! activated independently as long as their dependency requirements are met.
//!
//! ## Adding a new feature
//!
//! 1. Add a new constant to [`TempoFeature`] (assign the next sequential ID)
//! 2. Add a `requires()` entry if it depends on other features
//! 3. Map it from the appropriate `TempoHardfork` in [`TempoFeatures::from_hardfork`]
//! 4. Use `features.contains(TempoFeature::MY_FEATURE)` in gating logic
//!
//! ## Capacity
//!
//! The backing store grows dynamically — there is no upper limit on the number
//! of features. Each feature is identified by a `u32` ID.
//!
//! ## Relationship to hardforks
//!
//! Existing hardforks (T0–T2) are mapped to feature sets for backward compatibility.
//! New protocol changes should be defined as features directly, not as hardfork variants.

use crate::hardfork::TempoHardfork;

/// A single feature identified by a numeric ID.
///
/// Features are cheap to copy and compare. The ID is an index into the
/// [`TempoFeatures`] bitset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TempoFeature(u32);

impl TempoFeature {
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub const fn id(self) -> u32 {
        self.0
    }
}

// ── Feature constants ──────────────────────────────────────────────────────

impl TempoFeature {
    // ── T1 ──────────────────────────────────────────────────────────────
    /// Expiring nonce transactions (TIP-1005)
    pub const EXPIRING_NONCES: Self = Self(0);
    /// Updated base fee (20B attodollars) and fixed 30M general gas limit
    pub const T1_GAS_PARAMS: Self = Self(1);
    /// Keychain signature validation in EVM handler
    pub const KEYCHAIN_VALIDATION: Self = Self(2);

    // ── T1A ─────────────────────────────────────────────────────────────
    /// Remove EIP-7825 per-transaction gas limit, allow 30M
    pub const REMOVE_TX_GAS_LIMIT: Self = Self(3);

    // ── T1B ─────────────────────────────────────────────────────────────
    /// Replay hash v2 (includes chain_id + nonce_key)
    pub const REPLAY_HASH_V2: Self = Self(4);

    // ── T1C ─────────────────────────────────────────────────────────────
    /// Osaka EVM precompiles (vs Prague)
    pub const OSAKA_PRECOMPILES: Self = Self(5);

    // ── T2 ──────────────────────────────────────────────────────────────
    /// Compound transfer policies (TIP-1015)
    pub const COMPOUND_TRANSFERS: Self = Self(6);
    /// TIP-20 permit/nonces/DOMAIN_SEPARATOR
    pub const TIP20_PERMIT: Self = Self(7);
    /// ValidatorConfigV2 precompile
    pub const VALIDATOR_CONFIG_V2: Self = Self(8);
    /// TIP-403 compound policies & directional auth
    pub const TIP403_COMPOUND: Self = Self(9);
    /// Fee token query (getFeeToken) in TipFeeManager
    pub const FEE_TOKEN_QUERY: Self = Self(10);
    /// Updated 2D nonce key gas costs (adds 2 warm SLOADs)
    pub const T2_NONCE_GAS: Self = Self(11);

    /// Total number of currently defined features.
    pub const COUNT: u32 = 12;
}

// ── Dependency DAG ─────────────────────────────────────────────────────────

impl TempoFeature {
    /// Returns the set of features that must already be active before `self`
    /// can activate. Returns an empty set for root features.
    pub fn requires(self) -> TempoFeatures {
        match self {
            Self::REMOVE_TX_GAS_LIMIT => TempoFeatures::from_iter([Self::T1_GAS_PARAMS]),
            Self::REPLAY_HASH_V2 => TempoFeatures::from_iter([Self::EXPIRING_NONCES]),
            Self::OSAKA_PRECOMPILES => TempoFeatures::from_iter([Self::REPLAY_HASH_V2]),
            Self::COMPOUND_TRANSFERS => TempoFeatures::from_iter([Self::EXPIRING_NONCES]),
            Self::TIP20_PERMIT => TempoFeatures::from_iter([Self::EXPIRING_NONCES]),
            Self::VALIDATOR_CONFIG_V2 => TempoFeatures::from_iter([Self::EXPIRING_NONCES]),
            Self::TIP403_COMPOUND => TempoFeatures::from_iter([Self::COMPOUND_TRANSFERS]),
            Self::FEE_TOKEN_QUERY => TempoFeatures::from_iter([Self::EXPIRING_NONCES]),
            Self::T2_NONCE_GAS => TempoFeatures::from_iter([Self::EXPIRING_NONCES]),
            _ => TempoFeatures::empty(),
        }
    }
}

// ── Growable bitset of features ────────────────────────────────────────────

/// A dynamically-sized set of active [`TempoFeature`]s.
///
/// Backed by a `Vec<u64>` that grows as needed — no upper bound on the
/// number of features.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TempoFeatures {
    words: Vec<u64>,
}

impl TempoFeatures {
    /// An empty feature set.
    pub const fn empty() -> Self {
        Self { words: Vec::new() }
    }

    /// Returns true if no features are active.
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Insert a feature into the set.
    pub fn insert(&mut self, feature: TempoFeature) {
        let (word, bit) = Self::index(feature);
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= 1u64 << bit;
    }

    /// Remove a feature from the set.
    pub fn remove(&mut self, feature: TempoFeature) {
        let (word, bit) = Self::index(feature);
        if word < self.words.len() {
            self.words[word] &= !(1u64 << bit);
        }
    }

    /// Returns true if `feature` is in the set.
    pub fn contains(&self, feature: TempoFeature) -> bool {
        let (word, bit) = Self::index(feature);
        word < self.words.len() && (self.words[word] & (1u64 << bit)) != 0
    }

    /// Returns true if `self` is a superset of `other`.
    pub fn contains_all(&self, other: &Self) -> bool {
        for (i, &other_word) in other.words.iter().enumerate() {
            let self_word = self.words.get(i).copied().unwrap_or(0);
            if (self_word & other_word) != other_word {
                return false;
            }
        }
        true
    }

    /// Returns the union of `self` and `other`.
    pub fn union(&self, other: &Self) -> Self {
        let len = self.words.len().max(other.words.len());
        let mut words = vec![0u64; len];
        for (i, w) in words.iter_mut().enumerate() {
            let a = self.words.get(i).copied().unwrap_or(0);
            let b = other.words.get(i).copied().unwrap_or(0);
            *w = a | b;
        }
        Self { words }
    }

    /// Returns features in `other` that are not in `self`.
    pub fn difference(&self, other: &Self) -> Self {
        let len = self.words.len().max(other.words.len());
        let mut words = vec![0u64; len];
        for (i, w) in words.iter_mut().enumerate() {
            let self_word = self.words.get(i).copied().unwrap_or(0);
            let other_word = other.words.get(i).copied().unwrap_or(0);
            *w = other_word & !self_word;
        }
        Self { words }
    }

    /// Number of active features.
    pub fn count(&self) -> u32 {
        self.words.iter().map(|w| w.count_ones()).sum()
    }

    /// Iterate over all active feature IDs.
    pub fn iter(&self) -> impl Iterator<Item = TempoFeature> + '_ {
        self.words.iter().enumerate().flat_map(|(word_idx, &word)| {
            (0..64).filter_map(move |bit| {
                if word & (1u64 << bit) != 0 {
                    Some(TempoFeature::new((word_idx as u32) * 64 + bit))
                } else {
                    None
                }
            })
        })
    }

    fn index(feature: TempoFeature) -> (usize, u32) {
        let id = feature.id();
        ((id / 64) as usize, id % 64)
    }
}

impl FromIterator<TempoFeature> for TempoFeatures {
    fn from_iter<I: IntoIterator<Item = TempoFeature>>(iter: I) -> Self {
        let mut set = Self::empty();
        for f in iter {
            set.insert(f);
        }
        set
    }
}

// ── Error type ─────────────────────────────────────────────────────────────

/// Error returned when a feature's dependencies are not satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingDependencies {
    /// The feature that cannot be activated.
    pub feature: TempoFeature,
    /// The unsatisfied dependencies.
    pub missing: TempoFeatures,
}

impl std::fmt::Display for MissingDependencies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cannot activate feature {}: missing dependencies {:?}",
            self.feature.id(),
            self.missing.iter().map(|f| f.id()).collect::<Vec<_>>()
        )
    }
}

impl std::error::Error for MissingDependencies {}

// ── Activation validation ──────────────────────────────────────────────────

impl TempoFeature {
    /// Returns `Ok(())` if all dependencies for `self` are satisfied by `active`,
    /// or `Err` with the missing dependencies.
    pub fn can_activate(self, active: &TempoFeatures) -> Result<(), MissingDependencies> {
        let required = self.requires();
        let missing = active.difference(&required);
        if missing.is_empty() {
            Ok(())
        } else {
            Err(MissingDependencies {
                feature: self,
                missing,
            })
        }
    }
}

// ── Convenience method on TempoHardfork ────────────────────────────────────

impl TempoHardfork {
    /// Returns true if this hardfork activates the given feature.
    ///
    /// This is the primary API for feature-gating in EVM handlers, consensus,
    /// and transaction validation — anywhere you have a `TempoHardfork` (spec).
    ///
    /// ```ignore
    /// if spec.has(TempoFeature::REPLAY_HASH_V2) {
    ///     // new behavior
    /// }
    /// ```
    pub fn has(self, feature: TempoFeature) -> bool {
        TempoFeatures::from_hardfork(self).contains(feature)
    }
}

// ── Hardfork backward compatibility ────────────────────────────────────────

impl TempoFeatures {
    /// Construct the feature set implied by a legacy `TempoHardfork`.
    ///
    /// This provides backward compatibility: existing hardfork-gated code can be
    /// migrated incrementally to feature checks.
    pub fn from_hardfork(hf: TempoHardfork) -> Self {
        match hf {
            TempoHardfork::Genesis | TempoHardfork::T0 => Self::empty(),
            TempoHardfork::T1 => Self::from_iter([
                TempoFeature::EXPIRING_NONCES,
                TempoFeature::T1_GAS_PARAMS,
                TempoFeature::KEYCHAIN_VALIDATION,
            ]),
            TempoHardfork::T1A => {
                let mut f = Self::from_hardfork(TempoHardfork::T1);
                f.insert(TempoFeature::REMOVE_TX_GAS_LIMIT);
                f
            }
            TempoHardfork::T1B => {
                let mut f = Self::from_hardfork(TempoHardfork::T1A);
                f.insert(TempoFeature::REPLAY_HASH_V2);
                f
            }
            TempoHardfork::T1C => {
                let mut f = Self::from_hardfork(TempoHardfork::T1B);
                f.insert(TempoFeature::OSAKA_PRECOMPILES);
                f
            }
            TempoHardfork::T2 => {
                let mut f = Self::from_hardfork(TempoHardfork::T1C);
                f.insert(TempoFeature::COMPOUND_TRANSFERS);
                f.insert(TempoFeature::TIP20_PERMIT);
                f.insert(TempoFeature::VALIDATOR_CONFIG_V2);
                f.insert(TempoFeature::TIP403_COMPOUND);
                f.insert(TempoFeature::FEE_TOKEN_QUERY);
                f.insert(TempoFeature::T2_NONCE_GAS);
                f
            }
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

        assert!(t1a.contains_all(&t1));
        assert!(t1b.contains_all(&t1a));
        assert!(t1c.contains_all(&t1b));
        assert!(t2.contains_all(&t1c));
    }

    #[test]
    fn test_genesis_and_t0_are_empty() {
        assert!(TempoFeatures::from_hardfork(TempoHardfork::Genesis).is_empty());
        assert!(TempoFeatures::from_hardfork(TempoHardfork::T0).is_empty());
    }

    #[test]
    fn test_t1_features() {
        let t1 = TempoFeatures::from_hardfork(TempoHardfork::T1);
        assert!(t1.contains(TempoFeature::EXPIRING_NONCES));
        assert!(t1.contains(TempoFeature::T1_GAS_PARAMS));
        assert!(t1.contains(TempoFeature::KEYCHAIN_VALIDATION));
        assert!(!t1.contains(TempoFeature::REMOVE_TX_GAS_LIMIT));
    }

    #[test]
    fn test_t2_has_all_features() {
        let t2 = TempoFeatures::from_hardfork(TempoHardfork::T2);
        assert!(t2.contains(TempoFeature::COMPOUND_TRANSFERS));
        assert!(t2.contains(TempoFeature::TIP20_PERMIT));
        assert!(t2.contains(TempoFeature::VALIDATOR_CONFIG_V2));
        assert!(t2.contains(TempoFeature::TIP403_COMPOUND));
        assert!(t2.contains(TempoFeature::FEE_TOKEN_QUERY));
        assert!(t2.contains(TempoFeature::T2_NONCE_GAS));
    }

    #[test]
    fn test_dependency_satisfied() {
        let active = TempoFeatures::from_hardfork(TempoHardfork::T1);
        assert!(
            TempoFeature::REMOVE_TX_GAS_LIMIT
                .can_activate(&active)
                .is_ok()
        );
    }

    #[test]
    fn test_dependency_missing() {
        let active = TempoFeatures::empty();
        let result = TempoFeature::REMOVE_TX_GAS_LIMIT.can_activate(&active);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.missing.contains(TempoFeature::T1_GAS_PARAMS));
    }

    #[test]
    fn test_compound_requires_chain() {
        let empty = TempoFeatures::empty();
        assert!(TempoFeature::TIP403_COMPOUND.can_activate(&empty).is_err());

        let with_expiring = TempoFeatures::from_iter([TempoFeature::EXPIRING_NONCES]);
        assert!(
            TempoFeature::TIP403_COMPOUND
                .can_activate(&with_expiring)
                .is_err()
        );

        let with_compound = TempoFeatures::from_iter([
            TempoFeature::EXPIRING_NONCES,
            TempoFeature::COMPOUND_TRANSFERS,
        ]);
        assert!(
            TempoFeature::TIP403_COMPOUND
                .can_activate(&with_compound)
                .is_ok()
        );
    }

    #[test]
    fn test_no_self_dependency() {
        for id in 0..TempoFeature::COUNT {
            let feature = TempoFeature::new(id);
            let deps = feature.requires();
            assert!(!deps.contains(feature), "feature {id} depends on itself");
        }
    }

    #[test]
    fn test_feature_independence() {
        let active = TempoFeatures::from_iter([TempoFeature::EXPIRING_NONCES]);
        assert!(TempoFeature::TIP20_PERMIT.can_activate(&active).is_ok());
        assert!(
            TempoFeature::VALIDATOR_CONFIG_V2
                .can_activate(&active)
                .is_ok()
        );
    }

    #[test]
    fn test_unlimited_features() {
        // Features at very high IDs work fine
        let high = TempoFeature::new(10_000);
        let mut set = TempoFeatures::empty();
        assert!(!set.contains(high));
        set.insert(high);
        assert!(set.contains(high));
        assert_eq!(set.count(), 1);

        // Even higher
        let very_high = TempoFeature::new(100_000);
        set.insert(very_high);
        assert!(set.contains(very_high));
        assert_eq!(set.count(), 2);

        // Remove works
        set.remove(high);
        assert!(!set.contains(high));
        assert_eq!(set.count(), 1);
    }

    #[test]
    fn test_no_dependency_cycles() {
        for id in 0..TempoFeature::COUNT {
            let feature = TempoFeature::new(id);
            let mut visited = TempoFeatures::empty();
            let mut current_deps = feature.requires();
            loop {
                if current_deps.is_empty() {
                    break;
                }
                for dep in current_deps.iter() {
                    assert!(
                        !visited.contains(dep),
                        "cycle detected involving feature {}",
                        dep.id()
                    );
                }
                visited = visited.union(&current_deps);
                // Walk one level deeper — union all deps' deps
                let mut next = TempoFeatures::empty();
                for dep in current_deps.iter() {
                    next = next.union(&dep.requires());
                }
                current_deps = next;
            }
        }
    }

    #[test]
    fn test_hardfork_features_satisfy_all_dependencies() {
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
            for feature in features.iter() {
                let deps = feature.requires();
                assert!(
                    features.contains_all(&deps),
                    "{hf:?} includes feature {} but is missing deps",
                    feature.id()
                );
            }
        }
    }

    #[test]
    fn test_missing_dependencies_display() {
        let err = TempoFeature::REMOVE_TX_GAS_LIMIT
            .can_activate(&TempoFeatures::empty())
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot activate"));
        assert!(msg.contains("missing dependencies"));
    }

    #[test]
    fn test_empty_features_can_always_activate() {
        // A feature with no deps can activate from nothing
        assert!(
            TempoFeature::EXPIRING_NONCES
                .can_activate(&TempoFeatures::empty())
                .is_ok()
        );
    }

    #[test]
    fn test_base_features_have_no_dependencies() {
        assert!(TempoFeature::EXPIRING_NONCES.requires().is_empty());
        assert!(TempoFeature::T1_GAS_PARAMS.requires().is_empty());
        assert!(TempoFeature::KEYCHAIN_VALIDATION.requires().is_empty());
    }

    #[test]
    fn test_each_hardfork_adds_features() {
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
                next_f.contains_all(&prev_f),
                "{next:?} should be a superset of {prev:?}"
            );
        }
    }

    #[test]
    fn test_t2_feature_count() {
        let t2 = TempoFeatures::from_hardfork(TempoHardfork::T2);
        assert_eq!(t2.count(), 12, "T2 should activate all 12 defined features");
    }

    #[test]
    fn test_union_and_difference() {
        let a =
            TempoFeatures::from_iter([TempoFeature::EXPIRING_NONCES, TempoFeature::T1_GAS_PARAMS]);
        let b =
            TempoFeatures::from_iter([TempoFeature::T1_GAS_PARAMS, TempoFeature::REPLAY_HASH_V2]);

        let union = a.union(&b);
        assert!(union.contains(TempoFeature::EXPIRING_NONCES));
        assert!(union.contains(TempoFeature::T1_GAS_PARAMS));
        assert!(union.contains(TempoFeature::REPLAY_HASH_V2));
        assert_eq!(union.count(), 3);

        // difference: what's in b but not in a
        let diff = a.difference(&b);
        assert!(!diff.contains(TempoFeature::T1_GAS_PARAMS)); // in both
        assert!(diff.contains(TempoFeature::REPLAY_HASH_V2)); // only in b
        assert!(!diff.contains(TempoFeature::EXPIRING_NONCES)); // only in a
    }

    #[test]
    fn test_iter() {
        let set = TempoFeatures::from_hardfork(TempoHardfork::T1);
        let ids: Vec<u32> = set.iter().map(|f| f.id()).collect();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&0)); // EXPIRING_NONCES
        assert!(ids.contains(&1)); // T1_GAS_PARAMS
        assert!(ids.contains(&2)); // KEYCHAIN_VALIDATION
    }

    #[test]
    fn test_insert_remove_idempotent() {
        let mut set = TempoFeatures::empty();
        set.insert(TempoFeature::EXPIRING_NONCES);
        set.insert(TempoFeature::EXPIRING_NONCES); // double insert
        assert_eq!(set.count(), 1);

        set.remove(TempoFeature::EXPIRING_NONCES);
        set.remove(TempoFeature::EXPIRING_NONCES); // double remove
        assert!(set.is_empty());
    }

    #[test]
    fn test_remove_nonexistent_feature() {
        let mut set = TempoFeatures::empty();
        // Removing a feature that was never inserted (including high IDs) is fine
        set.remove(TempoFeature::new(9999));
        assert!(set.is_empty());
    }

    #[test]
    fn test_hardfork_has_convenience() {
        // spec.has() is the primary API for handler code
        assert!(TempoHardfork::T1.has(TempoFeature::EXPIRING_NONCES));
        assert!(TempoHardfork::T1.has(TempoFeature::T1_GAS_PARAMS));
        assert!(!TempoHardfork::T1.has(TempoFeature::REPLAY_HASH_V2));

        assert!(TempoHardfork::T1B.has(TempoFeature::REPLAY_HASH_V2));
        assert!(!TempoHardfork::T1B.has(TempoFeature::COMPOUND_TRANSFERS));

        assert!(TempoHardfork::T2.has(TempoFeature::COMPOUND_TRANSFERS));
        assert!(TempoHardfork::T2.has(TempoFeature::TIP20_PERMIT));

        assert!(!TempoHardfork::Genesis.has(TempoFeature::EXPIRING_NONCES));
        assert!(!TempoHardfork::T0.has(TempoFeature::EXPIRING_NONCES));
    }

    /// Demonstrates how feature flags replace `spec.is_tN()` checks in
    /// non-precompile code (e.g., EVM handler, consensus, tx validation).
    ///
    /// Before:
    /// ```ignore
    /// let replay_hash = if spec.is_t1b() {
    ///     tempo_tx_env.expiring_nonce_hash.ok_or(...)?
    /// } else {
    ///     tempo_tx_env.tx_hash
    /// };
    /// ```
    ///
    /// After:
    /// ```ignore
    /// let replay_hash = if spec.has(TempoFeature::REPLAY_HASH_V2) {
    ///     tempo_tx_env.expiring_nonce_hash.ok_or(...)?
    /// } else {
    ///     tempo_tx_env.tx_hash
    /// };
    /// ```
    #[test]
    fn test_handler_migration_pattern() {
        // Simulates the replay hash selection logic from handler.rs
        fn select_replay_hash(spec: TempoHardfork, v2_hash: u64, v1_hash: u64) -> u64 {
            if spec.has(TempoFeature::REPLAY_HASH_V2) {
                v2_hash
            } else {
                v1_hash
            }
        }

        // Pre-T1B: uses v1 hash
        assert_eq!(select_replay_hash(TempoHardfork::T1, 42, 7), 7);
        assert_eq!(select_replay_hash(TempoHardfork::T1A, 42, 7), 7);

        // T1B+: uses v2 hash
        assert_eq!(select_replay_hash(TempoHardfork::T1B, 42, 7), 42);
        assert_eq!(select_replay_hash(TempoHardfork::T2, 42, 7), 42);
    }

    /// Demonstrates multi-feature gating — e.g., a security fix that
    /// only applies when two features are both active.
    #[test]
    fn test_multi_feature_gating() {
        fn should_apply_security_fix(spec: TempoHardfork) -> bool {
            spec.has(TempoFeature::EXPIRING_NONCES) && spec.has(TempoFeature::REPLAY_HASH_V2)
        }

        assert!(!should_apply_security_fix(TempoHardfork::T1)); // has nonces, no replay v2
        assert!(should_apply_security_fix(TempoHardfork::T1B)); // has both
        assert!(should_apply_security_fix(TempoHardfork::T2)); // has both
    }
}
