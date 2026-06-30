//! Tempo feature registry.
//!
//! Feature names are ordered in [`FEATURE_REGISTRY`]. The chain stores the hash-chain head
//! for the active feature stack, so the zero head means no active features.

use alloy_primitives::{B256, Keccak256};
#[cfg(not(feature = "std"))]
use once_cell::sync::Lazy as LazyLock;
#[cfg(feature = "std")]
use std::sync::LazyLock;

/// No feature is active.
pub const NO_ACTIVE_FEATURE_HEAD: B256 = B256::ZERO;

const FEATURE_HEAD_DOMAIN: &[u8] = b"tempo.feature.v1";

macro_rules! tempo_features {
    (
        $(
            $(#[$meta:meta])*
            $variant:ident = $name:literal => $supports:ident,
        )+
    ) => {
        /// A feature supported by this binary.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(usize)]
        pub enum Feature {
            $(
                $(#[$meta])*
                $variant,
            )+
        }

        impl Feature {
            $(
                #[doc = concat!(
                    "Returns true if this active feature tip includes `",
                    $name,
                    "`."
                )]
                pub const fn $supports(self) -> bool {
                    self.supports(Self::$variant)
                }
            )+
        }

        /// Features supported by this binary, in activation-cursor order.
        pub const FEATURE_REGISTRY: &[Feature] = &[
            $(
                Feature::$variant,
            )+
        ];

        const FEATURE_NAMES: &[&str] = &[
            $(
                $name,
            )+
        ];
    };
}

tempo_features! {
    /// TIP-1063 feature registry and feature-head activation.
    Tip1063FeatureRegistry = "tip-1063.feature-registry" => is_tip1063_active,
}

const FEATURE_DIGESTS_COUNT: usize = FEATURE_REGISTRY.len() + 1;

impl Feature {
    const fn registry_index(self) -> usize {
        self as usize
    }

    /// Returns this feature's activation cursor index.
    ///
    /// Index `0` is reserved for [`NO_ACTIVE_FEATURE_HEAD`], so the first
    /// real feature has index `1`.
    pub const fn index(self) -> usize {
        self.registry_index() + 1
    }

    /// Returns the canonical dotted feature name used for hashing and tooling.
    pub const fn name(self) -> &'static str {
        FEATURE_NAMES[self.registry_index()]
    }

    /// Returns this feature's hash-chain digest.
    pub fn digest(self) -> B256 {
        FEATURE_DIGESTS[self.index()]
    }

    /// Resolves `digest` into the active feature tip known by this binary.
    ///
    /// Returns `None` for [`NO_ACTIVE_FEATURE_HEAD`] and unknown digests.
    pub fn from_digest(digest: B256) -> Option<Self> {
        let index = FEATURE_DIGESTS
            .iter()
            .position(|supported_digest| *supported_digest == digest)?;

        if index == 0 {
            return None;
        }

        Some(FEATURE_REGISTRY[index - 1])
    }

    /// Returns true if this active feature tip includes `feature`.
    pub const fn supports(self, feature: Self) -> bool {
        self.index() >= feature.index()
    }
}

/// Cached feature hash-chain digests.
///
/// Index `0` is [`NO_ACTIVE_FEATURE_HEAD`], and index `N > 0` is the digest
/// for features `1..=N`.
pub static FEATURE_DIGESTS: LazyLock<[B256; FEATURE_DIGESTS_COUNT]> =
    LazyLock::new(build_feature_digests);

fn build_feature_digests() -> [B256; FEATURE_DIGESTS_COUNT] {
    let mut digests = [NO_ACTIVE_FEATURE_HEAD; FEATURE_DIGESTS_COUNT];
    let mut head = NO_ACTIVE_FEATURE_HEAD;

    for (index, feature) in FEATURE_REGISTRY.iter().copied().enumerate() {
        head = extend_feature_head(head, feature);
        digests[index + 1] = head;
    }

    digests
}

/// Returns the head produced by appending `feature` to `parent_head`.
pub fn extend_feature_head(parent_head: B256, feature: Feature) -> B256 {
    let mut hasher = Keccak256::new();
    update_len_prefixed(&mut hasher, FEATURE_HEAD_DOMAIN);
    hasher.update(parent_head.as_slice());
    update_len_prefixed(&mut hasher, feature.name().as_bytes());
    hasher.finalize()
}

fn update_len_prefixed(hasher: &mut Keccak256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Highest feature head supported by this binary.
pub fn highest_supported_feature_head() -> B256 {
    *FEATURE_DIGESTS
        .last()
        .expect("feature digest cache always includes zero head")
}

/// Returns true if this binary's feature hash chain contains `feature_head`.
pub fn supports_feature_head(feature_head: B256) -> bool {
    FEATURE_DIGESTS.contains(&feature_head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_means_no_active_feature() {
        assert_eq!(NO_ACTIVE_FEATURE_HEAD, B256::ZERO);
        assert_eq!(FEATURE_DIGESTS[0], B256::ZERO);
        assert!(supports_feature_head(B256::ZERO));
        assert_eq!(Feature::from_digest(B256::ZERO), None);
    }

    #[test]
    fn feature_digest_hash_chain_includes_supported_prefixes() {
        for digest in FEATURE_DIGESTS.iter().copied() {
            assert!(supports_feature_head(digest));
        }
        assert_ne!(highest_supported_feature_head(), NO_ACTIVE_FEATURE_HEAD);
    }

    #[test]
    fn feature_digest_cache_matches_registry_prefixes() {
        assert_eq!(FEATURE_DIGESTS.len(), FEATURE_REGISTRY.len() + 1);
        assert_eq!(FEATURE_DIGESTS[0], NO_ACTIVE_FEATURE_HEAD);
        for digest in FEATURE_DIGESTS.iter().copied() {
            assert!(supports_feature_head(digest));
        }
    }

    #[test]
    fn macro_generated_features_have_names_indexes_and_helpers() {
        let feature = Feature::Tip1063FeatureRegistry;

        assert_eq!(feature.name(), "tip-1063.feature-registry");
        assert_eq!(feature.index(), 1);
        assert_eq!(FEATURE_REGISTRY, &[feature]);
        assert!(feature.supports(Feature::Tip1063FeatureRegistry));
        assert!(feature.is_tip1063_active());
    }

    #[test]
    fn feature_digest_resolves_to_typed_feature() {
        let head = Feature::Tip1063FeatureRegistry.digest();
        assert_eq!(head, highest_supported_feature_head());
        assert_eq!(
            Feature::from_digest(head),
            Some(Feature::Tip1063FeatureRegistry)
        );
    }

    #[test]
    fn feature_from_digest_resolves_known_heads() {
        assert_eq!(Feature::from_digest(NO_ACTIVE_FEATURE_HEAD), None);
        assert_eq!(
            Feature::from_digest(Feature::Tip1063FeatureRegistry.digest()),
            Some(Feature::Tip1063FeatureRegistry)
        );
    }

    #[test]
    fn feature_from_digest_returns_none_for_unknown_head() {
        let unknown = B256::repeat_byte(0xff);
        assert_eq!(Feature::from_digest(unknown), None);
        assert!(!supports_feature_head(unknown));
    }
}
