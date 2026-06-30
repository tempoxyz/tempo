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
            $variant:ident = $name:literal,
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
            /// Returns this feature's activation cursor index.
            ///
            /// Index `0` is reserved for [`NO_ACTIVE_FEATURE_HEAD`], so the first
            /// real feature has index `1`.
            pub const fn index(self) -> usize {
                self as usize + 1
            }

            /// Returns the canonical dotted feature name used for hashing and tooling.
            pub const fn name(self) -> &'static str {
                match self {
                    $(
                        Self::$variant => $name,
                    )+
                }
            }
        }

        /// Features supported by this binary, in activation-cursor order.
        pub const FEATURE_REGISTRY: &[Feature] = &[
            $(
                Feature::$variant,
            )+
        ];
    };
}

tempo_features! {
    /// TIP-1063 feature registry and feature-head activation.
    Tip1063FeatureRegistry = "tip-1063.feature-registry",
}

const FEATURE_HEADS_COUNT: usize = FEATURE_REGISTRY.len() + 1;

/// Cached feature hash-chain heads.
///
/// Index `0` is [`NO_ACTIVE_FEATURE_HEAD`], and index `N > 0` is the head for
/// feature IDs `1..=N`.
pub static FEATURE_HEADS: LazyLock<[B256; FEATURE_HEADS_COUNT]> =
    LazyLock::new(build_feature_heads);

fn build_feature_heads() -> [B256; FEATURE_HEADS_COUNT] {
    let mut heads = [NO_ACTIVE_FEATURE_HEAD; FEATURE_HEADS_COUNT];
    let mut head = NO_ACTIVE_FEATURE_HEAD;

    for (index, feature) in FEATURE_REGISTRY.iter().copied().enumerate() {
        head = extend_feature_head(head, feature);
        heads[index + 1] = head;
    }

    heads
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
    *FEATURE_HEADS
        .last()
        .expect("feature head cache always includes zero head")
}

/// Returns the feature head for `feature`.
pub fn feature_head(feature: Feature) -> B256 {
    FEATURE_HEADS[feature.index()]
}

/// Returns the activation cursor index for `feature_head`, if it belongs to this binary's chain.
pub fn feature_head_index(feature_head: B256) -> Option<usize> {
    FEATURE_HEADS
        .iter()
        .position(|supported_head| *supported_head == feature_head)
}

/// Returns true if this binary's feature hash chain contains `feature_head`.
pub fn supports_feature_head(feature_head: B256) -> bool {
    feature_head_index(feature_head).is_some()
}

/// An active feature stack resolved against this binary's local feature chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveFeatures {
    head: B256,
    active_index: usize,
}

impl ActiveFeatures {
    /// Resolves `head` into an active feature stack.
    pub fn new(head: B256) -> Result<Self, UnknownFeatureHead> {
        let Some(active_index) = feature_head_index(head) else {
            return Err(UnknownFeatureHead { head });
        };

        Ok(Self { head, active_index })
    }

    /// Returns an active feature stack with no active features.
    pub const fn none() -> Self {
        Self {
            head: NO_ACTIVE_FEATURE_HEAD,
            active_index: 0,
        }
    }

    /// Returns the active feature head used to build this stack.
    pub const fn head(self) -> B256 {
        self.head
    }

    /// Returns the active feature cursor index.
    pub const fn active_index(self) -> usize {
        self.active_index
    }

    /// Returns true if `feature` is active in this stack.
    pub fn is_active(self, feature: Feature) -> bool {
        self.active_index >= feature.index()
    }
}

/// Error returned when a feature head is not in this binary's local feature chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownFeatureHead {
    /// Unknown active feature head.
    pub head: B256,
}

impl core::fmt::Display for UnknownFeatureHead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown feature head {:?}", self.head)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownFeatureHead {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_means_no_active_feature() {
        assert_eq!(NO_ACTIVE_FEATURE_HEAD, B256::ZERO);
        assert_eq!(FEATURE_HEADS[0], B256::ZERO);
        assert!(supports_feature_head(B256::ZERO));
    }

    #[test]
    fn feature_head_hash_chain_includes_supported_prefixes() {
        for head in FEATURE_HEADS.iter().copied() {
            assert!(supports_feature_head(head));
        }
        assert_ne!(highest_supported_feature_head(), NO_ACTIVE_FEATURE_HEAD);
    }

    #[test]
    fn feature_head_cache_matches_registry_prefixes() {
        assert_eq!(FEATURE_HEADS.len(), FEATURE_REGISTRY.len() + 1);
        assert_eq!(FEATURE_HEADS[0], NO_ACTIVE_FEATURE_HEAD);
        for head in FEATURE_HEADS.iter().copied() {
            assert!(supports_feature_head(head));
        }
    }

    #[test]
    fn macro_generated_features_have_names_and_indexes() {
        assert_eq!(
            Feature::Tip1063FeatureRegistry.name(),
            "tip-1063.feature-registry"
        );
        assert_eq!(Feature::Tip1063FeatureRegistry.index(), 1);
        assert_eq!(FEATURE_REGISTRY, &[Feature::Tip1063FeatureRegistry]);
    }

    #[test]
    fn feature_head_lookup_returns_typed_feature_head() {
        let head = feature_head(Feature::Tip1063FeatureRegistry);
        assert_eq!(head, highest_supported_feature_head());
        assert_eq!(
            feature_head_index(head),
            Some(Feature::Tip1063FeatureRegistry.index())
        );
    }

    #[test]
    fn active_features_resolve_known_heads() {
        let no_active =
            ActiveFeatures::new(NO_ACTIVE_FEATURE_HEAD).expect("zero feature head is always known");
        assert_eq!(no_active, ActiveFeatures::none());
        assert!(!no_active.is_active(Feature::Tip1063FeatureRegistry));

        let active = ActiveFeatures::new(feature_head(Feature::Tip1063FeatureRegistry))
            .expect("typed feature head is known");
        assert_eq!(active.head(), feature_head(Feature::Tip1063FeatureRegistry));
        assert_eq!(
            active.active_index(),
            Feature::Tip1063FeatureRegistry.index()
        );
        assert!(active.is_active(Feature::Tip1063FeatureRegistry));
    }

    #[test]
    fn active_features_reject_unknown_head() {
        let unknown = B256::repeat_byte(0xff);
        assert_eq!(
            ActiveFeatures::new(unknown),
            Err(UnknownFeatureHead { head: unknown })
        );
    }
}
