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

/// A feature supported by this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feature {
    /// Canonical dotted feature name used in off-chain metadata and operator tooling.
    pub name: &'static str,
}

/// Features supported by this binary, in activation-cursor order.
pub const FEATURE_REGISTRY: &[Feature] = &[Feature {
    name: "tip-1063.feature-registry",
}];

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

    for (index, feature) in FEATURE_REGISTRY.iter().enumerate() {
        head = extend_feature_head(head, feature);
        heads[index + 1] = head;
    }

    heads
}

/// Returns the head produced by appending `feature` to `parent_head`.
pub fn extend_feature_head(parent_head: B256, feature: &Feature) -> B256 {
    let mut hasher = Keccak256::new();
    update_len_prefixed(&mut hasher, FEATURE_HEAD_DOMAIN);
    hasher.update(parent_head.as_slice());
    update_len_prefixed(&mut hasher, feature.name.as_bytes());
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

/// Returns true if this binary's feature hash chain contains `feature_head`.
pub fn supports_feature_head(feature_head: B256) -> bool {
    FEATURE_HEADS.contains(&feature_head)
}

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
}
