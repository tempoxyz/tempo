//! Tempo protocol feature registry.
//!
//! Feature IDs are 1-indexed positions in [`PROTOCOL_FEATURE_REGISTRY`]. The chain currently stores
//! only the highest active feature ID, so zero means no active protocol features.

use core::fmt;

use alloy_primitives::{B256, Keccak256};

/// No protocol feature is active.
pub const NO_ACTIVE_PROTOCOL_FEATURE_ID: u64 = 0;

/// Storage slot containing the highest active protocol feature ID.
pub const HIGHEST_ACTIVE_PROTOCOL_FEATURE_ID_SLOT: alloy_primitives::U256 =
    alloy_primitives::U256::ZERO;

/// A protocol feature supported by this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolFeature {
    /// 1-indexed feature ID. This must match the feature's registry position.
    pub id: u64,
    /// Canonical dotted feature name used in support reports, off-chain metadata, and operator tooling.
    pub name: &'static str,
    /// Encoded minimum Tempo version that supports this feature.
    pub minimum_supported_version_key: u64,
}

/// Protocol features supported by this binary, in activation-cursor order.
pub const PROTOCOL_FEATURE_REGISTRY: &[ProtocolFeature] = &[ProtocolFeature {
    id: 1,
    name: "tip-1063.feature-registry",
    // TODO: update before merge if this feature does not ship in 1.8.1.
    minimum_supported_version_key: version_key(1, 8, 1),
}];

/// Encodes a semver version as `(major << 32) | (minor << 16) | patch`.
#[allow(clippy::cast_lossless)]
pub const fn version_key(major: u16, minor: u16, patch: u16) -> u64 {
    ((major as u64) << 32) | ((minor as u64) << 16) | patch as u64
}

/// Highest protocol feature ID supported by this binary.
#[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
pub const fn highest_supported_protocol_feature_id() -> u64 {
    PROTOCOL_FEATURE_REGISTRY.len() as u64
}

/// Returns true if this binary supports every feature up to `highest_active_feature_id`.
pub const fn supports_protocol_feature_id(highest_active_feature_id: u64) -> bool {
    highest_active_feature_id <= highest_supported_protocol_feature_id()
}

/// Returns the protocol feature with `id`.
pub fn protocol_feature_by_id(id: u64) -> Option<&'static ProtocolFeature> {
    if id == NO_ACTIVE_PROTOCOL_FEATURE_ID {
        return None;
    }
    let index = usize::try_from(id.checked_sub(1)?).ok()?;
    PROTOCOL_FEATURE_REGISTRY.get(index)
}

/// Returns the digest validators must report when supporting every feature through `features_tip`.
///
/// Feature tip `0` means no supported protocol feature flags and has the zero digest. Higher tips
/// commit to the ordered `(feature_id, name)` prefix of [`PROTOCOL_FEATURE_REGISTRY`].
pub fn protocol_features_digest(features_tip: u64) -> Option<B256> {
    if features_tip == NO_ACTIVE_PROTOCOL_FEATURE_ID {
        return Some(B256::ZERO);
    }

    let features_len = u64::try_from(PROTOCOL_FEATURE_REGISTRY.len()).ok()?;
    if features_tip > features_len {
        return None;
    }

    let mut hasher = Keccak256::new();
    for feature in PROTOCOL_FEATURE_REGISTRY
        .iter()
        .take(usize::try_from(features_tip).ok()?)
    {
        let name = feature.name.as_bytes();
        let name_len = u64::try_from(name.len()).ok()?;
        hasher.update(feature.id.to_be_bytes());
        hasher.update(name_len.to_be_bytes());
        hasher.update(name);
    }

    Some(hasher.finalize())
}

/// Error returned when chain history has activated a feature this binary does not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedProtocolFeature {
    /// Highest active feature ID read from chain state.
    pub active: u64,
    /// Highest feature ID supported by this binary.
    pub supported: u64,
}

impl fmt::Display for UnsupportedProtocolFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported protocol feature active: chain requires feature {}, binary supports up to {}",
            self.active, self.supported
        )
    }
}

/// Validates the on-chain protocol feature cursor against this binary.
pub const fn ensure_supported_protocol_feature_id(
    highest_active_feature_id: u64,
) -> Result<(), UnsupportedProtocolFeature> {
    let supported = highest_supported_protocol_feature_id();
    if highest_active_feature_id <= supported {
        Ok(())
    } else {
        Err(UnsupportedProtocolFeature {
            active: highest_active_feature_id,
            supported,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_means_no_active_feature() {
        assert_eq!(NO_ACTIVE_PROTOCOL_FEATURE_ID, 0);
        assert_eq!(protocol_feature_by_id(0), None);
        assert_eq!(protocol_features_digest(0), Some(B256::ZERO));
        assert!(supports_protocol_feature_id(0));
    }

    #[test]
    fn feature_ids_match_registry_order() {
        for (offset, feature) in PROTOCOL_FEATURE_REGISTRY.iter().enumerate() {
            let expected_id = u64::try_from(offset).expect("feature offset fits in u64") + 1;
            assert_eq!(feature.id, expected_id);
            assert_eq!(protocol_feature_by_id(feature.id), Some(feature));
        }
    }

    #[test]
    fn feature_digest_commits_to_ordered_feature_names() {
        let mut hasher = Keccak256::new();
        hasher.update(1u64.to_be_bytes());
        hasher.update(25u64.to_be_bytes());
        hasher.update(b"tip-1063.feature-registry");

        assert_eq!(protocol_features_digest(1), Some(hasher.finalize()));
        assert_eq!(protocol_features_digest(2), None);
    }

    #[test]
    fn rejects_active_feature_past_local_registry() {
        let unsupported = highest_supported_protocol_feature_id() + 1;
        assert_eq!(
            ensure_supported_protocol_feature_id(unsupported),
            Err(UnsupportedProtocolFeature {
                active: unsupported,
                supported: highest_supported_protocol_feature_id(),
            })
        );
    }

    #[test]
    fn version_key_encodes_semver() {
        assert_eq!(version_key(1, 2, 3), 0x0000_0001_0002_0003);
    }
}
