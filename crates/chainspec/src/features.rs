//! Tempo protocol feature registry.
//!
//! Feature IDs are globally unique registry keys and bitmap indexes. Activation order is chain
//! history and is not encoded by local registry order.

use core::fmt;

use alloy_primitives::U256;

/// Feature ID reserved for "no feature".
pub const RESERVED_PROTOCOL_FEATURE_ID: u64 = 0;

/// Number of feature IDs represented by one feature bitmap word.
pub const PROTOCOL_FEATURE_BITMAP_WORD_BITS: u64 = 256;

/// A protocol feature supported by this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolFeature {
    /// Globally unique feature ID and bitmap index.
    pub id: u64,
    /// Canonical dotted feature name used in off-chain metadata and operator tooling.
    pub name: &'static str,
    /// Encoded minimum Tempo version that supports this feature.
    pub minimum_supported_version_key: u64,
}

/// Protocol features supported by this binary.
///
/// Order is local metadata order only. It does not encode activation order.
pub const PROTOCOL_FEATURE_REGISTRY: &[ProtocolFeature] = &[];

/// Encodes a semver version as `(major << 32) | (minor << 16) | patch`.
#[allow(clippy::cast_lossless)]
pub const fn version_key(major: u16, minor: u16, patch: u16) -> u64 {
    ((major as u64) << 32) | ((minor as u64) << 16) | patch as u64
}

/// Returns the protocol feature with `id`.
pub fn protocol_feature_by_id(id: u64) -> Option<&'static ProtocolFeature> {
    protocol_feature_by_id_in(PROTOCOL_FEATURE_REGISTRY, id)
}

fn protocol_feature_by_id_in(
    registry: &'static [ProtocolFeature],
    id: u64,
) -> Option<&'static ProtocolFeature> {
    if id == RESERVED_PROTOCOL_FEATURE_ID {
        return None;
    }

    registry.iter().find(|feature| feature.id == id)
}

/// Returns true if this binary supports `feature_id`.
pub fn supports_protocol_feature_id(feature_id: u64) -> bool {
    supports_protocol_feature_id_in(PROTOCOL_FEATURE_REGISTRY, feature_id)
}

fn supports_protocol_feature_id_in(registry: &'static [ProtocolFeature], feature_id: u64) -> bool {
    protocol_feature_by_id_in(registry, feature_id).is_some()
}

/// Error returned when chain history has activated a feature this binary does not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedProtocolFeature {
    /// An active feature ID is not in this binary's registry.
    UnsupportedFeatureId {
        /// Active feature ID read from chain state.
        feature_id: u64,
    },
    /// A bitmap bit position cannot be represented as a `u64` feature ID.
    FeatureIdOverflow {
        /// Active bitmap word index.
        word_index: usize,
        /// Active bit index within the word.
        bit_index: usize,
    },
}

impl fmt::Display for UnsupportedProtocolFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFeatureId { feature_id } => write!(
                f,
                "unsupported protocol feature active: chain requires feature {feature_id}"
            ),
            Self::FeatureIdOverflow {
                word_index,
                bit_index,
            } => write!(
                f,
                "unsupported protocol feature active: bitmap position {word_index}:{bit_index} cannot be represented as a u64 feature ID"
            ),
        }
    }
}

/// Validates one active protocol feature ID against this binary.
pub fn ensure_supported_protocol_feature_id(
    feature_id: u64,
) -> Result<(), UnsupportedProtocolFeature> {
    ensure_supported_protocol_feature_id_in(PROTOCOL_FEATURE_REGISTRY, feature_id)
}

fn ensure_supported_protocol_feature_id_in(
    registry: &'static [ProtocolFeature],
    feature_id: u64,
) -> Result<(), UnsupportedProtocolFeature> {
    if supports_protocol_feature_id_in(registry, feature_id) {
        Ok(())
    } else {
        Err(UnsupportedProtocolFeature::UnsupportedFeatureId { feature_id })
    }
}

/// Validates active protocol feature IDs against this binary.
pub fn ensure_supported_protocol_feature_ids(
    active_feature_ids: impl IntoIterator<Item = u64>,
) -> Result<(), UnsupportedProtocolFeature> {
    ensure_supported_protocol_feature_ids_in(PROTOCOL_FEATURE_REGISTRY, active_feature_ids)
}

fn ensure_supported_protocol_feature_ids_in(
    registry: &'static [ProtocolFeature],
    active_feature_ids: impl IntoIterator<Item = u64>,
) -> Result<(), UnsupportedProtocolFeature> {
    for feature_id in active_feature_ids {
        ensure_supported_protocol_feature_id_in(registry, feature_id)?;
    }

    Ok(())
}

/// Returns the bitmap word and bit index for `feature_id`.
pub fn protocol_feature_bitmap_position(feature_id: u64) -> Option<(usize, usize)> {
    let word_index = usize::try_from(feature_id / PROTOCOL_FEATURE_BITMAP_WORD_BITS).ok()?;
    let bit_index = usize::try_from(feature_id % PROTOCOL_FEATURE_BITMAP_WORD_BITS).ok()?;
    Some((word_index, bit_index))
}

fn protocol_feature_id_from_bitmap_position(
    word_index: usize,
    bit_index: usize,
) -> Result<u64, UnsupportedProtocolFeature> {
    let original_word_index = word_index;
    let original_bit_index = bit_index;
    let word_index =
        u64::try_from(word_index).map_err(|_| UnsupportedProtocolFeature::FeatureIdOverflow {
            word_index: original_word_index,
            bit_index: original_bit_index,
        })?;
    let bit_index =
        u64::try_from(bit_index).map_err(|_| UnsupportedProtocolFeature::FeatureIdOverflow {
            word_index: original_word_index,
            bit_index: original_bit_index,
        })?;

    word_index
        .checked_mul(PROTOCOL_FEATURE_BITMAP_WORD_BITS)
        .and_then(|base| base.checked_add(bit_index))
        .ok_or(UnsupportedProtocolFeature::FeatureIdOverflow {
            word_index: original_word_index,
            bit_index: original_bit_index,
        })
}

/// Returns true if `active_feature_bitmap` contains `feature_id`.
pub fn protocol_feature_bitmap_contains(active_feature_bitmap: &[U256], feature_id: u64) -> bool {
    let Some((word_index, bit_index)) = protocol_feature_bitmap_position(feature_id) else {
        return false;
    };
    let Some(word) = active_feature_bitmap.get(word_index) else {
        return false;
    };

    (*word & (U256::ONE << bit_index)) != U256::ZERO
}

/// Validates an active protocol feature bitmap against this binary.
pub fn ensure_supported_protocol_feature_bitmap(
    active_feature_bitmap: &[U256],
) -> Result<(), UnsupportedProtocolFeature> {
    ensure_supported_protocol_feature_bitmap_in(PROTOCOL_FEATURE_REGISTRY, active_feature_bitmap)
}

fn ensure_supported_protocol_feature_bitmap_in(
    registry: &'static [ProtocolFeature],
    active_feature_bitmap: &[U256],
) -> Result<(), UnsupportedProtocolFeature> {
    for (word_index, word) in active_feature_bitmap.iter().enumerate() {
        if *word == U256::ZERO {
            continue;
        }

        for bit_index in 0..usize::try_from(PROTOCOL_FEATURE_BITMAP_WORD_BITS)
            .expect("bitmap word bit count fits in usize")
        {
            if (*word & (U256::ONE << bit_index)) == U256::ZERO {
                continue;
            }

            let feature_id = protocol_feature_id_from_bitmap_position(word_index, bit_index)?;
            ensure_supported_protocol_feature_id_in(registry, feature_id)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REGISTRY: &[ProtocolFeature] = &[
        ProtocolFeature {
            id: 2,
            name: "tempo.two",
            minimum_supported_version_key: version_key(1, 0, 0),
        },
        ProtocolFeature {
            id: 9,
            name: "tempo.nine",
            minimum_supported_version_key: version_key(1, 1, 0),
        },
    ];

    #[test]
    fn zero_is_reserved() {
        assert_eq!(RESERVED_PROTOCOL_FEATURE_ID, 0);
        assert_eq!(protocol_feature_by_id(0), None);
        assert!(!supports_protocol_feature_id(0));
    }

    #[test]
    fn feature_ids_are_registry_keys_not_positions() {
        assert_eq!(protocol_feature_by_id_in(TEST_REGISTRY, 1), None);
        assert_eq!(
            protocol_feature_by_id_in(TEST_REGISTRY, 2),
            Some(&TEST_REGISTRY[0])
        );
        assert_eq!(
            protocol_feature_by_id_in(TEST_REGISTRY, 9),
            Some(&TEST_REGISTRY[1])
        );
    }

    #[test]
    fn validates_active_feature_ids_as_a_set() {
        assert!(ensure_supported_protocol_feature_ids_in(TEST_REGISTRY, [2, 9]).is_ok());
        assert_eq!(
            ensure_supported_protocol_feature_ids_in(TEST_REGISTRY, [2, 4]),
            Err(UnsupportedProtocolFeature::UnsupportedFeatureId { feature_id: 4 })
        );
    }

    #[test]
    fn validates_active_feature_bitmap_by_feature_id_bits() {
        let bitmap = [U256::ONE << 2 | U256::ONE << 9];

        assert!(protocol_feature_bitmap_contains(&bitmap, 2));
        assert!(protocol_feature_bitmap_contains(&bitmap, 9));
        assert!(!protocol_feature_bitmap_contains(&bitmap, 1));
        assert!(ensure_supported_protocol_feature_bitmap_in(TEST_REGISTRY, &bitmap).is_ok());

        let unsupported_bitmap = [bitmap[0] | (U256::ONE << 4)];
        assert_eq!(
            ensure_supported_protocol_feature_bitmap_in(TEST_REGISTRY, &unsupported_bitmap),
            Err(UnsupportedProtocolFeature::UnsupportedFeatureId { feature_id: 4 })
        );
    }

    #[test]
    fn version_key_encodes_semver() {
        assert_eq!(version_key(1, 2, 3), 0x0000_0001_0002_0003);
    }
}
