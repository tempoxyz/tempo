//! Proof schemes accepted by ZK signatures ([TIP-1131]).
//!
//! [TIP-1131]: https://docs.tempo.xyz/protocol/tips/tip-1131

use crate::groth16::{PointError, PreparedVerifyingKey, VERIFYING_KEY_LENGTH, VerifyingKey};
use std::sync::OnceLock;

/// Scheme `0x01`: OIDC ID tokens signed with RS256 ([TIP-1133]).
///
/// [TIP-1133]: https://docs.tempo.xyz/protocol/tips/tip-1133
pub const SCHEME_OIDC_RS256_V1: u8 = 0x01;

/// The OIDC address namespace.
pub const NAMESPACE_OIDC: u8 = 0x01;

/// `VK_OIDC_RS256_V1` from the TIP-1133 trusted setup. It is fixed when the ceremony completes;
/// until then scheme `0x01` has no verifying key and rejects every proof.
const VK_OIDC_RS256_V1: Option<&[u8; VERIFYING_KEY_LENGTH]> = None;

/// A circuit and verifying key for one statement format.
#[derive(Debug)]
pub struct Scheme {
    /// The scheme byte carried in signatures.
    pub id: u8,
    /// The namespace mixed into addresses. Schemes sharing a namespace share addresses.
    pub namespace: u8,
    /// The longest allowed `valid_until - issued_at`, in seconds.
    pub max_window: u64,
    /// Whether the scheme also accepts message signatures.
    pub message_form: bool,
    verifying_key: Option<&'static [u8; VERIFYING_KEY_LENGTH]>,
    prepared: OnceLock<Option<PreparedVerifyingKey>>,
    genesis_key: OnceLock<GenesisKey>,
    image: OnceLock<[u32; 8]>,
}

/// A verifying key from a development chain's genesis.
#[derive(Debug)]
struct GenesisKey {
    encoded: [u8; VERIFYING_KEY_LENGTH],
    prepared: PreparedVerifyingKey,
}

static OIDC_RS256_V1: Scheme = Scheme {
    id: SCHEME_OIDC_RS256_V1,
    namespace: NAMESPACE_OIDC,
    max_window: 600,
    message_form: true,
    verifying_key: VK_OIDC_RS256_V1,
    prepared: OnceLock::new(),
    genesis_key: OnceLock::new(),
    image: OnceLock::new(),
};

/// Returns the scheme with the given byte, if one is defined.
pub fn scheme(id: u8) -> Option<&'static Scheme> {
    match id {
        SCHEME_OIDC_RS256_V1 => Some(&OIDC_RS256_V1),
        0x80 => Some(&OIDC_MLDSA65),
        _ => None,
    }
}

/// Sets verifying keys a development chain's genesis supplies, by scheme byte, for schemes
/// without a protocol key. Setting the same key again is a no-op.
pub fn set_genesis_keys<'a>(
    keys: impl IntoIterator<Item = (u8, &'a [u8])>,
) -> Result<(), GenesisKeyError> {
    for (id, key) in keys {
        scheme(id)
            .ok_or(GenesisKeyError::UnknownScheme(id))?
            .set_genesis_key(key)?;
    }
    Ok(())
}

static OIDC_MLDSA65: Scheme = Scheme {
    id: 0x80,
    namespace: 0x80,
    max_window: crate::pq::MAX_WINDOW,
    message_form: false,
    verifying_key: None,
    prepared: OnceLock::new(),
    genesis_key: OnceLock::new(),
    image: OnceLock::new(),
};

impl Scheme {
    /// Whether the chain has pinned the verifier for this scheme.
    pub fn is_active(&'static self) -> bool {
        if self.id == 0x80 {
            self.image.get().is_some()
        } else {
            self.verifying_key().is_some()
        }
    }

    /// Experimental guest image pinned by a development genesis.
    pub fn image_id(&self) -> Option<[u32; 8]> {
        self.image.get().copied()
    }

    /// Returns the scheme's prepared verifying key, or `None` while it has none.
    ///
    /// The protocol key takes precedence over a key set from genesis.
    pub fn verifying_key(&'static self) -> Option<&'static PreparedVerifyingKey> {
        #[cfg(feature = "test-utils")]
        if let Some(key) = crate::test_utils::verifying_key_override(self.id) {
            return Some(key);
        }
        self.protocol_key()
            .or_else(|| self.genesis_key.get().map(|key| &key.prepared))
    }

    fn protocol_key(&'static self) -> Option<&'static PreparedVerifyingKey> {
        self.prepared
            .get_or_init(|| {
                let bytes = self.verifying_key?;
                let key = VerifyingKey::decode(bytes).expect("scheme verifying keys are valid");
                Some(key.prepare())
            })
            .as_ref()
    }

    /// Sets the verifying key a development chain's genesis supplies. Fails if the scheme has a
    /// protocol key or a different genesis key.
    pub fn set_genesis_key(&'static self, encoded: &[u8]) -> Result<(), GenesisKeyError> {
        if self.id == 0x80 {
            let bytes: [u8; 32] = encoded.try_into().map_err(|_| GenesisKeyError::Length {
                scheme: self.id,
                length: encoded.len(),
            })?;
            let image = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    bytes[i * 4..i * 4 + 4]
                        .try_into()
                        .expect("four-byte image word"),
                )
            });
            if image == [0; 8] {
                return Err(GenesisKeyError::Conflict(self.id));
            }
            let _ = self.image.set(image);
            return if self.image.get() == Some(&image) {
                Ok(())
            } else {
                Err(GenesisKeyError::Conflict(self.id))
            };
        }
        if self.verifying_key.is_some() {
            return Err(GenesisKeyError::ProtocolKey(self.id));
        }
        let encoded: [u8; VERIFYING_KEY_LENGTH] =
            encoded.try_into().map_err(|_| GenesisKeyError::Length {
                scheme: self.id,
                length: encoded.len(),
            })?;
        if self.genesis_key.get().is_none() {
            let prepared = VerifyingKey::decode(&encoded)
                .map_err(|error| GenesisKeyError::Invalid {
                    scheme: self.id,
                    error,
                })?
                .prepare();
            // A concurrent caller may win the race; the comparison below decides either way.
            let _ = self.genesis_key.set(GenesisKey { encoded, prepared });
        }
        match self.genesis_key.get() {
            Some(key) if key.encoded == encoded => Ok(()),
            _ => Err(GenesisKeyError::Conflict(self.id)),
        }
    }
}

/// Why a genesis verifying key was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GenesisKeyError {
    /// No scheme uses this byte.
    #[error("unknown ZK signature scheme {0}")]
    UnknownScheme(u8),
    /// The scheme has a protocol verifying key, which genesis cannot replace.
    #[error("ZK signature scheme {0} has a protocol verifying key")]
    ProtocolKey(u8),
    /// The key has the wrong length for its scheme.
    #[error("verifying key for ZK signature scheme {scheme} has unsupported length {length} bytes")]
    Length {
        /// The scheme byte.
        scheme: u8,
        /// The key's length.
        length: usize,
    },
    /// A point of the key is invalid.
    #[error("verifying key for ZK signature scheme {scheme} is invalid: {error}")]
    Invalid {
        /// The scheme byte.
        scheme: u8,
        /// Why the point was rejected.
        error: PointError,
    },
    /// The scheme already has a different genesis key.
    #[error("ZK signature scheme {0} already has a different genesis verifying key")]
    Conflict(u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestTrapdoor;

    #[test]
    fn oidc_scheme_parameters() {
        let scheme = scheme(SCHEME_OIDC_RS256_V1).unwrap();
        assert_eq!(scheme.namespace, NAMESPACE_OIDC);
        assert_eq!(scheme.max_window, 600);
        assert!(scheme.message_form);
        assert!(super::scheme(0x00).is_none());
        assert!(super::scheme(0x02).is_none());
    }

    const fn test_scheme(verifying_key: Option<&'static [u8; VERIFYING_KEY_LENGTH]>) -> Scheme {
        Scheme {
            id: 0xfe,
            namespace: 0xfe,
            max_window: 600,
            message_form: false,
            verifying_key,
            prepared: OnceLock::new(),
            genesis_key: OnceLock::new(),
            image: OnceLock::new(),
        }
    }

    #[test]
    fn genesis_key_fills_a_scheme_without_a_protocol_key() {
        static SCHEME: Scheme = test_scheme(None);
        let key = TestTrapdoor::new(1).verifying_key().encode();
        assert!(SCHEME.verifying_key().is_none());

        SCHEME.set_genesis_key(&key).unwrap();
        assert!(SCHEME.verifying_key().is_some());
        // Setting the same key again is a no-op; a different one conflicts.
        SCHEME.set_genesis_key(&key).unwrap();
        let other = TestTrapdoor::new(2).verifying_key().encode();
        assert_eq!(
            SCHEME.set_genesis_key(&other),
            Err(GenesisKeyError::Conflict(0xfe))
        );
    }

    #[test]
    fn genesis_key_never_replaces_a_protocol_key() {
        static PROTOCOL_KEY: [u8; VERIFYING_KEY_LENGTH] = [0; VERIFYING_KEY_LENGTH];
        static SCHEME: Scheme = test_scheme(Some(&PROTOCOL_KEY));
        let key = TestTrapdoor::new(1).verifying_key().encode();
        assert_eq!(
            SCHEME.set_genesis_key(&key),
            Err(GenesisKeyError::ProtocolKey(0xfe))
        );
    }

    #[test]
    fn genesis_key_must_be_valid() {
        static SCHEME: Scheme = test_scheme(None);
        assert_eq!(
            SCHEME.set_genesis_key(&[0; 10]),
            Err(GenesisKeyError::Length {
                scheme: 0xfe,
                length: 10
            })
        );
        assert!(matches!(
            SCHEME.set_genesis_key(&[0; VERIFYING_KEY_LENGTH]),
            Err(GenesisKeyError::Invalid { scheme: 0xfe, .. })
        ));
        assert!(SCHEME.verifying_key().is_none());
        assert_eq!(
            set_genesis_keys([(0x02, &[0u8; VERIFYING_KEY_LENGTH][..])]),
            Err(GenesisKeyError::UnknownScheme(0x02))
        );
    }
}
