use alloy_primitives::B256;
use alloy_rlp::Decodable;

#[derive(Debug)]
pub struct InvalidPublicKey;

impl core::fmt::Display for InvalidPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid ed25519 public key")
    }
}

/// Validated Ed25519 public key bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, alloy_rlp::RlpEncodableWrapper)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "B256", try_from = "B256"))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
pub struct PublicKey(B256);

impl PublicKey {
    pub fn to_inner(&self) -> commonware_cryptography::ed25519::PublicKey {
        commonware_cryptography::ed25519::PublicKey::try_from(<[u8; 32]>::from(self.0))
            .expect("stored ed25519 public key was validated at construction")
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn from_seed(seed: u64) -> Self {
        use commonware_cryptography::Signer;
        let key = commonware_cryptography::ed25519::PrivateKey::from_seed(seed).public_key();
        Self(B256::from(<[u8; 32]>::from(&key)))
    }
}

impl Decodable for PublicKey {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        B256::decode(buf)?
            .try_into()
            .map_err(|_| alloy_rlp::Error::Custom("malformed ed25519 public key"))
    }
}

impl From<PublicKey> for B256 {
    fn from(value: PublicKey) -> Self {
        value.0
    }
}

impl<'a> From<&'a PublicKey> for B256 {
    fn from(value: &'a PublicKey) -> Self {
        value.0
    }
}

impl TryFrom<B256> for PublicKey {
    type Error = InvalidPublicKey;

    fn try_from(value: B256) -> Result<Self, Self::Error> {
        #[cfg(feature = "std")]
        if VALIDATED.with_borrow(|keys| keys.contains(&value)) {
            return Ok(Self(value));
        }
        commonware_cryptography::ed25519::PublicKey::try_from(<[u8; 32]>::from(value))
            .map_err(|_| InvalidPublicKey)?;
        #[cfg(feature = "std")]
        VALIDATED.with_borrow_mut(|keys| {
            if keys.len() >= MAX_VALIDATED {
                keys.clear();
            }
            keys.insert(value);
        });

        Ok(Self(value))
    }
}

/// Most validated keys remembered per thread; the set is cleared when full.
#[cfg(feature = "std")]
const MAX_VALIDATED: usize = 1024;

#[cfg(feature = "std")]
std::thread_local! {
    /// Keys that already passed point decompression on this thread. Every header carries its
    /// proposer's key and validators repeat, so decoding a run of headers validates each key
    /// once instead of decompressing it per header.
    static VALIDATED: std::cell::RefCell<alloy_primitives::map::B256HashSet> =
        std::cell::RefCell::default();
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for PublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        commonware_cryptography::ed25519::PublicKey::arbitrary(u)
            .map(|key| Self(B256::from(<[u8; 32]>::from(&key))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn public_key_conversions_and_rlp() {
        let pk = PublicKey::from_seed(41);
        let pk2 = PublicKey::from_seed(42);

        // different seeds produce different keys
        assert_ne!(pk, pk2);

        // PublicKey → B256 roundtrip (ref and owned)
        let b256: B256 = B256::from(&pk);
        let b256_owned: B256 = B256::from(pk);
        assert_eq!(b256, b256_owned);
        let recovered = PublicKey::try_from(b256).unwrap();
        assert_eq!(pk, recovered);

        // RLP encode → decode roundtrip
        let mut buf = Vec::new();
        pk.encode(&mut buf);
        assert_eq!(buf, alloy_rlp::encode(b256));
        assert_eq!(buf.len(), pk.length());
        let decoded = PublicKey::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(pk, decoded);

        // truncated RLP fails
        let short_buf = &buf[..buf.len() - 1];
        assert!(PublicKey::decode(&mut &short_buf[..]).is_err());

        // Hash + Eq: same seed → same key
        let pk_dup = PublicKey::from_seed(41);
        assert_eq!(pk, pk_dup);
    }

    #[test]
    fn invalid_key_rejected_after_valid_keys_cached() {
        let valid = B256::from(PublicKey::from_seed(7));
        assert_eq!(PublicKey::try_from(valid).unwrap(), PublicKey(valid));
        // Served from the validated set the second time.
        assert_eq!(PublicKey::try_from(valid).unwrap(), PublicKey(valid));

        let invalid = (0..=u8::MAX)
            .map(B256::repeat_byte)
            .find(|bytes| {
                commonware_cryptography::ed25519::PublicKey::try_from(<[u8; 32]>::from(*bytes))
                    .is_err()
            })
            .expect("some repeated byte is not a curve point");
        for _ in 0..2 {
            assert!(matches!(
                PublicKey::try_from(invalid),
                Err(InvalidPublicKey)
            ));
        }
    }
}
