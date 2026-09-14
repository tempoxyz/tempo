use alloy_primitives::B256;
use alloy_rlp::{Decodable, Encodable};

#[derive(Debug)]
pub struct InvalidPublicKey;

impl core::fmt::Display for InvalidPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid ed25519 public key")
    }
}

/// Validated Ed25519 public key bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

impl Encodable for PublicKey {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.0.encode(out);
    }

    fn length(&self) -> usize {
        self.0.length()
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
        commonware_cryptography::ed25519::PublicKey::try_from(<[u8; 32]>::from(value))
            .map_err(|_| InvalidPublicKey)?;

        Ok(Self(value))
    }
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
}
