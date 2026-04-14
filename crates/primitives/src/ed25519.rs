//! Wrapper for [`ed25519`] to use in tempo headers.

use alloy_primitives::B256;
use alloy_rlp::{Decodable, Encodable};
use ed25519_consensus::{VerificationKey, VerificationKeyBytes};

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "B256"))]
#[cfg_attr(feature = "serde", serde(try_from = "B256"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
pub struct PublicKey(VerificationKey);

impl PublicKey {
    pub fn get(&self) -> VerificationKey {
        self.0
    }

    #[cfg(any(test, feature = "arbitrary"))]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        ed25519_consensus::SigningKey::from(seed)
            .verification_key()
            .into()
    }
}

impl Encodable for PublicKey {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.0.as_bytes().encode(out)
    }

    fn length(&self) -> usize {
        self.0.as_bytes().length()
    }
}

impl Decodable for PublicKey {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let inner = <[u8; 32]>::decode(buf)?;
        let key = VerificationKey::try_from(inner)
            .map_err(|_| alloy_rlp::Error::Custom("malformed ed25519 public key"))?;
        Ok(Self(key))
    }
}

impl From<ed25519_consensus::VerificationKey> for PublicKey {
    fn from(value: ed25519_consensus::VerificationKey) -> Self {
        Self(value)
    }
}

impl From<PublicKey> for B256 {
    fn from(value: PublicKey) -> Self {
        <[u8; 32]>::from(VerificationKeyBytes::from(value.0)).into()
    }
}

impl<'a> From<&'a PublicKey> for B256 {
    fn from(value: &'a PublicKey) -> Self {
        <[u8; 32]>::from(VerificationKeyBytes::from(value.0)).into()
    }
}

impl TryFrom<B256> for PublicKey {
    type Error = ed25519_consensus::Error;

    fn try_from(value: B256) -> Result<Self, Self::Error> {
        let inner = VerificationKeyBytes::from(<[u8; 32]>::from(value)).try_into()?;
        Ok(Self(inner))
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for PublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_seed(u.arbitrary()?))
    }
}
