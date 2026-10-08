//! Bounded owner approvals, excluding recursive account signatures.

use crate::transaction::{
    PrimitiveSignature, SECP256K1_SIGNATURE_LENGTH, SIGNATURE_TYPE_ZK, SignatureType, ZkSignature,
};
use alloc::boxed::Box;
use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::{Address, B256};

/// Signature over a a native multisig digest: a root key signature, or a TIP-1131 ZK signature.
///
/// Encoded as the signature's bytes, so the wire format of primitive signatures is unchanged.
/// Keychain signatures cannot sign key authorizations.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub enum OwnerSignature {
    /// A secp256k1, P256, or WebAuthn signature by the root key.
    Primitive(PrimitiveSignature),
    /// A ZK signature for the root account. Boxed to keep primitive signatures small.
    Zk(Box<ZkSignature>),
}

impl OwnerSignature {
    /// Parses a signature from its bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() > 1
            && data.len() != SECP256K1_SIGNATURE_LENGTH
            && data[0] == SIGNATURE_TYPE_ZK
        {
            return ZkSignature::from_bytes(data).map(Self::from);
        }
        PrimitiveSignature::from_bytes(data).map(Self::Primitive)
    }

    /// Returns the signature's bytes.
    pub fn to_bytes(&self) -> alloy_primitives::Bytes {
        match self {
            Self::Primitive(signature) => signature.to_bytes(),
            Self::Zk(signature) => signature.to_bytes(),
        }
    }

    /// Writes the signature's bytes into `out`.
    pub fn encode_bytes_into(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Primitive(signature) => signature.encode_bytes_into(out),
            Self::Zk(signature) => signature.encode_bytes_into(out),
        }
    }

    /// Returns the length of the signature's bytes.
    pub fn encoded_length(&self) -> usize {
        match self {
            Self::Primitive(signature) => signature.encoded_length(),
            Self::Zk(signature) => signature.encoded_length(),
        }
    }

    /// Returns the signature type, which for a ZK signature is its access key's type.
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Primitive(signature) => signature.signature_type(),
            Self::Zk(signature) => signature.access_key_signature.signature_type(),
        }
    }

    /// Returns the in-memory size of the signature.
    pub fn size(&self) -> usize {
        core::mem::size_of::<Self>()
            + match self {
                Self::Primitive(signature) => {
                    signature.size() - core::mem::size_of::<PrimitiveSignature>()
                }
                Self::Zk(signature) => signature.size(),
            }
    }

    /// Recovers the signer for `sig_hash`.
    ///
    /// A primitive signature is verified. A ZK signature returns the address it names WITHOUT
    /// verification: the handler checks its times, issuer key, access key signature, and proof.
    pub fn recover_signer(&self, sig_hash: &B256) -> Result<Address, RecoveryError> {
        match self {
            Self::Primitive(signature) => signature.recover_signer(sig_hash),
            Self::Zk(signature) => signature.address().ok_or_else(RecoveryError::new),
        }
    }

    /// Returns the primitive signature, if this is one.
    pub fn as_primitive(&self) -> Option<&PrimitiveSignature> {
        match self {
            Self::Primitive(signature) => Some(signature),
            Self::Zk(_) => None,
        }
    }

    /// Returns the ZK signature, if this is one.
    pub fn as_zk(&self) -> Option<&ZkSignature> {
        match self {
            Self::Zk(signature) => Some(signature),
            Self::Primitive(_) => None,
        }
    }
}

impl From<PrimitiveSignature> for OwnerSignature {
    fn from(signature: PrimitiveSignature) -> Self {
        Self::Primitive(signature)
    }
}

impl From<ZkSignature> for OwnerSignature {
    fn from(signature: ZkSignature) -> Self {
        Self::Zk(Box::new(signature))
    }
}

impl Default for OwnerSignature {
    fn default() -> Self {
        Self::Primitive(PrimitiveSignature::default())
    }
}

impl alloy_rlp::Encodable for OwnerSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        alloy_rlp::Header {
            list: false,
            payload_length: self.encoded_length(),
        }
        .encode(out);
        self.encode_bytes_into(out);
    }

    fn length(&self) -> usize {
        alloy_rlp::Header {
            list: false,
            payload_length: self.encoded_length(),
        }
        .length_with_payload()
    }
}

impl alloy_rlp::Decodable for OwnerSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        Self::from_bytes(bytes).map_err(alloy_rlp::Error::Custom)
    }
}
