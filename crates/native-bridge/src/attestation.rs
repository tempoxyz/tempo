use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::message::G1_COMPRESSED_LEN;

/// A partial BLS signature from a single validator.
///
/// Uses MinSig variant: signatures are G1 points (48 bytes compressed).
/// This matches consensus signing, allowing reuse of DKG shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSignature {
    pub index: u32,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; G1_COMPRESSED_LEN],
}

impl PartialSignature {
    pub const fn new(index: u32, signature: [u8; G1_COMPRESSED_LEN]) -> Self {
        Self { index, signature }
    }
}

/// An aggregated threshold signature.
///
/// Uses MinSig variant: signatures are G1 points (48 bytes compressed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedSignature {
    #[serde(with = "signature_bytes")]
    pub signature: [u8; G1_COMPRESSED_LEN],
    pub epoch: u64,
}

impl AggregatedSignature {
    pub const fn new(signature: [u8; G1_COMPRESSED_LEN], epoch: u64) -> Self {
        Self { signature, epoch }
    }
}

/// Pending attestation collecting partial signatures.
#[derive(Debug, Clone)]
pub struct PendingAttestation {
    pub attestation_hash: B256,
    pub partials: Vec<PartialSignature>,
    pub threshold: usize,
}

impl PendingAttestation {
    pub fn new(attestation_hash: B256, threshold: usize) -> Self {
        Self {
            attestation_hash,
            partials: Vec::new(),
            threshold,
        }
    }

    pub fn add_partial(&mut self, partial: PartialSignature) -> bool {
        if self.partials.iter().any(|p| p.index == partial.index) {
            return false;
        }
        self.partials.push(partial);
        true
    }

    pub fn has_threshold(&self) -> bool {
        self.partials.len() >= self.threshold
    }
}

/// Serde helper for [u8; 48] (G1 compressed) as hex string.
mod signature_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = const_hex::encode(bytes);
        hex.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = const_hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid signature length"))
    }
}
