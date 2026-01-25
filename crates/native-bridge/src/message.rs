use alloy_primitives::{Address, B256, keccak256};
use serde::{Deserialize, Serialize};

/// Domain separator for bridge messages.
pub const BRIDGE_DOMAIN: &[u8] = b"TEMPO_BRIDGE_V1";

/// BLS domain separation tag for hash-to-curve.
/// Uses G1 target curve (MinSig variant) to match consensus signing.
pub const BLS_DST: &[u8] = b"TEMPO_BRIDGE_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// Domain separator for key rotation.
pub const KEY_ROTATION_DOMAIN: &[u8] = b"TEMPO_BRIDGE_KEY_ROTATION_V1";

/// Compressed G1 public key length (48 bytes).
pub const G1_COMPRESSED_LEN: usize = 48;

/// Uncompressed G1 public key length (128 bytes) - used in EIP-2537 format.
pub const G1_UNCOMPRESSED_LEN: usize = 128;

/// Compressed G2 signature length (96 bytes).
pub const G2_COMPRESSED_LEN: usize = 96;

/// Uncompressed G2 signature length (256 bytes) - used in EIP-2537 format.
pub const G2_UNCOMPRESSED_LEN: usize = 256;

/// A cross-chain bridge message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// The sender address on the origin chain.
    pub sender: Address,
    /// The 32-byte message hash (payload-agnostic).
    pub message_hash: B256,
    /// The origin chain ID.
    pub origin_chain_id: u64,
    /// The destination chain ID.
    pub destination_chain_id: u64,
}

impl Message {
    /// Create a new message.
    pub const fn new(
        sender: Address,
        message_hash: B256,
        origin_chain_id: u64,
        destination_chain_id: u64,
    ) -> Self {
        Self {
            sender,
            message_hash,
            origin_chain_id,
            destination_chain_id,
        }
    }

    /// Compute the attestation hash that validators sign.
    ///
    /// Format: keccak256(domain || sender || messageHash || originChainId || destinationChainId)
    /// Total: 15 + 20 + 32 + 8 + 8 = 83 bytes
    pub fn attestation_hash(&self) -> B256 {
        let mut data = Vec::with_capacity(83);
        data.extend_from_slice(BRIDGE_DOMAIN);
        data.extend_from_slice(self.sender.as_slice());
        data.extend_from_slice(self.message_hash.as_slice());
        data.extend_from_slice(&self.origin_chain_id.to_be_bytes());
        data.extend_from_slice(&self.destination_chain_id.to_be_bytes());
        keccak256(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_hash_deterministic() {
        let msg = Message {
            sender: Address::repeat_byte(0xAA),
            message_hash: B256::repeat_byte(0x11),
            origin_chain_id: 1,
            destination_chain_id: 12345,
        };

        let hash1 = msg.attestation_hash();
        let hash2 = msg.attestation_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_sender_different_hash() {
        let msg1 = Message::new(
            Address::repeat_byte(0xAA),
            B256::repeat_byte(0x11),
            1,
            12345,
        );
        let msg2 = Message::new(
            Address::repeat_byte(0xBB),
            B256::repeat_byte(0x11),
            1,
            12345,
        );
        assert_ne!(msg1.attestation_hash(), msg2.attestation_hash());
    }
}
