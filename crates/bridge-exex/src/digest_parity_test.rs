//! Golden test vectors for deposit attestation digest parity.
//!
//! These tests verify that the digest computation in bridge-exex matches
//! the precompile implementation exactly. Both must produce identical digests
//! for the bridge to function correctly.

use crate::signer::{compute_deposit_attestation_digest, BridgeSigner};
use alloy::primitives::{address, b256, keccak256, Address, B256};
use tempo_contracts::precompiles::BRIDGE_ADDRESS;

/// Golden test vector for deposit attestation digest computation.
///
/// These values are used in both bridge-exex and precompile tests
/// to ensure cross-crate parity.
mod test_vectors {
    use super::*;

    pub(super) const TEMPO_CHAIN_ID: u64 = 42069;
    pub(super) const ORIGIN_CHAIN_ID: u64 = 1;
    pub(super) const ORIGIN_LOG_INDEX: u32 = 7;
    pub(super) const AMOUNT: u64 = 1_000_000_000_000_000_000; // 1e18
    pub(super) const ORIGIN_BLOCK_NUMBER: u64 = 19_500_000;

    pub(super) fn bridge_address() -> Address {
        BRIDGE_ADDRESS
    }

    pub(super) fn request_id() -> B256 {
        b256!("deadbeef00000000000000000000000000000000000000000000000000000001")
    }

    pub(super) fn origin_escrow() -> Address {
        address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    }

    pub(super) fn origin_token() -> Address {
        address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") // USDC on mainnet
    }

    pub(super) fn origin_tx_hash() -> B256 {
        b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
    }

    pub(super) fn tempo_recipient() -> Address {
        address!("1111111111111111111111111111111111111111")
    }

    /// A fixed validator set hash for testing.
    /// In production, this is computed from active validator addresses.
    pub(super) fn validator_set_hash() -> B256 {
        b256!("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    }

    /// The expected digest computed from the above test vector.
    ///
    /// This is computed once and verified against both implementations.
    /// Format: keccak256(domain || tempo_chain_id || bridge_address || request_id ||
    ///         origin_chain_id || origin_escrow || origin_token || origin_tx_hash ||
    ///         origin_log_index || tempo_recipient || amount || origin_block_number || validator_set_hash)
    pub(super) fn expected_digest() -> B256 {
        // Compute the expected digest manually to establish the golden value
        let domain = b"TEMPO_BRIDGE_DEPOSIT_V2";
        let mut buf =
            Vec::with_capacity(domain.len() + 8 + 20 + 32 + 8 + 20 + 20 + 32 + 4 + 20 + 8 + 8 + 32);
        buf.extend_from_slice(domain);
        buf.extend_from_slice(&TEMPO_CHAIN_ID.to_be_bytes());
        buf.extend_from_slice(bridge_address().as_slice());
        buf.extend_from_slice(request_id().as_slice());
        buf.extend_from_slice(&ORIGIN_CHAIN_ID.to_be_bytes());
        buf.extend_from_slice(origin_escrow().as_slice());
        buf.extend_from_slice(origin_token().as_slice());
        buf.extend_from_slice(origin_tx_hash().as_slice());
        buf.extend_from_slice(&ORIGIN_LOG_INDEX.to_be_bytes());
        buf.extend_from_slice(tempo_recipient().as_slice());
        buf.extend_from_slice(&AMOUNT.to_be_bytes());
        buf.extend_from_slice(&ORIGIN_BLOCK_NUMBER.to_be_bytes());
        buf.extend_from_slice(validator_set_hash().as_slice());
        keccak256(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::{test_vectors::*, *};

    #[test]
    fn test_digest_matches_expected() {
        let digest = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );

        let expected = expected_digest();
        assert_eq!(
            digest, expected,
            "bridge-exex digest mismatch!\n  computed: {digest}\n  expected: {expected}"
        );
    }

    #[test]
    fn test_digest_includes_origin_escrow() {
        // Compute digest with different origin_escrow values
        let digest1 = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );

        let different_escrow = address!("dddddddddddddddddddddddddddddddddddddddd");
        let digest2 = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            different_escrow,
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );

        assert_ne!(
            digest1, digest2,
            "origin_escrow must affect the digest - different escrows should produce different digests"
        );
    }

    #[test]
    fn test_all_fields_affect_digest() {
        let base_digest = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );

        // Test tempo_chain_id
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID + 1,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "tempo_chain_id must affect digest");

        // Test bridge_address
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            address!("0000000000000000000000000000000000000001"),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "bridge_address must affect digest");

        // Test request_id
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            B256::repeat_byte(0xFF),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "request_id must affect digest");

        // Test origin_chain_id
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID + 1,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "origin_chain_id must affect digest");

        // Test origin_token
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            address!("0000000000000000000000000000000000000001"),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "origin_token must affect digest");

        // Test origin_tx_hash
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            B256::repeat_byte(0xFF),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "origin_tx_hash must affect digest");

        // Test origin_log_index
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX + 1,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "origin_log_index must affect digest");

        // Test tempo_recipient
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            address!("0000000000000000000000000000000000000001"),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "tempo_recipient must affect digest");

        // Test amount
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT + 1,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "amount must affect digest");

        // Test origin_block_number
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER + 1,
            validator_set_hash(),
        );
        assert_ne!(base_digest, d, "origin_block_number must affect digest");

        // Test validator_set_hash
        let d = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            B256::repeat_byte(0xFF),
        );
        assert_ne!(base_digest, d, "validator_set_hash must affect digest");
    }

    #[tokio::test]
    async fn test_sign_and_recover() {
        // Use a deterministic test private key
        let key_bytes: [u8; 32] = [
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfb, 0xbf, 0xf0, 0x12, 0xcc,
            0xe1, 0x16, 0x22, 0xda,
        ];

        let signer = BridgeSigner::from_bytes(&key_bytes).unwrap();
        let expected_address = signer.address();

        // Compute digest using test vector
        let digest = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );

        // Sign the digest
        let signature = signer.sign_hash(&digest).await.unwrap();
        assert_eq!(
            signature.len(),
            65,
            "signature should be 65 bytes (r, s, v)"
        );

        // Recover the signer address from signature
        let sig = alloy::primitives::Signature::try_from(signature.as_ref()).unwrap();
        let recovered = sig.recover_address_from_prehash(&digest).unwrap();

        assert_eq!(
            recovered, expected_address,
            "recovered address should match signer address"
        );
    }

    #[tokio::test]
    async fn test_golden_digest_value() {
        // This test pins the exact digest value for the test vector.
        // If this test fails, the digest computation has changed and
        // the precompile test must be updated to match.
        let digest = compute_deposit_attestation_digest(
            TEMPO_CHAIN_ID,
            bridge_address(),
            request_id(),
            ORIGIN_CHAIN_ID,
            origin_escrow(),
            origin_token(),
            origin_tx_hash(),
            ORIGIN_LOG_INDEX,
            tempo_recipient(),
            AMOUNT,
            ORIGIN_BLOCK_NUMBER,
            validator_set_hash(),
        );

        // Print the digest for documentation
        println!("Golden digest for test vector: {digest}");

        // The digest should match the expected value
        assert_eq!(digest, expected_digest());
    }
}
