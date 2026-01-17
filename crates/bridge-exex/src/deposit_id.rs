//! Canonical deposit ID computation.
//!
//! The deposit ID must be computed identically across:
//! - origin_watcher (bridge-exex): when detecting deposits
//! - Bridge precompile (tempo): when registering deposits
//!
//! Formula: keccak256(origin_chain_id || escrow_address || origin_tx_hash || origin_log_index)
//!
//! This uses tx_hash + log_index for global uniqueness, as these are immutable
//! properties of the deposit event on the origin chain.

use alloy::primitives::{Address, B256, keccak256};

/// Compute the canonical deposit ID from origin chain event data.
///
/// This formula must match `Bridge::compute_request_id` in the precompile.
pub fn compute_canonical_deposit_id(
    origin_chain_id: u64,
    escrow_address: Address,
    origin_tx_hash: B256,
    origin_log_index: u32,
) -> B256 {
    let mut buf = Vec::with_capacity(8 + 20 + 32 + 4);
    buf.extend_from_slice(&origin_chain_id.to_be_bytes());
    buf.extend_from_slice(escrow_address.as_slice());
    buf.extend_from_slice(origin_tx_hash.as_slice());
    buf.extend_from_slice(&origin_log_index.to_be_bytes());
    keccak256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_deposit_id_deterministic() {
        let chain_id = 1u64;
        let escrow = address!("1234567890123456789012345678901234567890");
        let tx_hash = B256::from([0xab; 32]);
        let log_index = 5u32;

        let id1 = compute_canonical_deposit_id(chain_id, escrow, tx_hash, log_index);
        let id2 = compute_canonical_deposit_id(chain_id, escrow, tx_hash, log_index);
        assert_eq!(id1, id2);

        // Different log index should produce different ID
        let id3 = compute_canonical_deposit_id(chain_id, escrow, tx_hash, 6);
        assert_ne!(id1, id3);
    }
}
