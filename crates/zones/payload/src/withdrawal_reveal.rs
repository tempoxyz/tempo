use alloy_primitives::{Address, B256};
use std::fmt;

/// Encrypts authenticated-withdrawal sender reveal payloads for finalized batches.
pub trait WithdrawalRevealEncryptor: fmt::Debug + Send + Sync + 'static {
    fn encrypt_sender(
        &self,
        reveal_to: &[u8],
        sender: Address,
        tx_hash: B256,
        fallback_nonce: u64,
    ) -> Option<Vec<u8>>;
}
