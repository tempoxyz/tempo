//! Signature generation for bridge attestations.

use alloy::{
    primitives::{keccak256, Address, Bytes, B256},
    signers::{local::PrivateKeySigner, Signer},
};
use eyre::Result;

/// Domain separator for deposit signatures
pub const DEPOSIT_DOMAIN: &[u8] = b"TEMPO_BRIDGE_DEPOSIT_V1";

/// Bridge signer using validator's existing key
pub struct BridgeSigner {
    signer: PrivateKeySigner,
    validator_address: Address,
}

impl BridgeSigner {
    /// Create from private key bytes
    pub fn from_bytes(key_bytes: &[u8; 32]) -> Result<Self> {
        let signer = PrivateKeySigner::from_bytes(&(*key_bytes).into())?;
        let validator_address = signer.address();

        Ok(Self {
            signer,
            validator_address,
        })
    }

    /// Get validator address
    pub fn address(&self) -> Address {
        self.validator_address
    }

    /// Sign a deposit request ID
    pub async fn sign_deposit(&self, request_id: &B256) -> Result<Bytes> {
        let signature = self.signer.sign_hash(request_id).await?;
        Ok(Bytes::from(signature.as_bytes().to_vec()))
    }

    /// Compute deposit request ID (must match precompile)
    pub fn compute_deposit_id(
        origin_chain_id: u64,
        origin_token: Address,
        origin_tx_hash: B256,
        origin_log_index: u32,
        tempo_recipient: Address,
        amount: u64,
        origin_block_number: u64,
    ) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(DEPOSIT_DOMAIN);
        data.extend_from_slice(&origin_chain_id.to_be_bytes());
        data.extend_from_slice(origin_token.as_slice());
        data.extend_from_slice(origin_tx_hash.as_slice());
        data.extend_from_slice(&origin_log_index.to_be_bytes());
        data.extend_from_slice(tempo_recipient.as_slice());
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&origin_block_number.to_be_bytes());
        keccak256(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sign_deposit() {
        let key = [1u8; 32];
        let signer = BridgeSigner::from_bytes(&key).unwrap();

        let request_id = B256::repeat_byte(0x42);
        let sig = signer.sign_deposit(&request_id).await.unwrap();

        assert_eq!(sig.len(), 65);
    }
}
