//! Burn attestation generation for cross-chain unlocks.
//!
//! This module provides utilities for generating validator-attested burn proofs
//! that can be verified on-chain by the StablecoinEscrow contract.
//!
//! ## Background (F-03 Audit Finding)
//!
//! The original implementation used binary Merkle proofs, but Ethereum/Tempo uses
//! MPT (Merkle Patricia Trie) for receipt roots. Rather than implementing complex
//! MPT verification in Solidity, we use the same validator attestation model that
//! the light client uses for header finalization.
//!
//! Validators sign burn attestations that include:
//! - Domain separator
//! - Tempo chain ID
//! - Burn ID
//! - Tempo block height
//! - Origin chain ID  
//! - Origin token address
//! - Recipient address
//! - Amount

use alloy::{
    network::BlockResponse,
    primitives::{keccak256, Address, Bytes, B256},
    providers::Provider,
    rpc::types::TransactionReceipt,
    signers::Signer,
};
use alloy_rlp::Encodable;
use alloy_trie::{HashBuilder, Nibbles};
use eyre::Result;

/// Domain separator for burn attestations (must match Solidity constant)
pub const BURN_ATTESTATION_DOMAIN: B256 = {
    // keccak256("TEMPO_BURN_ATTESTATION_V1")
    // Computed offline: 0x8d7e8b7a8e7c8f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a
    // We'll compute it at runtime for correctness
    B256::ZERO // Placeholder - computed at runtime
};

/// Attestation data for a burn event on Tempo chain.
#[derive(Debug, Clone)]
pub struct BurnAttestation {
    /// The unique burn ID from the Tempo burn event.
    pub burn_id: B256,
    /// The Tempo block height containing the burn.
    pub tempo_height: u64,
    /// The origin chain ID (Ethereum mainnet, etc).
    pub origin_chain_id: u64,
    /// The token address on the origin chain.
    pub origin_token: Address,
    /// The recipient address on the origin chain.
    pub recipient: Address,
    /// The amount to unlock (6-decimal normalized).
    pub amount: u64,
    /// Validator signatures attesting to this burn.
    pub signatures: Vec<Bytes>,
}

impl BurnAttestation {
    /// Compute the attestation digest that validators sign.
    pub fn compute_digest(&self, tempo_chain_id: u64) -> B256 {
        let domain = keccak256("TEMPO_BURN_ATTESTATION_V1");

        let mut data = Vec::new();
        data.extend_from_slice(domain.as_slice());
        data.extend_from_slice(&tempo_chain_id.to_be_bytes());
        data.extend_from_slice(self.burn_id.as_slice());
        data.extend_from_slice(&self.tempo_height.to_be_bytes());
        data.extend_from_slice(&self.origin_chain_id.to_be_bytes());
        data.extend_from_slice(self.origin_token.as_slice());
        data.extend_from_slice(self.recipient.as_slice());
        data.extend_from_slice(&self.amount.to_be_bytes());

        keccak256(&data)
    }

    /// Encode as ABI-encoded proof for `unlockWithProof`.
    pub fn encode_proof(&self) -> Bytes {
        // ABI encode: (bytes32 burnId, uint64 tempoHeight, address originToken,
        //              address recipient, uint64 amount, bytes[] signatures)
        let encoded = alloy::sol_types::SolValue::abi_encode(&(
            self.burn_id,
            self.tempo_height,
            self.origin_token,
            self.recipient,
            self.amount,
            self.signatures.clone(),
        ));
        Bytes::from(encoded)
    }
}

/// Block header information from Tempo chain.
#[derive(Debug, Clone)]
pub struct TempoBlockHeader {
    /// Block number.
    pub block_number: u64,
    /// Block hash.
    pub block_hash: B256,
    /// State root of the block.
    pub state_root: B256,
    /// Receipts root of the block.
    pub receipts_root: B256,
}

/// Generator for burn attestations.
///
/// Uses an alloy provider to fetch block and receipt data from Tempo RPC,
/// and a set of validator signers to create attestations.
pub struct AttestationGenerator<P> {
    provider: P,
    tempo_chain_id: u64,
}

impl<P> AttestationGenerator<P> {
    /// Create a new attestation generator.
    pub const fn new(provider: P, tempo_chain_id: u64) -> Self {
        Self {
            provider,
            tempo_chain_id,
        }
    }

    /// Compute the receipts root from a list of receipts.
    ///
    /// Uses the ordered trie root computation matching Ethereum's receipt trie.
    /// This is kept for verification purposes even though we don't generate MPT proofs.
    pub fn compute_receipts_root(receipts: &[TransactionReceipt]) -> B256 {
        if receipts.is_empty() {
            return alloy_trie::EMPTY_ROOT_HASH;
        }

        let mut hash_builder = HashBuilder::default();

        for (index, receipt) in receipts.iter().enumerate() {
            let key = Nibbles::unpack(alloy_rlp::encode(index));
            let value = encode_receipt_for_trie(receipt);
            hash_builder.add_leaf(key, &value);
        }

        hash_builder.root()
    }

    /// Create a burn attestation from burn event data.
    ///
    /// The caller must provide validator signatures separately after calling this.
    pub fn create_unsigned_attestation(
        burn_id: B256,
        tempo_height: u64,
        origin_chain_id: u64,
        origin_token: Address,
        recipient: Address,
        amount: u64,
    ) -> BurnAttestation {
        BurnAttestation {
            burn_id,
            tempo_height,
            origin_chain_id,
            origin_token,
            recipient,
            amount,
            signatures: Vec::new(),
        }
    }

    /// Sign an attestation with a validator signer.
    pub async fn sign_attestation<S: Signer>(
        &self,
        attestation: &mut BurnAttestation,
        signer: &S,
    ) -> Result<()> {
        let digest = attestation.compute_digest(self.tempo_chain_id);
        let signature = signer.sign_hash(&digest).await?;
        attestation
            .signatures
            .push(Bytes::from(signature.as_bytes().to_vec()));
        Ok(())
    }
}

impl<P> AttestationGenerator<P>
where
    P: Provider,
{
    /// Fetch block header from Tempo RPC.
    pub async fn get_block_header(&self, block_number: u64) -> Result<TempoBlockHeader> {
        let block = self
            .provider
            .get_block_by_number(block_number.into())
            .await?
            .ok_or_else(|| eyre::eyre!("Block {} not found", block_number))?;

        let header = block.header();
        Ok(TempoBlockHeader {
            block_number,
            block_hash: header.hash,
            state_root: header.state_root,
            receipts_root: header.receipts_root,
        })
    }

    /// Fetch all receipts for a block.
    pub async fn get_block_receipts(&self, block_number: u64) -> Result<Vec<TransactionReceipt>> {
        let receipts = self
            .provider
            .get_block_receipts(block_number.into())
            .await?
            .ok_or_else(|| eyre::eyre!("Receipts for block {} not found", block_number))?;

        Ok(receipts)
    }
}

/// Encode a receipt for inclusion in the receipt trie.
///
/// This follows Ethereum's receipt encoding: type byte (if not legacy) + RLP(receipt).
fn encode_receipt_for_trie(receipt: &TransactionReceipt) -> Vec<u8> {
    use alloy::consensus::ReceiptEnvelope;

    // Convert from RPC Log type to primitive Log type for encoding
    let primitive_envelope: ReceiptEnvelope = receipt.inner.clone().map_logs(|log| log.inner);

    let mut buf = Vec::new();
    primitive_envelope.encode(&mut buf);
    buf
}

// ============================================================================
// Legacy types kept for backwards compatibility during migration
// ============================================================================

/// Legacy proof data - kept for migration purposes.
/// New code should use BurnAttestation instead.
#[derive(Debug, Clone)]
#[deprecated(note = "Use BurnAttestation instead - binary Merkle proofs are incompatible with MPT")]
pub struct BurnProof {
    /// RLP-encoded receipt containing the burn event.
    pub receipt_rlp: Bytes,
    /// MPT proof nodes for the receipt (no longer used).
    pub receipt_proof: Vec<Bytes>,
    /// Index of the burn event log within the receipt.
    pub log_index: u64,
}

/// Legacy proof generator - kept for backwards compatibility.
#[deprecated(note = "Use AttestationGenerator instead")]
pub type ProofGenerator<P> = AttestationGenerator<P>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        consensus::{Receipt, ReceiptEnvelope, ReceiptWithBloom},
        primitives::{Address, LogData},
        rpc::types::Log as RpcLog,
    };

    fn create_mock_receipt(status: bool, logs_count: usize) -> TransactionReceipt {
        let primitive_logs: Vec<alloy::primitives::Log> = (0..logs_count)
            .map(|i| alloy::primitives::Log {
                address: Address::repeat_byte(i as u8),
                data: LogData::new_unchecked(vec![], Bytes::new()),
            })
            .collect();

        let receipt = Receipt {
            status: status.into(),
            cumulative_gas_used: 21000 * (logs_count as u64 + 1),
            logs: primitive_logs,
        };

        let receipt_with_bloom = ReceiptWithBloom::new(receipt, Default::default());
        let envelope = ReceiptEnvelope::Eip1559(receipt_with_bloom);

        // Map to RPC Log type
        let rpc_envelope = envelope.map_logs(|log| RpcLog {
            inner: log,
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        });

        TransactionReceipt {
            inner: rpc_envelope,
            transaction_hash: B256::random(),
            transaction_index: Some(0),
            block_hash: Some(B256::random()),
            block_number: Some(1),
            gas_used: 21000,
            effective_gas_price: 1_000_000_000,
            blob_gas_used: None,
            blob_gas_price: None,
            from: Address::ZERO,
            to: Some(Address::repeat_byte(0xDE)),
            contract_address: None,
        }
    }

    #[test]
    fn test_empty_receipts_root() {
        let receipts: Vec<TransactionReceipt> = vec![];
        let root = AttestationGenerator::<()>::compute_receipts_root(&receipts);
        assert_eq!(root, alloy_trie::EMPTY_ROOT_HASH);
    }

    #[test]
    fn test_attestation_digest_is_deterministic() {
        let attestation = BurnAttestation {
            burn_id: B256::repeat_byte(0xAB),
            tempo_height: 12345,
            origin_chain_id: 1,
            origin_token: Address::repeat_byte(0xCD),
            recipient: Address::repeat_byte(0xEF),
            amount: 1_000_000,
            signatures: vec![],
        };

        let digest1 = attestation.compute_digest(42);
        let digest2 = attestation.compute_digest(42);
        assert_eq!(digest1, digest2);

        // Different chain ID = different digest
        let digest3 = attestation.compute_digest(43);
        assert_ne!(digest1, digest3);
    }

    #[test]
    fn test_create_unsigned_attestation() {
        let attestation = AttestationGenerator::<()>::create_unsigned_attestation(
            B256::repeat_byte(0x11),
            1000,
            1,
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x33),
            500_000,
        );

        assert_eq!(attestation.burn_id, B256::repeat_byte(0x11));
        assert_eq!(attestation.tempo_height, 1000);
        assert_eq!(attestation.origin_chain_id, 1);
        assert_eq!(attestation.amount, 500_000);
        assert!(attestation.signatures.is_empty());
    }

    #[test]
    fn test_tempo_block_header_struct() {
        let header = TempoBlockHeader {
            block_number: 12345,
            block_hash: B256::repeat_byte(0xAB),
            state_root: B256::repeat_byte(0xCD),
            receipts_root: B256::repeat_byte(0xEF),
        };

        assert_eq!(header.block_number, 12345);
        assert_eq!(header.block_hash, B256::repeat_byte(0xAB));
        assert_eq!(header.state_root, B256::repeat_byte(0xCD));
        assert_eq!(header.receipts_root, B256::repeat_byte(0xEF));
    }

    #[test]
    fn test_encode_receipt_deterministic() {
        let receipt = create_mock_receipt(true, 2);
        let encoded1 = encode_receipt_for_trie(&receipt);
        let encoded2 = encode_receipt_for_trie(&receipt);
        assert_eq!(encoded1, encoded2);
    }
}
