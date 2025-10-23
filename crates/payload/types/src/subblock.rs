use alloy_primitives::{B256, Bytes, keccak256};
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use alloy_rpc_types_eth::TransactionTrait;
use tempo_primitives::TempoTxEnvelope;

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct SubBlock {
    /// Hash of the parent block. This subblock can only be included as
    /// part of the block building on top of the specified parent.
    pub parent_hash: B256,
    /// Transactions included in the subblock.
    pub transactions: Vec<TempoTxEnvelope>,
}

impl SubBlock {
    /// Returns the hash for the signature.
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::new();
        self.parent_hash.encode(&mut buf);
        self.transactions.encode(&mut buf);
        keccak256(&buf)
    }

    /// Returns the total gas occupied by the subblock.
    pub fn occupied_gas(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.gas_limit()).sum()
    }
}

/// A subblock with a signature.
#[derive(Debug, Clone, RlpEncodable, RlpDecodable, derive_more::Deref, derive_more::DerefMut)]
pub struct SignedSubBlock {
    /// The subblock.
    #[deref]
    #[deref_mut]
    pub inner: SubBlock,
    /// The signature of the subblock.
    pub signature: Bytes,
}
