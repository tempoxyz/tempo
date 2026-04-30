use alloy_consensus::{BlockHeader, Header, Sealable};
use alloy_primitives::{Address, B64, B256, BlockNumber, Bloom, Bytes, U256, keccak256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

use crate::ed25519::PublicKey;

/// Consensus context metadata for a Tempo block.
///
/// The `proposer` is validated as a valid Ed25519 public key during RLP
/// decoding to reject malformed blocks at the network boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
pub struct TempoConsensusContext {
    pub epoch: u64,
    pub view: u64,
    pub parent_view: u64,
    pub proposer: PublicKey,
}

/// Tempo block header.
///
/// RLP-encoded as `[general_gas_limit, shared_gas_limit, timestamp_millis_part, inner,
/// consensus_context?]`. The `consensus_context` is trailing and omitted for pre-fork blocks.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[rlp(trailing)]
pub struct TempoHeader {
    /// Non-payment gas limit for the block.
    #[cfg_attr(
        feature = "serde",
        serde(with = "alloy_serde::quantity", rename = "mainBlockGeneralGasLimit")
    )]
    pub general_gas_limit: u64,

    /// Shared gas limit allocated for the subblocks section of the block.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub shared_gas_limit: u64,

    /// Sub-second (milliseconds) portion of the timestamp.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub timestamp_millis_part: u64,

    /// Inner Ethereum [`Header`].
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub inner: Header,

    /// Consensus metadata for the block. `None` for pre-fork blocks.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub consensus_context: Option<TempoConsensusContext>,
}

impl TempoHeader {
    /// Returns the timestamp in milliseconds.
    pub fn timestamp_millis(&self) -> u64 {
        self.inner
            .timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timestamp_millis_part)
    }
}

impl AsRef<Self> for TempoHeader {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl BlockHeader for TempoHeader {
    fn parent_hash(&self) -> B256 {
        self.inner.parent_hash()
    }

    fn ommers_hash(&self) -> B256 {
        self.inner.ommers_hash()
    }

    fn beneficiary(&self) -> Address {
        self.inner.beneficiary()
    }

    fn state_root(&self) -> B256 {
        self.inner.state_root()
    }

    fn transactions_root(&self) -> B256 {
        self.inner.transactions_root()
    }

    fn receipts_root(&self) -> B256 {
        self.inner.receipts_root()
    }

    fn withdrawals_root(&self) -> Option<B256> {
        self.inner.withdrawals_root()
    }

    fn logs_bloom(&self) -> Bloom {
        self.inner.logs_bloom()
    }

    fn difficulty(&self) -> U256 {
        self.inner.difficulty()
    }

    fn number(&self) -> BlockNumber {
        self.inner.number()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_used(&self) -> u64 {
        self.inner.gas_used()
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn mix_hash(&self) -> Option<B256> {
        self.inner.mix_hash()
    }

    fn nonce(&self) -> Option<B64> {
        self.inner.nonce()
    }

    fn base_fee_per_gas(&self) -> Option<u64> {
        self.inner.base_fee_per_gas()
    }

    fn blob_gas_used(&self) -> Option<u64> {
        self.inner.blob_gas_used()
    }

    fn excess_blob_gas(&self) -> Option<u64> {
        self.inner.excess_blob_gas()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }

    fn requests_hash(&self) -> Option<B256> {
        self.inner.requests_hash()
    }

    fn block_access_list_hash(&self) -> Option<B256> {
        self.inner.block_access_list_hash()
    }

    fn slot_number(&self) -> Option<u64> {
        self.inner.slot_number()
    }

    fn extra_data(&self) -> &Bytes {
        self.inner.extra_data()
    }
}

impl Sealable for TempoHeader {
    fn hash_slow(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::Decodable as _;

    #[test]
    fn consensus_context_rlp_roundtrip() {
        let ctx = TempoConsensusContext {
            epoch: 1,
            view: 5,
            proposer: PublicKey::from_seed([0xab; 32]),
            parent_view: 4,
        };

        let encoded = alloy_rlp::encode(ctx);
        let decoded = TempoConsensusContext::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(ctx, decoded);
    }
}
