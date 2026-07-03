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
#[rlp(trailing(no_gaps))]
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
    use alloy_rlp::{Decodable as _, EMPTY_STRING_CODE, Header as RlpHeader};

    fn append_explicit_none_to_rlp_list(encoded: &[u8]) -> Vec<u8> {
        let mut payload = encoded;
        let header = RlpHeader::decode(&mut payload).unwrap();
        assert!(header.list);
        assert_eq!(payload.len(), header.payload_length);

        let mut out = Vec::new();
        RlpHeader {
            list: true,
            payload_length: header.payload_length + 1,
        }
        .encode(&mut out);
        out.extend_from_slice(payload);
        out.push(EMPTY_STRING_CODE);
        out
    }

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

    #[test]
    fn timestamp_millis_variations() {
        // basic: 100s + 500ms = 100_500
        let header = TempoHeader {
            timestamp_millis_part: 500,
            inner: Header {
                timestamp: 100,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(header.timestamp_millis(), 100_500);

        // zero timestamp
        let header = TempoHeader::default();
        assert_eq!(header.timestamp_millis(), 0);

        // millis part only (timestamp=0)
        let header = TempoHeader {
            timestamp_millis_part: 999,
            ..Default::default()
        };
        assert_eq!(header.timestamp_millis(), 999);

        // large timestamp saturating_mul safety
        let header = TempoHeader {
            timestamp_millis_part: 999,
            inner: Header {
                timestamp: u64::MAX / 1000,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = header.timestamp_millis();
        assert!(result > 0);
    }

    #[test]
    fn header_block_header_delegation() {
        let inner = Header {
            number: 42,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            ..Default::default()
        };
        let header = TempoHeader {
            inner: inner.clone(),
            ..Default::default()
        };

        assert_eq!(BlockHeader::number(&header), 42);
        assert_eq!(BlockHeader::gas_limit(&header), 30_000_000);
        assert_eq!(BlockHeader::gas_used(&header), 21_000);
        assert_eq!(BlockHeader::timestamp(&header), 1_700_000_000);
        assert_eq!(BlockHeader::base_fee_per_gas(&header), Some(1_000_000_000));
        assert_eq!(BlockHeader::parent_hash(&header), inner.parent_hash());
        assert_eq!(BlockHeader::state_root(&header), inner.state_root());
        assert_eq!(BlockHeader::difficulty(&header), inner.difficulty());
    }

    #[test]
    fn header_rlp_roundtrip() {
        let header = TempoHeader {
            general_gas_limit: 15_000_000,
            shared_gas_limit: 5_000_000,
            timestamp_millis_part: 123,
            inner: Header {
                number: 1,
                timestamp: 100,
                ..Default::default()
            },
            consensus_context: Some(TempoConsensusContext {
                epoch: 1,
                view: 2,
                parent_view: 1,
                proposer: PublicKey::from_seed([0x01; 32]),
            }),
        };

        let encoded = alloy_rlp::encode(&header);
        let decoded = TempoHeader::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(header, decoded);

        // without consensus_context
        let header_no_ctx = TempoHeader {
            general_gas_limit: 10_000_000,
            shared_gas_limit: 3_000_000,
            timestamp_millis_part: 0,
            inner: Header::default(),
            consensus_context: None,
        };
        let encoded = alloy_rlp::encode(&header_no_ctx);
        let decoded = TempoHeader::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(header_no_ctx, decoded);
    }

    #[test]
    fn header_rejects_explicit_none_context_rlp() {
        let header = TempoHeader {
            general_gas_limit: 10_000_000,
            shared_gas_limit: 3_000_000,
            timestamp_millis_part: 0,
            inner: Header::default(),
            consensus_context: None,
        };

        let encoded = alloy_rlp::encode(&header);
        let malformed = append_explicit_none_to_rlp_list(&encoded);
        assert!(TempoHeader::decode(&mut malformed.as_slice()).is_err());
    }

    #[test]
    fn header_sealable_hash() {
        let header = TempoHeader {
            general_gas_limit: 1,
            inner: Header {
                number: 42,
                ..Default::default()
            },
            ..Default::default()
        };

        // deterministic
        let h1 = header.hash_slow();
        let h2 = header.hash_slow();
        assert_eq!(h1, h2);
        assert_ne!(h1, B256::ZERO);

        // different header → different hash
        let header2 = TempoHeader {
            general_gas_limit: 2,
            inner: Header {
                number: 42,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_ne!(header.hash_slow(), header2.hash_slow());
    }
}
