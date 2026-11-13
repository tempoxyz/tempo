use alloy_consensus::BlockHeader;
use alloy_network::primitives::HeaderResponse;
use alloy_primitives::{Address, B64, B256, BlockHash, Bloom, Bytes, U256};
use alloy_rpc_types_eth::Header;
use serde::{Deserialize, Serialize};
use tempo_primitives::TempoHeader;

/// Tempo RPC header response type.
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::Deref, derive_more::DerefMut)]
#[serde(rename_all = "camelCase")]
pub struct TempoHeaderResponse {
    /// Inner [`Header`].
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    pub inner: Header<TempoHeader>,

    /// Block timestamp in milliseconds.
    #[serde(with = "alloy_serde::quantity")]
    pub timestamp_millis: u64,
}

impl BlockHeader for TempoHeaderResponse {
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

    fn number(&self) -> u64 {
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

impl HeaderResponse for TempoHeaderResponse {
    fn hash(&self) -> BlockHash {
        self.inner.hash()
    }
}

impl AsRef<TempoHeader> for TempoHeaderResponse {
    fn as_ref(&self) -> &TempoHeader {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Sealable;
    use alloy_primitives::b256;
    use tempo_primitives::TempoConsensusContext;

    #[test]
    fn header_response_serde_roundtrip_preserves_hash() {
        let header = TempoHeader {
            general_gas_limit: 15_000_000,
            shared_gas_limit: 5_000_000,
            timestamp_millis_part: 123,
            inner: alloy_consensus::Header {
                parent_hash: B256::repeat_byte(0x01),
                number: 42,
                gas_limit: 30_000_000,
                gas_used: 21_000,
                timestamp: 1_700_000_000,
                extra_data: Bytes::from_static(b"tempo"),
                base_fee_per_gas: Some(1_000_000_000),
                withdrawals_root: Some(B256::repeat_byte(0x02)),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                parent_beacon_block_root: Some(B256::repeat_byte(0x03)),
                requests_hash: Some(B256::repeat_byte(0x04)),
                ..Default::default()
            },
            consensus_context: Some(TempoConsensusContext {
                epoch: 1,
                view: 5,
                parent_view: 4,
                // RFC 8032 test vector 1 public key.
                proposer: b256!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                    .try_into()
                    .unwrap(),
            }),
        };
        let response = TempoHeaderResponse {
            timestamp_millis: header.timestamp_millis(),
            inner: Header::new(header.clone()),
        };
        assert_eq!(response.hash(), header.hash_slow());

        let json = serde_json::to_string(&response).unwrap();
        let decoded: TempoHeaderResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.inner.inner, header);
        assert_eq!(decoded.inner.inner.hash_slow(), response.hash());
        assert_eq!(decoded.hash(), response.hash());
        assert_eq!(decoded.timestamp_millis, response.timestamp_millis);
    }
}
