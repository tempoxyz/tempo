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
    use alloy_consensus::Header as ConsensusHeader;
    use alloy_rpc_types_eth::Header as RpcHeader;

    fn response_with_proof_root(proof_root: Option<B256>) -> TempoHeaderResponse {
        let header = TempoHeader {
            proof_root,
            inner: ConsensusHeader {
                number: 1,
                timestamp: 2,
                ..Default::default()
            },
            ..Default::default()
        };

        TempoHeaderResponse {
            inner: RpcHeader::new(header),
            timestamp_millis: 2_000,
        }
    }

    #[test]
    fn rpc_header_serializes_proof_root_when_present() {
        let proof_root = B256::repeat_byte(0x42);
        let value = serde_json::to_value(response_with_proof_root(Some(proof_root))).unwrap();

        assert_eq!(
            value.get("proofRoot"),
            Some(&serde_json::Value::String(format!("{proof_root:#x}")))
        );
    }

    #[test]
    fn rpc_header_omits_proof_root_when_absent() {
        let value = serde_json::to_value(response_with_proof_root(None)).unwrap();

        assert!(value.get("proofRoot").is_none());
    }
}
