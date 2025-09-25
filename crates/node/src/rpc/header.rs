use alloy::primitives::{Bytes, U256};
use alloy_network::primitives::HeaderResponse;
use alloy_primitives::{Address, B64, B256, BlockHash, Bloom};
use reth_primitives_traits::{AlloyBlockHeader, SealedHeader};
use reth_rpc_convert::transaction::FromConsensusHeader;
use serde::{Deserialize, Serialize};
use tempo_consensus::TempoExtraData;

/// Tempo RPC block header
#[derive(Debug, Clone, derive_more::Deref, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    /// Inner Ethereum header.
    #[deref]
    #[serde(flatten)]
    pub inner: alloy_rpc_types_eth::Header,
    /// Non-payment gas limit.
    #[serde(with = "alloy::serde::quantity")]
    pub non_payment_gas_limit: u64,
    /// Non-payment gas used.
    #[serde(with = "alloy::serde::quantity")]
    pub non_payment_gas_used: u64,
}

impl FromConsensusHeader<tempo_primitives::Header> for Header {
    fn from_consensus_header(
        header: SealedHeader<tempo_primitives::Header>,
        block_size: usize,
    ) -> Self {
        let extra_data = TempoExtraData::decode(&header.extra_data);

        let non_payment_gas_limit = extra_data
            .as_ref()
            .map(|e| e.non_payment_gas_limit)
            .unwrap_or_default();

        let non_payment_gas_used = extra_data
            .as_ref()
            .map(|e| e.non_payment_gas_used)
            .unwrap_or_default();

        Self {
            non_payment_gas_limit,
            non_payment_gas_used,
            inner: alloy_rpc_types_eth::Header::from_consensus_header(header, block_size),
        }
    }
}

impl AlloyBlockHeader for Header {
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

    fn extra_data(&self) -> &Bytes {
        self.inner.extra_data()
    }
}

impl HeaderResponse for Header {
    fn hash(&self) -> BlockHash {
        self.inner.hash()
    }
}

impl AsRef<alloy::consensus::Header> for Header {
    fn as_ref(&self) -> &tempo_primitives::Header {
        self.inner.as_ref()
    }
}
