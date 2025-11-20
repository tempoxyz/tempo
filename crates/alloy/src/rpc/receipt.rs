use alloy_consensus::ReceiptWithBloom;
use alloy_network::ReceiptResponse;
use alloy_primitives::{Address, B256, BlockHash, TxHash};
use alloy_rpc_types_eth::{Log, TransactionReceipt};
use serde::{Deserialize, Serialize};
use tempo_primitives::TempoReceipt;

/// Tempo RPC receipt type.
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::Deref, derive_more::DerefMut)]
#[serde(rename_all = "camelCase")]
pub struct TempoTransactionReceipt {
    /// Inner [`TransactionReceipt`].
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    pub inner: TransactionReceipt<ReceiptWithBloom<TempoReceipt<Log>>>,

    /// Token that was used to pay fees for the transaction.
    ///
    /// None if the transaction was free.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_token: Option<Address>,

    /// Address that paid the fees for the transaction.
    pub fee_payer: Address,
}

impl ReceiptResponse for TempoTransactionReceipt {
    fn contract_address(&self) -> Option<Address> {
        self.inner.contract_address()
    }

    fn status(&self) -> bool {
        self.inner.status()
    }

    fn block_hash(&self) -> Option<BlockHash> {
        self.inner.block_hash()
    }

    fn block_number(&self) -> Option<u64> {
        self.inner.block_number()
    }

    fn transaction_hash(&self) -> TxHash {
        self.inner.transaction_hash()
    }

    fn transaction_index(&self) -> Option<u64> {
        self.inner.transaction_index()
    }

    fn gas_used(&self) -> u64 {
        self.inner.gas_used()
    }

    fn effective_gas_price(&self) -> u128 {
        self.inner.effective_gas_price()
    }

    fn blob_gas_used(&self) -> Option<u64> {
        self.inner.blob_gas_used()
    }

    fn blob_gas_price(&self) -> Option<u128> {
        self.inner.blob_gas_price()
    }

    fn from(&self) -> Address {
        self.inner.from()
    }

    fn to(&self) -> Option<Address> {
        self.inner.to()
    }

    fn cumulative_gas_used(&self) -> u64 {
        self.inner.cumulative_gas_used()
    }

    fn state_root(&self) -> Option<B256> {
        self.inner.state_root()
    }
}
