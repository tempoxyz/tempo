use std::{convert::Infallible, fmt::Debug, sync::Arc};

use alloy_consensus::{BlobTransactionValidationError, Transaction, transaction::TxHashRef};
use alloy_eips::{
    eip2718::{Encodable2718, Typed2718},
    eip2930::AccessList,
    eip4844::env_settings::KzgSettings,
    eip7594::BlobTransactionSidecarVariant,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, B256, Bytes, TxHash, TxKind, U256, bytes};
use reth_primitives_traits::{InMemorySize, Recovered};
use reth_transaction_pool::{
    EthBlobTransactionSidecar, EthPoolTransaction, EthPooledTransaction, PoolTransaction,
};
use tempo_primitives::TempoTxEnvelope;

/// Tempo pooled transaction representation.
///
/// This is a wrapper around the regular ethereum [`EthPooledTransaction`], but with tempo specific implementations.
#[derive(Debug, Clone)]
pub struct TempoPooledTransaction {
    inner: EthPooledTransaction<TempoTxEnvelope>,
}

impl TempoPooledTransaction {
    /// Create new instance of [Self] from the given consensus transactions and the encoded size.
    pub fn new(transaction: Recovered<TempoTxEnvelope>, encoded_length: usize) -> Self {
        Self::from_eth(EthPooledTransaction::new(transaction, encoded_length))
    }

    pub fn from_eth(eth_pooled: EthPooledTransaction<TempoTxEnvelope>) -> Self {
        Self { inner: eth_pooled }
    }

    /// Get the cost of the transaction in the fee token.
    pub fn fee_token_cost(&self) -> U256 {
        self.inner.cost - self.inner.value()
    }

    /// Returns a reference to inner [`TempoTxEnvelope`].
    pub fn inner(&self) -> &TempoTxEnvelope {
        &self.inner.transaction
    }
}

impl InMemorySize for TempoPooledTransaction {
    fn size(&self) -> usize {
        self.inner.size()
    }
}

impl Typed2718 for TempoPooledTransaction {
    fn ty(&self) -> u8 {
        self.inner.transaction.ty()
    }
}

impl Encodable2718 for TempoPooledTransaction {
    fn type_flag(&self) -> Option<u8> {
        self.inner.transaction.type_flag()
    }

    fn encode_2718_len(&self) -> usize {
        self.inner.transaction.encode_2718_len()
    }

    fn encode_2718(&self, out: &mut dyn bytes::BufMut) {
        self.inner.transaction.encode_2718(out)
    }
}

impl PoolTransaction for TempoPooledTransaction {
    type TryFromConsensusError = Infallible;
    type Consensus = TempoTxEnvelope;
    type Pooled = TempoTxEnvelope;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.inner.transaction.clone()
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.inner.transaction
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        let len = tx.encode_2718_len();
        Self::from_eth(EthPooledTransaction::new(tx, len))
    }

    fn hash(&self) -> &TxHash {
        self.inner.transaction.tx_hash()
    }

    fn sender(&self) -> Address {
        self.inner.transaction.signer()
    }

    fn sender_ref(&self) -> &Address {
        self.inner.transaction.signer_ref()
    }

    fn cost(&self) -> &U256 {
        &U256::ZERO
    }

    fn encoded_length(&self) -> usize {
        self.inner.encoded_length
    }
}

impl alloy_consensus::Transaction for TempoPooledTransaction {
    fn chain_id(&self) -> Option<u64> {
        self.inner.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.inner.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.inner.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.inner.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.inner.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.inner.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.inner.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.inner.is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.inner.kind()
    }

    fn is_create(&self) -> bool {
        self.inner.is_create()
    }

    fn value(&self) -> U256 {
        self.inner.value()
    }

    fn input(&self) -> &Bytes {
        self.inner.input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.inner.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.inner.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.inner.authorization_list()
    }
}

impl EthPoolTransaction for TempoPooledTransaction {
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        EthBlobTransactionSidecar::None
    }

    fn try_into_pooled_eip4844(
        self,
        _sidecar: Arc<BlobTransactionSidecarVariant>,
    ) -> Option<Recovered<Self::Pooled>> {
        None
    }

    fn try_from_eip4844(
        _tx: Recovered<Self::Consensus>,
        _sidecar: BlobTransactionSidecarVariant,
    ) -> Option<Self> {
        None
    }

    fn validate_blob(
        &self,
        _sidecar: &BlobTransactionSidecarVariant,
        _settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        Err(BlobTransactionValidationError::NotBlobTransaction(
            self.ty(),
        ))
    }
}
