use std::{fmt::Debug, sync::Arc};

use alloy_consensus::{BlobTransactionValidationError, error::ValueError};
use alloy_eips::{
    eip2718::{Encodable2718, Typed2718, WithEncoded},
    eip2930::AccessList,
    eip4844::env_settings::KzgSettings,
    eip7594::BlobTransactionSidecarVariant,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, B256, Bytes, TxHash, TxKind, U256, bytes};
use reth_ethereum_primitives::{PooledTransactionVariant, TransactionSigned};
use reth_primitives_traits::{InMemorySize, Recovered};
use reth_transaction_pool::{
    EthBlobTransactionSidecar, EthPoolTransaction, EthPooledTransaction, PoolTransaction,
};

/// Tempo pooled transaction representation.
///
/// This is a wrapper around the regular ethereum [`EthPooledTransaction`], but with tempo specific implementations.
#[derive(Debug, Clone)]
pub struct TempoPooledTransaction {
    inner: EthPooledTransaction,
}

impl TempoPooledTransaction {
    /// Create new instance of [Self] from the given consensus transactions and the encoded size.
    pub fn new(transaction: Recovered<TransactionSigned>, encoded_length: usize) -> Self {
        Self::from_eth(EthPooledTransaction::new(transaction, encoded_length))
    }

    fn from_eth(eth_pooled: EthPooledTransaction) -> Self {
        Self { inner: eth_pooled }
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
    type TryFromConsensusError = ValueError<TransactionSigned>;
    type Consensus = TransactionSigned;
    type Pooled = PooledTransactionVariant;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.inner.clone_into_consensus()
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.inner.transaction
    }

    fn into_consensus_with2718(self) -> WithEncoded<Recovered<Self::Consensus>> {
        self.inner.into_consensus_with2718()
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        Self::from_eth(EthPooledTransaction::from_pooled(tx))
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
        self.inner.take_blob()
    }

    fn try_into_pooled_eip4844(
        self,
        sidecar: Arc<BlobTransactionSidecarVariant>,
    ) -> Option<Recovered<Self::Pooled>> {
        self.inner.try_into_pooled_eip4844(sidecar)
    }

    fn try_from_eip4844(
        tx: Recovered<Self::Consensus>,
        sidecar: BlobTransactionSidecarVariant,
    ) -> Option<Self> {
        EthPooledTransaction::try_from_eip4844(tx, sidecar).map(Self::from_eth)
    }

    fn validate_blob(
        &self,
        sidecar: &BlobTransactionSidecarVariant,
        settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        self.inner.validate_blob(sidecar, settings)
    }
}
