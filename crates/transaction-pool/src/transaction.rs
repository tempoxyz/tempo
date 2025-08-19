use std::{fmt::Debug, sync::Arc};

use alloy_consensus::{BlobTransactionValidationError, TxEnvelope};
use alloy_eips::{
    eip2718::{Encodable2718, Typed2718, WithEncoded},
    eip2930::AccessList,
    eip4844::env_settings::KzgSettings,
    eip7594::BlobTransactionSidecarVariant,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{Address, B256, Bytes, TxHash, TxKind, U256, bytes};
use reth_ethereum_primitives::TransactionSigned;
use reth_primitives_traits::{InMemorySize, Recovered, SignedTransaction};
use reth_transaction_pool::{
    EthBlobTransactionSidecar, EthPoolTransaction, EthPooledTransaction, PoolTransaction,
};

#[derive(Debug, Clone)]
pub struct TempoPooledTransaction<Cons = TransactionSigned, Pooled = TxEnvelope> {
    pub inner: EthPooledTransaction<Cons>,
    /// The pooled transaction type.
    _pd: core::marker::PhantomData<Pooled>,
}

impl<Cons: SignedTransaction, Pooled> TempoPooledTransaction<Cons, Pooled> {
    /// Create new instance of [Self].
    pub fn new(transaction: Recovered<Cons>, encoded_length: usize) -> Self {
        Self {
            inner: EthPooledTransaction::new(transaction, encoded_length),
            _pd: core::marker::PhantomData,
        }
    }
}

impl<Cons, Pooled> InMemorySize for TempoPooledTransaction<Cons, Pooled>
where
    Cons: InMemorySize,
    Pooled: InMemorySize,
{
    fn size(&self) -> usize {
        self.inner.size()
    }
}

impl<Cons, Pooled> Typed2718 for TempoPooledTransaction<Cons, Pooled>
where
    Cons: Typed2718,
{
    fn ty(&self) -> u8 {
        self.inner.transaction.ty()
    }
}

impl<Cons, Pooled> Encodable2718 for TempoPooledTransaction<Cons, Pooled>
where
    Cons: Encodable2718,
    Pooled: Send + Sync,
{
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

impl<Cons, Pooled> PoolTransaction for TempoPooledTransaction<Cons, Pooled>
where
    Cons: SignedTransaction + From<Pooled> + InMemorySize,
    Pooled: SignedTransaction + TryFrom<Cons, Error: core::error::Error> + InMemorySize,
{
    type TryFromConsensusError = <Pooled as TryFrom<Cons>>::Error;
    type Consensus = Cons;
    type Pooled = Pooled;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.inner.transaction().clone()
    }

    fn into_consensus(self) -> Recovered<Self::Consensus> {
        self.inner.transaction
    }

    fn into_consensus_with2718(self) -> WithEncoded<Recovered<Self::Consensus>> {
        let mut buf = Vec::new();
        self.inner.transaction.encode_2718(&mut buf);
        self.inner.transaction.into_encoded_with(buf)
    }

    fn from_pooled(tx: Recovered<Self::Pooled>) -> Self {
        let encoded_len = tx.encode_2718_len();
        Self::new(tx.convert(), encoded_len)
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

impl<Cons, Pooled> alloy_consensus::Transaction for TempoPooledTransaction<Cons, Pooled>
where
    Cons: alloy_consensus::Transaction + InMemorySize,
    Pooled: Debug + Send + Sync + 'static + InMemorySize,
{
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

impl<Cons, Pooled> EthPoolTransaction for TempoPooledTransaction<Cons, Pooled>
where
    Cons: SignedTransaction + From<Pooled> + InMemorySize,
    Pooled: SignedTransaction + TryFrom<Cons> + InMemorySize,
    <Pooled as TryFrom<Cons>>::Error: core::error::Error,
{
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        todo!()
    }

    fn try_into_pooled_eip4844(
        self,
        _sidecar: Arc<BlobTransactionSidecarVariant>,
    ) -> Option<Recovered<Self::Pooled>> {
        // TODO:
        None
    }

    fn try_from_eip4844(
        _tx: Recovered<Self::Consensus>,
        _sidecar: BlobTransactionSidecarVariant,
    ) -> Option<Self> {
        // TODO:
        None
    }

    fn validate_blob(
        &self,
        _sidecar: &BlobTransactionSidecarVariant,
        _settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        // TODO:
        Ok(())
    }
}
