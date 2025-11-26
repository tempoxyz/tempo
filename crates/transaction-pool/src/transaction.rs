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
    error::PoolTransactionError,
};
use std::{convert::Infallible, fmt::Debug, sync::Arc};
use tempo_primitives::{TempoTxEnvelope, transaction::calc_gas_balance_spending};
use thiserror::Error;

/// Tempo pooled transaction representation.
///
/// This is a wrapper around the regular ethereum [`EthPooledTransaction`], but with tempo specific implementations.
#[derive(Debug, Clone)]
pub struct TempoPooledTransaction {
    inner: EthPooledTransaction<TempoTxEnvelope>,
    /// Cached payment classification for efficient block building
    is_payment: bool,
}

impl TempoPooledTransaction {
    /// Create new instance of [Self] from the given consensus transactions and the encoded size.
    pub fn new(transaction: Recovered<TempoTxEnvelope>) -> Self {
        let is_payment = transaction.is_payment();
        Self {
            inner: EthPooledTransaction {
                cost: calc_gas_balance_spending(
                    transaction.gas_limit(),
                    transaction.max_fee_per_gas(),
                )
                .saturating_add(transaction.value()),
                encoded_length: transaction.encode_2718_len(),
                blob_sidecar: EthBlobTransactionSidecar::None,
                transaction,
            },
            is_payment,
        }
    }

    /// Get the cost of the transaction in the fee token.
    pub fn fee_token_cost(&self) -> U256 {
        self.inner.cost - self.inner.value()
    }

    /// Returns a reference to inner [`TempoTxEnvelope`].
    pub fn inner(&self) -> &Recovered<TempoTxEnvelope> {
        &self.inner.transaction
    }

    /// Returns whether this is a payment transaction.
    ///
    /// Based on classifier v1: payment if tx.to has TIP20 reserved prefix.
    pub fn is_payment(&self) -> bool {
        self.is_payment
    }
}

#[derive(Debug, Error)]
pub enum TempoPoolTransactionError {
    #[error(
        "Transaction exceeds non payment gas limit, please see https://docs.tempo.xyz/errors/tx/ExceedsNonPaymentLimit for more"
    )]
    ExceedsNonPaymentLimit,

    #[error(
        "Invalid fee token: {0}, please see https://docs.tempo.xyz/errors/tx/InvalidFeeToken for more"
    )]
    InvalidFeeToken(Address),

    #[error(
        "No fee token preference configured, please see https://docs.tempo.xyz/errors/tx/MissingFeeToken for more"
    )]
    MissingFeeToken,

    #[error(
        "Keychain signature validation failed: {0}, please see https://docs.tempo.xyz/errors/tx/Keychain for more"
    )]
    Keychain(&'static str),

    #[error(
        "Native transfers are not supported, if you were trying to transfer a stablecoin, please call TIP20::Transfer"
    )]
    NonZeroValue,
}

impl PoolTransactionError for TempoPoolTransactionError {
    fn is_bad_transaction(&self) -> bool {
        match self {
            Self::ExceedsNonPaymentLimit
            | Self::InvalidFeeToken(_)
            | Self::MissingFeeToken
            | Self::Keychain(_) => false,
            Self::NonZeroValue => true,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
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
        Self::new(tx)
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use tempo_primitives::TxFeeToken;

    #[test]
    fn test_payment_classification_caching() {
        // Test that payment classification is properly cached in TempoPooledTransaction
        let payment_addr = address!("20c0000000000000000000000000000000000001");
        let tx = TxFeeToken {
            to: TxKind::Call(payment_addr),
            gas_limit: 21000,
            ..Default::default()
        };

        let envelope = TempoTxEnvelope::FeeToken(alloy_consensus::Signed::new_unchecked(
            tx,
            alloy_primitives::Signature::test_signature(),
            alloy_primitives::B256::ZERO,
        ));

        let recovered = Recovered::new_unchecked(
            envelope,
            address!("0000000000000000000000000000000000000001"),
        );

        // Create via new() and verify caching
        let pooled_tx = TempoPooledTransaction::new(recovered);
        assert!(pooled_tx.is_payment());
    }
}
