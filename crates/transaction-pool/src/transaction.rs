use crate::tt_2d_pool::{AA2dTransactionId, AASequenceId};
use alloy_consensus::{BlobTransactionValidationError, Transaction, transaction::TxHashRef};
use alloy_eips::{
    eip2718::{Encodable2718, Typed2718},
    eip2930::AccessList,
    eip4844::env_settings::KzgSettings,
    eip7594::BlobTransactionSidecarVariant,
    eip7702::SignedAuthorization,
};
use alloy_evm::FromRecoveredTx;
use alloy_primitives::{Address, B256, Bytes, TxHash, TxKind, U256, bytes};
use alloy_sol_types::SolCall;
use reth_evm::execute::WithTxEnv;
use reth_primitives_traits::{InMemorySize, Recovered};
use reth_transaction_pool::{
    EthBlobTransactionSidecar, EthPoolTransaction, EthPooledTransaction, PoolTransaction,
    error::PoolTransactionError,
};
use std::{
    convert::Infallible,
    fmt::Debug,
    sync::{Arc, OnceLock},
};
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::nonce::NonceManager;
use tempo_precompiles::tip20::TIP20Token;
use tempo_primitives::{TempoTxEnvelope, transaction::calc_gas_balance_spending};
use tempo_revm::TempoTxEnv;
use thiserror::Error;

/// Tempo pooled transaction representation.
///
/// This is a wrapper around the regular ethereum [`EthPooledTransaction`], but with tempo specific implementations.
#[derive(Debug, Clone)]
pub struct TempoPooledTransaction {
    inner: EthPooledTransaction<TempoTxEnvelope>,
    /// Cached payment classification for efficient block building
    is_payment: bool,
    /// Cached prepared [`TempoTxEnv`] for payload building.
    tx_env: OnceLock<TempoTxEnv>,
    /// Cached storage slots this tx may access
    cached_slots: CachedSlots,
}

#[derive(Debug, Clone, Default)]
pub struct CachedSlots {
    /// Cached slot of the 2D nonce, if any.
    pub nonce_key: OnceLock<Option<U256>>,
    /// Cached slot for sender's fee token balance
    pub fee_token_balance: OnceLock<Option<U256>>,
    /// Cached slot for TIP-20 transfer sender's balance
    pub tip20_from_balance: OnceLock<Option<U256>>,
    /// Cached slot for TIP-20 transfer recipient's balance
    pub tip20_to_balance: OnceLock<Option<U256>>,
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
            tx_env: OnceLock::new(),
            cached_slots: Default::default(),
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

    /// Returns true if this is an AA transaction
    pub fn is_aa(&self) -> bool {
        self.inner().is_aa()
    }

    /// Returns the nonce key of this transaction if it's an [`AASigned`](tempo_primitives::AASigned) transaction.
    pub fn nonce_key(&self) -> Option<U256> {
        self.inner.transaction.nonce_key()
    }

    /// Returns the storage slot for the nonce key of this transaction.
    pub fn nonce_key_slot(&self) -> Option<U256> {
        *self.cached_slots.nonce_key.get_or_init(|| {
            let nonce_key = self.nonce_key()?;
            let sender = self.sender();
            let slot = NonceManager::new().nonces.at(sender).at(nonce_key).slot();
            Some(slot)
        })
    }

    /// Returns the storage slot for sender's fee token balance if transaction contains fee token
    pub fn fee_token_balance_slot(&self) -> Option<U256> {
        *self.cached_slots.fee_token_balance.get_or_init(|| {
            self.inner.transaction.fee_token().map(|token_address| {
                let sender = self.sender();
                TIP20Token::from_address(token_address)
                    .unwrap()
                    .balances
                    .at(sender)
                    .slot()
            })
        })
    }

    /// Returns the storage slot for the sender's token balance if this is a TIP-20 transfer transaction.
    ///
    /// Decodes the transaction payload to extract the sender address.
    /// For `transfer()` calls, sender is the transaction signer.
    /// For `transferFrom()` calls, sender is decoded from the calldata.
    pub fn tip_20_from_balance_slot(&self) -> Option<U256> {
        *self.cached_slots.tip20_from_balance.get_or_init(|| {
            if !self.inner.transaction.is_payment() {
                return None;
            }

            let token_address = self.to()?;

            // Decode the transfer call to extract the sender address
            let input = self.input();
            let tx_sender = self.sender();
            let (from_addr, _to_addr) = decode_transfer_addresses(input, tx_sender)?;

            let slot = TIP20Token::from_address(token_address)
                .ok()?
                .balances
                .at(from_addr)
                .slot();
            Some(slot)
        })
    }

    /// Returns the storage slot for the transfer recipient's token balance if this is a TIP-20 transfer transaction.
    ///
    /// Decodes the transaction payload to extract the recipient address.
    /// Supports all transfer methods: `transfer`, `transferWithMemo`, `transferFrom`, and `transferFromWithMemo`.
    pub fn tip_20_to_balance_slot(&self) -> Option<U256> {
        *self.cached_slots.tip20_to_balance.get_or_init(|| {
            if !self.inner.transaction.is_payment() {
                return None;
            }

            let token_address = self.to()?;

            // Decode the transfer call to extract the recipient address
            let input = self.input();
            let tx_sender = self.sender();
            let (_from_addr, to_addr) = decode_transfer_addresses(input, tx_sender)?;

            let slot = TIP20Token::from_address(token_address)
                .ok()?
                .balances
                .at(to_addr)
                .slot();
            Some(slot)
        })
    }

    /// Returns whether this is a payment transaction.
    ///
    /// Based on classifier v1: payment if tx.to has TIP20 reserved prefix.
    pub fn is_payment(&self) -> bool {
        self.is_payment
    }

    /// Returns true if this transaction belongs into the 2D nonce pool:
    /// - AA transaction with a `nonce key != 0`
    pub(crate) fn is_aa_2d(&self) -> bool {
        self.inner
            .transaction
            .as_aa()
            .map(|tx| !tx.tx().nonce_key.is_zero())
            .unwrap_or(false)
    }

    /// Returns the unique identifier for this AA transaction.
    pub(crate) fn aa_transaction_id(&self) -> Option<AA2dTransactionId> {
        let nonce_key = self.nonce_key()?;
        let sender = AASequenceId {
            address: self.sender(),
            nonce_key,
        };
        Some(AA2dTransactionId {
            seq_id: sender,
            nonce: self.nonce(),
        })
    }

    /// Computes the [`TempoTxEnv`] for this transaction.
    fn tx_env_slow(&self) -> TempoTxEnv {
        TempoTxEnv::from_recovered_tx(self.inner().inner(), self.sender())
    }

    /// Pre-computes and caches the [`TempoTxEnv`].
    ///
    /// This should be called during validation to prepare the transaction environment
    /// ahead of time, avoiding it during payload building.
    pub fn prepare_tx_env(&self) {
        self.tx_env.get_or_init(|| self.tx_env_slow());
    }

    /// Returns a [`WithTxEnv`] wrapper containing the cached [`TempoTxEnv`].
    ///
    /// If the [`TempoTxEnv`] was pre-computed via [`Self::prepare_tx_env`], the cached
    /// value is used. Otherwise, it is computed on-demand.
    pub fn into_with_tx_env(mut self) -> WithTxEnv<TempoTxEnv, Recovered<TempoTxEnvelope>> {
        let tx_env = self.tx_env.take().unwrap_or_else(|| self.tx_env_slow());
        WithTxEnv {
            tx_env,
            tx: Arc::new(self.inner.transaction),
        }
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

    #[error("No fee token preference configured")]
    MissingFeeToken,

    #[error(
        "'valid_before' {valid_before} is too close to current time (min allowed: {min_allowed})"
    )]
    InvalidValidBefore { valid_before: u64, min_allowed: u64 },

    #[error("'valid_after' {valid_after} is too far in the future (max allowed: {max_allowed})")]
    InvalidValidAfter { valid_after: u64, max_allowed: u64 },

    #[error(
        "Keychain signature validation failed: {0}, please see https://docs.tempo.xyz/errors/tx/Keychain for more"
    )]
    Keychain(&'static str),

    #[error(
        "Native transfers are not supported, if you were trying to transfer a stablecoin, please call TIP20::Transfer"
    )]
    NonZeroValue,

    /// Thrown if a Tempo Transaction with a nonce key prefixed with the sub-block prefix marker added to the pool
    #[error("Tempo Transaction with subblock nonce key prefix aren't supported in the pool")]
    SubblockNonceKey,

    /// Thrown if the fee payer of a transaction cannot transfer (is blacklisted) the fee token, thus making the payment impossible.
    #[error("Fee payer {fee_payer} is blacklisted by fee token: {fee_token}")]
    BlackListedFeePayer {
        fee_token: Address,
        fee_payer: Address,
    },

    /// Thrown when we couldn't find a recently used validator token that has enough liquidity
    /// in fee AMM pair with the user token this transaction will pay fees in.
    #[error(
        "Insufficient liquidity for fee token: {0}, please see https://docs.tempo.xyz/protocol/fees for more"
    )]
    InsufficientLiquidity(Address),
}

impl PoolTransactionError for TempoPoolTransactionError {
    fn is_bad_transaction(&self) -> bool {
        match self {
            Self::ExceedsNonPaymentLimit
            | Self::InvalidFeeToken(_)
            | Self::MissingFeeToken
            | Self::BlackListedFeePayer { .. }
            | Self::InvalidValidBefore { .. }
            | Self::InvalidValidAfter { .. }
            | Self::Keychain(_)
            | Self::InsufficientLiquidity(_) => false,
            Self::NonZeroValue | Self::SubblockNonceKey => true,
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

    fn requires_nonce_check(&self) -> bool {
        self.inner
            .transaction()
            .as_aa()
            .map(|tx| {
                // for AA transaction with a custom nonce key we can skip the nonce validation
                tx.tx().nonce_key.is_zero()
            })
            .unwrap_or(true)
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

/// Decodes a TIP-20/ERC-20 transfer call and extracts sender and recipient addresses.
///
/// Returns `Some((from, to))` if the calldata is a valid transfer call, `None` otherwise.
/// Supports: `transfer`, `transferWithMemo`, `transferFrom`, and `transferFromWithMemo`.
///
/// For `transfer()` calls, the sender is the transaction signer (`tx_sender` parameter).
/// For `transferFrom()` calls, the sender is decoded from the calldata.
fn decode_transfer_addresses(calldata: &Bytes, tx_sender: Address) -> Option<(Address, Address)> {
    // Try transfer(address,uint256) - sender is tx_sender
    if let Ok(call) = ITIP20::transferCall::abi_decode(calldata) {
        return Some((tx_sender, call.to));
    }

    // Try transferWithMemo(address,uint256,bytes32) - sender is tx_sender
    if let Ok(call) = ITIP20::transferWithMemoCall::abi_decode(calldata) {
        return Some((tx_sender, call.to));
    }

    // Try transferFrom(address,address,uint256) - sender is in calldata
    if let Ok(call) = ITIP20::transferFromCall::abi_decode(calldata) {
        return Some((call.from, call.to));
    }

    // Try transferFromWithMemo(address,address,uint256,bytes32) - sender is in calldata
    if let Ok(call) = ITIP20::transferFromWithMemoCall::abi_decode(calldata) {
        return Some((call.from, call.to));
    }

    None
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
