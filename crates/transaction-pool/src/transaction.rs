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
use alloy_primitives::{Address, B256, Bytes, TxHash, TxKind, U256, bytes, map::AddressMap};
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
use tempo_precompiles::{DEFAULT_FEE_TOKEN, nonce::NonceManager};
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
    /// Cached expiring nonce classification
    is_expiring_nonce: bool,
    /// Cached slot of the 2D nonce, if any.
    nonce_key_slot: OnceLock<Option<U256>>,
    /// Cached prepared [`TempoTxEnv`] for payload building.
    tx_env: OnceLock<TempoTxEnv>,
    /// Keychain key expiry timestamp (set during validation for keychain-signed txs).
    ///
    /// `Some(expiry)` for keychain transactions where expiry < u64::MAX (finite expiry).
    /// `None` for non-keychain transactions or keys that never expire.
    key_expiry: OnceLock<Option<u64>>,
}

impl TempoPooledTransaction {
    /// Create new instance of [Self] from the given consensus transactions and the encoded size.
    pub fn new(transaction: Recovered<TempoTxEnvelope>) -> Self {
        let is_payment = transaction.is_payment();
        let is_expiring_nonce = transaction
            .as_aa()
            .map(|tx| tx.tx().is_expiring_nonce_tx())
            .unwrap_or(false);
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
            is_expiring_nonce,
            nonce_key_slot: OnceLock::new(),
            tx_env: OnceLock::new(),
            key_expiry: OnceLock::new(),
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
        *self.nonce_key_slot.get_or_init(|| {
            let nonce_key = self.nonce_key()?;
            let sender = self.sender();
            let slot = NonceManager::new().nonces[sender][nonce_key].slot();
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
    /// - AA transaction with a `nonce key != 0` (includes expiring nonce txs)
    pub(crate) fn is_aa_2d(&self) -> bool {
        self.inner
            .transaction
            .as_aa()
            .map(|tx| !tx.tx().nonce_key.is_zero())
            .unwrap_or(false)
    }

    /// Returns true if this is an expiring nonce transaction.
    pub(crate) fn is_expiring_nonce(&self) -> bool {
        self.is_expiring_nonce
    }

    /// Extracts the keychain subject (account, key_id, fee_token) from this transaction.
    ///
    /// Returns `None` if:
    /// - This is not an AA transaction
    /// - The signature is not a keychain signature
    /// - The key_id cannot be recovered from the signature
    ///
    /// Used for matching transactions against revocation and spending limit events.
    pub fn keychain_subject(&self) -> Option<KeychainSubject> {
        let aa_tx = self.inner().as_aa()?;
        let keychain_sig = aa_tx.signature().as_keychain()?;
        let key_id = keychain_sig.key_id(&aa_tx.signature_hash()).ok()?;
        let fee_token = self.inner().fee_token().unwrap_or(DEFAULT_FEE_TOKEN);
        Some(KeychainSubject {
            account: keychain_sig.user_address,
            key_id,
            fee_token,
        })
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

    /// Sets the keychain key expiry timestamp for this transaction.
    ///
    /// Called during validation when we read the AuthorizedKey from state.
    /// Pass `Some(expiry)` for keys with finite expiry, `None` for non-keychain txs
    /// or keys that never expire.
    pub fn set_key_expiry(&self, expiry: Option<u64>) {
        let _ = self.key_expiry.set(expiry);
    }

    /// Returns the keychain key expiry timestamp, if set during validation.
    ///
    /// Returns `Some(expiry)` for keychain transactions with finite expiry.
    /// Returns `None` if not a keychain tx, key never expires, or not yet validated.
    pub fn key_expiry(&self) -> Option<u64> {
        self.key_expiry.get().copied().flatten()
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
        "Fee token {0} is paused, please see https://docs.tempo.xyz/errors/tx/PausedFeeToken for more"
    )]
    PausedFeeToken(Address),

    #[error("No fee token preference configured")]
    MissingFeeToken,

    #[error(
        "'valid_before' {valid_before} is too close to current time (min allowed: {min_allowed})"
    )]
    InvalidValidBefore { valid_before: u64, min_allowed: u64 },

    #[error("'valid_after' {valid_after} is too far in the future (max allowed: {max_allowed})")]
    InvalidValidAfter { valid_after: u64, max_allowed: u64 },

    #[error(
        "max_fee_per_gas {max_fee_per_gas} is below the minimum base fee {min_base_fee} for the current hardfork"
    )]
    FeeCapBelowMinBaseFee {
        max_fee_per_gas: u128,
        min_base_fee: u64,
    },

    #[error(
        "Keychain signature validation failed: {0}, please see https://docs.tempo.xyz/errors/tx/Keychain for more"
    )]
    Keychain(&'static str),

    #[error("Fee payer signature recovery failed")]
    InvalidFeePayerSignature,

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

    /// Thrown when an AA transaction's gas limit is insufficient for the calculated intrinsic gas.
    /// This includes per-call costs, signature verification, and other AA-specific gas costs.
    #[error(
        "Insufficient gas for AA transaction: gas limit {gas_limit} is less than intrinsic gas {intrinsic_gas}"
    )]
    InsufficientGasForAAIntrinsicCost { gas_limit: u64, intrinsic_gas: u64 },

    /// Thrown when an AA transaction has too many authorizations in its authorization list.
    #[error(
        "Too many authorizations in AA transaction: {count} exceeds maximum allowed {max_allowed}"
    )]
    TooManyAuthorizations { count: usize, max_allowed: usize },

    /// Thrown when an AA transaction has too many calls.
    #[error("Too many calls in AA transaction: {count} exceeds maximum allowed {max_allowed}")]
    TooManyCalls { count: usize, max_allowed: usize },

    /// Thrown when an AA transaction has no calls.
    #[error("AA transaction has no calls")]
    NoCalls,

    /// Thrown when a call in an AA transaction is the second call and is a CREATE.
    #[error("CREATE calls must be the first call in an AA transaction")]
    CreateCallNotFirst,

    /// Thrown when an AA transaction contains both a CREATE call and an authorization list.
    #[error("CREATE calls are not allowed in the same transaction that has an authorization list")]
    CreateCallWithAuthorizationList,

    /// Thrown when a call in an AA transaction has input data exceeding the maximum allowed size.
    #[error(
        "Call input size {size} exceeds maximum allowed {max_allowed} bytes (call index: {call_index})"
    )]
    CallInputTooLarge {
        call_index: usize,
        size: usize,
        max_allowed: usize,
    },

    /// Thrown when an AA transaction has too many accounts in its access list.
    #[error("Too many access list accounts: {count} exceeds maximum allowed {max_allowed}")]
    TooManyAccessListAccounts { count: usize, max_allowed: usize },

    /// Thrown when an access list entry has too many storage keys.
    #[error(
        "Too many storage keys in access list entry {account_index}: {count} exceeds maximum allowed {max_allowed}"
    )]
    TooManyStorageKeysPerAccount {
        account_index: usize,
        count: usize,
        max_allowed: usize,
    },

    /// Thrown when the total number of storage keys across all access list entries is too large.
    #[error(
        "Too many total storage keys in access list: {count} exceeds maximum allowed {max_allowed}"
    )]
    TooManyTotalStorageKeys { count: usize, max_allowed: usize },

    /// Thrown when a key authorization has too many token limits.
    #[error(
        "Too many token limits in key authorization: {count} exceeds maximum allowed {max_allowed}"
    )]
    TooManyTokenLimits { count: usize, max_allowed: usize },

    /// Thrown when an expiring nonce transaction's valid_before is too far in the future.
    #[error(
        "Expiring nonce 'valid_before' {valid_before} exceeds max allowed {max_allowed} (must be within 30s)"
    )]
    ExpiringNonceValidBeforeTooFar { valid_before: u64, max_allowed: u64 },

    /// Thrown when an expiring nonce transaction's hash has already been seen (replay).
    #[error("Expiring nonce transaction replay: tx hash already seen and not expired")]
    ExpiringNonceReplay,

    /// Thrown when an expiring nonce transaction is missing the required valid_before field.
    #[error("Expiring nonce transactions must have 'valid_before' set")]
    ExpiringNonceMissingValidBefore,

    /// Thrown when an expiring nonce transaction has a non-zero nonce.
    #[error("Expiring nonce transactions must have nonce == 0")]
    ExpiringNonceNonceNotZero,

    /// Thrown when an access key has expired.
    #[error("Access key expired: expiry {expiry} <= current time {current_time}")]
    AccessKeyExpired { expiry: u64, current_time: u64 },

    /// Thrown when a KeyAuthorization has expired.
    #[error("KeyAuthorization expired: expiry {expiry} <= current time {current_time}")]
    KeyAuthorizationExpired { expiry: u64, current_time: u64 },

    /// Thrown when a keychain transaction's fee token cost exceeds the spending limit.
    #[error(
        "Fee token spending limit exceeded: cost {cost} exceeds remaining limit {remaining} for token {fee_token}"
    )]
    SpendingLimitExceeded {
        fee_token: Address,
        cost: U256,
        remaining: U256,
    },
}

impl PoolTransactionError for TempoPoolTransactionError {
    fn is_bad_transaction(&self) -> bool {
        match self {
            Self::ExceedsNonPaymentLimit
            | Self::InvalidFeeToken(_)
            | Self::PausedFeeToken(_)
            | Self::MissingFeeToken
            | Self::BlackListedFeePayer { .. }
            | Self::InvalidValidBefore { .. }
            | Self::InvalidValidAfter { .. }
            | Self::ExpiringNonceValidBeforeTooFar { .. }
            | Self::ExpiringNonceReplay
            | Self::Keychain(_)
            | Self::InsufficientLiquidity(_)
            | Self::SpendingLimitExceeded { .. } => false,
            Self::NonZeroValue
            | Self::SubblockNonceKey
            | Self::InsufficientGasForAAIntrinsicCost { .. }
            | Self::TooManyAuthorizations { .. }
            | Self::TooManyCalls { .. }
            | Self::CallInputTooLarge { .. }
            | Self::TooManyAccessListAccounts { .. }
            | Self::TooManyStorageKeysPerAccount { .. }
            | Self::TooManyTotalStorageKeys { .. }
            | Self::TooManyTokenLimits { .. }
            | Self::ExpiringNonceMissingValidBefore
            | Self::ExpiringNonceNonceNotZero
            | Self::AccessKeyExpired { .. }
            | Self::KeyAuthorizationExpired { .. }
            | Self::InvalidFeePayerSignature
            | Self::NoCalls
            | Self::CreateCallWithAuthorizationList
            | Self::CreateCallNotFirst
            | Self::FeeCapBelowMinBaseFee { .. } => true,
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

    fn consensus_ref(&self) -> Recovered<&Self::Consensus> {
        Recovered::new_unchecked(&*self.inner.transaction, self.inner.transaction.signer())
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TxBuilder;
    use alloy_consensus::TxEip1559;
    use alloy_primitives::{Address, Signature, TxKind, address};
    use tempo_precompiles::nonce::NonceManager;
    use tempo_primitives::transaction::{
        TempoTransaction,
        tempo_transaction::Call,
        tt_signature::{PrimitiveSignature, TempoSignature},
        tt_signed::AASigned,
    };

    #[test]
    fn test_payment_classification_positive() {
        // Test that TIP20 address prefix is correctly classified as payment
        let payment_addr = address!("20c0000000000000000000000000000000000001");
        let tx = TxEip1559 {
            to: TxKind::Call(payment_addr),
            gas_limit: 21000,
            ..Default::default()
        };

        let envelope = TempoTxEnvelope::Eip1559(alloy_consensus::Signed::new_unchecked(
            tx,
            Signature::test_signature(),
            B256::ZERO,
        ));

        let recovered = Recovered::new_unchecked(
            envelope,
            address!("0000000000000000000000000000000000000001"),
        );

        let pooled_tx = TempoPooledTransaction::new(recovered);
        assert!(pooled_tx.is_payment());
    }

    #[test]
    fn test_payment_classification_negative() {
        // Test that non-TIP20 address is NOT classified as payment
        let non_payment_addr = Address::random();
        let pooled_tx = TxBuilder::eip1559(non_payment_addr)
            .gas_limit(21000)
            .build_eip1559();
        assert!(!pooled_tx.is_payment());
    }

    #[test]
    fn test_fee_token_cost() {
        let sender = Address::random();
        let value = U256::from(1000);
        let tx = TxBuilder::aa(sender)
            .gas_limit(1_000_000)
            .value(value)
            .build();

        // fee_token_cost = cost - value = gas spending
        // gas spending = calc_gas_balance_spending(1_000_000, 20_000_000_000)
        //              = (1_000_000 * 20_000_000_000) / 1_000_000_000_000 = 20000
        let expected_fee_cost = U256::from(20000);
        assert_eq!(tx.fee_token_cost(), expected_fee_cost);
        assert_eq!(tx.inner.cost, expected_fee_cost + value);
    }

    #[test]
    fn test_non_aa_transaction_helpers() {
        let tx = TxBuilder::eip1559(Address::random())
            .gas_limit(21000)
            .build_eip1559();

        // Non-AA transactions should return None/false for AA-specific helpers
        assert!(!tx.is_aa(), "Non-AA tx should not be AA");
        assert!(
            tx.nonce_key().is_none(),
            "Non-AA tx should have no nonce key"
        );
        assert!(
            tx.nonce_key_slot().is_none(),
            "Non-AA tx should have no nonce key slot"
        );
        assert!(!tx.is_aa_2d(), "Non-AA tx should not be AA 2D");
        assert!(
            tx.aa_transaction_id().is_none(),
            "Non-AA tx should have no AA transaction ID"
        );
    }

    #[test]
    fn test_aa_transaction_with_zero_nonce_key() {
        let sender = Address::random();
        let nonce = 5u64;
        let tx = TxBuilder::aa(sender).nonce(nonce).build();

        assert!(tx.is_aa(), "AA tx should be AA");
        assert_eq!(
            tx.nonce_key(),
            Some(U256::ZERO),
            "Should have nonce_key = 0"
        );
        assert!(!tx.is_aa_2d(), "AA tx with nonce_key=0 should NOT be 2D");

        // Check aa_transaction_id
        let aa_id = tx
            .aa_transaction_id()
            .expect("Should have AA transaction ID");
        assert_eq!(aa_id.seq_id.address, sender);
        assert_eq!(aa_id.seq_id.nonce_key, U256::ZERO);
        assert_eq!(aa_id.nonce, nonce);
    }

    #[test]
    fn test_aa_transaction_with_nonzero_nonce_key() {
        let sender = Address::random();
        let nonce_key = U256::from(42);
        let nonce = 10u64;
        let tx = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .nonce(nonce)
            .build();

        assert!(tx.is_aa(), "AA tx should be AA");
        assert_eq!(
            tx.nonce_key(),
            Some(nonce_key),
            "Should have correct nonce_key"
        );
        assert!(tx.is_aa_2d(), "AA tx with nonce_key > 0 should be 2D");

        // Check aa_transaction_id
        let aa_id = tx
            .aa_transaction_id()
            .expect("Should have AA transaction ID");
        assert_eq!(aa_id.seq_id.address, sender);
        assert_eq!(aa_id.seq_id.nonce_key, nonce_key);
        assert_eq!(aa_id.nonce, nonce);
    }

    #[test]
    fn test_nonce_key_slot_caching_for_2d_tx() {
        let sender = Address::random();
        let nonce_key = U256::from(123);
        let tx = TxBuilder::aa(sender).nonce_key(nonce_key).build();

        // Compute expected slot
        let expected_slot = NonceManager::new().nonces[sender][nonce_key].slot();

        // First call should compute and cache
        let slot1 = tx.nonce_key_slot();
        assert_eq!(slot1, Some(expected_slot));

        // Second call should return cached value (same result)
        let slot2 = tx.nonce_key_slot();
        assert_eq!(slot2, Some(expected_slot));
        assert_eq!(slot1, slot2);
    }

    #[test]
    fn test_is_bad_transaction() {
        let cases: &[(TempoPoolTransactionError, bool)] = &[
            (TempoPoolTransactionError::ExceedsNonPaymentLimit, false),
            (
                TempoPoolTransactionError::InvalidFeeToken(Address::ZERO),
                false,
            ),
            (TempoPoolTransactionError::MissingFeeToken, false),
            (
                TempoPoolTransactionError::InvalidValidBefore {
                    valid_before: 100,
                    min_allowed: 200,
                },
                false,
            ),
            (
                TempoPoolTransactionError::InvalidValidAfter {
                    valid_after: 200,
                    max_allowed: 100,
                },
                false,
            ),
            (TempoPoolTransactionError::Keychain("test error"), false),
            (
                TempoPoolTransactionError::InsufficientLiquidity(Address::ZERO),
                false,
            ),
            (
                TempoPoolTransactionError::BlackListedFeePayer {
                    fee_token: Address::ZERO,
                    fee_payer: Address::ZERO,
                },
                false,
            ),
            (TempoPoolTransactionError::InvalidFeePayerSignature, true),
            (TempoPoolTransactionError::NonZeroValue, true),
            (TempoPoolTransactionError::SubblockNonceKey, true),
            (
                TempoPoolTransactionError::InsufficientGasForAAIntrinsicCost {
                    gas_limit: 21000,
                    intrinsic_gas: 50000,
                },
                true,
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(
                err.is_bad_transaction(),
                *expected,
                "Unexpected is_bad_transaction() for: {err}"
            );
        }
    }

    #[test]
    fn test_requires_nonce_check() {
        let cases: &[(TempoPooledTransaction, bool, &str)] = &[
            (
                TxBuilder::eip1559(Address::random())
                    .gas_limit(21000)
                    .build_eip1559(),
                true,
                "Non-AA should require nonce check",
            ),
            (
                TxBuilder::aa(Address::random()).build(),
                true,
                "AA with nonce_key=0 should require nonce check",
            ),
            (
                TxBuilder::aa(Address::random())
                    .nonce_key(U256::from(1))
                    .build(),
                false,
                "AA with nonce_key > 0 should NOT require nonce check",
            ),
        ];

        for (tx, expected, msg) in cases {
            assert_eq!(tx.requires_nonce_check(), *expected, "{msg}");
        }
    }

    #[test]
    fn test_validate_blob_returns_not_blob_transaction() {
        use alloy_eips::eip7594::BlobTransactionSidecarVariant;

        let tx = TxBuilder::eip1559(Address::random())
            .gas_limit(21000)
            .build_eip1559();

        // Create a minimal sidecar (empty blobs)
        let sidecar = BlobTransactionSidecarVariant::Eip4844(Default::default());
        // Use a static reference to avoid needing KzgSettings::default()
        let settings = alloy_eips::eip4844::env_settings::EnvKzgSettings::Default.get();

        let result = tx.validate_blob(&sidecar, settings);

        assert!(matches!(
            result,
            Err(BlobTransactionValidationError::NotBlobTransaction(ty)) if ty == tx.ty()
        ));
    }

    #[test]
    fn test_take_blob_returns_none() {
        let mut tx = TxBuilder::eip1559(Address::random())
            .gas_limit(21000)
            .build_eip1559();
        let blob = tx.take_blob();
        assert!(matches!(blob, EthBlobTransactionSidecar::None));
    }

    #[test]
    fn test_pool_transaction_hash_and_sender() {
        let sender = Address::random();
        let tx = TxBuilder::aa(sender).build();

        assert!(!tx.hash().is_zero(), "Hash should not be zero");
        assert_eq!(tx.sender(), sender);
        assert_eq!(tx.sender_ref(), &sender);
    }

    #[test]
    fn test_pool_transaction_clone_into_consensus() {
        let sender = Address::random();
        let tx = TxBuilder::aa(sender).build();
        let hash = *tx.hash();

        let cloned = tx.clone_into_consensus();
        assert_eq!(cloned.tx_hash(), &hash);
        assert_eq!(cloned.signer(), sender);
    }

    #[test]
    fn test_pool_transaction_into_consensus() {
        let sender = Address::random();
        let tx = TxBuilder::aa(sender).build();
        let hash = *tx.hash();

        let consensus = tx.into_consensus();
        assert_eq!(consensus.tx_hash(), &hash);
        assert_eq!(consensus.signer(), sender);
    }

    #[test]
    fn test_pool_transaction_from_pooled() {
        let sender = Address::random();
        let nonce = 42u64;
        let aa_tx = TempoTransaction {
            chain_id: 1,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 1_000_000,
            calls: vec![Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: Default::default(),
            }],
            nonce_key: U256::ZERO,
            nonce,
            ..Default::default()
        };

        let signature =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let aa_signed = AASigned::new_unhashed(aa_tx, signature);
        let envelope: TempoTxEnvelope = aa_signed.into();
        let recovered = Recovered::new_unchecked(envelope, sender);

        let pooled = TempoPooledTransaction::from_pooled(recovered);
        assert_eq!(pooled.sender(), sender);
        assert_eq!(pooled.nonce(), nonce);
    }

    #[test]
    fn test_transaction_trait_forwarding() {
        let sender = Address::random();
        let tx = TxBuilder::aa(sender)
            .gas_limit(1_000_000)
            .value(U256::from(500))
            .build();

        // Test various Transaction trait methods
        assert_eq!(tx.chain_id(), Some(1));
        assert_eq!(tx.nonce(), 0);
        assert_eq!(tx.gas_limit(), 1_000_000);
        assert_eq!(tx.max_fee_per_gas(), 20_000_000_000);
        assert_eq!(tx.max_priority_fee_per_gas(), Some(1_000_000_000));
        assert!(tx.is_dynamic_fee());
        assert!(!tx.is_create());
    }

    #[test]
    fn test_cost_returns_zero() {
        let tx = TxBuilder::aa(Address::random())
            .gas_limit(1_000_000)
            .value(U256::from(1000))
            .build();

        // PoolTransaction::cost() returns &U256::ZERO for Tempo
        assert_eq!(*tx.cost(), U256::ZERO);
    }
}

// ========================================
// Keychain invalidation types
// ========================================

/// Index of revoked keychain keys, keyed by account for efficient lookup.
///
/// Uses account as the primary key with a list of revoked key_ids,
/// avoiding the need to construct full keys during lookup.
#[derive(Debug, Clone, Default)]
pub struct RevokedKeys {
    /// Map from account to list of revoked key_ids.
    by_account: AddressMap<Vec<Address>>,
}

impl RevokedKeys {
    /// Creates a new empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a revoked key.
    pub fn insert(&mut self, account: Address, key_id: Address) {
        self.by_account.entry(account).or_default().push(key_id);
    }

    /// Returns true if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.by_account.is_empty()
    }

    /// Returns the total number of revoked keys.
    pub fn len(&self) -> usize {
        self.by_account.values().map(Vec::len).sum()
    }

    /// Returns true if the given (account, key_id) combination is in the index.
    pub fn contains(&self, account: Address, key_id: Address) -> bool {
        self.by_account
            .get(&account)
            .is_some_and(|key_ids| key_ids.contains(&key_id))
    }
}

/// Index of spending limit updates, keyed by account for efficient lookup.
///
/// Uses account as the primary key with a list of (key_id, token) pairs,
/// avoiding the need to construct full keys during lookup.
#[derive(Debug, Clone, Default)]
pub struct SpendingLimitUpdates {
    /// Map from account to list of (key_id, token) pairs that had limit changes.
    by_account: AddressMap<Vec<(Address, Address)>>,
}

impl SpendingLimitUpdates {
    /// Creates a new empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a spending limit update.
    pub fn insert(&mut self, account: Address, key_id: Address, token: Address) {
        self.by_account
            .entry(account)
            .or_default()
            .push((key_id, token));
    }

    /// Returns true if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.by_account.is_empty()
    }

    /// Returns the total number of spending limit updates.
    pub fn len(&self) -> usize {
        self.by_account.values().map(Vec::len).sum()
    }

    /// Returns true if the given (account, key_id, token) combination is in the index.
    pub fn contains(&self, account: Address, key_id: Address, token: Address) -> bool {
        self.by_account
            .get(&account)
            .is_some_and(|pairs: &Vec<(Address, Address)>| {
                pairs.iter().any(|&(k, t)| k == key_id && t == token)
            })
    }
}

/// Keychain identity extracted from a transaction.
///
/// Contains the account (user_address), key_id, and fee_token for matching against
/// revocation and spending limit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeychainSubject {
    /// The account that owns the keychain key (from `user_address` in the signature).
    pub account: Address,
    /// The key ID recovered from the keychain signature.
    pub key_id: Address,
    /// The fee token used by this transaction.
    pub fee_token: Address,
}

impl KeychainSubject {
    /// Returns true if this subject matches any of the revoked keys.
    ///
    /// Uses account-keyed index for O(1) account lookup, then linear scan over
    /// the typically small list of key_ids for that account.
    pub fn matches_revoked(&self, revoked_keys: &RevokedKeys) -> bool {
        revoked_keys.contains(self.account, self.key_id)
    }

    /// Returns true if this subject is affected by any of the spending limit updates.
    ///
    /// Uses account-keyed index for O(1) account lookup, then linear scan over
    /// the typically small list of (key_id, token) pairs for that account.
    pub fn matches_spending_limit_update(
        &self,
        spending_limit_updates: &SpendingLimitUpdates,
    ) -> bool {
        spending_limit_updates.contains(self.account, self.key_id, self.fee_token)
    }
}
