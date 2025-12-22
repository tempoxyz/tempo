use crate::TempoInvalidTransaction;
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, Typed2718, crypto::secp256k1};
use alloy_evm::{FromRecoveredTx, FromTxWithEncoded, IntoTxEnv};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use reth_evm::TransactionEnv;
use revm::context::{
    Transaction, TxEnv,
    either::Either,
    result::InvalidTransaction,
    transaction::{
        AccessList, AccessListItem, RecoveredAuthority, RecoveredAuthorization, SignedAuthorization,
    },
};
use tempo_primitives::{
    AASigned, TempoSignature, TempoTransaction, TempoTxEnvelope, TxFeeToken,
    transaction::{
        Call, RecoveredTempoAuthorization, SignedKeyAuthorization, calc_gas_balance_spending,
    },
};

/// Tempo transaction environment for AA features.
#[derive(Debug, Clone, Default)]
pub struct TempoBatchCallEnv {
    /// Signature bytes for Tempo transactions
    pub signature: TempoSignature,

    /// validBefore timestamp
    pub valid_before: Option<u64>,

    /// validAfter timestamp
    pub valid_after: Option<u64>,

    /// Multiple calls for Tempo transactions
    pub aa_calls: Vec<Call>,

    /// Authorization list (EIP-7702 with Tempo signatures)
    ///
    /// Each authorization lazily recovers the authority on first access and caches the result.
    /// The signature is preserved for gas calculation.
    pub tempo_authorization_list: Vec<RecoveredTempoAuthorization>,

    /// Nonce key for 2D nonce system
    pub nonce_key: U256,

    /// Whether the transaction is a subblock transaction.
    pub subblock_transaction: bool,

    /// Optional key authorization for provisioning access keys
    pub key_authorization: Option<SignedKeyAuthorization>,

    /// Transaction signature hash (for signature verification)
    pub signature_hash: B256,

    /// Optional access key ID override for gas estimation.
    /// When provided in eth_call/eth_estimateGas, enables spending limits simulation
    /// This is not used in actual transaction execution - the key_id is recovered from the signature.
    pub override_key_id: Option<Address>,
}
/// Tempo transaction environment.
#[derive(Debug, Clone, Default, derive_more::Deref, derive_more::DerefMut)]
pub struct TempoTxEnv {
    /// Inner Ethereum [`TxEnv`].
    #[deref]
    #[deref_mut]
    pub inner: TxEnv,

    /// Optional fee token preference specified for the transaction.
    pub fee_token: Option<Address>,

    /// Whether the transaction is a system transaction.
    pub is_system_tx: bool,

    /// Optional fee payer specified for the transaction.
    ///
    /// - Some(Some(address)) corresponds to a successfully recovered fee payer
    /// - Some(None) corresponds to a failed recovery and means that transaction is invalid
    /// - None corresponds to a transaction without a fee payer
    pub fee_payer: Option<Option<Address>>,

    /// AA-specific transaction environment (boxed to keep TempoTxEnv lean for non-AA tx)
    pub tempo_tx_env: Option<Box<TempoBatchCallEnv>>,
}

impl TempoTxEnv {
    /// Resolves fee payer from the signature.
    pub fn fee_payer(&self) -> Result<Address, TempoInvalidTransaction> {
        if let Some(fee_payer) = self.fee_payer {
            fee_payer.ok_or(TempoInvalidTransaction::InvalidFeePayerSignature)
        } else {
            Ok(self.caller())
        }
    }

    /// Returns true if the transaction is a subblock transaction.
    pub fn is_subblock_transaction(&self) -> bool {
        self.tempo_tx_env
            .as_ref()
            .is_some_and(|aa| aa.subblock_transaction)
    }

    /// Returns the first top-level call in the transaction.
    pub fn first_call(&self) -> Option<(&TxKind, &[u8])> {
        if let Some(aa) = self.tempo_tx_env.as_ref() {
            aa.aa_calls
                .first()
                .map(|call| (&call.to, call.input.as_ref()))
        } else {
            Some((&self.inner.kind, &self.inner.data))
        }
    }

    /// Invokes the given closure for each top-level call in the transaction and
    /// returns true if all calls returned true.
    pub fn calls(&self) -> impl Iterator<Item = (&TxKind, &[u8])> {
        if let Some(aa) = self.tempo_tx_env.as_ref() {
            Either::Left(
                aa.aa_calls
                    .iter()
                    .map(|call| (&call.to, call.input.as_ref())),
            )
        } else {
            Either::Right(core::iter::once((
                &self.inner.kind,
                self.inner.input().as_ref(),
            )))
        }
    }
}

impl From<TxEnv> for TempoTxEnv {
    fn from(inner: TxEnv) -> Self {
        Self {
            inner,
            ..Default::default()
        }
    }
}

impl Transaction for TempoTxEnv {
    type AccessListItem<'a> = &'a AccessListItem;
    type Authorization<'a> = &'a Either<SignedAuthorization, RecoveredAuthorization>;

    fn tx_type(&self) -> u8 {
        self.inner.tx_type()
    }

    fn kind(&self) -> TxKind {
        self.inner.kind()
    }

    fn caller(&self) -> Address {
        self.inner.caller()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_price(&self) -> u128 {
        self.inner.gas_price()
    }

    fn value(&self) -> U256 {
        self.inner.value()
    }

    fn nonce(&self) -> u64 {
        Transaction::nonce(&self.inner)
    }

    fn chain_id(&self) -> Option<u64> {
        self.inner.chain_id()
    }

    fn access_list(&self) -> Option<impl Iterator<Item = Self::AccessListItem<'_>>> {
        self.inner.access_list()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.inner.max_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> u128 {
        self.inner.max_fee_per_blob_gas()
    }

    fn authorization_list_len(&self) -> usize {
        self.inner.authorization_list_len()
    }

    fn authorization_list(&self) -> impl Iterator<Item = Self::Authorization<'_>> {
        self.inner.authorization_list()
    }

    fn input(&self) -> &Bytes {
        self.inner.input()
    }

    fn blob_versioned_hashes(&self) -> &[B256] {
        self.inner.blob_versioned_hashes()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.max_priority_fee_per_gas()
    }

    fn max_balance_spending(&self) -> Result<U256, InvalidTransaction> {
        calc_gas_balance_spending(self.gas_limit(), self.max_fee_per_gas())
            .checked_add(self.value())
            .ok_or(InvalidTransaction::OverflowPaymentInTransaction)
    }

    fn effective_balance_spending(
        &self,
        base_fee: u128,
        _blob_price: u128,
    ) -> Result<U256, InvalidTransaction> {
        calc_gas_balance_spending(self.gas_limit(), self.effective_gas_price(base_fee))
            .checked_add(self.value())
            .ok_or(InvalidTransaction::OverflowPaymentInTransaction)
    }
}

impl TransactionEnv for TempoTxEnv {
    fn set_gas_limit(&mut self, gas_limit: u64) {
        self.inner.set_gas_limit(gas_limit);
    }

    fn nonce(&self) -> u64 {
        Transaction::nonce(&self.inner)
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.inner.set_nonce(nonce);
    }

    fn set_access_list(&mut self, access_list: AccessList) {
        self.inner.set_access_list(access_list);
    }
}

impl IntoTxEnv<Self> for TempoTxEnv {
    fn into_tx_env(self) -> Self {
        self
    }
}

impl FromRecoveredTx<EthereumTxEnvelope<TxEip4844>> for TempoTxEnv {
    fn from_recovered_tx(tx: &EthereumTxEnvelope<TxEip4844>, sender: Address) -> Self {
        TxEnv::from_recovered_tx(tx, sender).into()
    }
}

impl FromRecoveredTx<TxFeeToken> for TempoTxEnv {
    fn from_recovered_tx(tx: &TxFeeToken, caller: Address) -> Self {
        let TxFeeToken {
            chain_id,
            nonce,
            gas_limit,
            to,
            value,
            input,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            access_list,
            authorization_list,
            fee_token,
            fee_payer_signature,
        } = tx;
        Self {
            inner: TxEnv {
                tx_type: tx.ty(),
                caller,
                gas_limit: *gas_limit,
                gas_price: *max_fee_per_gas,
                kind: *to,
                value: *value,
                data: input.clone(),
                nonce: *nonce,
                chain_id: Some(*chain_id),
                gas_priority_fee: Some(*max_priority_fee_per_gas),
                access_list: access_list.clone(),
                authorization_list: authorization_list
                    .iter()
                    .map(|auth| {
                        Either::Right(RecoveredAuthorization::new_unchecked(
                            auth.inner().clone(),
                            auth.signature()
                                .ok()
                                .and_then(|signature| {
                                    secp256k1::recover_signer(&signature, auth.signature_hash())
                                        .ok()
                                })
                                .map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid),
                        ))
                    })
                    .collect(),
                ..Default::default()
            },
            fee_token: *fee_token,
            is_system_tx: false,
            fee_payer: fee_payer_signature.map(|sig| {
                secp256k1::recover_signer(&sig, tx.fee_payer_signature_hash(caller)).ok()
            }),
            tempo_tx_env: None, // Non-AA transaction
        }
    }
}

impl FromRecoveredTx<AASigned> for TempoTxEnv {
    fn from_recovered_tx(aa_signed: &AASigned, caller: Address) -> Self {
        let tx = aa_signed.tx();
        let signature = aa_signed.signature();

        // Populate the key_id cache for Keychain signatures before cloning
        // This parallelizes recovery during Tx->TxEnv conversion, and the cache is preserved when cloned
        if let Some(keychain_sig) = signature.as_keychain() {
            let _ = keychain_sig.key_id(&aa_signed.signature_hash());
        }

        let TempoTransaction {
            chain_id,
            fee_token,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            calls,
            access_list,
            nonce_key,
            nonce,
            fee_payer_signature,
            valid_before,
            valid_after,
            key_authorization,
            tempo_authorization_list,
        } = tx;

        // Extract to/value/input from calls (use first call or defaults)
        let (to, value, input) = if let Some(first_call) = calls.first() {
            (first_call.to, first_call.value, first_call.input.clone())
        } else {
            (
                alloy_primitives::TxKind::Create,
                alloy_primitives::U256::ZERO,
                alloy_primitives::Bytes::new(),
            )
        };

        Self {
            inner: TxEnv {
                tx_type: tx.ty(),
                caller,
                gas_limit: *gas_limit,
                gas_price: *max_fee_per_gas,
                kind: to,
                value,
                data: input,
                nonce: *nonce, // AA: nonce maps to TxEnv.nonce
                chain_id: Some(*chain_id),
                gas_priority_fee: Some(*max_priority_fee_per_gas),
                access_list: access_list.clone(),
                // Convert Tempo authorization list to RecoveredAuthorization upfront
                authorization_list: tempo_authorization_list
                    .iter()
                    .map(|auth| {
                        let authority = auth
                            .recover_authority()
                            .map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid);
                        Either::Right(RecoveredAuthorization::new_unchecked(
                            auth.inner().clone(),
                            authority,
                        ))
                    })
                    .collect(),
                ..Default::default()
            },
            fee_token: *fee_token,
            is_system_tx: false,
            fee_payer: fee_payer_signature.map(|sig| {
                secp256k1::recover_signer(&sig, tx.fee_payer_signature_hash(caller)).ok()
            }),
            // Bundle AA-specific fields into TempoBatchCallEnv
            tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                signature: signature.clone(),
                valid_before: *valid_before,
                valid_after: *valid_after,
                aa_calls: calls.clone(),
                // Recover authorizations upfront to avoid recovery during execution
                tempo_authorization_list: tempo_authorization_list
                    .iter()
                    .map(|auth| RecoveredTempoAuthorization::recover(auth.clone()))
                    .collect(),
                nonce_key: *nonce_key,
                subblock_transaction: aa_signed.tx().subblock_proposer().is_some(),
                key_authorization: key_authorization.clone(),
                signature_hash: aa_signed.signature_hash(),
                // override_key_id is only used for gas estimation, not actual execution
                override_key_id: None,
            })),
        }
    }
}

impl FromRecoveredTx<TempoTxEnvelope> for TempoTxEnv {
    fn from_recovered_tx(tx: &TempoTxEnvelope, sender: Address) -> Self {
        match tx {
            tx @ TempoTxEnvelope::Legacy(inner) => Self {
                inner: TxEnv::from_recovered_tx(inner.tx(), sender),
                fee_token: None,
                is_system_tx: tx.is_system_tx(),
                fee_payer: None,
                tempo_tx_env: None, // Non-AA transaction
            },
            TempoTxEnvelope::Eip2930(tx) => TxEnv::from_recovered_tx(tx.tx(), sender).into(),
            TempoTxEnvelope::Eip1559(tx) => TxEnv::from_recovered_tx(tx.tx(), sender).into(),
            TempoTxEnvelope::Eip7702(tx) => TxEnv::from_recovered_tx(tx.tx(), sender).into(),
            TempoTxEnvelope::AA(tx) => Self::from_recovered_tx(tx, sender),
            TempoTxEnvelope::FeeToken(tx) => Self::from_recovered_tx(tx.tx(), sender),
        }
    }
}

impl FromTxWithEncoded<EthereumTxEnvelope<TxEip4844>> for TempoTxEnv {
    fn from_encoded_tx(
        tx: &EthereumTxEnvelope<TxEip4844>,
        sender: Address,
        _encoded: Bytes,
    ) -> Self {
        Self::from_recovered_tx(tx, sender)
    }
}

impl FromTxWithEncoded<TxFeeToken> for TempoTxEnv {
    fn from_encoded_tx(tx: &TxFeeToken, sender: Address, _encoded: Bytes) -> Self {
        Self::from_recovered_tx(tx, sender)
    }
}

impl FromTxWithEncoded<AASigned> for TempoTxEnv {
    fn from_encoded_tx(tx: &AASigned, sender: Address, _encoded: Bytes) -> Self {
        Self::from_recovered_tx(tx, sender)
    }
}

impl FromTxWithEncoded<TempoTxEnvelope> for TempoTxEnv {
    fn from_encoded_tx(tx: &TempoTxEnvelope, sender: Address, _encoded: Bytes) -> Self {
        Self::from_recovered_tx(tx, sender)
    }
}
