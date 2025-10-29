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
    AASignature, AASigned, TempoTxEnvelope, TxAA, TxFeeToken,
    transaction::{AASignedAuthorization, Call},
};

/// Account Abstraction transaction environment.
#[derive(Debug, Clone, Default)]
pub struct AATxEnv {
    /// Signature bytes for AA transactions
    pub signature: AASignature,

    /// validBefore timestamp
    pub valid_before: Option<u64>,

    /// validAfter timestamp
    pub valid_after: Option<u64>,

    /// Multiple calls for AA transactions
    pub aa_calls: Vec<Call>,

    /// Authorization list (EIP-7702 with AA signatures)
    pub aa_authorization_list: Vec<AASignedAuthorization>,
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
    pub aa_tx_env: Option<Box<AATxEnv>>,
}

impl TempoTxEnv {
    /// Resolves fee payer from the signature.
    pub fn fee_payer(&self) -> Result<Address, InvalidTransaction> {
        if let Some(fee_payer) = self.fee_payer {
            // todo: introduce custom error type or Other variant upstream
            fee_payer.ok_or(InvalidTransaction::OverflowPaymentInTransaction)
        } else {
            Ok(self.caller())
        }
    }
}

impl From<TxEnv> for TempoTxEnv {
    fn from(inner: TxEnv) -> Self {
        Self {
            inner,
            fee_token: None,
            is_system_tx: false,
            fee_payer: None,
            aa_tx_env: None,
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
                sig.recover_address_from_prehash(&tx.fee_payer_signature_hash(caller))
                    .ok()
            }),
            aa_tx_env: None, // Non-AA transaction
        }
    }
}

impl FromRecoveredTx<AASigned> for TempoTxEnv {
    fn from_recovered_tx(aa_signed: &AASigned, caller: Address) -> Self {
        let tx = aa_signed.tx();
        let signature = aa_signed.signature();

        let TxAA {
            chain_id,
            fee_token,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            calls,
            access_list,
            // Ignored for now, will be used in the future
            nonce_key: _,
            nonce,
            fee_payer_signature,
            valid_before,
            valid_after,
            aa_authorization_list,
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
                // Convert AA authorization list to RecoveredAuthorization
                authorization_list: aa_authorization_list
                    .iter()
                    .map(|aa_auth| {
                        let authority = aa_auth
                            .recover_authority()
                            .map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid);
                        Either::Right(RecoveredAuthorization::new_unchecked(
                            aa_auth.inner().clone(),
                            authority,
                        ))
                    })
                    .collect(),
                ..Default::default()
            },
            fee_token: *fee_token,
            is_system_tx: false,
            fee_payer: fee_payer_signature.map(|sig| {
                sig.recover_address_from_prehash(&tx.fee_payer_signature_hash(caller))
                    .ok()
            }),
            // Bundle AA-specific fields into AATxEnv
            aa_tx_env: Some(Box::new(AATxEnv {
                signature: signature.clone(),
                valid_before: *valid_before,
                valid_after: *valid_after,
                aa_calls: calls.clone(),
                aa_authorization_list: aa_authorization_list.clone(),
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
                aa_tx_env: None, // Non-AA transaction
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

#[cfg(feature = "rpc")]
impl reth_rpc_convert::transaction::TryIntoTxEnv<TempoTxEnv>
    for alloy_rpc_types_eth::TransactionRequest
{
    type Err = reth_rpc_convert::transaction::EthTxEnvError;

    fn try_into_tx_env<Spec>(
        self,
        cfg_env: &revm::context::CfgEnv<Spec>,
        block_env: &revm::context::BlockEnv,
    ) -> Result<TempoTxEnv, Self::Err> {
        Ok(TempoTxEnv {
            inner: self.try_into_tx_env(cfg_env, block_env)?,
            fee_token: None,
            is_system_tx: false,
            fee_payer: None,
            aa_tx_env: None, // RPC transactions are not AA transactions
        })
    }
}
