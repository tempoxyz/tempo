use alloy_consensus::{EthereumTxEnvelope, TxEip4844, Typed2718, crypto::secp256k1};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use reth_evm::{
    FromRecoveredTx, FromTxWithEncoded, IntoTxEnv, TransactionEnv,
    revm::context::{
        Transaction, TxEnv,
        either::Either,
        transaction::{
            AccessList, AccessListItem, RecoveredAuthority, RecoveredAuthorization,
            SignedAuthorization,
        },
    },
};
use tempo_primitives::{TempoTxEnvelope, TxFeeToken};

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
}

impl From<TxEnv> for TempoTxEnv {
    fn from(inner: TxEnv) -> Self {
        Self {
            inner,
            fee_token: None,
            is_system_tx: false,
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
        let inner = TxEnv::from_recovered_tx(tx, sender);
        Self {
            inner,
            fee_token: None,
            is_system_tx: false,
        }
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
            },
            TempoTxEnvelope::Eip2930(tx) => TxEnv::from_recovered_tx(tx.tx(), sender).into(),
            TempoTxEnvelope::Eip1559(tx) => TxEnv::from_recovered_tx(tx.tx(), sender).into(),
            TempoTxEnvelope::Eip7702(tx) => TxEnv::from_recovered_tx(tx.tx(), sender).into(),
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
        cfg_env: &reth_evm::revm::context::CfgEnv<Spec>,
        block_env: &reth_evm::revm::context::BlockEnv,
    ) -> Result<TempoTxEnv, Self::Err> {
        Ok(TempoTxEnv {
            inner: self.try_into_tx_env(cfg_env, block_env)?,
            fee_token: None,
            is_system_tx: false,
        })
    }
}
