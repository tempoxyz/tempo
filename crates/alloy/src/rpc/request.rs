use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxEip7702, TxLegacy, error::ValueError};
use alloy_contract::{CallBuilder, CallDecoder};
use alloy_eips::Typed2718;
use alloy_primitives::{Address, Bytes};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{TransactionRequest, TransactionTrait};
use serde::{Deserialize, Serialize};
use tempo_primitives::{
    AASigned, SignatureType, TempoTxEnvelope, TxAA, TxFeeToken,
    transaction::{AASignedAuthorization, Call, TempoTypedTransaction},
};

use crate::TempoNetwork;

/// An Ethereum [`TransactionRequest`] with an optional `fee_token`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempoTransactionRequest {
    /// Inner [`TransactionRequest`]
    #[serde(flatten)]
    pub inner: TransactionRequest,

    /// Optional fee token preference
    pub fee_token: Option<Address>,

    /// Optional calls array, for AA transactions.
    #[serde(default)]
    pub calls: Vec<Call>,

    /// Optional key type for gas estimation of AA transactions.
    /// Specifies the signature verification algorithm to calculate accurate gas costs.
    pub key_type: Option<SignatureType>,

    /// Optional key-specific data for gas estimation (e.g., webauthn authenticator data).
    /// Required when key_type is WebAuthn to calculate calldata gas costs.
    pub key_data: Option<Bytes>,

    /// Optional AA authorization list for AA transactions (supports multiple signature types)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aa_authorization_list: Vec<AASignedAuthorization>,
}

impl TempoTransactionRequest {
    /// Builder-pattern method for setting the fee token.
    pub fn with_fee_token(mut self, fee_token: Address) -> Self {
        self.fee_token = Some(fee_token);
        self
    }

    pub fn build_fee_token(self) -> Result<TxFeeToken, ValueError<Self>> {
        let Some(to) = self.inner.to else {
            return Err(ValueError::new(
                self,
                "Missing 'to' field for FeeToken transaction.",
            ));
        };
        let Some(nonce) = self.inner.nonce else {
            return Err(ValueError::new(
                self,
                "Missing 'nonce' field for FeeToken transaction.",
            ));
        };
        let Some(gas_limit) = self.inner.gas else {
            return Err(ValueError::new(
                self,
                "Missing 'gas_limit' field for FeeToken transaction.",
            ));
        };
        let Some(max_fee_per_gas) = self.inner.max_fee_per_gas else {
            return Err(ValueError::new(
                self,
                "Missing 'max_fee_per_gas' field for FeeToken transaction.",
            ));
        };
        let Some(max_priority_fee_per_gas) = self.inner.max_priority_fee_per_gas else {
            return Err(ValueError::new(
                self,
                "Missing 'max_priority_fee_per_gas' field for FeeToken transaction.",
            ));
        };

        Ok(TxFeeToken {
            chain_id: self.inner.chain_id.unwrap_or(1),
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to,
            fee_token: self.fee_token,
            value: self.inner.value.unwrap_or_default(),
            input: self.inner.input.into_input().unwrap_or_default(),
            access_list: self.inner.access_list.unwrap_or_default(),
            authorization_list: self.inner.authorization_list.unwrap_or_default(),
            fee_payer_signature: None,
        })
    }

    pub fn build_aa(self) -> Result<TxAA, ValueError<Self>> {
        if self.calls.is_empty() && self.inner.to.is_none() {
            return Err(ValueError::new(
                self,
                "Missing 'calls' or 'to' field for AA transaction.",
            ));
        }

        let Some(nonce) = self.inner.nonce else {
            return Err(ValueError::new(
                self,
                "Missing 'nonce' field for FeeToken transaction.",
            ));
        };
        let Some(gas_limit) = self.inner.gas else {
            return Err(ValueError::new(
                self,
                "Missing 'gas_limit' field for FeeToken transaction.",
            ));
        };
        let Some(max_fee_per_gas) = self.inner.max_fee_per_gas else {
            return Err(ValueError::new(
                self,
                "Missing 'max_fee_per_gas' field for FeeToken transaction.",
            ));
        };
        let Some(max_priority_fee_per_gas) = self.inner.max_priority_fee_per_gas else {
            return Err(ValueError::new(
                self,
                "Missing 'max_priority_fee_per_gas' field for FeeToken transaction.",
            ));
        };

        let mut calls = self.calls;
        if let Some(to) = self.inner.to {
            calls.push(Call {
                to,
                value: self.inner.value.unwrap_or_default(),
                input: self.inner.input.into_input().unwrap_or_default(),
            });
        }

        Ok(TxAA {
            chain_id: self.inner.chain_id.unwrap_or(1),
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            fee_token: self.fee_token,
            access_list: self.inner.access_list.unwrap_or_default(),
            calls,
            aa_authorization_list: self.aa_authorization_list,
            ..Default::default()
        })
    }
}

impl AsRef<TransactionRequest> for TempoTransactionRequest {
    fn as_ref(&self) -> &TransactionRequest {
        &self.inner
    }
}

impl AsMut<TransactionRequest> for TempoTransactionRequest {
    fn as_mut(&mut self) -> &mut TransactionRequest {
        &mut self.inner
    }
}

impl From<TransactionRequest> for TempoTransactionRequest {
    fn from(value: TransactionRequest) -> Self {
        Self {
            inner: value,
            fee_token: None,
            ..Default::default()
        }
    }
}

impl From<TempoTransactionRequest> for TransactionRequest {
    fn from(value: TempoTransactionRequest) -> Self {
        value.inner
    }
}

impl From<TempoTxEnvelope> for TempoTransactionRequest {
    fn from(value: TempoTxEnvelope) -> Self {
        match value {
            TempoTxEnvelope::Legacy(tx) => tx.into(),
            TempoTxEnvelope::Eip2930(tx) => tx.into(),
            TempoTxEnvelope::Eip1559(tx) => tx.into(),
            TempoTxEnvelope::Eip7702(tx) => tx.into(),
            TempoTxEnvelope::FeeToken(tx) => tx.into(),
            TempoTxEnvelope::AA(tx) => tx.into(),
        }
    }
}

pub trait FeeToken {
    fn fee_token(&self) -> Option<Address>;
}

impl FeeToken for TxFeeToken {
    fn fee_token(&self) -> Option<Address> {
        self.fee_token
    }
}

impl FeeToken for TxAA {
    fn fee_token(&self) -> Option<Address> {
        self.fee_token
    }
}

impl FeeToken for TxEip7702 {
    fn fee_token(&self) -> Option<Address> {
        None
    }
}

impl FeeToken for TxEip1559 {
    fn fee_token(&self) -> Option<Address> {
        None
    }
}

impl FeeToken for TxEip2930 {
    fn fee_token(&self) -> Option<Address> {
        None
    }
}

impl FeeToken for TxLegacy {
    fn fee_token(&self) -> Option<Address> {
        None
    }
}

impl<T: TransactionTrait + FeeToken> From<Signed<T>> for TempoTransactionRequest {
    fn from(value: Signed<T>) -> Self {
        Self {
            fee_token: value.tx().fee_token(),
            inner: TransactionRequest::from_transaction(value),
            ..Default::default()
        }
    }
}

impl From<TxAA> for TempoTransactionRequest {
    fn from(tx: TxAA) -> Self {
        Self {
            fee_token: tx.fee_token,
            inner: TransactionRequest {
                from: None,
                to: Some(tx.kind()),
                gas: Some(tx.gas_limit()),
                gas_price: tx.gas_price(),
                max_fee_per_gas: Some(tx.max_fee_per_gas()),
                max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
                value: Some(tx.value()),
                input: alloy_rpc_types_eth::TransactionInput::new(tx.input().clone()),
                nonce: Some(tx.nonce()),
                chain_id: tx.chain_id(),
                access_list: tx.access_list().cloned(),
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                sidecar: None,
                authorization_list: None,
                transaction_type: Some(tx.ty()),
            },
            calls: tx.calls,
            aa_authorization_list: tx.aa_authorization_list,
            key_type: None,
            key_data: None,
        }
    }
}

impl From<AASigned> for TempoTransactionRequest {
    fn from(value: AASigned) -> Self {
        value.into_parts().0.into()
    }
}

impl From<TempoTypedTransaction> for TempoTransactionRequest {
    fn from(value: TempoTypedTransaction) -> Self {
        match value {
            TempoTypedTransaction::Legacy(tx) => Self {
                inner: tx.into(),
                fee_token: None,
                ..Default::default()
            },
            TempoTypedTransaction::Eip2930(tx) => Self {
                inner: tx.into(),
                fee_token: None,
                ..Default::default()
            },
            TempoTypedTransaction::Eip1559(tx) => Self {
                inner: tx.into(),
                fee_token: None,
                ..Default::default()
            },
            TempoTypedTransaction::Eip7702(tx) => Self {
                inner: tx.into(),
                fee_token: None,
                ..Default::default()
            },
            TempoTypedTransaction::FeeToken(tx) => Self {
                fee_token: tx.fee_token,
                inner: TransactionRequest::from_transaction(tx),
                ..Default::default()
            },
            TempoTypedTransaction::AA(tx) => tx.into(),
        }
    }
}

/// Extension trait for [`CallBuilder`]
pub trait TempoTransactionCallBuilderExt {
    /// Sets the `fee_token` field in the transaction to the provided value
    fn fee_token(self, fee_token: Address) -> Self;
}

impl<P: Provider<TempoNetwork>, D: CallDecoder> TempoTransactionCallBuilderExt
    for CallBuilder<P, D, TempoNetwork>
{
    fn fee_token(self, fee_token: Address) -> Self {
        self.map(|request| request.with_fee_token(fee_token))
    }
}
