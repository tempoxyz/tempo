use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxEip7702, TxLegacy, error::ValueError};
use alloy_contract::{CallBuilder, CallDecoder};
use alloy_eips::Typed2718;
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{TransactionRequest, TransactionTrait};
use serde::{Deserialize, Serialize};
use tempo_primitives::{
    AASigned, SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{Call, SignedKeyAuthorization, TempoSignedAuthorization, TempoTypedTransaction},
};

use crate::TempoNetwork;

/// An Ethereum [`TransactionRequest`] with an optional `fee_token`.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    derive_more::Deref,
    derive_more::DerefMut,
)]
#[serde(rename_all = "camelCase")]
pub struct TempoTransactionRequest {
    /// Inner [`TransactionRequest`]
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    pub inner: TransactionRequest,

    /// Optional fee token preference
    pub fee_token: Option<Address>,

    /// Optional nonce key for a 2D [`TempoTransaction`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_key: Option<U256>,

    /// Optional calls array, for Tempo transactions.
    #[serde(default)]
    pub calls: Vec<Call>,

    /// Optional key type for gas estimation of Tempo transactions.
    /// Specifies the signature verification algorithm to calculate accurate gas costs.
    pub key_type: Option<SignatureType>,

    /// Optional key-specific data for gas estimation (e.g., webauthn authenticator data).
    /// Required when key_type is WebAuthn to calculate calldata gas costs.
    pub key_data: Option<Bytes>,

    /// Optional access key ID for gas estimation.
    /// When provided, indicates the transaction uses a Keychain (access key) signature.
    /// This enables accurate gas estimation for:
    /// - Keychain signature validation overhead (+3,000 gas)
    /// - Spending limits enforcement during execution
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Address>,

    /// Optional authorization list for Tempo transactions (supports multiple signature types)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        rename = "aaAuthorizationList"
    )]
    pub tempo_authorization_list: Vec<TempoSignedAuthorization>,

    /// Key authorization for provisioning an access key (for gas estimation).
    /// Provide a signed KeyAuthorization when the transaction provisions an access key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_authorization: Option<SignedKeyAuthorization>,

    /// Transaction valid before timestamp (for expiring nonces, TIP-1009).
    /// Transaction can only be included in a block before this timestamp.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "alloy_serde::quantity::opt"
    )]
    pub valid_before: Option<u64>,

    /// Transaction valid after timestamp (for expiring nonces, TIP-1009).
    /// Transaction can only be included in a block after this timestamp.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "alloy_serde::quantity::opt"
    )]
    pub valid_after: Option<u64>,

    /// Fee payer signature for sponsored transactions.
    /// The sponsor signs fee_payer_signature_hash(sender) to commit to paying gas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_payer_signature: Option<alloy_primitives::Signature>,
}

impl TempoTransactionRequest {
    /// Builder-pattern method for setting the fee token.
    pub fn with_fee_token(mut self, fee_token: Address) -> Self {
        self.fee_token = Some(fee_token);
        self
    }

    /// Set the 2D nonce key for the [`TempoTransaction`] transaction.
    pub fn set_nonce_key(&mut self, nonce_key: U256) {
        self.nonce_key = Some(nonce_key);
    }

    /// Builder-pattern method for setting a 2D nonce key for a [`TempoTransaction`].
    pub fn with_nonce_key(mut self, nonce_key: U256) -> Self {
        self.nonce_key = Some(nonce_key);
        self
    }

    /// Set the valid_before timestamp for expiring nonces (TIP-1009).
    pub fn set_valid_before(&mut self, valid_before: u64) {
        self.valid_before = Some(valid_before);
    }

    /// Builder-pattern method for setting valid_before timestamp.
    pub fn with_valid_before(mut self, valid_before: u64) -> Self {
        self.valid_before = Some(valid_before);
        self
    }

    /// Set the valid_after timestamp for expiring nonces (TIP-1009).
    pub fn set_valid_after(&mut self, valid_after: u64) {
        self.valid_after = Some(valid_after);
    }

    /// Builder-pattern method for setting valid_after timestamp.
    pub fn with_valid_after(mut self, valid_after: u64) -> Self {
        self.valid_after = Some(valid_after);
        self
    }

    /// Set the fee payer signature for sponsored transactions.
    pub fn set_fee_payer_signature(&mut self, signature: alloy_primitives::Signature) {
        self.fee_payer_signature = Some(signature);
    }

    /// Builder-pattern method for setting fee payer signature.
    pub fn with_fee_payer_signature(mut self, signature: alloy_primitives::Signature) -> Self {
        self.fee_payer_signature = Some(signature);
        self
    }

    /// Attempts to build a [`TempoTransaction`] with the configured fields.
    pub fn build_aa(self) -> Result<TempoTransaction, ValueError<Self>> {
        if self.calls.is_empty() && self.inner.to.is_none() {
            return Err(ValueError::new(
                self,
                "Missing 'calls' or 'to' field for Tempo transaction.",
            ));
        }

        let Some(nonce) = self.inner.nonce else {
            return Err(ValueError::new(
                self,
                "Missing 'nonce' field for Tempo transaction.",
            ));
        };
        let Some(gas_limit) = self.inner.gas else {
            return Err(ValueError::new(
                self,
                "Missing 'gas_limit' field for Tempo transaction.",
            ));
        };
        let Some(max_fee_per_gas) = self.inner.max_fee_per_gas else {
            return Err(ValueError::new(
                self,
                "Missing 'max_fee_per_gas' field for Tempo transaction.",
            ));
        };
        let Some(max_priority_fee_per_gas) = self.inner.max_priority_fee_per_gas else {
            return Err(ValueError::new(
                self,
                "Missing 'max_priority_fee_per_gas' field for Tempo transaction.",
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

        Ok(TempoTransaction {
            // TODO: use tempo mainnet chainid once assigned
            chain_id: self.inner.chain_id.unwrap_or(1),
            nonce,
            fee_payer_signature: self.fee_payer_signature,
            valid_before: self.valid_before,
            valid_after: self.valid_after,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            fee_token: self.fee_token,
            access_list: self.inner.access_list.unwrap_or_default(),
            calls,
            tempo_authorization_list: self.tempo_authorization_list,
            nonce_key: self.nonce_key.unwrap_or_default(),
            key_authorization: None,
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
            TempoTxEnvelope::AA(tx) => tx.into(),
        }
    }
}

pub trait FeeToken {
    fn fee_token(&self) -> Option<Address>;
}

impl FeeToken for TempoTransaction {
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

impl From<TempoTransaction> for TempoTransactionRequest {
    fn from(tx: TempoTransaction) -> Self {
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
            tempo_authorization_list: tx.tempo_authorization_list,
            key_type: None,
            key_data: None,
            key_id: None,
            nonce_key: Some(tx.nonce_key),
            key_authorization: tx.key_authorization,
            valid_before: tx.valid_before,
            valid_after: tx.valid_after,
            fee_payer_signature: tx.fee_payer_signature,
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
            TempoTypedTransaction::AA(tx) => tx.into(),
        }
    }
}

/// Extension trait for [`CallBuilder`]
pub trait TempoCallBuilderExt {
    /// Sets the `fee_token` field in the [`TempoTransaction`] transaction to the provided value
    fn fee_token(self, fee_token: Address) -> Self;

    /// Sets the `nonce_key` field in the [`TempoTransaction`] transaction to the provided value
    fn nonce_key(self, nonce_key: U256) -> Self;
}

impl<P: Provider<TempoNetwork>, D: CallDecoder> TempoCallBuilderExt
    for CallBuilder<P, D, TempoNetwork>
{
    fn fee_token(self, fee_token: Address) -> Self {
        self.map(|request| request.with_fee_token(fee_token))
    }

    fn nonce_key(self, nonce_key: U256) -> Self {
        self.map(|request| request.with_nonce_key(nonce_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;

    #[test]
    fn test_set_valid_before() {
        let mut request = TempoTransactionRequest::default();
        assert!(request.valid_before.is_none());

        request.set_valid_before(1234567890);
        assert_eq!(request.valid_before, Some(1234567890));
    }

    #[test]
    fn test_set_valid_after() {
        let mut request = TempoTransactionRequest::default();
        assert!(request.valid_after.is_none());

        request.set_valid_after(1234567800);
        assert_eq!(request.valid_after, Some(1234567800));
    }

    #[test]
    fn test_with_valid_before() {
        let request = TempoTransactionRequest::default().with_valid_before(1234567890);
        assert_eq!(request.valid_before, Some(1234567890));
    }

    #[test]
    fn test_with_valid_after() {
        let request = TempoTransactionRequest::default().with_valid_after(1234567800);
        assert_eq!(request.valid_after, Some(1234567800));
    }

    #[test]
    fn test_build_aa_with_validity_window() {
        let request = TempoTransactionRequest::default()
            .with_nonce_key(TEMPO_EXPIRING_NONCE_KEY)
            .with_valid_before(1234567890)
            .with_valid_after(1234567800);

        // Set required fields for build_aa
        let mut request = request;
        request.inner.nonce = Some(0);
        request.inner.gas = Some(21000);
        request.inner.max_fee_per_gas = Some(1000000000);
        request.inner.max_priority_fee_per_gas = Some(1000000);
        request.inner.to = Some(address!("0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D").into());

        let tx = request.build_aa().expect("should build transaction");
        assert_eq!(tx.valid_before, Some(1234567890));
        assert_eq!(tx.valid_after, Some(1234567800));
        assert_eq!(tx.nonce_key, TEMPO_EXPIRING_NONCE_KEY);
        assert_eq!(tx.nonce, 0);
    }

    #[test]
    fn test_from_tempo_transaction_preserves_validity_window() {
        let tx = TempoTransaction {
            chain_id: 1,
            nonce: 0,
            fee_payer_signature: None,
            valid_before: Some(1234567890),
            valid_after: Some(1234567800),
            gas_limit: 21000,
            max_fee_per_gas: 1000000000,
            max_priority_fee_per_gas: 1000000,
            fee_token: None,
            access_list: Default::default(),
            calls: vec![Call {
                to: address!("0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D").into(),
                value: Default::default(),
                input: Default::default(),
            }],
            tempo_authorization_list: vec![],
            nonce_key: TEMPO_EXPIRING_NONCE_KEY,
            key_authorization: None,
        };

        let request: TempoTransactionRequest = tx.into();
        assert_eq!(request.valid_before, Some(1234567890));
        assert_eq!(request.valid_after, Some(1234567800));
        assert_eq!(request.nonce_key, Some(TEMPO_EXPIRING_NONCE_KEY));
    }

    #[test]
    fn test_expiring_nonce_builder_chain() {
        let request = TempoTransactionRequest::default()
            .with_nonce_key(TEMPO_EXPIRING_NONCE_KEY)
            .with_valid_before(1234567890)
            .with_valid_after(1234567800)
            .with_fee_token(address!("0x20c0000000000000000000000000000000000000"));

        assert_eq!(request.nonce_key, Some(TEMPO_EXPIRING_NONCE_KEY));
        assert_eq!(request.valid_before, Some(1234567890));
        assert_eq!(request.valid_after, Some(1234567800));
        assert_eq!(
            request.fee_token,
            Some(address!("0x20c0000000000000000000000000000000000000"))
        );
    }

    #[test]
    fn test_set_fee_payer_signature() {
        use alloy_primitives::Signature;

        let mut request = TempoTransactionRequest::default();
        assert!(request.fee_payer_signature.is_none());

        let sig = Signature::test_signature();
        request.set_fee_payer_signature(sig);
        assert!(request.fee_payer_signature.is_some());
    }

    #[test]
    fn test_with_fee_payer_signature() {
        use alloy_primitives::Signature;

        let sig = Signature::test_signature();
        let request = TempoTransactionRequest::default().with_fee_payer_signature(sig);
        assert!(request.fee_payer_signature.is_some());
    }

    #[test]
    fn test_build_aa_with_fee_payer_signature() {
        use alloy_primitives::Signature;

        let sig = Signature::test_signature();
        let mut request = TempoTransactionRequest::default().with_fee_payer_signature(sig);

        request.inner.nonce = Some(0);
        request.inner.gas = Some(21000);
        request.inner.max_fee_per_gas = Some(1000000000);
        request.inner.max_priority_fee_per_gas = Some(1000000);
        request.inner.to = Some(address!("0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D").into());

        let tx = request.build_aa().expect("should build transaction");
        assert_eq!(tx.fee_payer_signature, Some(sig));
    }

    #[test]
    fn test_from_tempo_transaction_preserves_fee_payer_signature() {
        use alloy_primitives::Signature;

        let sig = Signature::test_signature();
        let tx = TempoTransaction {
            chain_id: 1,
            nonce: 0,
            fee_payer_signature: Some(sig),
            valid_before: None,
            valid_after: None,
            gas_limit: 21000,
            max_fee_per_gas: 1000000000,
            max_priority_fee_per_gas: 1000000,
            fee_token: None,
            access_list: Default::default(),
            calls: vec![Call {
                to: address!("0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D").into(),
                value: Default::default(),
                input: Default::default(),
            }],
            tempo_authorization_list: vec![],
            nonce_key: Default::default(),
            key_authorization: None,
        };

        let request: TempoTransactionRequest = tx.into();
        assert_eq!(request.fee_payer_signature, Some(sig));
    }
}
