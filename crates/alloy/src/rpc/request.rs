use alloy_consensus::{Signed, TxEip1559, TxEip2930, TxEip7702, TxLegacy, error::ValueError};
use alloy_contract::{CallBuilder, CallDecoder};
use alloy_eips::Typed2718;
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{TransactionRequest, TransactionTrait};
use core::num::NonZeroU64;
use serde::{Deserialize, Serialize};
use tempo_primitives::{
    AASigned, SignatureType, TempoTransaction, TempoTxEnvelope,
    transaction::{
        Call, SignedKeyAuthorization, TempoSignedAuthorization, TempoTypedTransaction,
        key_authorization::serde_nonzero_quantity_opt,
    },
};

use crate::TempoNetwork;

/// An Ethereum [`TransactionRequest`] extended with Tempo-specific fields.
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
    #[serde(default)]
    pub fee_token: Option<Address>,

    /// Optional nonce key for a 2D [`TempoTransaction`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_key: Option<U256>,

    /// Optional calls array, for Tempo transactions.
    #[serde(default)]
    pub calls: Vec<Call>,

    /// Optional key type for gas estimation of Tempo transactions.
    /// Specifies the signature verification algorithm to calculate accurate gas costs.
    #[serde(default)]
    pub key_type: Option<SignatureType>,

    /// Optional key-specific data for gas estimation (e.g., webauthn authenticator data).
    /// Required when key_type is WebAuthn to calculate calldata gas costs.
    #[serde(default)]
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

    /// Transaction valid before timestamp in seconds (for expiring nonces, [TIP-1009]).
    /// Transaction can only be included in a block before this timestamp.
    ///
    /// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_nonzero_quantity_opt"
    )]
    pub valid_before: Option<NonZeroU64>,

    /// Transaction valid after timestamp in seconds (for expiring nonces, [TIP-1009]).
    /// Transaction can only be included in a block after this timestamp.
    ///
    /// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_nonzero_quantity_opt"
    )]
    pub valid_after: Option<NonZeroU64>,

    /// Fee payer signature for sponsored transactions.
    /// The sponsor signs fee_payer_signature_hash(sender) to commit to paying gas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_payer_signature: Option<alloy_primitives::Signature>,
}

impl TempoTransactionRequest {
    /// Set the fee token for the [`TempoTransaction`] transaction.
    pub fn set_fee_token(&mut self, fee_token: Address) {
        self.fee_token = Some(fee_token);
    }

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

    /// Replace the Tempo call list for this transaction.
    pub fn set_calls(&mut self, calls: Vec<Call>) {
        self.calls = calls;
    }

    /// Builder-pattern method for replacing the Tempo call list.
    pub fn with_calls(mut self, calls: Vec<Call>) -> Self {
        self.calls = calls;
        self
    }

    /// Append one call to the Tempo call list.
    pub fn push_call(&mut self, call: Call) {
        self.calls.push(call);
    }

    /// Set the access-key signature type used for gas estimation.
    pub fn set_key_type(&mut self, key_type: SignatureType) {
        self.key_type = Some(key_type);
    }

    /// Builder-pattern method for setting the access-key signature type.
    pub fn with_key_type(mut self, key_type: SignatureType) -> Self {
        self.key_type = Some(key_type);
        self
    }

    /// Set key-specific signature data used for gas estimation.
    pub fn set_key_data(&mut self, key_data: impl Into<Bytes>) {
        self.key_data = Some(key_data.into());
    }

    /// Builder-pattern method for setting key-specific signature data.
    pub fn with_key_data(mut self, key_data: impl Into<Bytes>) -> Self {
        self.key_data = Some(key_data.into());
        self
    }

    /// Set the access-key ID used for gas estimation.
    pub fn set_key_id(&mut self, key_id: Address) {
        self.key_id = Some(key_id);
    }

    /// Builder-pattern method for setting the access-key ID.
    pub fn with_key_id(mut self, key_id: Address) -> Self {
        self.key_id = Some(key_id);
        self
    }

    /// Set the key authorization attached to this transaction.
    pub fn set_key_authorization(&mut self, key_authorization: SignedKeyAuthorization) {
        self.key_authorization = Some(key_authorization);
    }

    /// Builder-pattern method for setting the key authorization.
    pub fn with_key_authorization(mut self, key_authorization: SignedKeyAuthorization) -> Self {
        self.key_authorization = Some(key_authorization);
        self
    }

    /// Set the valid_before timestamp for expiring nonces ([TIP-1009]).
    ///
    /// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
    pub fn set_valid_before(&mut self, valid_before: NonZeroU64) {
        self.valid_before = Some(valid_before);
    }

    /// Builder-pattern method for setting valid_before timestamp.
    pub fn with_valid_before(mut self, valid_before: NonZeroU64) -> Self {
        self.valid_before = Some(valid_before);
        self
    }

    /// Set the valid_after timestamp for expiring nonces ([TIP-1009]).
    ///
    /// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
    pub fn set_valid_after(&mut self, valid_after: NonZeroU64) {
        self.valid_after = Some(valid_after);
    }

    /// Builder-pattern method for setting valid_after timestamp.
    pub fn with_valid_after(mut self, valid_after: NonZeroU64) -> Self {
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
            chain_id: self.inner.chain_id.unwrap_or(4217),
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
            key_authorization: self.key_authorization,
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
                // AA transactions store their calls in `calls` below.
                // `to`, `value`, `input` must stay unset to avoid the builder
                // creating a duplicate call from the envelope fields.
                to: None,
                gas: Some(tx.gas_limit()),
                gas_price: tx.gas_price(),
                max_fee_per_gas: Some(tx.max_fee_per_gas()),
                max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
                value: None,
                input: alloy_rpc_types_eth::TransactionInput::default(),
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

    /// Sets the `valid_before` field in the [`TempoTransaction`] transaction.
    fn valid_before(self, valid_before: NonZeroU64) -> Self;

    /// Sets the `valid_after` field in the [`TempoTransaction`] transaction.
    fn valid_after(self, valid_after: NonZeroU64) -> Self;

    /// Sets the `key_id` field in the [`TempoTransaction`] transaction.
    fn key_id(self, key_id: Address) -> Self;

    /// Sets the `key_type` field in the [`TempoTransaction`] transaction.
    fn key_type(self, key_type: SignatureType) -> Self;

    /// Sets the `key_data` field in the [`TempoTransaction`] transaction.
    fn key_data(self, key_data: Bytes) -> Self;

    /// Sets the `key_authorization` field in the [`TempoTransaction`] transaction.
    fn key_authorization(self, key_authorization: SignedKeyAuthorization) -> Self;
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

    fn valid_before(self, valid_before: NonZeroU64) -> Self {
        self.map(|request| request.with_valid_before(valid_before))
    }

    fn valid_after(self, valid_after: NonZeroU64) -> Self {
        self.map(|request| request.with_valid_after(valid_after))
    }

    fn key_id(self, key_id: Address) -> Self {
        self.map(|request| request.with_key_id(key_id))
    }

    fn key_type(self, key_type: SignatureType) -> Self {
        self.map(|request| request.with_key_type(key_type))
    }

    fn key_data(self, key_data: Bytes) -> Self {
        self.map(|request| request.with_key_data(key_data))
    }

    fn key_authorization(self, key_authorization: SignedKeyAuthorization) -> Self {
        self.map(|request| request.with_key_authorization(key_authorization))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, Signature, address};
    use tempo_primitives::transaction::{
        Call, KeyAuthorization, PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY,
    };

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test timestamp must be non-zero")
    }

    #[test]
    fn test_set_valid_before() {
        let mut request = TempoTransactionRequest::default();
        assert!(request.valid_before.is_none());

        request.set_valid_before(nz(1234567890));
        assert_eq!(request.valid_before, Some(nz(1234567890)));
    }

    #[test]
    fn test_set_valid_after() {
        let mut request = TempoTransactionRequest::default();
        assert!(request.valid_after.is_none());

        request.set_valid_after(nz(1234567800));
        assert_eq!(request.valid_after, Some(nz(1234567800)));
    }

    #[test]
    fn test_with_valid_before() {
        let request = TempoTransactionRequest::default().with_valid_before(nz(1234567890));
        assert_eq!(request.valid_before, Some(nz(1234567890)));
    }

    #[test]
    fn test_with_valid_after() {
        let request = TempoTransactionRequest::default().with_valid_after(nz(1234567800));
        assert_eq!(request.valid_after, Some(nz(1234567800)));
    }

    #[test]
    fn test_build_aa_with_validity_window() {
        let request = TempoTransactionRequest::default()
            .with_nonce_key(TEMPO_EXPIRING_NONCE_KEY)
            .with_valid_before(nz(1234567890))
            .with_valid_after(nz(1234567800));

        // Set required fields for build_aa
        let mut request = request;
        request.inner.nonce = Some(0);
        request.inner.gas = Some(21000);
        request.inner.max_fee_per_gas = Some(1000000000);
        request.inner.max_priority_fee_per_gas = Some(1000000);
        request.inner.to = Some(address!("0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D").into());

        let tx = request.build_aa().expect("should build transaction");
        assert_eq!(tx.valid_before, Some(nz(1234567890)));
        assert_eq!(tx.valid_after, Some(nz(1234567800)));
        assert_eq!(tx.nonce_key, TEMPO_EXPIRING_NONCE_KEY);
        assert_eq!(tx.nonce, 0);
    }

    #[test]
    fn test_deserialize_rejects_zero_validity_window_bounds() {
        let err = serde_json::from_str::<TempoTransactionRequest>(r#"{"validBefore":"0x0"}"#)
            .expect_err("zero valid_before must be rejected during deserialization");
        assert!(err.to_string().contains("expected non-zero quantity"));

        let err = serde_json::from_str::<TempoTransactionRequest>(r#"{"validAfter":"0x0"}"#)
            .expect_err("zero valid_after must be rejected during deserialization");
        assert!(err.to_string().contains("expected non-zero quantity"));
    }

    #[test]
    fn test_from_tempo_transaction_preserves_validity_window() {
        let tx = TempoTransaction {
            chain_id: 1,
            nonce: 0,
            fee_payer_signature: None,
            valid_before: Some(NonZeroU64::new(1234567890).unwrap()),
            valid_after: Some(NonZeroU64::new(1234567800).unwrap()),
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
        assert_eq!(request.valid_before, Some(nz(1234567890)));
        assert_eq!(request.valid_after, Some(nz(1234567800)));
        assert_eq!(request.nonce_key, Some(TEMPO_EXPIRING_NONCE_KEY));
    }

    #[test]
    fn test_expiring_nonce_builder_chain() {
        let request = TempoTransactionRequest::default()
            .with_nonce_key(TEMPO_EXPIRING_NONCE_KEY)
            .with_valid_before(nz(1234567890))
            .with_valid_after(nz(1234567800))
            .with_fee_token(address!("0x20c0000000000000000000000000000000000000"));

        assert_eq!(request.nonce_key, Some(TEMPO_EXPIRING_NONCE_KEY));
        assert_eq!(request.valid_before, Some(nz(1234567890)));
        assert_eq!(request.valid_after, Some(nz(1234567800)));
        assert_eq!(
            request.fee_token,
            Some(address!("0x20c0000000000000000000000000000000000000"))
        );
    }

    #[test]
    fn test_set_fee_payer_signature() {
        let mut request = TempoTransactionRequest::default();
        assert!(request.fee_payer_signature.is_none());

        let sig = Signature::test_signature();
        request.set_fee_payer_signature(sig);
        assert!(request.fee_payer_signature.is_some());
    }

    #[test]
    fn test_with_fee_payer_signature() {
        let sig = Signature::test_signature();
        let request = TempoTransactionRequest::default().with_fee_payer_signature(sig);
        assert!(request.fee_payer_signature.is_some());
    }

    #[test]
    fn test_build_aa_with_fee_payer_signature() {
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

    #[test]
    fn test_build_aa_preserves_key_authorization() {
        let key_auth = KeyAuthorization::unrestricted(
            4217,
            SignatureType::Secp256k1,
            address!("0x1111111111111111111111111111111111111111"),
        )
        .into_signed(PrimitiveSignature::default());

        let mut request = TempoTransactionRequest {
            key_authorization: Some(key_auth.clone()),
            ..Default::default()
        };
        request.inner.nonce = Some(0);
        request.inner.gas = Some(21000);
        request.inner.max_fee_per_gas = Some(1000000000);
        request.inner.max_priority_fee_per_gas = Some(1000000);
        request.inner.to = Some(address!("0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D").into());

        let tx = request.build_aa().expect("should build transaction");
        assert_eq!(
            tx.key_authorization,
            Some(key_auth),
            "build_aa must preserve key_authorization from the request"
        );
    }

    #[test]
    fn test_set_calls_and_push_call() {
        let call = Call {
            to: address!("0x1111111111111111111111111111111111111111").into(),
            value: U256::ZERO,
            input: Bytes::from(vec![0xaa]),
        };

        let mut request = TempoTransactionRequest::default();
        request.set_calls(vec![call.clone()]);
        request.push_call(call.clone());

        assert_eq!(request.calls, vec![call.clone(), call]);
    }

    #[test]
    fn test_keychain_builder_helpers() {
        let key_auth = KeyAuthorization::unrestricted(
            4217,
            SignatureType::Secp256k1,
            address!("0x1111111111111111111111111111111111111111"),
        )
        .into_signed(PrimitiveSignature::default());

        let request = TempoTransactionRequest::default()
            .with_key_id(address!("0x2222222222222222222222222222222222222222"))
            .with_key_type(SignatureType::WebAuthn)
            .with_key_data(Bytes::from_static(b"auth-data"))
            .with_key_authorization(key_auth.clone());

        assert_eq!(
            request.key_id,
            Some(address!("0x2222222222222222222222222222222222222222"))
        );
        assert_eq!(request.key_type, Some(SignatureType::WebAuthn));
        assert_eq!(request.key_data, Some(Bytes::from_static(b"auth-data")));
        assert_eq!(request.key_authorization, Some(key_auth));
    }

    #[test]
    fn test_aa_roundtrip_preserves_count() {
        let base = TempoTransaction {
            chain_id: 4217,
            nonce: 1,
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            calls: vec![],
            ..Default::default()
        };

        // Regression: single-call AA round-trip must not duplicate the call + preserve.
        let call = vec![Call {
            to: address!("0x1111111111111111111111111111111111111111").into(),
            value: U256::ZERO,
            input: Bytes::from(vec![0xaa]),
        }];
        let mut original = base.clone();
        original.calls = call.clone();

        let roundtrip = TempoTransactionRequest::from(original)
            .build_aa()
            .expect("build_aa should succeed");
        assert_eq!(
            roundtrip.calls, call,
            "single-call AA must not gain extra calls on round-trip"
        );

        // Regression: multi-call AA round-trip must preserve exact call list.
        let batch = vec![
            Call {
                to: address!("0x1111111111111111111111111111111111111111").into(),
                value: U256::ZERO,
                input: Bytes::from(vec![0xaa]),
            },
            Call {
                to: address!("0x2222222222222222222222222222222222222222").into(),
                value: U256::ZERO,
                input: Bytes::from(vec![0xbb]),
            },
        ];
        let mut original = base;
        original.calls = batch.clone();

        let roundtrip = TempoTransactionRequest::from(original)
            .build_aa()
            .expect("build_aa should succeed");
        assert_eq!(
            roundtrip.calls, batch,
            "multi-call AA must not gain phantom calls on round-trip"
        );
    }
}
