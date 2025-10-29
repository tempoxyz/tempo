use alloy::{
    consensus::{
        EthereumTxEnvelope, Signed, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy,
        error::ValueError,
    },
    rpc::types::TransactionTrait,
};
use alloy_eips::Typed2718;
use alloy_network::TxSigner;
use alloy_primitives::{Address, Bytes, Signature};
use alloy_rpc_types_eth::TransactionRequest;
use reth_evm::revm::context::CfgEnv;
use reth_rpc_convert::{
    EthTxEnvError, SignTxRequestError, SignableTxRequest, TryIntoSimTx, transaction::TryIntoTxEnv,
};
use serde::{Deserialize, Serialize};
use tempo_evm::TempoBlockEnv;
use tempo_primitives::{
    AASignature, SignatureType, TempoTxEnvelope, TxAA, TxFeeToken,
    transaction::{AASignedAuthorization, Call, TempoTypedTransaction},
};
use tempo_revm::{AATxEnv, TempoTxEnv};

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

impl TryIntoSimTx<TempoTxEnvelope> for TempoTransactionRequest {
    fn try_into_sim_tx(self) -> Result<TempoTxEnvelope, ValueError<Self>> {
        if !self.calls.is_empty() {
            let tx = self.build_aa()?;

            // Create an empty signature for the transaction.
            let signature = AASignature::default();

            Ok(tx.into_signed(signature).into())
        } else if self.fee_token.is_some() {
            let tx = self.build_fee_token()?;

            // Create an empty signature for the transaction.
            let signature = Signature::new(Default::default(), Default::default(), false);

            Ok(tx.into_signed(signature).into())
        } else {
            let Self {
                inner,
                fee_token,
                calls,
                key_type,
                key_data,
                aa_authorization_list,
            } = self;
            let envelope =
                match TryIntoSimTx::<EthereumTxEnvelope<TxEip4844>>::try_into_sim_tx(inner.clone())
                {
                    Ok(inner) => inner,
                    Err(e) => {
                        return Err(e.map(|inner| Self {
                            inner,
                            fee_token,
                            calls,
                            key_type,
                            key_data,
                            aa_authorization_list,
                        }));
                    }
                };

            Ok(envelope
                .try_into()
                .map_err(|e: ValueError<EthereumTxEnvelope<TxEip4844>>| {
                    e.map(|_inner| Self {
                        inner,
                        fee_token,
                        calls,
                        key_type,
                        key_data,
                        aa_authorization_list,
                    })
                })?)
        }
    }
}

impl TryIntoTxEnv<TempoTxEnv, TempoBlockEnv> for TempoTransactionRequest {
    type Err = EthTxEnvError;

    fn try_into_tx_env<Spec>(
        self,
        cfg_env: &CfgEnv<Spec>,
        block_env: &TempoBlockEnv,
    ) -> Result<TempoTxEnv, Self::Err> {
        let Self {
            inner,
            fee_token,
            calls,
            key_type,
            key_data,
            aa_authorization_list,
        } = self;
        Ok(TempoTxEnv {
            inner: inner.try_into_tx_env(cfg_env, &block_env.inner)?,
            fee_token,
            is_system_tx: false,
            fee_payer: None,
            aa_tx_env: (!calls.is_empty() || !aa_authorization_list.is_empty()).then(|| {
                // Create mock signature for gas estimation
                // If key_type is not provided, default to secp256k1
                let mock_signature = key_type
                    .as_ref()
                    .map(|kt| create_mock_aa_signature(kt, key_data.as_ref()))
                    .unwrap_or_else(|| create_mock_aa_signature(&SignatureType::Secp256k1, None));

                Box::new(AATxEnv {
                    aa_calls: calls,
                    signature: mock_signature,
                    aa_authorization_list,
                    ..Default::default()
                })
            }),
        })
    }
}

/// Creates a mock AA signature for gas estimation based on key type hints
fn create_mock_aa_signature(key_type: &SignatureType, key_data: Option<&Bytes>) -> AASignature {
    use tempo_primitives::transaction::aa_signature::{
        AASignature, P256SignatureWithPreHash, WebAuthnSignature,
    };

    match key_type {
        SignatureType::Secp256k1 => {
            // Create a dummy secp256k1 signature (65 bytes)
            AASignature::Secp256k1(Signature::new(
                alloy_primitives::U256::ZERO,
                alloy_primitives::U256::ZERO,
                false,
            ))
        }
        SignatureType::P256 => {
            // Create a dummy P256 signature
            AASignature::P256(P256SignatureWithPreHash {
                r: alloy_primitives::B256::ZERO,
                s: alloy_primitives::B256::ZERO,
                pub_key_x: alloy_primitives::B256::ZERO,
                pub_key_y: alloy_primitives::B256::ZERO,
                pre_hash: false,
            })
        }
        SignatureType::WebAuthn => {
            // Create a dummy WebAuthn signature with the specified size
            // key_data contains the total size of webauthn_data (excluding 128 bytes for public keys)
            // Default: 200 bytes if no key_data provided

            // Base clientDataJSON template (50 bytes): {"type":"webauthn.get","challenge":"","origin":""}
            // Authenticator data (37 bytes): 32 rpIdHash + 1 flags + 4 signCount
            // Minimum total: 87 bytes
            const BASE_CLIENT_JSON: &str = r#"{"type":"webauthn.get","challenge":"","origin":""}"#;
            const AUTH_DATA_SIZE: usize = 37;
            const MIN_WEBAUTHN_SIZE: usize = AUTH_DATA_SIZE + BASE_CLIENT_JSON.len(); // 87 bytes
            const DEFAULT_WEBAUTHN_SIZE: usize = 800; // Default when no key_data provided

            // Parse size from key_data, or use default
            let size = if let Some(data) = key_data {
                match data.len() {
                    1 => data[0] as usize,
                    2 => u16::from_be_bytes([data[0], data[1]]) as usize,
                    4 => u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize,
                    _ => DEFAULT_WEBAUTHN_SIZE, // Fallback default
                }
            } else {
                DEFAULT_WEBAUTHN_SIZE // Default size when no key_data provided
            };

            // Ensure size is at least minimum
            let size = size.max(MIN_WEBAUTHN_SIZE);

            // Construct authenticatorData (37 bytes)
            let mut webauthn_data = vec![0u8; AUTH_DATA_SIZE];
            webauthn_data[32] = 0x01; // UP flag set

            // Construct clientDataJSON with padding in origin field if needed
            let additional_bytes = size - MIN_WEBAUTHN_SIZE;
            let client_json = if additional_bytes > 0 {
                // Add padding bytes to origin field
                // {"type":"webauthn.get","challenge":"","origin":"XXXXX"}
                let padding = "x".repeat(additional_bytes);
                format!(r#"{{"type":"webauthn.get","challenge":"","origin":"{padding}"}}"#,)
            } else {
                BASE_CLIENT_JSON.to_string()
            };

            webauthn_data.extend_from_slice(client_json.as_bytes());
            let webauthn_data = Bytes::from(webauthn_data);

            AASignature::WebAuthn(WebAuthnSignature {
                webauthn_data,
                r: alloy_primitives::B256::ZERO,
                s: alloy_primitives::B256::ZERO,
                pub_key_x: alloy_primitives::B256::ZERO,
                pub_key_y: alloy_primitives::B256::ZERO,
            })
        }
    }
}

impl SignableTxRequest<TempoTxEnvelope> for TempoTransactionRequest {
    async fn try_build_and_sign(
        self,
        signer: impl TxSigner<Signature> + Send,
    ) -> Result<TempoTxEnvelope, SignTxRequestError> {
        SignableTxRequest::<TempoTxEnvelope>::try_build_and_sign(self.inner, signer).await
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

trait FeeToken {
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

impl From<tempo_primitives::AASigned> for TempoTransactionRequest {
    fn from(tx: tempo_primitives::AASigned) -> Self {
        let (tx, _, _) = tx.into_parts();
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
