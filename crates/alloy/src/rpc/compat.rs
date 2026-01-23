use crate::rpc::{TempoHeaderResponse, TempoTransactionRequest};
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, error::ValueError};
use alloy_network::{TransactionBuilder, TxSigner};
use alloy_primitives::{Address, B256, Bytes, Signature};
use reth_evm::EvmEnv;
use reth_primitives_traits::SealedHeader;
use reth_rpc_convert::{
    SignTxRequestError, SignableTxRequest, TryIntoSimTx, TryIntoTxEnv,
    transaction::FromConsensusHeader,
};
use reth_rpc_eth_types::EthApiError;
use tempo_evm::TempoBlockEnv;
use tempo_primitives::{
    SignatureType, TempoHeader, TempoSignature, TempoTxEnvelope, TempoTxType,
    transaction::{Call, RecoveredTempoAuthorization},
};
use tempo_revm::{TempoBatchCallEnv, TempoTxEnv};

impl TryIntoSimTx<TempoTxEnvelope> for TempoTransactionRequest {
    fn try_into_sim_tx(self) -> Result<TempoTxEnvelope, ValueError<Self>> {
        match self.output_tx_type() {
            TempoTxType::AA => {
                let tx = self.build_aa()?;

                // Create an empty signature for the transaction.
                let signature = TempoSignature::default();

                Ok(tx.into_signed(signature).into())
            }
            TempoTxType::Legacy
            | TempoTxType::Eip2930
            | TempoTxType::Eip1559
            | TempoTxType::Eip7702 => {
                let Self {
                    inner,
                    fee_token,
                    nonce_key,
                    calls,
                    key_type,
                    key_data,
                    key_id,
                    tempo_authorization_list,
                    key_authorization,
                } = self;
                let envelope = match TryIntoSimTx::<EthereumTxEnvelope<TxEip4844>>::try_into_sim_tx(
                    inner.clone(),
                ) {
                    Ok(inner) => inner,
                    Err(e) => {
                        return Err(e.map(|inner| Self {
                            inner,
                            fee_token,
                            nonce_key,
                            calls,
                            key_type,
                            key_data,
                            key_id,
                            tempo_authorization_list,
                            key_authorization,
                        }));
                    }
                };

                Ok(envelope.try_into().map_err(
                    |e: ValueError<EthereumTxEnvelope<TxEip4844>>| {
                        e.map(|_inner| Self {
                            inner,
                            fee_token,
                            nonce_key,
                            calls,
                            key_type,
                            key_data,
                            key_id,
                            tempo_authorization_list,
                            key_authorization,
                        })
                    },
                )?)
            }
        }
    }
}

impl TryIntoTxEnv<TempoTxEnv, TempoBlockEnv> for TempoTransactionRequest {
    type Err = EthApiError;

    fn try_into_tx_env<Spec>(
        self,
        evm_env: &EvmEnv<Spec, TempoBlockEnv>,
    ) -> Result<TempoTxEnv, Self::Err> {
        let Self {
            inner,
            fee_token,
            calls,
            key_type,
            key_data,
            key_id,
            tempo_authorization_list,
            nonce_key,
            key_authorization,
        } = self;
        Ok(TempoTxEnv {
            fee_token,
            is_system_tx: false,
            fee_payer: None,
            tempo_tx_env: if !calls.is_empty()
                || !tempo_authorization_list.is_empty()
                || nonce_key.is_some()
                || key_authorization.is_some()
                || key_id.is_some()
            {
                // Create mock signature for gas estimation
                // If key_type is not provided, default to secp256k1
                // For Keychain signatures, use the caller's address as the root key address
                let caller_addr = inner.from.unwrap_or_default();
                let key_type = key_type.unwrap_or(SignatureType::Secp256k1);
                let mock_signature =
                    create_mock_tempo_signature(&key_type, key_data.as_ref(), key_id, caller_addr);

                let calls = if !calls.is_empty() {
                    calls
                } else if let Some(to) = &inner.to {
                    vec![Call {
                        to: *to,
                        value: inner.value.unwrap_or_default(),
                        input: inner.input.clone().into_input().unwrap_or_default(),
                    }]
                } else {
                    return Err(EthApiError::InvalidParams("empty calls list".to_string()));
                };

                Some(Box::new(TempoBatchCallEnv {
                    aa_calls: calls,
                    signature: mock_signature,
                    tempo_authorization_list: tempo_authorization_list
                        .into_iter()
                        .map(RecoveredTempoAuthorization::new)
                        .collect(),
                    nonce_key: nonce_key.unwrap_or_default(),
                    key_authorization,
                    signature_hash: B256::ZERO,
                    tx_hash: B256::ZERO,
                    valid_before: None,
                    valid_after: None,
                    subblock_transaction: false,
                    override_key_id: key_id,
                }))
            } else {
                None
            },
            inner: inner.try_into_tx_env(evm_env)?,
        })
    }
}

/// Creates a mock AA signature for gas estimation based on key type hints
///
/// - `key_type`: The primitive signature type (secp256k1, P256, WebAuthn)
/// - `key_data`: Type-specific data (e.g., WebAuthn size)
/// - `key_id`: If Some, wraps the signature in a Keychain wrapper (+3,000 gas for key validation)
/// - `caller_addr`: The transaction caller address (used as root key address for Keychain)
fn create_mock_tempo_signature(
    key_type: &SignatureType,
    key_data: Option<&Bytes>,
    key_id: Option<Address>,
    caller_addr: alloy_primitives::Address,
) -> TempoSignature {
    use tempo_primitives::transaction::tt_signature::{KeychainSignature, TempoSignature};

    let inner_sig = create_mock_primitive_signature(key_type, key_data.cloned());

    if key_id.is_some() {
        // For Keychain signatures, the root_key_address is the caller (account owner)
        TempoSignature::Keychain(KeychainSignature::new(caller_addr, inner_sig))
    } else {
        TempoSignature::Primitive(inner_sig)
    }
}

/// Creates a mock primitive signature for gas estimation
fn create_mock_primitive_signature(
    sig_type: &SignatureType,
    key_data: Option<Bytes>,
) -> tempo_primitives::transaction::tt_signature::PrimitiveSignature {
    use tempo_primitives::transaction::tt_signature::{
        P256SignatureWithPreHash, PrimitiveSignature, WebAuthnSignature,
    };

    match sig_type {
        SignatureType::Secp256k1 => {
            // Create a dummy secp256k1 signature (65 bytes)
            PrimitiveSignature::Secp256k1(Signature::new(
                alloy_primitives::U256::ZERO,
                alloy_primitives::U256::ZERO,
                false,
            ))
        }
        SignatureType::P256 => {
            // Create a dummy P256 signature
            PrimitiveSignature::P256(P256SignatureWithPreHash {
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
            // Default: 800 bytes if no key_data provided

            // Base clientDataJSON template (50 bytes): {"type":"webauthn.get","challenge":"","origin":""}
            // Authenticator data (37 bytes): 32 rpIdHash + 1 flags + 4 signCount
            // Minimum total: 87 bytes
            const BASE_CLIENT_JSON: &str = r#"{"type":"webauthn.get","challenge":"","origin":""}"#;
            const AUTH_DATA_SIZE: usize = 37;
            const MIN_WEBAUTHN_SIZE: usize = AUTH_DATA_SIZE + BASE_CLIENT_JSON.len(); // 87 bytes
            const DEFAULT_WEBAUTHN_SIZE: usize = 800; // Default when no key_data provided

            // Parse size from key_data, or use default
            let size = if let Some(data) = key_data.as_ref() {
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

            PrimitiveSignature::WebAuthn(WebAuthnSignature {
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

impl FromConsensusHeader<TempoHeader> for TempoHeaderResponse {
    fn from_consensus_header(header: SealedHeader<TempoHeader>, block_size: usize) -> Self {
        Self {
            timestamp_millis: header.timestamp_millis(),
            inner: FromConsensusHeader::from_consensus_header(header, block_size),
        }
    }
}
