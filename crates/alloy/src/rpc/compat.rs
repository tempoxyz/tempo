use crate::rpc::{TempoHeaderResponse, TempoTransactionRequest};
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, error::ValueError};
use alloy_network::TxSigner;
use alloy_primitives::{Bytes, Signature};
use reth_evm::EvmEnv;
use reth_primitives_traits::SealedHeader;
use reth_rpc_convert::{
    SignTxRequestError, SignableTxRequest, TryIntoSimTx, TryIntoTxEnv,
    transaction::FromConsensusHeader,
};
use reth_rpc_eth_types::EthApiError;
use tempo_evm::TempoBlockEnv;
use tempo_primitives::{AASignature, SignatureType, TempoHeader, TempoTxEnvelope};
use tempo_revm::{AATxEnv, TempoTxEnv};

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
            let Self { inner, fee_token, calls, key_type, key_data, aa_authorization_list } = self;
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

            Ok(envelope.try_into().map_err(|e: ValueError<EthereumTxEnvelope<TxEip4844>>| {
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
    type Err = EthApiError;

    fn try_into_tx_env<Spec>(
        self,
        evm_env: &EvmEnv<Spec, TempoBlockEnv>,
    ) -> Result<TempoTxEnv, Self::Err> {
        let Self { inner, fee_token, calls, key_type, key_data, aa_authorization_list } = self;
        Ok(TempoTxEnv {
            inner: inner.try_into_tx_env(evm_env)?,
            fee_token,
            is_system_tx: false,
            fee_payer: None,
            aa_tx_env: if !calls.is_empty() || !aa_authorization_list.is_empty() {
                // Create mock signature for gas estimation
                // If key_type is not provided, default to secp256k1
                let mock_signature = key_type
                    .as_ref()
                    .map(|kt| create_mock_aa_signature(kt, key_data.as_ref()))
                    .unwrap_or_else(|| create_mock_aa_signature(&SignatureType::Secp256k1, None));

                if calls.is_empty() {
                    return Err(EthApiError::InvalidParams("empty calls list".to_string()));
                }

                Some(Box::new(AATxEnv {
                    aa_calls: calls,
                    signature: mock_signature,
                    aa_authorization_list,
                    ..Default::default()
                }))
            } else {
                None
            },
        })
    }
}

/// Creates a mock AA signature for gas estimation based on key type hints
fn create_mock_aa_signature(key_type: &SignatureType, key_data: Option<&Bytes>) -> AASignature {
    use tempo_primitives::transaction::aa_signature::{
        AASignature, P256SignatureWithPreHash, PrimitiveSignature, WebAuthnSignature,
    };

    match key_type {
        SignatureType::Secp256k1 => {
            // Create a dummy secp256k1 signature (65 bytes)
            AASignature::Primitive(PrimitiveSignature::Secp256k1(Signature::new(
                alloy_primitives::U256::ZERO,
                alloy_primitives::U256::ZERO,
                false,
            )))
        }
        SignatureType::P256 => {
            // Create a dummy P256 signature
            AASignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: alloy_primitives::B256::ZERO,
                s: alloy_primitives::B256::ZERO,
                pub_key_x: alloy_primitives::B256::ZERO,
                pub_key_y: alloy_primitives::B256::ZERO,
                pre_hash: false,
            }))
        }
        SignatureType::WebAuthn => {
            // Create a dummy WebAuthn signature with the specified size
            // key_data contains the total size of webauthn_data (excluding 128 bytes for public
            // keys) Default: 200 bytes if no key_data provided

            // Base clientDataJSON template (50 bytes):
            // {"type":"webauthn.get","challenge":"","origin":""} Authenticator data (37
            // bytes): 32 rpIdHash + 1 flags + 4 signCount Minimum total: 87 bytes
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

            AASignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
                webauthn_data,
                r: alloy_primitives::B256::ZERO,
                s: alloy_primitives::B256::ZERO,
                pub_key_x: alloy_primitives::B256::ZERO,
                pub_key_y: alloy_primitives::B256::ZERO,
            }))
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
