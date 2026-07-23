use crate::rpc::{TempoHeaderResponse, TempoTransactionRequest};
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, error::ValueError, transaction::Recovered};
use alloy_network::{NetworkTransactionBuilder, TxSigner};
use alloy_primitives::{Address, B256, Bytes, Signature};
use reth_primitives_traits::SealedHeader;
use reth_rpc_convert::{
    FromConsensusHeader, SignTxRequestError, SignableTxRequest, TryIntoSimTx, TryIntoTxEnv,
};
use reth_rpc_eth_types::EthApiError;
use tempo_evm::{RecoveredTxEnvelope, TempoEvmEnv, TempoTxEnv};
use tempo_primitives::{SignatureType, TempoHeader, TempoSignature, TempoTxEnvelope, TempoTxType};

/// Non-zero transaction identifier used only for RPC simulations.
///
/// RPC requests are not final signed transactions, so gas filling and other request normalization
/// can make a simulated signing payload differ from the eventual submitted transaction. Use a
/// fixed sentinel instead of deriving a misleading future channel id from the simulated payload.
const RPC_SIMULATION_UNIQUE_TX_IDENTIFIER: B256 = B256::new(*b"TEMPO_RPC_SIMULATION_MPP_CONTEXT");

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
                    valid_before,
                    valid_after,
                    fee_payer_signature,
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
                            valid_before,
                            valid_after,
                            fee_payer_signature,
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
                            valid_before,
                            valid_after,
                            fee_payer_signature,
                        })
                    },
                )?)
            }
        }
    }
}

impl TryIntoTxEnv<Recovered<TempoTxEnv>, TempoEvmEnv> for TempoTransactionRequest {
    type Err = EthApiError;

    fn try_into_tx_env(self, evm_env: &TempoEvmEnv) -> Result<Recovered<TempoTxEnv>, Self::Err> {
        let caller_addr = self.inner.from.unwrap_or_default();
        let is_aa = self.output_tx_type() == TempoTxType::AA;
        if !is_aa {
            let transaction = TryIntoTxEnv::<RecoveredTxEnvelope, TempoEvmEnv>::try_into_tx_env(
                self.inner, evm_env,
            )?;
            return TempoTxEnv::from_recovered_eth(transaction)
                .ok_or(EthApiError::Unsupported("EIP-4844 transactions"))
                .map(|env| {
                    env.with_simulation_overrides(RPC_SIMULATION_UNIQUE_TX_IDENTIFIER, None, None)
                })
                .map(|env| Recovered::new_unchecked(env, caller_addr));
        }

        let key_type = self.key_type.unwrap_or(SignatureType::Secp256k1);
        let key_data = self.key_data.clone();
        let key_id = self.key_id;
        let has_fee_payer_signature = self.fee_payer_signature.is_some();
        let tx = self
            .build_aa()
            .map_err(|error| EthApiError::InvalidParams(error.to_string()))?;
        let fee_payer = has_fee_payer_signature
            .then(|| tx.recover_fee_payer(caller_addr).ok())
            .flatten();
        let signature = create_mock_tempo_sig(
            &key_type,
            key_data.as_ref(),
            key_id,
            caller_addr,
            evm_env.tempo_spec.is_t1c(),
        );

        let env = TempoTxEnv::from(Recovered::new_unchecked(
            TempoTxEnvelope::AA(tx.into_signed(signature)),
            caller_addr,
        ))
        .with_simulation_overrides(RPC_SIMULATION_UNIQUE_TX_IDENTIFIER, fee_payer, key_id);
        Ok(Recovered::new_unchecked(env, caller_addr))
    }
}

/// Creates a mock AA signature for gas estimation based on key type hints
///
/// - `key_type`: The primitive signature type (secp256k1, P256, WebAuthn)
/// - `key_data`: Type-specific data (e.g., WebAuthn size)
/// - `key_id`: If Some, wraps the signature in a Keychain wrapper (+3,000 gas for key validation)
/// - `caller_addr`: The transaction caller address (used as root key address for Keychain)
/// - `is_t1c`: Whether T1C is active — determines keychain signature version (V1 pre-T1C, V2 post-T1C)
fn create_mock_tempo_sig(
    key_type: &SignatureType,
    key_data: Option<&Bytes>,
    key_id: Option<Address>,
    caller_addr: alloy_primitives::Address,
    is_t1c: bool,
) -> TempoSignature {
    use tempo_primitives::transaction::tt_signature::{KeychainSignature, TempoSignature};

    let inner_sig = create_mock_primitive_signature(key_type, key_data.cloned());

    if key_id.is_some() {
        // For Keychain signatures, the root_key_address is the caller (account owner).
        let keychain_sig = if is_t1c {
            KeychainSignature::new(caller_addr, inner_sig)
        } else {
            KeychainSignature::new_v1(caller_addr, inner_sig)
        };
        TempoSignature::Keychain(keychain_sig)
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
            const MAX_WEBAUTHN_SIZE: usize = 8192; // Maximum realistic WebAuthn signature size

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

            // Clamp size to safe bounds to prevent DoS via unbounded allocation
            let size = size.clamp(MIN_WEBAUTHN_SIZE, MAX_WEBAUTHN_SIZE);

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
        if self.output_tx_type() == TempoTxType::AA {
            let mut tx = self
                .build_aa()
                .map_err(|_| SignTxRequestError::InvalidTransactionRequest)?;
            let signature = signer.sign_transaction(&mut tx).await?;
            Ok(tx.into_signed(signature.into()).into())
        } else {
            SignableTxRequest::<TempoTxEnvelope>::try_build_and_sign(self.inner, signer).await
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{TxKind, address};
    use alloy_rpc_types_eth::TransactionRequest;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use reth_rpc_convert::TryIntoTxEnv;
    use tempo_primitives::{
        TempoTransaction,
        transaction::{Call, FEE_PAYER_SIGNATURE_MARKER, tt_signature::PrimitiveSignature},
    };

    fn call_request(target: Address) -> TransactionRequest {
        TransactionRequest {
            from: Some(address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
            to: Some(TxKind::Call(target)),
            nonce: Some(0),
            gas: Some(100_000),
            max_fee_per_gas: Some(1_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000),
            chain_id: Some(4217),
            ..Default::default()
        }
    }

    #[test]
    fn test_estimate_gas_when_calls_set() {
        let existing_call = Call {
            to: TxKind::Call(address!("0x1111111111111111111111111111111111111111")),
            value: alloy_primitives::U256::from(1),
            input: Bytes::from(vec![0xaa]),
        };

        let req = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(address!(
                    "0x2222222222222222222222222222222222222222"
                ))),
                value: Some(alloy_primitives::U256::from(2)),
                input: alloy_rpc_types_eth::TransactionInput::new(Bytes::from(vec![0xbb])),
                nonce: Some(0),
                gas: Some(100_000),
                max_fee_per_gas: Some(1_000_000_000),
                max_priority_fee_per_gas: Some(1_000_000),
                ..Default::default()
            },
            calls: vec![existing_call],
            nonce_key: Some(alloy_primitives::U256::ZERO),
            ..Default::default()
        };

        let built_calls = req.clone().build_aa().expect("build_aa").calls;

        let evm_env = TempoEvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");
        let estimated_calls = tx_env
            .as_aa()
            .expect("AA transaction")
            .inner()
            .tx()
            .calls
            .clone();

        assert_eq!(estimated_calls, built_calls);
    }

    #[test]
    fn test_estimate_gas_key_hints_only_produce_aa_env() {
        let target = address!("0x2222222222222222222222222222222222222222");
        let req = TempoTransactionRequest {
            inner: call_request(target),
            key_type: Some(SignatureType::WebAuthn),
            ..Default::default()
        };

        let tx_env = req
            .try_into_tx_env(&TempoEvmEnv::default())
            .expect("try_into_tx_env");
        let signature = tx_env.as_aa().expect("AA transaction").inner().signature();
        assert!(matches!(
            signature,
            TempoSignature::Primitive(PrimitiveSignature::WebAuthn(_))
        ));

        let req = TempoTransactionRequest {
            inner: call_request(target),
            key_data: Some(Bytes::from_static(&[0x03, 0x20])),
            ..Default::default()
        };
        let tx_env = req
            .try_into_tx_env(&TempoEvmEnv::default())
            .expect("try_into_tx_env");
        assert!(
            tx_env.as_aa().is_some(),
            "key_data alone must produce an AA tx env"
        );
    }

    #[test]
    fn test_estimate_gas_fee_token_only_produces_aa_env() {
        let req = TempoTransactionRequest {
            inner: call_request(address!("0x2222222222222222222222222222222222222222")),
            fee_token: Some(address!("0x20c0000000000000000000000000000000000000")),
            ..Default::default()
        };

        let tx_env = req
            .try_into_tx_env(&TempoEvmEnv::default())
            .expect("try_into_tx_env");
        assert!(
            tx_env.as_aa().is_some(),
            "fee_token alone must produce an AA tx env"
        );
    }

    #[test]
    fn test_try_into_tx_env_sets_channel_open_context_hash_for_rpc_simulation() {
        let sender = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let target = address!("0x2222222222222222222222222222222222222222");

        let req = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(sender),
                to: Some(TxKind::Call(target)),
                nonce: Some(0),
                gas: Some(100_000),
                max_fee_per_gas: Some(1_000_000_000),
                max_priority_fee_per_gas: Some(1_000_000),
                chain_id: Some(4217),
                ..Default::default()
            },
            ..Default::default()
        };

        let evm_env = TempoEvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");

        assert_eq!(
            tx_env.channel_open_context_hash(),
            RPC_SIMULATION_UNIQUE_TX_IDENTIFIER
        );
        assert_ne!(
            tx_env.channel_open_context_hash(),
            B256::ZERO,
            "RPC simulations must seed a non-zero context hash so TIP20ChannelReserve.open() does not treat it as unset"
        );
    }

    #[test]
    fn test_webauthn_size_clamped_to_max() {
        // Attempt to create a signature with u32::MAX size (would be ~4GB without fix)
        let malicious_key_data = Bytes::from(0xFFFFFFFFu32.to_be_bytes().to_vec());
        let sig =
            create_mock_primitive_signature(&SignatureType::WebAuthn, Some(malicious_key_data));

        // Extract webauthn_data and verify it's clamped to MAX_WEBAUTHN_SIZE (8192)
        let PrimitiveSignature::WebAuthn(webauthn_sig) = sig else {
            panic!("Expected WebAuthn signature");
        };

        // The webauthn_data should be at most MAX_WEBAUTHN_SIZE bytes
        assert!(
            webauthn_sig.webauthn_data.len() <= 8192,
            "WebAuthn data size {} exceeds maximum 8192",
            webauthn_sig.webauthn_data.len()
        );
    }

    #[test]
    fn test_webauthn_size_respects_minimum() {
        // Attempt to create a signature with size 0
        let key_data = Bytes::from(vec![0u8]);
        let sig = create_mock_primitive_signature(&SignatureType::WebAuthn, Some(key_data));

        let PrimitiveSignature::WebAuthn(webauthn_sig) = sig else {
            panic!("Expected WebAuthn signature");
        };

        // Should be at least MIN_WEBAUTHN_SIZE (87 bytes)
        assert!(
            webauthn_sig.webauthn_data.len() >= 87,
            "WebAuthn data size {} is below minimum 87",
            webauthn_sig.webauthn_data.len()
        );
    }

    #[test]
    fn test_webauthn_default_size() {
        // No key_data should use default size (800)
        let sig = create_mock_primitive_signature(&SignatureType::WebAuthn, None);

        let PrimitiveSignature::WebAuthn(webauthn_sig) = sig else {
            panic!("Expected WebAuthn signature");
        };

        // Default is 800 bytes
        assert_eq!(webauthn_sig.webauthn_data.len(), 800);
    }

    #[test]
    fn test_estimate_gas_fee_payer_signature_only_produces_aa_env() {
        let sponsor = PrivateKeySigner::random();
        let sender = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let target = address!("0x2222222222222222222222222222222222222222");

        // Build a TempoTransaction so we can compute fee_payer_signature_hash
        let tx = TempoTransaction {
            chain_id: 4217,
            nonce: 0,
            fee_payer_signature: None,
            valid_before: None,
            valid_after: None,
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            fee_token: None,
            access_list: Default::default(),
            calls: vec![Call {
                to: target.into(),
                value: Default::default(),
                input: Default::default(),
            }],
            tempo_authorization_list: vec![],
            nonce_key: Default::default(),
            key_authorization: None,
        };
        let hash = tx.fee_payer_signature_hash(sender);
        let fee_payer_sig = sponsor.sign_hash_sync(&hash).expect("sign");

        // Request with ONLY fee_payer_signature as the Tempo-specific field
        let req = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(sender),
                to: Some(TxKind::Call(target)),
                nonce: Some(0),
                gas: Some(100_000),
                max_fee_per_gas: Some(1_000_000_000),
                max_priority_fee_per_gas: Some(1_000_000),
                chain_id: Some(4217),
                ..Default::default()
            },
            fee_payer_signature: Some(fee_payer_sig),
            ..Default::default()
        };

        let evm_env = TempoEvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");

        assert!(
            tx_env.as_aa().is_some(),
            "fee_payer_signature alone must produce an AA tx env"
        );
        assert_eq!(
            tx_env.fee_payer().expect("fee payer"),
            sponsor.address(),
            "fee_payer should recover sponsor address"
        );
    }

    #[test]
    fn test_aa_roundtrip_via_tx_env() {
        use alloy_primitives::U256;

        let calls = vec![
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

        let tx = TempoTransaction {
            chain_id: 4217,
            nonce: 1,
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            calls: calls.clone(),
            ..Default::default()
        };

        let req: TempoTransactionRequest = tx.into();

        let evm_env = TempoEvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");
        let aa_calls = tx_env
            .as_aa()
            .expect("AA transaction")
            .inner()
            .tx()
            .calls
            .clone();

        assert_eq!(
            aa_calls, calls,
            "roundtrip via try_into_tx_env must preserve exact call list"
        );
    }

    #[test]
    fn test_estimate_gas_invalid_fee_payer_signature_keeps_unresolved_fee_payer() {
        let sender = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let target = address!("0x2222222222222222222222222222222222222222");

        let req = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(sender),
                to: Some(TxKind::Call(target)),
                nonce: Some(0),
                gas: Some(100_000),
                max_fee_per_gas: Some(1_000_000_000),
                max_priority_fee_per_gas: Some(1_000_000),
                chain_id: Some(4217),
                ..Default::default()
            },
            fee_payer_signature: Some(FEE_PAYER_SIGNATURE_MARKER),
            ..Default::default()
        };

        let evm_env = TempoEvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");

        assert!(
            tx_env.as_aa().is_some(),
            "fee_payer_signature alone must produce an AA tx env"
        );
        assert!(
            tx_env.fee_payer().is_err(),
            "invalid fee_payer_signature should remain unresolved"
        );
    }

    #[tokio::test]
    async fn test_signable_tx_request_preserves_tempo_fields() {
        let signer = PrivateKeySigner::random();

        let call = Call {
            to: alloy_primitives::TxKind::Call(address!(
                "0x1111111111111111111111111111111111111111"
            )),
            value: alloy_primitives::U256::from(1),
            input: Bytes::from(vec![0xaa]),
        };

        let fee_token = address!("0x20c0000000000000000000000000000000000000");
        let nonce_key = alloy_primitives::U256::from(42);

        let req = TempoTransactionRequest {
            inner: TransactionRequest {
                nonce: Some(0),
                gas: Some(100_000),
                max_fee_per_gas: Some(1_000_000_000),
                max_priority_fee_per_gas: Some(1_000_000),
                chain_id: Some(4217),
                ..Default::default()
            },
            calls: vec![call.clone()],
            fee_token: Some(fee_token),
            nonce_key: Some(nonce_key),
            ..Default::default()
        };

        let envelope = SignableTxRequest::<TempoTxEnvelope>::try_build_and_sign(req, &signer)
            .await
            .expect("should build and sign");

        match &envelope {
            TempoTxEnvelope::AA(signed) => {
                let tx = signed.tx();
                assert_eq!(tx.fee_token, Some(fee_token), "fee_token must be preserved");
                assert_eq!(tx.nonce_key, nonce_key, "nonce_key must be preserved");
                assert_eq!(tx.calls, vec![call], "calls must be preserved");
            }
            other => panic!(
                "Expected AA envelope for request with Tempo fields, got {:?}",
                other.tx_type()
            ),
        }
    }
}
