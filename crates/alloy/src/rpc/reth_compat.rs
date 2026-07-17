use crate::rpc::{TempoHeaderResponse, TempoTransactionRequest};
use alloy_consensus::{EthereumTxEnvelope, TxEip4844, error::ValueError};
use alloy_network::{NetworkTransactionBuilder, TxSigner};
use alloy_primitives::Signature;
use reth_evm::EvmEnv;
use reth_primitives_traits::SealedHeader;
use reth_rpc_convert::{
    FromConsensusHeader, SignTxRequestError, SignableTxRequest, TryIntoSimTx, TryIntoTxEnv,
};
use reth_rpc_eth_types::EthApiError;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::TempoBlockEnv;
use tempo_primitives::{TempoHeader, TempoSignature, TempoTxEnvelope, TempoTxType};
use tempo_revm::TempoTxEnv;

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

impl TryIntoTxEnv<TempoTxEnv, TempoHardfork, TempoBlockEnv> for TempoTransactionRequest {
    type Err = EthApiError;

    fn try_into_tx_env(
        self,
        evm_env: &EvmEnv<TempoHardfork, TempoBlockEnv>,
    ) -> Result<TempoTxEnv, Self::Err> {
        let inner = self.inner.clone().try_into_tx_env(evm_env)?;
        self.apply_to_tempo_tx_env(inner.into(), evm_env.spec_id().is_t1c(), false)
            .map_err(|err| EthApiError::InvalidParams(err.to_string()))
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
    use crate::rpc::request::{
        RPC_SIMULATION_UNIQUE_TX_IDENTIFIER, create_mock_primitive_signature,
    };
    use alloy_primitives::{Address, B256, Bytes, TxKind, address};
    use alloy_rpc_types_eth::TransactionRequest;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use reth_rpc_convert::TryIntoTxEnv;
    use tempo_primitives::{
        SignatureType, TempoTransaction,
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

        let evm_env = EvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");
        let estimated_calls = tx_env.tempo_tx_env.expect("tempo_tx_env").aa_calls;

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
            .try_into_tx_env(&EvmEnv::default())
            .expect("try_into_tx_env");
        let signature = tx_env.tempo_tx_env.expect("tempo_tx_env").signature;
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
            .try_into_tx_env(&EvmEnv::default())
            .expect("try_into_tx_env");
        assert!(
            tx_env.tempo_tx_env.is_some(),
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
            .try_into_tx_env(&EvmEnv::default())
            .expect("try_into_tx_env");
        assert!(
            tx_env.tempo_tx_env.is_some(),
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

        let evm_env = EvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");

        assert_eq!(
            tx_env.channel_open_context_hash(),
            Some(RPC_SIMULATION_UNIQUE_TX_IDENTIFIER)
        );
        assert_ne!(
            tx_env.channel_open_context_hash(),
            Some(B256::ZERO),
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

        let evm_env = EvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");

        assert!(
            tx_env.tempo_tx_env.is_some(),
            "fee_payer_signature alone must produce an AA tx env"
        );
        assert_eq!(
            tx_env.fee_payer,
            Some(Some(sponsor.address())),
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

        let evm_env = EvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");
        let aa_calls = tx_env.tempo_tx_env.expect("tempo_tx_env").aa_calls;

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

        let evm_env = EvmEnv::default();
        let tx_env = req.try_into_tx_env(&evm_env).expect("try_into_tx_env");

        assert!(
            tx_env.tempo_tx_env.is_some(),
            "fee_payer_signature alone must produce an AA tx env"
        );
        assert_eq!(
            tx_env.fee_payer,
            Some(None),
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
