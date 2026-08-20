use super::{MultisigSimulationApproval, MultisigSimulationHint, TempoTransactionRequest};
use alloy_consensus::error::ValueError;
use alloy_primitives::{Address, B256, Bytes, Signature};
use core::num::NonZeroU64;
use tempo_primitives::{
    SignatureType, TempoSignature,
    transaction::{Call, PrimitiveSignature, RecoveredTempoAuthorization},
};
use tempo_revm::{ExecutionContext, TempoBatchCallEnv, TempoTxEnv};

/// Non-zero transaction identifier used only for RPC simulations.
///
/// RPC requests are not final signed transactions, so gas filling and other request normalization
/// can make a simulated signing payload differ from the eventual submitted transaction. Use a
/// fixed sentinel instead of deriving a misleading future channel id from the simulated payload.
pub(super) const RPC_SIMULATION_UNIQUE_TX_IDENTIFIER: B256 =
    B256::new(*b"TEMPO_RPC_SIMULATION_MPP_CONTEXT");

impl TempoTransactionRequest {
    /// Applies this request's Tempo-specific fields to a normalized simulation transaction env.
    ///
    /// The caller owns normalization of the inner Ethereum transaction env (fees, gas limit,
    /// nonce, and call defaults). This method owns Tempo AA simulation semantics, including mock
    /// signatures, access-key identity, sponsorship, authorizations, and expiring nonces.
    pub fn try_into_tempo_tx_env(
        self,
        mut tx_env: TempoTxEnv,
        is_t1c: bool,
    ) -> Result<TempoTxEnv, ValueError<Self>> {
        let caller_addr = self.inner.from.unwrap_or_default();
        let is_aa = self.has_aa_fields();

        if self.key_id.is_some()
            && (self.multisig_init.is_some()
                || self.multisig_signature_count.is_some()
                || self.multisig_simulation_hint.is_some())
        {
            return Err(ValueError::new(
                self,
                "keyId cannot be combined with native multisig simulation fields",
            ));
        }

        let fee_payer = if self.fee_payer_signature.is_some() {
            // Try to recover the fee payer address from the signature. A dummy or incomplete
            // simulation request retains the failed recovery for normal validation downstream.
            let recovered = self
                .clone()
                .build_aa()
                .ok()
                .and_then(|tx| tx.recover_fee_payer(caller_addr).ok());
            Some(recovered)
        } else {
            None
        };

        let key_type = self.key_type.unwrap_or(SignatureType::Secp256k1);
        let mock_signature = create_mock_native_multisig_sig_for_request(&self, &key_type)
            .map_err(|err| ValueError::new(self.clone(), err))?
            .unwrap_or_else(|| {
                create_mock_tempo_sig(
                    &key_type,
                    self.key_data.as_ref(),
                    self.key_id,
                    caller_addr,
                    is_t1c,
                )
            });

        let Self {
            inner,
            fee_token,
            calls,
            key_type: _,
            key_data: _,
            key_id,
            tempo_authorization_list,
            nonce_key,
            key_authorization,
            multisig_init: _,
            multisig_signature_count: _,
            multisig_simulation_hint: _,
            valid_before,
            valid_after,
            fee_payer_signature: _,
        } = self;

        tx_env.fee_token = fee_token;
        tx_env.is_system_tx = false;
        tx_env.execution_context = ExecutionContext::Simulation;
        tx_env.unique_tx_identifier = Some(RPC_SIMULATION_UNIQUE_TX_IDENTIFIER);
        tx_env.fee_payer = fee_payer;
        tx_env.tempo_tx_env = if is_aa {
            let mut calls = calls;
            if let Some(to) = inner
                .to
                .or_else(|| calls.is_empty().then_some(alloy_primitives::TxKind::Create))
            {
                calls.push(Call {
                    to,
                    value: inner.value.unwrap_or_default(),
                    input: inner.input.into_input().unwrap_or_default(),
                });
            }

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
                valid_before: valid_before.map(NonZeroU64::get),
                valid_after: valid_after.map(NonZeroU64::get),
                subblock_transaction: false,
                override_key_id: key_id,
                expiring_nonce_idx: None,
            }))
        } else {
            None
        };

        Ok(tx_env)
    }
}

pub(super) fn create_mock_native_multisig_sig_for_request(
    request: &TempoTransactionRequest,
    key_type: &SignatureType,
) -> Result<Option<TempoSignature>, &'static str> {
    if let Some(hint) = request.multisig_simulation_hint.as_ref() {
        create_mock_native_multisig_sig_from_hint(hint, request.multisig_init.as_ref()).map(Some)
    } else if let Some(init) = request.multisig_init.as_ref() {
        create_mock_native_multisig_sig(init, key_type, request.key_data.as_ref()).map(Some)
    } else if let Some(signature_count) = request.multisig_signature_count {
        create_mock_native_multisig_sig_for_account(
            request.inner.from.unwrap_or_default(),
            signature_count,
            key_type,
            request.key_data.as_ref(),
        )
        .map(Some)
    } else {
        Ok(None)
    }
}

pub(super) fn create_mock_native_multisig_sig(
    init: &tempo_primitives::transaction::InitMultisig,
    key_type: &SignatureType,
    key_data: Option<&Bytes>,
) -> Result<TempoSignature, &'static str> {
    use tempo_primitives::transaction::{
        MultisigConfigError, MultisigQuorumError, MultisigSignature,
        multisig_signature_count_for_threshold,
    };

    let account = init.account().map_err(MultisigConfigError::as_str)?;
    let signature_count = multisig_signature_count_for_threshold(
        init.owners.iter().map(|owner| owner.weight),
        init.threshold,
    )
    .map_err(MultisigQuorumError::as_str)?;
    let signatures =
        create_mock_native_multisig_owner_signatures(signature_count, key_type, key_data)?;

    MultisigSignature::from_decoded(account, signatures, Some(init.clone()))
        .map(TempoSignature::Multisig)
        .map_err(|error| error.as_str())
}

pub(super) fn create_mock_native_multisig_sig_for_account(
    account: Address,
    signature_count: usize,
    key_type: &SignatureType,
    key_data: Option<&Bytes>,
) -> Result<TempoSignature, &'static str> {
    use tempo_primitives::transaction::MultisigSignature;

    MultisigSignature::from_decoded(
        account,
        create_mock_native_multisig_owner_signatures(signature_count, key_type, key_data)?,
        None,
    )
    .map(TempoSignature::Multisig)
    .map_err(|error| error.as_str())
}

pub(super) fn create_mock_native_multisig_sig_from_hint(
    hint: &MultisigSimulationHint,
    init: Option<&tempo_primitives::transaction::InitMultisig>,
) -> Result<TempoSignature, &'static str> {
    create_mock_native_multisig_sig_from_hint_inner(hint, init, false)
}

fn create_mock_native_multisig_sig_from_hint_inner(
    hint: &MultisigSimulationHint,
    init: Option<&tempo_primitives::transaction::InitMultisig>,
    attach_config_validation_gas: bool,
) -> Result<TempoSignature, &'static str> {
    use tempo_primitives::transaction::MultisigSignature;

    let signatures = hint
        .approvals
        .iter()
        .map(|approval| match approval {
            MultisigSimulationApproval::Primitive { key_type, key_data } => {
                Ok(TempoSignature::Primitive(create_mock_primitive_signature(
                    key_type,
                    key_data.clone(),
                )))
            }
            MultisigSimulationApproval::UnknownPrimitive => Ok(TempoSignature::Primitive(
                create_conservative_native_multisig_primitive_signature(),
            )),
            MultisigSimulationApproval::Multisig(nested) => {
                create_mock_native_multisig_sig_from_hint_inner(nested, None, true)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    let signature = MultisigSignature::from_decoded(hint.account, signatures, init.cloned())?;
    let signature = if attach_config_validation_gas {
        signature.with_simulation_config_owner_count(hint.owner_count)?
    } else {
        signature
    };
    Ok(TempoSignature::Multisig(signature))
}

fn create_conservative_native_multisig_primitive_signature() -> PrimitiveSignature {
    use tempo_primitives::transaction::{
        MAX_WEBAUTHN_SIGNATURE_LENGTH, tt_signature::WebAuthnSignature,
    };

    const WEBAUTHN_FIXED_SIGNATURE_BYTES: usize = 128;
    PrimitiveSignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(vec![
            0xff;
            MAX_WEBAUTHN_SIGNATURE_LENGTH
                - WEBAUTHN_FIXED_SIGNATURE_BYTES
        ]),
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x: B256::ZERO,
        pub_key_y: B256::ZERO,
    })
}

fn create_mock_native_multisig_owner_signatures(
    signature_count: usize,
    key_type: &SignatureType,
    key_data: Option<&Bytes>,
) -> Result<Vec<TempoSignature>, &'static str> {
    use tempo_primitives::transaction::MAX_MULTISIG_SIGNATURES;

    if signature_count == 0 {
        return Err("multisig mock signature requires at least one owner");
    }
    if signature_count > MAX_MULTISIG_SIGNATURES {
        return Err("too many multisig signatures");
    }

    Ok((0..signature_count)
        .map(|_| {
            TempoSignature::Primitive(create_mock_primitive_signature(key_type, key_data.cloned()))
        })
        .collect())
}

/// Creates a mock AA signature for gas estimation based on key type hints.
pub(super) fn create_mock_tempo_sig(
    key_type: &SignatureType,
    key_data: Option<&Bytes>,
    key_id: Option<Address>,
    caller_addr: Address,
    is_t1c: bool,
) -> TempoSignature {
    use tempo_primitives::transaction::tt_signature::{KeychainSignature, TempoSignature};

    let inner_sig = create_mock_primitive_signature(key_type, key_data.cloned());

    if key_id.is_some() {
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

/// Creates a mock primitive signature for gas estimation.
pub(super) fn create_mock_primitive_signature(
    sig_type: &SignatureType,
    key_data: Option<Bytes>,
) -> tempo_primitives::transaction::tt_signature::PrimitiveSignature {
    use tempo_primitives::transaction::tt_signature::{
        P256SignatureWithPreHash, PrimitiveSignature, WebAuthnSignature,
    };

    match sig_type {
        SignatureType::Secp256k1 => PrimitiveSignature::Secp256k1(Signature::new(
            alloy_primitives::U256::ZERO,
            alloy_primitives::U256::ZERO,
            false,
        )),
        SignatureType::P256 => PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: B256::ZERO,
            pub_key_y: B256::ZERO,
            pre_hash: false,
        }),
        SignatureType::WebAuthn => {
            // Base clientDataJSON template (50 bytes) plus 37 bytes of authenticator data.
            const BASE_CLIENT_JSON: &str = r#"{"type":"webauthn.get","challenge":"","origin":""}"#;
            const AUTH_DATA_SIZE: usize = 37;
            const MIN_WEBAUTHN_SIZE: usize = AUTH_DATA_SIZE + BASE_CLIENT_JSON.len();
            const DEFAULT_WEBAUTHN_SIZE: usize = 800;
            const MAX_WEBAUTHN_SIZE: usize = 8192;

            let size = if let Some(data) = key_data.as_ref() {
                match data.len() {
                    1 => data[0] as usize,
                    2 => u16::from_be_bytes([data[0], data[1]]) as usize,
                    4 => u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize,
                    _ => DEFAULT_WEBAUTHN_SIZE,
                }
            } else {
                DEFAULT_WEBAUTHN_SIZE
            }
            .clamp(MIN_WEBAUTHN_SIZE, MAX_WEBAUTHN_SIZE);

            let mut webauthn_data = vec![0u8; AUTH_DATA_SIZE];
            webauthn_data[32] = 0x01;

            let additional_bytes = size - MIN_WEBAUTHN_SIZE;
            let client_json = if additional_bytes > 0 {
                let padding = "x".repeat(additional_bytes);
                format!(r#"{{"type":"webauthn.get","challenge":"","origin":"{padding}"}}"#,)
            } else {
                BASE_CLIENT_JSON.to_string()
            };
            webauthn_data.extend_from_slice(client_json.as_bytes());

            PrimitiveSignature::WebAuthn(WebAuthnSignature {
                webauthn_data: Bytes::from(webauthn_data),
                r: B256::ZERO,
                s: B256::ZERO,
                pub_key_x: B256::ZERO,
                pub_key_y: B256::ZERO,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{TxKind, address};
    use alloy_rpc_types_eth::TransactionRequest;

    #[test]
    fn access_key_request_populates_typed_simulation_env() {
        let root = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let key_id = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let target = address!("0xcccccccccccccccccccccccccccccccccccccccc");
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(root),
                to: Some(TxKind::Call(target)),
                ..Default::default()
            },
            key_type: Some(SignatureType::Secp256k1),
            key_id: Some(key_id),
            ..Default::default()
        };

        let env = request
            .try_into_tempo_tx_env(TempoTxEnv::default(), true)
            .expect("valid simulation request");
        let aa = env.tempo_tx_env.as_ref().expect("AA simulation env");

        assert_eq!(aa.override_key_id, Some(key_id));
        assert_eq!(aa.aa_calls.len(), 1);
        assert_eq!(aa.aa_calls[0].to, TxKind::Call(target));
        assert!(matches!(aa.signature, TempoSignature::Keychain(_)));
        assert_eq!(env.execution_context(), ExecutionContext::Simulation);
        assert_eq!(
            env.unique_tx_identifier,
            Some(RPC_SIMULATION_UNIQUE_TX_IDENTIFIER)
        );
    }

    #[test]
    fn access_key_request_rejects_multisig_simulation_fields() {
        let request = TempoTransactionRequest {
            key_id: Some(address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")),
            multisig_signature_count: Some(1),
            ..Default::default()
        };

        let err = request
            .try_into_tempo_tx_env(TempoTxEnv::default(), true)
            .expect_err("access-key and multisig simulation fields conflict");
        assert_eq!(
            err.to_string(),
            "keyId cannot be combined with native multisig simulation fields"
        );
    }

    #[test]
    fn multisig_simulation_preserves_contract_creation() {
        let account = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let initcode = Bytes::from_static(&[0x60, 0x00]);
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                input: initcode.clone().into(),
                ..Default::default()
            },
            multisig_signature_count: Some(1),
            ..Default::default()
        };

        let env = request
            .try_into_tempo_tx_env(TempoTxEnv::default(), true)
            .expect("valid multisig creation simulation");
        let calls = &env.tempo_tx_env.expect("AA simulation env").aa_calls;

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].to, TxKind::Create);
        assert_eq!(calls[0].input, initcode);
    }

    #[test]
    fn multisig_simulation_hint_preserves_nested_primitive_types() {
        let account = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let nested_account = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let target = address!("0xcccccccccccccccccccccccccccccccccccccccc");
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                to: Some(TxKind::Call(target)),
                ..Default::default()
            },
            key_type: Some(SignatureType::Secp256k1),
            multisig_simulation_hint: Some(MultisigSimulationHint {
                account,
                owner_count: 1,
                approvals: vec![MultisigSimulationApproval::Multisig(Box::new(
                    MultisigSimulationHint {
                        account: nested_account,
                        owner_count: 2,
                        approvals: vec![
                            MultisigSimulationApproval::Primitive {
                                key_type: SignatureType::P256,
                                key_data: None,
                            },
                            MultisigSimulationApproval::Primitive {
                                key_type: SignatureType::WebAuthn,
                                key_data: Some(Bytes::from_static(&[0x00, 0x80])),
                            },
                        ],
                    },
                ))],
            }),
            ..Default::default()
        };

        let env = request
            .try_into_tempo_tx_env(TempoTxEnv::default(), true)
            .expect("valid simulation request");
        let signature = env
            .tempo_tx_env
            .expect("AA simulation env")
            .signature
            .as_multisig()
            .expect("outer multisig")
            .clone();
        assert_eq!(signature.account(), account);
        assert_eq!(signature.signature_count(), 1);
        assert_eq!(signature.simulation_config_owner_count(), None);
        let nested = signature.signatures()[0]
            .as_multisig()
            .expect("nested multisig");
        assert_eq!(nested.account(), nested_account);
        assert_eq!(nested.signature_count(), 2);
        assert_eq!(nested.simulation_config_owner_count(), Some(2));
        assert!(matches!(
            &nested.signatures()[0],
            TempoSignature::Primitive(tempo_primitives::transaction::PrimitiveSignature::P256(_))
        ));
        let TempoSignature::Primitive(tempo_primitives::transaction::PrimitiveSignature::WebAuthn(
            signature,
        )) = &nested.signatures()[1]
        else {
            panic!("second nested approval should use WebAuthn")
        };
        assert_eq!(signature.webauthn_data.len(), 128);
    }

    #[test]
    fn unknown_multisig_primitive_uses_conservative_webauthn_cost() {
        use tempo_primitives::transaction::{
            MAX_MULTISIG_OWNER_SIGNATURE_BYTES, MAX_WEBAUTHN_SIGNATURE_LENGTH,
        };

        let account = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let target = address!("0xcccccccccccccccccccccccccccccccccccccccc");
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                to: Some(TxKind::Call(target)),
                ..Default::default()
            },
            key_type: Some(SignatureType::Secp256k1),
            multisig_simulation_hint: Some(MultisigSimulationHint {
                account,
                owner_count: 1,
                approvals: vec![MultisigSimulationApproval::UnknownPrimitive],
            }),
            ..Default::default()
        };

        let env = request
            .try_into_tempo_tx_env(TempoTxEnv::default(), true)
            .expect("valid simulation request");
        let signature = env
            .tempo_tx_env
            .expect("AA simulation env")
            .signature
            .as_multisig()
            .expect("outer multisig")
            .signatures()[0]
            .clone();
        assert_eq!(
            signature.encoded_length(),
            MAX_MULTISIG_OWNER_SIGNATURE_BYTES
        );
        let TempoSignature::Primitive(tempo_primitives::transaction::PrimitiveSignature::WebAuthn(
            signature,
        )) = signature
        else {
            panic!("unknown primitive should use a WebAuthn mock")
        };

        assert_eq!(
            signature.webauthn_data.len(),
            MAX_WEBAUTHN_SIGNATURE_LENGTH - 128
        );
        assert!(signature.webauthn_data.iter().all(|byte| *byte == 0xff));
    }

    #[test]
    fn multisig_signature_count_rejects_zero_sender() {
        let target = address!("0xcccccccccccccccccccccccccccccccccccccccc");
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(target)),
                ..Default::default()
            },
            multisig_signature_count: Some(1),
            ..Default::default()
        };

        let err = request
            .try_into_tempo_tx_env(TempoTxEnv::default(), true)
            .expect_err("zero multisig sender must be rejected");
        assert_eq!(err.to_string(), "multisig account cannot be zero");
    }

    #[test]
    fn multisig_init_rejects_oversized_mock_owner_signature() {
        use tempo_primitives::transaction::{InitMultisig, MultisigOwner};

        let init = InitMultisig {
            salt: B256::repeat_byte(0x55),
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: address!("0x1111111111111111111111111111111111111111"),
                weight: 1,
            }],
        };
        let account = init.account().expect("valid multisig config");
        let target = address!("0xcccccccccccccccccccccccccccccccccccccccc");
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                to: Some(TxKind::Call(target)),
                ..Default::default()
            },
            key_type: Some(SignatureType::WebAuthn),
            key_data: Some(Bytes::from([0x20, 0x00])),
            multisig_init: Some(init),
            ..Default::default()
        };

        let err = request
            .try_into_tempo_tx_env(TempoTxEnv::default(), true)
            .expect_err("oversized multisig approval must be rejected");
        assert_eq!(err.to_string(), "multisig owner signature too large");
    }
}
