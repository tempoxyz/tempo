use super::TempoTransactionRequest;
use alloy_consensus::error::ValueError;
use alloy_primitives::{Address, B256, Bytes, Signature};
use core::num::NonZeroU64;
use tempo_primitives::{
    SignatureType, TempoSignature,
    transaction::{Call, RecoveredTempoAuthorization},
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

        if is_aa && self.calls.is_empty() && self.inner.to.is_none() {
            return Err(ValueError::new(self, "empty calls list"));
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
            let key_type = key_type.unwrap_or(SignatureType::Secp256k1);
            let mock_signature =
                create_mock_tempo_sig(&key_type, key_data.as_ref(), key_id, caller_addr, is_t1c);

            let mut calls = calls;
            if let Some(to) = &inner.to {
                calls.push(Call {
                    to: *to,
                    value: inner.value.unwrap_or_default(),
                    input: inner.input.clone().into_input().unwrap_or_default(),
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
}
