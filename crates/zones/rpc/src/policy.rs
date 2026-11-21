//! Privacy policy enforcement helpers.
//!
//! Shared by [`ZoneRpcApi`](crate::ZoneRpcApi) implementations.

use alloy_consensus::transaction::SignerRecoverable;
use alloy_eips::eip2718::Decodable2718;
use alloy_network::TransactionBuilder;
use alloy_primitives::Address;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_primitives::{TempoTxEnvelope, transaction::FEE_PAYER_SIGNATURE_MARKER};
use zone_primitives::constants::CONTRACT_DEPLOYER_ALLOWLIST;

use crate::{auth::AuthContext, types::JsonRpcError};

/// Enforce all redacted RPC authorization rules for simulation-style requests.
pub fn enforce_authorized(
    request: &mut TempoTransactionRequest,
    auth: &AuthContext,
) -> Result<(), JsonRpcError> {
    enforce_from(request, auth)?;
    enforce_no_fee_payer_signature(request)?;
    enforce_contract_creation(request, auth.caller)
}

/// Enforce that `from` matches the authenticated caller.
///
/// - If `from` is omitted, sets it to `auth.caller`.
/// - If present and mismatched, returns `-32004 Account mismatch`.
pub fn enforce_from(
    request: &mut TempoTransactionRequest,
    auth: &AuthContext,
) -> Result<(), JsonRpcError> {
    match TransactionBuilder::from(request as &TempoTransactionRequest) {
        Some(from) if from != auth.caller => Err(JsonRpcError::account_mismatch()),
        None => {
            request.set_from(auth.caller);
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Reject requests that carry a concrete fee payer signature.
///
/// A concrete signature makes the simulation resolve the sponsor as the fee payer, so the
/// sponsor's private fee-token balance bounds the gas allowance that estimation errors report.
/// Zone execution also charges fee-payer-dependent costs (e.g. outbox withdrawal fees), so the
/// outcome would depend on sponsor state as well. Since T2 a fee payer signature always names an
/// account other than the sender, so there is no self-sponsored case to preserve.
///
/// [`FEE_PAYER_SIGNATURE_MARKER`] stays allowed: it never resolves to an account and only flags
/// the request as sponsored by a not-yet-known fee payer. Requests are rejected rather than
/// stripped because dropping the signature would make the sender the fee payer, changing
/// execution semantics.
pub fn enforce_no_fee_payer_signature(
    request: &TempoTransactionRequest,
) -> Result<(), JsonRpcError> {
    match request.fee_payer_signature {
        Some(signature) if signature != FEE_PAYER_SIGNATURE_MARKER => Err(
            JsonRpcError::invalid_params("fee payer signature not allowed"),
        ),
        _ => Ok(()),
    }
}

/// Apply the protocol contract-deployer allowlist to create-style transaction requests.
///
/// Plain Ethereum-style create requests (`to = null`) and Tempo AA calls to `TxKind::Create`
/// are rejected with `-32602 Invalid params` unless the caller is a protocol-allowed deployer.
pub fn enforce_contract_creation(
    request: &TempoTransactionRequest,
    caller: Address,
) -> Result<(), JsonRpcError> {
    enforce_contract_creation_with_allowlist(request, caller, CONTRACT_DEPLOYER_ALLOWLIST)
}

fn enforce_contract_creation_with_allowlist(
    request: &TempoTransactionRequest,
    caller: Address,
    allowlist: &[Address],
) -> Result<(), JsonRpcError> {
    if allowlist.contains(&caller) {
        return Ok(());
    }

    let outer_create = request.inner.to.is_some_and(|to| to.is_create());
    let implicit_plain_create = request.calls.is_empty() && request.inner.to.is_none();
    let tempo_create = request.calls.iter().any(|call| call.to.is_create());
    if outer_create || implicit_plain_create || tempo_create {
        return Err(JsonRpcError::invalid_params(
            "contract creation not supported on zones",
        ));
    }

    Ok(())
}

/// Decode a raw transaction and verify the recovered sender matches the
/// authenticated caller. Returns `-32003 Transaction rejected` on mismatch.
pub fn verify_raw_tx_sender(data: &[u8], auth: &AuthContext) -> Result<(), JsonRpcError> {
    let tx = TempoTxEnvelope::decode_2718_exact(data)
        .map_err(|_| JsonRpcError::invalid_params("failed to decode transaction"))?;

    let sender = tx
        .recover_signer()
        .map_err(|_| JsonRpcError::invalid_params("invalid transaction signature"))?;

    if sender != auth.caller {
        return Err(JsonRpcError::transaction_rejected());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
    use tempo_alloy::rpc::TempoTransactionRequest;
    use tempo_primitives::transaction::{Call, FEE_PAYER_SIGNATURE_MARKER};
    use test_case::test_case;

    use super::{
        enforce_authorized, enforce_contract_creation, enforce_contract_creation_with_allowlist,
        enforce_no_fee_payer_signature,
    };
    use crate::auth::{AuthContext, AuthSigner};

    fn call_target(byte: u8) -> TxKind {
        TxKind::Call(Address::repeat_byte(byte))
    }

    fn call_request(to: Option<TxKind>) -> TempoTransactionRequest {
        TempoTransactionRequest {
            inner: TransactionRequest {
                to,
                input: TransactionInput::new(Bytes::default()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn contract_creation_policy_allows_standard_call_request() {
        let request = call_request(Some(call_target(0x11)));
        assert!(enforce_contract_creation(&request, Address::repeat_byte(0x01)).is_ok());
    }

    #[test]
    fn contract_creation_policy_rejects_plain_create_request() {
        let request = call_request(None);
        let err = enforce_contract_creation(&request, Address::repeat_byte(0x01)).unwrap_err();
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "contract creation not supported on zones");
    }

    #[test]
    fn contract_creation_policy_rejects_explicit_outer_create_request() {
        let request = call_request(Some(TxKind::Create));
        let err = enforce_contract_creation(&request, Address::repeat_byte(0x01)).unwrap_err();
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "contract creation not supported on zones");
    }

    #[test]
    fn contract_creation_policy_allows_tempo_calls_without_outer_to() {
        let mut request = call_request(None);
        request.calls = vec![Call {
            to: call_target(0x22),
            value: U256::ZERO,
            input: Bytes::default(),
        }];

        assert!(enforce_contract_creation(&request, Address::repeat_byte(0x01)).is_ok());
    }

    #[test]
    fn contract_creation_policy_rejects_tempo_create_call() {
        let mut request = call_request(None);
        request.calls = vec![Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::default(),
        }];

        let err = enforce_contract_creation(&request, Address::repeat_byte(0x01)).unwrap_err();
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "contract creation not supported on zones");
    }

    #[test]
    fn contract_creation_policy_allows_designated_deployer() {
        let caller = Address::repeat_byte(0x11);
        let request = call_request(None);

        assert!(enforce_contract_creation_with_allowlist(&request, caller, &[]).is_err());
        assert!(enforce_contract_creation_with_allowlist(&request, caller, &[caller]).is_ok());
    }

    #[test_case(None, true; "no signature")]
    #[test_case(Some(FEE_PAYER_SIGNATURE_MARKER), true; "fee payer marker")]
    #[test_case(Some(Signature::test_signature()), false; "concrete signature")]
    fn fee_payer_signature_policy(signature: Option<Signature>, allowed: bool) {
        let mut request = call_request(Some(call_target(0x11)));
        request.fee_payer_signature = signature;

        let result = enforce_no_fee_payer_signature(&request);
        if allowed {
            assert!(result.is_ok());
        } else {
            let err = result.unwrap_err();
            assert_eq!(err.code, -32602);
            assert_eq!(err.message, "fee payer signature not allowed");
        }
    }

    #[test]
    fn enforce_authorized_rejects_concrete_fee_payer_signature() {
        let caller = Address::repeat_byte(0x01);
        let auth = AuthContext {
            caller,
            expires_at: u64::MAX,
            signer: AuthSigner::Root,
        };

        let mut request = call_request(Some(call_target(0x11)));
        request.inner.from = Some(caller);
        assert!(enforce_authorized(&mut request, &auth).is_ok());

        request.fee_payer_signature = Some(FEE_PAYER_SIGNATURE_MARKER);
        assert!(enforce_authorized(&mut request, &auth).is_ok());

        request.fee_payer_signature = Some(Signature::test_signature());
        let err = enforce_authorized(&mut request, &auth).unwrap_err();
        assert_eq!(err.code, -32602);
        assert_eq!(err.message, "fee payer signature not allowed");
    }
}
