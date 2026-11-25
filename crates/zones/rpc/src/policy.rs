//! Privacy policy enforcement helpers.
//!
//! Shared by [`ZoneRpcApi`](crate::ZoneRpcApi) implementations.

use alloy_consensus::transaction::SignerRecoverable;
use alloy_eips::eip2718::Decodable2718;
use alloy_network::TransactionBuilder;
use alloy_primitives::Address;
use alloy_sol_types::SolCall;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_contracts::zones::{IZoneAddressRegistry, ZONE_ADDRESS_REGISTRY_ADDRESS};
use tempo_primitives::TempoTxEnvelope;
use zone_primitives::constants::CONTRACT_DEPLOYER_ALLOWLIST;

use crate::{auth::AuthContext, types::JsonRpcError};

/// Enforce all redacted RPC authorization rules for simulation-style requests.
pub fn enforce_authorized(
    request: &mut TempoTransactionRequest,
    auth: &AuthContext,
) -> Result<(), JsonRpcError> {
    enforce_from(request, auth)?;
    enforce_contract_creation(request, auth.caller)
}

/// Refuse simulations of TIP-1094 `registerMaster` unless the caller is its recipient or its
/// named creator.
///
/// Its return value is the recipient's existing master ID, or the next sequential one, so a
/// simulation for someone else reveals their registrations and the registration count. Submitting
/// a registration on someone else's behalf is still allowed; only simulating one is refused.
pub fn enforce_registration_recipient(
    request: &TempoTransactionRequest,
    caller: Address,
) -> Result<(), JsonRpcError> {
    let registers_other = |to: Option<Address>, input: &[u8]| {
        to == Some(ZONE_ADDRESS_REGISTRY_ADDRESS)
            && IZoneAddressRegistry::registerMasterCall::abi_decode(input)
                .is_ok_and(|call| call.recipient != caller && call.creator != caller)
    };
    let outer = registers_other(
        request.inner.to.and_then(|to| to.to().copied()),
        request
            .inner
            .input
            .input()
            .map(|input| input.as_ref())
            .unwrap_or_default(),
    );
    let inner = request
        .calls
        .iter()
        .any(|call| registers_other(call.to.to().copied(), &call.input));
    if outer || inner {
        return Err(JsonRpcError::invalid_params(
            "registerMaster can only be simulated for the caller",
        ));
    }
    Ok(())
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
    use alloy_primitives::{Address, Bytes, TxKind, U256};
    use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
    use tempo_alloy::rpc::TempoTransactionRequest;
    use tempo_primitives::transaction::Call;

    use super::{
        IZoneAddressRegistry, SolCall, ZONE_ADDRESS_REGISTRY_ADDRESS, enforce_contract_creation,
        enforce_contract_creation_with_allowlist, enforce_registration_recipient,
    };

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

    #[test]
    fn simulating_register_master_for_another_recipient_is_refused() {
        let caller = Address::repeat_byte(0x11);
        let call = |recipient: Address, creator: Address| {
            let mut request = TempoTransactionRequest::default();
            request.inner.to = Some(alloy_primitives::TxKind::Call(
                ZONE_ADDRESS_REGISTRY_ADDRESS,
            ));
            request.inner.input = alloy_rpc_types_eth::TransactionInput::new(
                IZoneAddressRegistry::registerMasterCall {
                    recipient,
                    creator,
                    salt: alloy_primitives::B256::ZERO,
                }
                .abi_encode()
                .into(),
            );
            request
        };
        let other = Address::repeat_byte(0x22);
        assert!(enforce_registration_recipient(&call(caller, Address::ZERO), caller).is_ok());
        assert!(enforce_registration_recipient(&call(other, caller), caller).is_ok());
        assert!(enforce_registration_recipient(&call(other, Address::ZERO), caller).is_err());
        assert!(
            enforce_registration_recipient(&call(other, Address::repeat_byte(0x33)), caller)
                .is_err()
        );
    }
}
