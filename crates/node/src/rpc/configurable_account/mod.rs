use alloy_primitives::{Address, B256, KECCAK256_EMPTY};
use reth_errors::RethError;
use reth_evm::Database;
use reth_rpc_eth_types::EthApiError;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoBlockExt, transaction_error::ConfigurableAccountError};
use tempo_precompiles::configurable_account::valid_account;
use tempo_primitives::{
    SignatureType, TempoSignature, TempoTxEnvelope,
    account::decode_config_commitment,
    transaction::{
        ConfigurableAccountSignature, ConfigurableAccountStateError, SignedKeyAuthorization,
    },
};

/// Checks independent role witnesses against the exact database selected for this call.
pub(super) fn prepare_configurable_account_simulation(
    request: &mut TempoTransactionRequest,
    hardfork: TempoHardfork,
    block: &TempoBlockExt,
    db: &mut impl Database<Error: Into<EthApiError>>,
) -> Result<(), EthApiError> {
    request.configurable_account_simulation_prepared = false;
    if !request.has_configurable_simulation() {
        return Ok(());
    }
    let invalid = |message: &str| EthApiError::InvalidParams(message.into());
    if !hardfork.is_t14() {
        return Err(invalid(
            "configurable account simulation requires T14 at the requested state",
        ));
    }
    let factory = block
        .configurable_account_recovery_factory()
        .ok_or_else(|| {
            EthApiError::InvalidParams(ConfigurableAccountError::FactoryNotConfigured.to_string())
        })?;
    let parent = request
        .inner
        .from
        .ok_or_else(|| invalid("configurable account simulation requires from"))?;
    if request.key_id == Some(parent)
        && (request.configurable_account_simulation.is_some()
            || request.configurable_account_simulation_signature.is_some())
    {
        return Err(invalid("a configurable delegate cannot be its own parent"));
    }
    if let Some(spec) = request.configurable_account_simulation.as_ref() {
        let account = request.key_id.unwrap_or(parent);
        let signature = spec
            .mock_signature(account)
            .map_err(|error| EthApiError::InvalidParams(error.to_string()))?;
        validate_witness(&signature, factory, hardfork, db)?;
        request.configurable_account_simulation_signature = Some(signature);
        // Retain the source witness so every estimation pass rebuilds and checks its mock.
    } else if request.configurable_account_simulation_signature.is_some() {
        return Err(invalid(
            "configurable account simulation signature requires its source witness",
        ));
    }
    if let Some(spec) = request.key_authorization_simulation.as_ref() {
        let authorization = request
            .key_authorization
            .as_ref()
            .ok_or_else(|| invalid("keyAuthorizationSimulation requires keyAuthorization"))?;
        let signer = spec.signer.unwrap_or(parent);
        validate_grant_binding(
            authorization,
            parent,
            signer,
            request.key_id,
            "admin-signed grant simulation requires its signer as keyId and the parent as account",
        )?;
        let signature = spec
            .mock_signature(signer)
            .map_err(|error| EthApiError::InvalidParams(error.to_string()))?;
        validate_witness(&signature, factory, hardfork, db)?;
        request.set_key_authorization(authorization.authorization.clone().into_signed(signature));
    } else if let Some(authorization) = &request.key_authorization
        && let Some(signature) = authorization.signature.as_configurable_account()
    {
        validate_grant_binding(
            authorization,
            parent,
            signature.account(),
            request.key_id,
            "admin-signed grant requires its signer as keyId and the parent as account",
        )?;
        validate_witness(signature, factory, hardfork, db)?;
        signature
            .verify_approvals(authorization.signature_hash())
            .map_err(|error| {
                EthApiError::InvalidParams(ConfigurableAccountError::from(error).to_string())
            })?;
    }
    request.configurable_account_simulation_prepared = true;
    Ok(())
}

/// Removes simulation hints while retaining the exact real grant for the unsigned response.
pub(super) fn prepare_fill_output(
    request: &mut TempoTransactionRequest,
) -> Result<Option<SignedKeyAuthorization>, EthApiError> {
    if request.key_authorization_simulation.is_some() {
        return Err(EthApiError::InvalidParams("fillTransaction requires a real signed grant; keyAuthorizationSimulation is supported only by call and estimateGas".into()));
    }
    request.configurable_account_simulation = None;
    request.configurable_account_simulation_signature = None;
    request.configurable_account_simulation_prepared = false;
    // Keep AA selection while passing the ordinary unsigned converter.
    request.set_key_type(SignatureType::Secp256k1);
    request.key_data = None;
    Ok(request.key_authorization.take())
}

pub(super) fn restore_fill_authorization(
    tx: TempoTxEnvelope,
    authorization: Option<SignedKeyAuthorization>,
) -> Result<TempoTxEnvelope, EthApiError> {
    let TempoTxEnvelope::AA(signed) = tx else {
        return Err(EthApiError::InvalidParams(
            "configurable fill requires an AA transaction".into(),
        ));
    };
    let mut tx = signed.strip_signature();
    tx.key_authorization = authorization;
    Ok(tx.into_signed(TempoSignature::default()).into())
}

/// Rejects a grant bound to another account; a grant signed by an admin (`signer != parent`) must
/// name the parent as `account` and use the signer as `keyId`.
fn validate_grant_binding(
    authorization: &SignedKeyAuthorization,
    parent: Address,
    signer: Address,
    key_id: Option<Address>,
    admin_error: &str,
) -> Result<(), EthApiError> {
    if let Some(actual) = authorization.account
        && actual != parent
    {
        return Err(EthApiError::InvalidParams(format!(
            "key authorization account mismatch: expected {parent}, actual {actual}"
        )));
    }
    if signer != parent && (authorization.account != Some(parent) || key_id != Some(signer)) {
        return Err(EthApiError::InvalidParams(admin_error.into()));
    }
    Ok(())
}

fn validate_witness(
    signature: &ConfigurableAccountSignature,
    factory: Address,
    hardfork: TempoHardfork,
    db: &mut impl Database<Error: Into<EthApiError>>,
) -> Result<(), EthApiError> {
    let account = signature.account();
    if !valid_account(account, hardfork) {
        return Err(EthApiError::InvalidParams(
            ConfigurableAccountError::InvalidAccount { account }.to_string(),
        ));
    }
    // A missing account is an unregistered one: no code and the zero commitment.
    let info = db.get_account(&account).map_err(Into::into)?;
    if info
        .as_ref()
        .is_some_and(|info| info.code_hash != KECCAK256_EMPTY)
    {
        return Err(EthApiError::InvalidParams(format!(
            "configurable account {account} has code at the requested state"
        )));
    }
    let stored = info
        .map_or(Ok(B256::ZERO), |info| {
            decode_config_commitment(&info.extension, hardfork)
        })
        .map_err(|error| EthApiError::Internal(RethError::msg(error.to_string())))?;
    signature
        .validate_account_commitment(stored, Some(factory))
        .map_err(|error| {
            let message = match error {
                ConfigurableAccountStateError::CommitmentMismatch { .. } => {
                    format!("{error} for {account} at the requested state")
                }
                ConfigurableAccountStateError::InitialAccountMismatch { expected, actual } => {
                    format!("initial configurable account mismatch at the requested state: expected {expected}, actual {actual}")
                }
                _ => error.to_string(),
            };
            EthApiError::InvalidParams(message)
        })
}

#[cfg(test)]
mod tests;
