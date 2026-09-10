use alloy_primitives::Address;
use reth_evm::revm::Database;
use reth_rpc_eth_types::EthApiError;
use tempo_alloy::rpc::{TempoTransactionRequest, create_mock_native_multisig_signature};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::{
    TempoBlockEnv, TempoSignature, account::decode_config_commitment,
    transaction::MultisigSignature,
};
use tempo_revm::native_multisig::{NativeAuthorization, NativeMultisigError};

/// Checks independent role witnesses against the exact database selected for this call.
pub(super) fn prepare_native_multisig_simulation(
    request: &mut TempoTransactionRequest,
    hardfork: TempoHardfork,
    block: &TempoBlockEnv,
    db: &mut impl Database<Error: Into<EthApiError>>,
) -> Result<(), EthApiError> {
    request.multisig_simulation_prepared = false;
    if !request.has_configurable_simulation() {
        return Ok(());
    }
    let invalid = |message: &str| EthApiError::InvalidParams(message.into());
    if !hardfork.is_t12() {
        return Err(invalid(
            "native multisig simulation requires T12 at the requested state",
        ));
    }
    let factory = block
        .multisig_recovery_factory
        .filter(|address| !address.is_zero())
        .ok_or_else(|| {
            EthApiError::InvalidParams(NativeMultisigError::FactoryNotConfigured.to_string())
        })?;
    let parent = request
        .inner
        .from
        .ok_or_else(|| invalid("native multisig simulation requires from"))?;
    if request.key_id == Some(parent)
        && (request.multisig_simulation.is_some()
            || request.multisig_simulation_signature.is_some())
    {
        return Err(invalid("a configurable delegate cannot be its own parent"));
    }
    if let Some(spec) = request.multisig_simulation.as_ref() {
        let account = request.key_id.unwrap_or(parent);
        let signature = create_mock_native_multisig_signature(account, spec)
            .map_err(EthApiError::InvalidParams)?;
        validate_witness(&signature, factory, hardfork, db)?;
        request.multisig_simulation_signature = Some(signature);
        // Retain the source witness so every estimation pass rebuilds and checks its mock.
    } else if request.multisig_simulation_signature.is_some() {
        return Err(invalid(
            "multisig simulation signature requires its source witness",
        ));
    }
    if let Some(spec) = request.key_authorization_simulation.as_ref() {
        let authorization = request
            .key_authorization
            .as_ref()
            .ok_or_else(|| invalid("keyAuthorizationSimulation requires keyAuthorization"))?;
        if authorization
            .account
            .is_some_and(|account| account != parent)
        {
            return Err(EthApiError::InvalidParams(format!(
                "key authorization account mismatch: expected {parent}, actual {}",
                authorization.account.unwrap()
            )));
        }
        let signature = create_mock_native_multisig_signature(parent, spec)
            .map_err(EthApiError::InvalidParams)?;
        validate_witness(&signature, factory, hardfork, db)?;
        request.key_authorization = Some(
            authorization
                .authorization
                .clone()
                .into_signed(TempoSignature::Multisig(signature)),
        );
    } else if let Some(authorization) = &request.key_authorization
        && let TempoSignature::Multisig(signature) = &authorization.signature
    {
        if let Some(actual) = authorization.account
            && actual != parent
        {
            return Err(EthApiError::InvalidParams(format!(
                "key authorization account mismatch: expected {parent}, actual {actual}"
            )));
        }
        if signature.account() != parent {
            return Err(EthApiError::InvalidParams(format!(
                "multisig signature account mismatch: expected {parent}, actual {}",
                signature.account()
            )));
        }
        validate_witness(signature, factory, hardfork, db)?;
        NativeAuthorization {
            signature,
            inner_digest: authorization.signature_hash(),
        }
        .verify()
        .map_err(|error| EthApiError::InvalidParams(error.to_string()))?;
    }
    request.multisig_simulation_prepared = true;
    Ok(())
}

fn validate_witness(
    signature: &MultisigSignature,
    factory: Address,
    hardfork: TempoHardfork,
    db: &mut impl Database<Error: Into<EthApiError>>,
) -> Result<(), EthApiError> {
    let account = signature.account();
    if !tempo_precompiles::native_multisig::valid_account(account, hardfork) {
        return Err(EthApiError::InvalidParams(
            NativeMultisigError::InvalidAccount { account }.to_string(),
        ));
    }
    let info = db.basic(account).map_err(Into::into)?.unwrap_or_default();
    if !info.is_empty_code_hash() {
        return Err(EthApiError::InvalidParams(format!(
            "configurable account {account} has code at the requested state"
        )));
    }
    let stored = decode_config_commitment(&info.extension, hardfork.is_t12())
        .map_err(|error| EthApiError::Internal(reth_errors::RethError::msg(error.to_string())))?;
    let supplied = signature.config_commitment();
    if supplied.is_zero() || (!stored.is_zero() && stored != supplied) {
        return Err(EthApiError::InvalidParams(format!(
            "{} for {account} at the requested state",
            NativeMultisigError::ConfigurationCommitmentMismatch {
                expected: stored,
                actual: supplied
            },
        )));
    }
    if stored.is_zero() {
        if signature.config().version != 0 {
            return Err(EthApiError::InvalidParams(format!(
                "unregistered configuration version mismatch: expected 0, actual {}",
                signature.config().version
            )));
        }
        let expected = signature
            .config()
            .derive_account(factory)
            .map_err(|error| EthApiError::InvalidParams(error.to_string()))?;
        if expected != account {
            return Err(EthApiError::InvalidParams(format!(
                "initial multisig account mismatch at the requested state: expected {expected}, actual {account}"
            )));
        }
    }
    Ok(())
}

/// Removes simulation hints while retaining the exact real grant for the unsigned response.
pub(super) fn prepare_fill_output(
    request: &mut TempoTransactionRequest,
) -> Result<Option<tempo_primitives::transaction::SignedKeyAuthorization>, EthApiError> {
    if request.key_authorization_simulation.is_some() {
        return Err(EthApiError::InvalidParams("fillTransaction requires a real signed grant; keyAuthorizationSimulation is supported only by call and estimateGas".into()));
    }
    request.multisig_simulation = None;
    request.multisig_simulation_signature = None;
    request.multisig_simulation_prepared = false;
    // Keep AA selection while passing the ordinary unsigned converter.
    request.key_type = Some(tempo_primitives::SignatureType::Secp256k1);
    request.key_data = None;
    Ok(request.key_authorization.take())
}

pub(super) fn restore_fill_authorization(
    tx: tempo_primitives::TempoTxEnvelope,
    authorization: Option<tempo_primitives::transaction::SignedKeyAuthorization>,
) -> Result<tempo_primitives::TempoTxEnvelope, EthApiError> {
    let tempo_primitives::TempoTxEnvelope::AA(signed) = tx else {
        return Err(EthApiError::InvalidParams(
            "configurable fill requires an AA transaction".into(),
        ));
    };
    let mut tx = signed.strip_signature();
    tx.key_authorization = authorization;
    Ok(tx.into_signed(TempoSignature::default()).into())
}

#[cfg(test)]
mod tests;
