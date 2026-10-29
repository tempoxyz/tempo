//! Zone transaction policies shared by pool admission and block execution.

use alloy_primitives::{Address, TxKind};
use alloy_sol_types::SolCall;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount};
use tempo_evm::{
    TempoInvalidTransaction, TempoTx, TempoTxEnv, transaction_error::ConfigurableAccountError,
};

/// Validates transaction policies enforced by the Zone EVM.
pub fn validate_transaction(
    tx: &TempoTxEnv,
    contract_deployer_allowlist: &[Address],
    spec: TempoHardfork,
) -> Result<(), TempoInvalidTransaction> {
    let has_eip7702_authorizations = tx
        .as_eip7702()
        .is_some_and(|tx| !tx.authorization_list.is_empty());
    let has_tempo_authorizations = tx
        .as_aa()
        .is_some_and(|tx| !tx.inner().tx().tempo_authorization_list.is_empty());
    if has_eip7702_authorizations || has_tempo_authorizations {
        return Err(TempoInvalidTransaction::CallsValidation(
            "authorization lists are not supported",
        ));
    }

    if contract_creation_deployer(tx)
        .is_some_and(|deployer| !contract_deployer_allowlist.contains(&deployer))
    {
        return Err(TempoInvalidTransaction::CallsValidation(
            "contract creation is not supported",
        ));
    }

    // Configurable accounts stay blocked until zones sync configurations (TIP-1114 Zones).
    if spec.is_t14()
        && (tx.as_aa().is_some_and(|aa| {
            aa.signature().is_or_wraps_configurable_account()
                || aa.granted_configurable_account().is_some()
        }) || tx.calls().any(|(kind, input)| {
            kind == TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS)
                && matches!(
                    input.first_chunk(),
                    Some(
                        &IConfigurableAccount::updateConfigCall::SELECTOR
                            | &IConfigurableAccount::upgradeAccountCall::SELECTOR
                    )
                )
        }))
    {
        return Err(ConfigurableAccountError::UnsupportedContext.into());
    }

    Ok(())
}

fn contract_creation_deployer(tx: &TempoTxEnv) -> Option<Address> {
    tx.calls()
        .any(|(kind, _)| kind.is_create())
        .then(|| tx.caller())
}
