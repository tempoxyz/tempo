//! Zone transaction policies shared by pool admission and block execution.

use alloy_primitives::Address;
use tempo_evm::{TempoInvalidTransaction, TempoTx, TempoTxEnv};

/// Validates transaction policies enforced by the Zone EVM.
pub fn validate_transaction(
    tx: &TempoTxEnv,
    contract_deployer_allowlist: &[Address],
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

    Ok(())
}

fn contract_creation_deployer(tx: &TempoTxEnv) -> Option<Address> {
    tx.calls()
        .any(|(kind, _)| kind.is_create())
        .then(|| tx.caller())
}
