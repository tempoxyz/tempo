//! Configurable account transaction authority (TIP-1112, TIP-1113).

use super::{TempoEvmTypes, access_key_id};
use crate::{
    ExecutionContext, TempoInvalidTransaction, TempoTx as _, TempoTxEnv,
    transaction_error::RootKeyRole,
};
use alloy_consensus::Transaction as _;
use alloy_primitives::{Address, B256, TxKind};
use evm2::{
    Evm,
    registry::HandlerResult,
    version::{GasId, GasParams},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    CONFIGURABLE_ACCOUNT_ADDRESS,
    configurable_account::{ConfigurableAccount, UpgradeEligibility},
    error::TempoPrecompileError,
    storage::account_config_commitment,
};
use tempo_primitives::transaction::TempoSignature;

/// State of one account loaded (and warmed) for authorization checks.
struct LoadedAccount {
    was_cold: bool,
    commitment: B256,
}

impl TempoTxEnv {
    /// Seeds the transaction authority read by the configurable-account precompile.
    ///
    /// `upgradeAccount` must be the whole transaction: no other call and no authorization or key
    /// authorization that could change the account beside it. No signature type authorizes a
    /// configurable account directly, so no account is directly authorized.
    pub(crate) fn seed_upgrade_authority(&self) -> Result<(), TempoPrecompileError> {
        let aa = self.as_aa();
        let sole_call = match aa {
            None => {
                self.kind() == TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS)
                    && self
                        .as_eip7702()
                        .is_none_or(|tx| tx.authorization_list.is_empty())
            }
            Some(aa) => {
                let tx = aa.tx();
                matches!(
                    tx.calls.as_slice(),
                    [call] if call.to == TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS)
                ) && tx.tempo_authorization_list.is_empty()
                    && tx.key_authorization.is_none()
            }
        };
        let eligibility = if !sole_call {
            UpgradeEligibility::NotSoleCall
        } else if !self.signed_by_primitive_root() {
            UpgradeEligibility::NotPrimitiveRoot
        } else {
            UpgradeEligibility::PrimitiveRoot
        };
        ConfigurableAccount::new().set_authority(self.caller(), Address::ZERO, eligibility)
    }

    /// Whether the sender signs with a bare primitive key, as every non-AA transaction does.
    fn signed_by_primitive_root(&self) -> bool {
        self.as_aa().is_none_or(|aa| match aa.signature() {
            TempoSignature::Primitive(_) => true,
            TempoSignature::Keychain(_) => false,
        })
    }
}

/// Validates the account state every transaction role depends on, returning the regular
/// intrinsic gas. Does no signature verification of its own, except that T14 key-authorization
/// and access-key identities are recovered to name the accounts whose root-key retirement is
/// checked.
///
/// At T14, bare primitive authority is rejected with
/// [`TempoInvalidTransaction::RootKeyRetired`] for any account with a nonzero configuration
/// commitment, in the order sender, key authorization signer, fee payer, access key. RPC
/// simulation skips only the sender check.
/// Loads and warms accounts, but does not register commitments.
/// Caller must charge the returned gas.
/// Transaction access-list and beneficiary warmth must be initialized before loading non-caller
/// accounts.
pub(crate) fn validate_state(
    host: &mut Evm<'_, TempoEvmTypes>,
    envelope: &TempoTxEnv,
    spec: TempoHardfork,
) -> HandlerResult<u64> {
    if !spec.is_t14() {
        return Ok(0);
    }
    validate_root_keys(host, envelope, spec)
}

/// Gas for loading one account: a warm read, plus the cold surcharge when it was not yet accessed.
pub fn account_access_gas(gas: &GasParams, is_cold: bool) -> u64 {
    gas.get(GasId::WarmStorageReadCost)
        + if is_cold {
            gas.cold_account_additional_cost()
        } else {
            0
        }
}

/// Loads and warms `address` once, reading its commitment.
fn load_account(
    host: &mut Evm<'_, TempoEvmTypes>,
    address: Address,
    spec: TempoHardfork,
) -> HandlerResult<LoadedAccount> {
    let mut account = host.state_mut().account(&address)?;
    let was_cold = account.warm();
    let info = account.get();
    let commitment = info.map_or(Ok(B256::ZERO), |info| account_config_commitment(info, spec))?;
    Ok(LoadedAccount {
        was_cold,
        commitment,
    })
}

/// Rejects bare primitive authority of accounts with a nonzero commitment (TIP-1112).
///
/// Each distinct non-caller account is charged one account access.
fn validate_root_keys(
    host: &mut Evm<'_, TempoEvmTypes>,
    envelope: &TempoTxEnv,
    spec: TempoHardfork,
) -> HandlerResult<u64> {
    let caller = envelope.caller();
    let mut accounts = Vec::new();
    let mut extra_gas = 0;
    let mut check = |host: &mut Evm<'_, TempoEvmTypes>,
                     account: Address,
                     role: RootKeyRole|
     -> HandlerResult<()> {
        let loaded = load_account(host, account, spec)?;
        if account != caller && !accounts.contains(&account) {
            extra_gas += account_access_gas(&host.version().gas_params, loaded.was_cold);
        }
        accounts.push(account);
        if loaded.commitment.is_zero() {
            Ok(())
        } else {
            Err(TempoInvalidTransaction::RootKeyRetired { account, role }.into())
        }
    };
    // RPC simulation supplies a placeholder sender signature.
    let simulation = matches!(envelope.execution_context(), ExecutionContext::Simulation);
    if !simulation && envelope.signed_by_primitive_root() {
        check(host, caller, RootKeyRole::Sender)?;
    }
    let Some(aa) = envelope.as_aa() else {
        return Ok(extra_gas);
    };
    if let Some(auth) = &aa.tx().key_authorization {
        let signer = auth
            .recover_signer()
            .map_err(|_| TempoInvalidTransaction::KeyAuthorizationSignatureRecoveryFailed)?;
        check(host, signer, RootKeyRole::KeyAuthorizationSigner)?;
    }
    if aa.tx().fee_payer_signature.is_some() {
        let fee_payer = envelope
            .fee_payer()
            .map_err(|_| TempoInvalidTransaction::InvalidFeePayerSignature)?;
        check(host, fee_payer, RootKeyRole::FeePayer)?;
    }
    if let Some(key_id) = access_key_id(aa)? {
        check(host, key_id, RootKeyRole::AccessKey)?;
    }
    Ok(extra_gas)
}
