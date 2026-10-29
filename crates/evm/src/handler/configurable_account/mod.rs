//! Configurable account transaction authority (TIP-1112, TIP-1113).

use super::{TempoEvmTypes, access_key_id};
use crate::{
    ExecutionContext, TempoAaTx, TempoInvalidTransaction, TempoTx as _, TempoTxEnv,
    transaction_error::{ConfigurableAccountError, RootKeyRole},
};
use alloy_consensus::Transaction as _;
use alloy_primitives::{Address, B256, TxKind};
use evm2::{
    Evm,
    evm::AccountInfo,
    registry::{HandlerError, HandlerResult},
    version::{GasId, GasParams},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    CONFIGURABLE_ACCOUNT_ADDRESS,
    configurable_account::{
        ConfigurableAccount, UpgradeEligibility, valid_account, valid_account_code,
    },
    error::TempoPrecompileError,
    storage::{ConfigCommitmentWriteGas, StorageCtx, account_config_commitment},
};
use tempo_primitives::transaction::{
    ConfigurableAccountSignature, ConfigurableAccountStateError, KeychainSignature, SignatureType,
    TempoSignature,
};

/// An independently signed role.
struct ConfigurableRole<'a> {
    signature: &'a ConfigurableAccountSignature,
    /// Role digest before configurable account domain separation.
    inner_digest: B256,
}

/// What [`validate_configurable_roles`] charges and loads for the configurable roles of a
/// transaction.
struct ConfigurableRoleCharges {
    extra_gas: u64,
    state_gas: u64,
    /// Configurable role accounts already loaded, in role order.
    accounts: Vec<Address>,
}

/// State of one account loaded (and warmed) for authorization checks.
struct LoadedAccount {
    was_cold: bool,
    invalid_code: bool,
    is_empty: bool,
    nonce: u64,
    commitment: B256,
}

impl TempoAaTx {
    /// The outer (direct or delegated) role, when a configurable account signs the transaction.
    fn configurable_role(&self) -> Option<ConfigurableRole<'_>> {
        match self.signature() {
            TempoSignature::ConfigurableAccount(signature) => Some(ConfigurableRole {
                signature,
                inner_digest: self.signature_hash(),
            }),
            TempoSignature::Keychain(keychain) => {
                keychain
                    .signature
                    .as_configurable_account()
                    .map(|signature| ConfigurableRole {
                        signature,
                        inner_digest: KeychainSignature::signing_hash(
                            self.signature_hash(),
                            keychain.user_address,
                        ),
                    })
            }
            TempoSignature::Primitive(_) => None,
        }
    }

    /// The configurable account an inline key authorization grants as an access key, if any.
    pub fn granted_configurable_account(&self) -> Option<Address> {
        self.tx()
            .key_authorization
            .as_ref()
            .filter(|auth| auth.key_type == SignatureType::ConfigurableAccount)
            .map(|auth| auth.key_id)
    }
}

impl TempoTxEnv {
    /// Seeds the transaction authority read by the configurable-account precompile.
    ///
    /// `upgradeAccount` must be the whole transaction: no other call and no authorization or key
    /// authorization that could change the account beside it.
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
        let direct = match aa.and_then(|aa| aa.signature().as_configurable_account()) {
            Some(signature) => signature.account(),
            // RPC simulation has no owner witness: a registered caller without an access-key
            // override stands in for its own quorum.
            None if matches!(self.execution_context(), ExecutionContext::Simulation)
                && aa.is_none_or(|aa| aa.override_key_id().is_none())
                && !StorageCtx.config_commitment(self.caller())?.is_zero() =>
            {
                self.caller()
            }
            None => Address::ZERO,
        };
        ConfigurableAccount::new().set_authority(self.caller(), direct, eligibility)
    }

    /// Whether the sender signs with a bare primitive key, as every non-AA transaction does.
    fn signed_by_primitive_root(&self) -> bool {
        self.as_aa().is_none_or(|aa| match aa.signature() {
            TempoSignature::Primitive(_) => true,
            TempoSignature::Keychain(_) | TempoSignature::ConfigurableAccount(_) => false,
        })
    }
}

/// Validates the account state every transaction role depends on, returning regular and state
/// intrinsic gas. Does no signature or quorum verification of its own (see [`verify`]), except
/// that T14 key-authorization and access-key identities are recovered to name the accounts
/// whose root-key retirement is checked.
///
/// Configurable roles are checked first. At T14, bare primitive authority is then rejected with
/// [`TempoInvalidTransaction::RootKeyRetired`] for any account with a nonzero configuration
/// commitment, in the order sender, key authorization signer, fee payer, access key. RPC
/// simulation skips only the sender check.
/// Loads and warms accounts, but does not register commitments.
/// Caller must charge both components.
/// Transaction access-list and beneficiary warmth must be initialized before loading non-caller
/// accounts.
pub(crate) fn validate_state(
    host: &mut Evm<'_, TempoEvmTypes>,
    envelope: &TempoTxEnv,
    spec: TempoHardfork,
) -> HandlerResult<(u64, u64)> {
    let ConfigurableRoleCharges {
        mut extra_gas,
        state_gas,
        mut accounts,
    } = match envelope.as_aa() {
        Some(aa) => validate_configurable_roles(host, aa, spec)?,
        // Non-AA transactions have no configurable roles or granted configurable account.
        None => ConfigurableRoleCharges {
            extra_gas: 0,
            state_gas: 0,
            accounts: Vec::new(),
        },
    };
    if spec.is_t14() {
        extra_gas += validate_root_keys(host, envelope, spec, &mut accounts)?;
        if let Some(aa) = envelope.as_aa() {
            extra_gas += granted_configurable_account_access_gas(host, aa, spec, &accounts)?;
        }
    }
    Ok((extra_gas, state_gas))
}

/// Verifies the owner quorum of the signed role. Sender recovery already verified and cached it,
/// so this only rechecks transactions built without recovery. RPC simulation must validate the
/// claimed owner quorum before constructing its mock witness; this function skips quorum recovery
/// only in that mode.
pub(crate) fn verify(
    context: ExecutionContext,
    aa: &TempoAaTx,
) -> Result<(), TempoInvalidTransaction> {
    match context {
        ExecutionContext::Transaction { .. } => {
            if let Some(role) = aa.configurable_role() {
                role.signature
                    .verify_approvals(role.inner_digest)
                    .map_err(ConfigurableAccountError::Quorum)?;
            }
        }
        ExecutionContext::Simulation => {}
    }
    Ok(())
}

/// Registers the commitment of the signing configurable account when it has none yet.
///
/// Runs after validation, authorization and fee collection, outside the batch checkpoint: the
/// initial registration persists on execution failure, while later owner updates stay inside it.
pub(crate) fn register_commitments(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
) -> HandlerResult<()> {
    let Some(role) = aa.configurable_role() else {
        return Ok(());
    };
    let (account, commitment) = (role.signature.account(), role.signature.config_commitment());
    StorageCtx::enter_evm_without_tip1060_accounting(host, || {
        // Re-read to avoid threading `validate_state`'s value through: nothing writes the
        // commitment in between, so both reads agree.
        if StorageCtx.config_commitment(account)?.is_zero() {
            StorageCtx.set_config_commitment(
                account,
                commitment,
                ConfigCommitmentWriteGas::Intrinsic,
            )?;
        }
        Ok::<(), TempoPrecompileError>(())
    })?;
    Ok(())
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

/// Loads and warms `address` once, reading its code, emptiness, nonce and commitment.
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
        invalid_code: !valid_account_code(account.code_hash(), commitment),
        is_empty: info.is_none_or(AccountInfo::is_empty),
        nonce: account.nonce(),
        commitment,
    })
}

/// Configurable roles only: returns extra gas, state gas, and the role accounts already loaded.
fn validate_configurable_roles(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
    spec: TempoHardfork,
) -> HandlerResult<ConfigurableRoleCharges> {
    let caller = aa.signer();
    let tx = aa.tx();
    let role = aa.configurable_role();
    // Context rejection must not depend on account reads.
    if role.is_some() && !spec.is_t14() {
        return Err(ConfigurableAccountError::UnsupportedContext.into());
    }
    if spec.is_t14() && aa.signature().is_keychain() {
        let account = load_account(host, caller, spec)?;
        if !account.commitment.is_zero() && account.invalid_code {
            return Err(ConfigurableAccountError::InvalidAccount { account: caller }.into());
        }
    }
    let Some(role) = role else {
        return Ok(ConfigurableRoleCharges {
            extra_gas: 0,
            state_gas: 0,
            accounts: Vec::new(),
        });
    };
    let signature = role.signature;
    let address = signature.account();
    if aa.signature().is_configurable_account() && address != caller {
        return Err(ConfigurableAccountError::AccountMismatch {
            expected: caller,
            actual: address,
        }
        .into());
    }
    if !valid_account(address, spec) {
        return Err(ConfigurableAccountError::InvalidAccount { account: address }.into());
    }
    let account = load_account(host, address, spec)?;
    if account.invalid_code {
        return Err(ConfigurableAccountError::InvalidAccount { account: address }.into());
    }
    let mut extra_gas = 0;
    let mut state_gas = 0;
    if address != caller {
        extra_gas += account_access_gas(&host.version().gas_params, account.was_cold);
    }
    signature
        .validate_account_commitment(account.commitment)
        .map_err(|error| match error {
            ConfigurableAccountStateError::CommitmentMismatch { expected, actual } => {
                HandlerError::from(ConfigurableAccountError::ConfigurationCommitmentMismatch {
                    expected,
                    actual,
                })
            }
            ConfigurableAccountStateError::UnregisteredVersion { .. }
            | ConfigurableAccountStateError::InitialAccountMismatch { .. } => {
                ConfigurableAccountError::InvalidAccount { account: address }.into()
            }
        })?;
    if account.commitment.is_zero() {
        extra_gas += signature
            .config()
            .derivation_gas()
            .ok_or(TempoPrecompileError::OutOfGas)?;
        let gas = &host.version().gas_params;
        // TIP-1108 prices the commitment write like account creation.
        extra_gas += gas.get(GasId::NewAccountCost);
        state_gas += gas.new_account_state_gas();
        // The sender's creation is free here only when another TIP-1000 charge pays it: the
        // nonce-zero charge of a protocol-nonce transaction, or the first-call CREATE charge of
        // a 2D or expiring nonce key.
        let pays_nonce_zero_account_gas = tx.nonce_key.is_zero() && tx.nonce == 0;
        let pays_first_call_create_account_gas = !tx.nonce_key.is_zero()
            && tx.calls.first().is_some_and(|call| call.to.is_create())
            && account.nonce == 0;
        let sender_creation_paid = address == caller
            && (pays_nonce_zero_account_gas || pays_first_call_create_account_gas);
        if account.is_empty && !sender_creation_paid {
            extra_gas += gas.get(GasId::NewAccountCost);
            state_gas += gas.new_account_state_gas();
        }
    }
    Ok(ConfigurableRoleCharges {
        extra_gas,
        state_gas,
        accounts: vec![address],
    })
}

/// Rejects bare primitive authority of accounts with a nonzero commitment (TIP-1112).
///
/// Each distinct non-caller account is charged one account access, deduplicated against
/// `accounts` (which collects every charged account). Configurable signers and delegates always
/// carry a commitment and are never primitive roots, so only primitive signatures are checked.
fn validate_root_keys(
    host: &mut Evm<'_, TempoEvmTypes>,
    envelope: &TempoTxEnv,
    spec: TempoHardfork,
    accounts: &mut Vec<Address>,
) -> HandlerResult<u64> {
    let caller = envelope.caller();
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
    if let Some(keychain) = aa.signature().as_keychain()
        && !keychain.signature.is_configurable_account()
        && let Some(key_id) = access_key_id(aa)?
    {
        check(host, key_id, RootKeyRole::AccessKey)?;
    }
    Ok(extra_gas)
}

/// The inline grant's code check runs with intrinsic-only metering. Charge its account load
/// here, unless caller loading or a configurable signing role already accounts for that address.
/// Merely naming a recipient neither validates an owner witness nor registers a commitment.
fn granted_configurable_account_access_gas(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
    spec: TempoHardfork,
    accounts: &[Address],
) -> HandlerResult<u64> {
    if let Some(granted) = aa.granted_configurable_account()
        && granted != aa.signer()
        && !accounts.contains(&granted)
    {
        let loaded = load_account(host, granted, spec)?;
        return Ok(account_access_gas(
            &host.version().gas_params,
            loaded.was_cold,
        ));
    }
    Ok(0)
}
