//! Configurable account authorization (TIP-1112) shared by execution, pool validation and
//! simulation.

use super::{TempoEvmTypes, access_key_id};
use crate::{
    ExecutionContext, TempoAaTx, TempoInvalidTransaction, TempoTx, TempoTxEnv,
    transaction_error::{ConfigurableAccountError, RootKeyRole},
};
use alloy_consensus::Transaction as _;
use alloy_eips::eip7702::{RecoveredAuthority, RecoveredAuthorization};
use alloy_primitives::{Address, B256, TxKind, U256};
use evm2::{
    Evm,
    ethereum::{LazyAuthorization, LazyTxEip7702},
    registry::{HandlerError, HandlerResult},
    version::{GasId, GasParams},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    CONFIGURABLE_ACCOUNT_ADDRESS,
    configurable_account::{ConfigurableAccount, UpgradeEligibility, valid_account_code},
    error::TempoPrecompileError,
    storage::account_config_commitment,
};
use tempo_primitives::transaction::{
    ConfigurableAccountSignature, ConfigurableAccountStateError, KeychainSignature, SignatureType,
    TempoSignature,
};

/// An independently signed role. Repeated accounts still require both role digests.
struct NativeAuthorization<'a> {
    signature: &'a ConfigurableAccountSignature,
    /// Role digest before configurable account domain separation.
    inner_digest: B256,
}

/// What [`validate_native_roles`] charges and loads for the native roles of a transaction.
struct NativeRoles {
    extra_gas: u64,
    /// Native role accounts already loaded, in role order.
    accounts: Vec<Address>,
}

/// State of one account loaded (and warmed) for authorization checks.
struct LoadedAccount {
    was_cold: bool,
    invalid_code: bool,
    commitment: B256,
}

impl TempoAaTx {
    /// Outer (direct or delegated) role, then inline grant role; either slot may be absent.
    fn native_authorizations(&self) -> [Option<NativeAuthorization<'_>>; 2] {
        let signature_hash = self.signature_hash();
        let outer =
            match self.signature() {
                TempoSignature::ConfigurableAccount(signature) => Some(NativeAuthorization {
                    signature,
                    inner_digest: signature_hash,
                }),
                TempoSignature::Keychain(keychain) => keychain
                    .signature
                    .as_configurable_account()
                    .map(|signature| NativeAuthorization {
                        signature,
                        inner_digest: KeychainSignature::signing_hash(
                            signature_hash,
                            keychain.user_address,
                        ),
                    }),
                TempoSignature::Primitive(_) => None,
            };
        let grant = self.tx().key_authorization.as_ref().and_then(|auth| {
            Some(NativeAuthorization {
                signature: auth.signature.as_configurable_account()?,
                inner_digest: auth.signature_hash(),
            })
        });
        [outer, grant]
    }

    /// The configurable account delegate named by an inline key authorization, if any.
    pub(crate) fn grant_delegate(&self) -> Option<Address> {
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
        let direct = aa
            .and_then(|aa| aa.signature().as_configurable_account())
            .map_or(Address::ZERO, ConfigurableAccountSignature::account);
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

/// Validates the account state every transaction role depends on, returning extra regular
/// intrinsic gas. Does no signature or quorum verification of its own (see [`verify`]), except
/// that T14 key-authorization and access-key identities are recovered to name the accounts
/// whose root-key retirement is checked.
///
/// Native roles are checked first. At T14, bare primitive authority is then rejected with
/// [`TempoInvalidTransaction::RootKeyRetired`] for any account with a nonzero configuration
/// commitment, in the order sender, key authorization signer, fee payer, access key. RPC
/// simulation skips only the sender check.
/// Loads and warms accounts, but writes nothing. Caller must charge the returned gas.
/// Transaction access-list and beneficiary warmth must be initialized before loading non-caller
/// accounts.
pub(crate) fn validate_state(
    host: &mut Evm<'_, TempoEvmTypes>,
    envelope: &TempoTxEnv,
    spec: TempoHardfork,
) -> HandlerResult<u64> {
    let NativeRoles {
        mut extra_gas,
        mut accounts,
    } = match envelope.as_aa() {
        Some(aa) => validate_native_roles(host, aa, spec)?,
        // Non-AA transactions have no native roles or grant delegate.
        None => NativeRoles {
            extra_gas: 0,
            accounts: Vec::new(),
        },
    };
    if spec.is_t14() {
        extra_gas += validate_root_keys(host, envelope, spec, &mut accounts)?;
    }
    if let Some(aa) = envelope.as_aa() {
        extra_gas += grant_delegate_access_gas(host, aa, spec, &accounts)?;
    }
    Ok(extra_gas)
}

/// Returns `authorizations` with every entry the T14 rule skips replaced by an invalid recovered
/// authorization, or `None` when no entry is skipped.
///
/// From T14, entries whose authority has a nonzero configuration commitment are skipped
/// (TIP-1112): they install no delegation, remove none, bump no nonce and earn no refund.
/// Other entries behave exactly as in evm2.
///
/// Only entries evm2 would load are checked: chain id 0 or `chain_id`, nonce below `u64::MAX`
/// and a recoverable authority (`validate_one_auth` rejects the rest before loading anything).
/// The checked authority is loaded and warmed, as evm2 does for an entry it rejects on code or
/// nonce, so warmth and refunds stay identical to the same entry with a mismatched nonce. The
/// commitment is read once, before any entry applies: delegation never changes it.
pub(crate) fn apply_authorizations(
    host: &mut Evm<'_, TempoEvmTypes>,
    tx: &LazyTxEip7702,
    spec: TempoHardfork,
) -> HandlerResult<Option<LazyTxEip7702>> {
    if !spec.is_t14() {
        return Ok(None);
    }
    let chain_id = U256::from(host.version().chain_id);
    let mut skipped = Vec::new();
    for (index, authorization) in tx.authorization_list.iter().enumerate() {
        let chain = *authorization.chain_id();
        let loaded_by_evm2 =
            (chain.is_zero() || chain == chain_id) && authorization.nonce() != u64::MAX;
        if loaded_by_evm2
            && let Some(authority) = authorization.authority()
            && retired_authority(host, authority, spec)?
        {
            skipped.push(index);
        }
    }
    if skipped.is_empty() {
        return Ok(None);
    }
    let mut tx = tx.clone();
    for index in skipped {
        let authorization = &mut tx.authorization_list[index];
        *authorization = LazyAuthorization::Recovered(RecoveredAuthorization::new_unchecked(
            authorization.inner().clone(),
            RecoveredAuthority::Invalid,
        ));
    }
    Ok(Some(tx))
}

/// Loads and warms an EIP-7702 `authority` and returns whether the T14 rule skips its
/// authorization (TIP-1112): it has a nonzero configuration commitment.
pub(crate) fn retired_authority(
    host: &mut Evm<'_, TempoEvmTypes>,
    authority: Address,
    spec: TempoHardfork,
) -> HandlerResult<bool> {
    Ok(spec.is_t14() && !load_account(host, authority, spec)?.commitment.is_zero())
}

/// Verifies the owner quorum of each signed role separately. Sender recovery already verified and
/// cached these, so this only rechecks transactions built without recovery. RPC simulation must
/// validate the claimed owner quorum before constructing its mock witness; this function skips
/// quorum recovery only in that mode.
pub(crate) fn verify(
    context: ExecutionContext,
    aa: &TempoAaTx,
) -> Result<(), TempoInvalidTransaction> {
    match context {
        ExecutionContext::Transaction { .. } => {
            for role in aa.native_authorizations().into_iter().flatten() {
                role.signature
                    .verify_approvals(role.inner_digest)
                    .map_err(ConfigurableAccountError::Quorum)?;
            }
        }
        ExecutionContext::Simulation => {}
    }
    Ok(())
}

/// Gas for loading one account: a warm read, plus the cold surcharge when it was not yet accessed.
pub fn account_access_gas(gas: &GasParams, is_cold: bool) -> u64 {
    u64::from(gas.get(GasId::WarmStorageReadCost))
        + if is_cold {
            gas.cold_account_additional_cost()
        } else {
            0
        }
}

/// Loads and warms `address` once, reading its code and commitment.
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
        commitment,
    })
}

/// Native roles only: returns extra gas and the native role accounts already loaded.
fn validate_native_roles(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
    spec: TempoHardfork,
) -> HandlerResult<NativeRoles> {
    let caller = aa.signer();
    let roles = aa.native_authorizations();
    // Context rejection must not depend on account reads.
    if roles.iter().any(Option::is_some) && !spec.is_t14() {
        return Err(ConfigurableAccountError::UnsupportedContext.into());
    }
    if spec.is_t14() && aa.signature().is_keychain() {
        let account = load_account(host, caller, spec)?;
        if !account.commitment.is_zero() && account.invalid_code {
            return Err(ConfigurableAccountError::InvalidAccount { account: caller }.into());
        }
    }
    if roles.iter().all(Option::is_none) {
        return Ok(NativeRoles {
            extra_gas: 0,
            accounts: Vec::new(),
        });
    }
    // Grant signers may be admin access keys; key authorization validation binds them to the
    // caller.
    if let Some(signature) = aa.signature().as_configurable_account()
        && signature.account() != caller
    {
        return Err(ConfigurableAccountError::AccountMismatch {
            expected: caller,
            actual: signature.account(),
        }
        .into());
    }
    let mut accounts = Vec::with_capacity(2);
    let mut extra_gas = 0;
    for role in roles.into_iter().flatten() {
        let signature = role.signature;
        let address = signature.account();
        let account = load_account(host, address, spec)?;
        if account.invalid_code {
            return Err(ConfigurableAccountError::InvalidAccount { account: address }.into());
        }
        let first = !accounts.contains(&address);
        if first && address != caller {
            extra_gas += account_access_gas(&host.version().gas_params, account.was_cold);
        }
        accounts.push(address);
        signature
            .validate_account_commitment(account.commitment)
            .map_err(|error| match error {
                ConfigurableAccountStateError::CommitmentMismatch { expected, actual } => {
                    HandlerError::from(ConfigurableAccountError::ConfigurationCommitmentMismatch {
                        expected,
                        actual,
                    })
                }
                ConfigurableAccountStateError::NotConfigurable => {
                    ConfigurableAccountError::NotConfigurable { account: address }.into()
                }
            })?;
    }
    Ok(NativeRoles {
        extra_gas,
        accounts,
    })
}

/// Rejects bare primitive authority of accounts with a nonzero commitment (TIP-1112).
///
/// Each distinct non-caller account is charged one account access, deduplicated against
/// `accounts` (which collects every charged account). Configurable account signers and delegates
/// are native accounts that always carry a commitment and are never primitive roots, so only
/// primitive signatures are checked.
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
    let aa = envelope.as_aa();
    // RPC simulation supplies a placeholder sender signature.
    let simulation = match envelope.execution_context() {
        ExecutionContext::Transaction { .. } => false,
        ExecutionContext::Simulation => true,
    };
    if !simulation && envelope.signed_by_primitive_root() {
        check(host, caller, RootKeyRole::Sender)?;
    }
    let Some(aa) = aa else {
        return Ok(extra_gas);
    };
    if let Some(auth) = &aa.tx().key_authorization
        && auth.signature.as_configurable_account().is_none()
    {
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
        && keychain.signature.as_configurable_account().is_none()
        && let Some(key_id) = access_key_id(aa)?
    {
        check(host, key_id, RootKeyRole::AccessKey)?;
    }
    Ok(extra_gas)
}

/// The inline grant's code check runs with intrinsic-only metering. Charge its account load
/// here, unless caller loading or a native signing role already accounts for that address.
/// Merely naming a recipient does not validate an owner witness.
fn grant_delegate_access_gas(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
    spec: TempoHardfork,
    signers: &[Address],
) -> HandlerResult<u64> {
    if spec.is_t14()
        && let Some(delegate) = aa.grant_delegate()
        && delegate != aa.signer()
        && !signers.contains(&delegate)
    {
        let loaded = load_account(host, delegate, spec)?;
        return Ok(account_access_gas(
            &host.version().gas_params,
            loaded.was_cold,
        ));
    }
    Ok(0)
}
