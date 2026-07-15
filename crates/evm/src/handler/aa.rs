use super::{TempoFeeContext, TempoHandlerHooks, invalid};
use crate::{FeePaymentError, TempoAaTx, TempoEvmTypes, TempoInvalidTransaction, TempoTxEnv};
use alloy_primitives::{Address, KECCAK256_EMPTY, TxKind, U256};
use evm2::{
    Evm, EvmFeatures, TxResult,
    env::TxEnv,
    ethereum::{
        access_list_counts, initial_gas_and_reservoir, initial_message, validate_block_gas_limit,
        validate_chain_id, validate_create_initcode, validate_floor_gas, validate_gas_price,
        validate_intrinsic_gas, validate_nonce_not_overflow, validate_priority_fee,
        validate_regular_gas_limit_cap, validate_tx_gas_limit_cap, warm_access_list,
        warm_base_accounts,
    },
    evm::handler::{GasSettlement, SettlementRequest, TxHandlerHooks},
    interpreter::{GasTracker, Host, InstrStop, MessageResult},
    precompiles::PrecompileError,
    registry::{HandlerError, HandlerResult, TxRequest},
    version::GasId,
};
use std::cmp::Ordering;
use tempo_chainspec::{constants::gas::STORAGE_CREDIT_VALUE, hardfork::TempoHardfork};
use tempo_contracts::precompiles::IAccountKeychain::SignatureType as PrecompileSignatureType;
use tempo_precompiles::{
    account_keychain::{
        AccountKeychain, AuthorizedKey, CallScope as PrecompileCallScope, KeyRestrictions,
        SelectorRule as PrecompileSelectorRule, TokenLimit,
    },
    error::TempoPrecompileError,
    nonce::{
        EXPIRING_NONCE_MAX_EXPIRY_SECS, EXPIRING_NONCE_SET_CAPACITY, INonce::getNonceCall,
        NonceManager,
    },
    storage::{Handler as _, StorageCtx},
};
use tempo_primitives::transaction::{
    PrimitiveSignature, SignedKeyAuthorization, TEMPO_EXPIRING_NONCE_KEY, TempoSignature,
    validate_calls,
};

const P256_VERIFY_GAS: u64 = 5_000;
const KEYCHAIN_VALIDATION_GAS: u64 = 2_100 + 900;
const KEY_AUTH_BASE_GAS: u64 = 27_000;
const KEY_AUTH_PER_LIMIT_GAS: u64 = 22_000;
const KEY_AUTH_EXTRA_EVENT_BUFFER: u64 = 1_500;
const ECRECOVER_GAS: u64 = 3_000;
const EXPIRING_NONCE_GAS: u64 = 2 * 2_100 + 100 + 3 * 2_900;

fn calldata_tokens(input: &[u8]) -> u64 {
    input
        .iter()
        .map(|byte| if *byte == 0 { 1 } else { 4 })
        .sum()
}

fn primitive_signature_gas(signature: &PrimitiveSignature) -> u64 {
    match signature {
        PrimitiveSignature::Secp256k1(_) => 0,
        PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
        PrimitiveSignature::WebAuthn(signature) => {
            P256_VERIFY_GAS + calldata_tokens(&signature.webauthn_data) * 4
        }
    }
}

fn signature_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(signature) => primitive_signature_gas(signature),
        TempoSignature::Keychain(signature) => {
            primitive_signature_gas(&signature.signature) + KEYCHAIN_VALIDATION_GAS
        }
    }
}

fn call_scope_storage_slots(
    authorization: &tempo_primitives::transaction::KeyAuthorization,
    spec: TempoHardfork,
) -> u64 {
    match authorization.allowed_calls.as_ref() {
        None => 0,
        Some(scopes) if scopes.is_empty() => 1,
        Some(scopes) => {
            let mut selector_sets = 0u64;
            let mut selectors = 0u64;
            let mut constrained_selectors = 0u64;
            let mut recipients = 0u64;

            for scope in scopes {
                if spec.is_t4() && !scope.selector_rules.is_empty() {
                    selector_sets += 1;
                }
                selectors += scope.selector_rules.len() as u64;
                for rule in &scope.selector_rules {
                    if !rule.recipients.is_empty() {
                        constrained_selectors += 1;
                        recipients += rule.recipients.len() as u64;
                    }
                }
            }

            if spec.is_t4() {
                1 + scopes.len() as u64 * 2
                    + 1
                    + selectors * 2
                    + selector_sets
                    + constrained_selectors
                    + recipients * 2
            } else {
                1 + scopes.len() as u64 * 3 + selectors * 3 + constrained_selectors + recipients * 2
            }
        }
    }
}

fn call_scope_extra_gas(authorization: &tempo_primitives::transaction::KeyAuthorization) -> u64 {
    const BASE: u64 = 5_000;
    const TARGET: u64 = 7_000;
    const SELECTOR: u64 = 7_000;
    const RECIPIENT: u64 = 5_000;

    let Some(scopes) = authorization.allowed_calls.as_ref() else {
        return BASE;
    };
    let targets = scopes.len() as u64;
    let selectors = scopes
        .iter()
        .map(|scope| scope.selector_rules.len() as u64)
        .sum::<u64>();
    let recipients = scopes
        .iter()
        .flat_map(|scope| &scope.selector_rules)
        .map(|rule| rule.recipients.len() as u64)
        .sum::<u64>();
    BASE + TARGET.saturating_mul(targets)
        + SELECTOR.saturating_mul(selectors)
        + RECIPIENT.saturating_mul(recipients)
}

fn key_authorization_gas(
    authorization: &tempo_primitives::transaction::SignedKeyAuthorization,
    host: &Evm<'_, TempoEvmTypes>,
    spec: TempoHardfork,
) -> (u64, u64) {
    let signature = ECRECOVER_GAS + primitive_signature_gas(&authorization.signature);
    let limits = authorization
        .limits
        .as_ref()
        .map_or(0, |limits| limits.len() as u64);

    if !spec.is_t1b() {
        return (
            KEY_AUTH_BASE_GAS + signature + limits * KEY_AUTH_PER_LIMIT_GAS,
            0,
        );
    }

    let params = &host.version().gas_params;
    let load = u64::from(params.get(GasId::WarmStorageReadCost))
        + u64::from(params.get(GasId::ColdStorageAdditionalCost));
    let limit_slots = if spec.is_t3() { limits * 2 } else { limits };
    let mut stores = 1 + limit_slots;
    if spec.is_t3() {
        stores += call_scope_storage_slots(&authorization.authorization, spec);
    }
    let mut store = u64::from(params.get(GasId::SstoreSetWithoutLoadCost));
    if spec.is_t7() {
        store = store.saturating_add(STORAGE_CREDIT_VALUE);
    }
    let mut regular = signature + load + stores * store + 2_000;
    if authorization.has_witness() {
        regular += load + KEY_AUTH_EXTRA_EVENT_BUFFER;
    }
    if spec.is_t6() && authorization.is_admin() {
        regular += KEY_AUTH_EXTRA_EVENT_BUFFER;
    }
    if spec.is_t4() {
        regular += call_scope_extra_gas(&authorization.authorization);
    }
    let state = stores * u64::from(params.get(GasId::SstoreSetState));
    (regular, state)
}

fn intrinsic_gas(host: &Evm<'_, TempoEvmTypes>, aa: &TempoAaTx) -> HandlerResult<(u64, u64, u64)> {
    let signed = aa.inner();
    let tx = signed.tx();
    let spec = host.config_spec_id();
    let params = &host.version().gas_params;
    let mut regular = u64::from(params.get(GasId::TxBaseStipend));
    let mut state = 0u64;
    let mut tokens = 0u64;

    regular = regular.saturating_add(signature_gas(signed.signature()));
    let cold_account = u64::from(params.get(GasId::WarmStorageReadCost))
        + u64::from(params.get(GasId::ColdAccountAdditionalCost));
    regular = regular
        .saturating_add(cold_account.saturating_mul(tx.calls.len().saturating_sub(1) as u64));

    for authorization in &tx.tempo_authorization_list {
        regular = regular
            .saturating_add(u64::from(params.get(GasId::TxEip7702PerEmptyAccountCost)))
            .saturating_add(signature_gas(authorization.signature()));
        state = state.saturating_add(params.eip7702_auth_state_gas());
        if spec.is_t1() && authorization.nonce == 0 {
            regular = regular.saturating_add(u64::from(params.get(GasId::NewAccountCost)));
            state = state.saturating_add(params.new_account_state_gas());
        }
    }

    if let Some(authorization) = &tx.key_authorization {
        let (auth_regular, auth_state) = key_authorization_gas(authorization, host, spec);
        regular = regular.saturating_add(auth_regular);
        state = state.saturating_add(auth_state);
    }

    for call in &tx.calls {
        if !call.value.is_zero() {
            return Err(invalid(
                TempoInvalidTransaction::ValueTransferNotAllowedInAATx,
            ));
        }
        tokens = tokens.saturating_add(calldata_tokens(&call.input));
        if call.to.is_create() {
            regular = regular
                .saturating_add(u64::from(params.get(GasId::Create)))
                .saturating_add(params.initcode_cost(call.input.len()));
            state = state.saturating_add(params.create_state_gas());
        }
    }
    regular =
        regular.saturating_add(tokens.saturating_mul(u64::from(params.get(GasId::TxTokenCost))));

    let (accounts, storage_keys) = access_list_counts(&tx.access_list);
    regular = regular
        .saturating_add(
            accounts.saturating_mul(u64::from(params.get(GasId::TxAccessListAddressCost))),
        )
        .saturating_add(
            storage_keys.saturating_mul(u64::from(params.get(GasId::TxAccessListStorageKeyCost))),
        );

    if spec.is_t1() {
        if tx.nonce_key == TEMPO_EXPIRING_NONCE_KEY {
            regular = regular.saturating_add(EXPIRING_NONCE_GAS);
        } else if tx.nonce == 0 {
            regular = regular.saturating_add(u64::from(params.get(GasId::NewAccountCost)));
            state = state.saturating_add(params.new_account_state_gas());
        } else if !tx.nonce_key.is_zero() {
            regular = regular.saturating_add(spec.gas_existing_nonce_key());
        }
    } else if !tx.nonce_key.is_zero() {
        regular = regular.saturating_add(if tx.nonce == 0 {
            spec.gas_new_nonce_key()
        } else {
            spec.gas_existing_nonce_key()
        });
    }

    let floor = if host.feature(EvmFeatures::EIP7623) {
        let mut floor_tokens = tokens;
        let multiplier = u64::from(params.get(GasId::TxAccessListFloorByteMultiplier));
        floor_tokens = floor_tokens.saturating_add(
            (accounts.saturating_mul(20) + storage_keys.saturating_mul(32))
                .saturating_mul(multiplier),
        );
        u64::from(params.get(GasId::TxFloorCostBase)).saturating_add(
            floor_tokens.saturating_mul(u64::from(params.get(GasId::TxFloorCostPerToken))),
        )
    } else {
        0
    };

    Ok((regular, state, floor))
}

fn validate_time_window(
    valid_after: Option<u64>,
    valid_before: Option<u64>,
    timestamp: u64,
) -> HandlerResult<()> {
    if let Some(valid_after) = valid_after
        && timestamp < valid_after
    {
        return Err(invalid(TempoInvalidTransaction::ValidAfter {
            current: timestamp,
            valid_after,
        }));
    }
    if let Some(valid_before) = valid_before
        && timestamp >= valid_before
    {
        return Err(invalid(TempoInvalidTransaction::ValidBefore {
            current: timestamp,
            valid_before,
        }));
    }
    Ok(())
}

fn access_key_id(aa: &TempoAaTx) -> HandlerResult<Option<Address>> {
    let signed = aa.inner();
    let Some(signature) = signed.signature().as_keychain() else {
        return Ok(None);
    };
    aa.override_key_id()
        .map(Ok)
        .unwrap_or_else(|| {
            signature
                .key_id(&signed.signature_hash())
                .map_err(|_| invalid(TempoInvalidTransaction::AccessKeyRecoveryFailed))
        })
        .map(Some)
}

fn validate_key_authorization(
    aa: &TempoAaTx,
    chain_id: u64,
    spec: TempoHardfork,
) -> HandlerResult<()> {
    let signed = aa.inner();
    let tx = signed.tx();
    let Some(key_auth) = tx.key_authorization.as_ref() else {
        return Ok(());
    };

    let access_key = access_key_id(aa)?;
    let same_tx_auth_use = access_key == Some(key_auth.key_id);
    if access_key.is_some() && !same_tx_auth_use && !spec.is_t6() {
        return Err(invalid(
            TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys,
        ));
    }

    if same_tx_auth_use
        && spec.is_t3()
        && signed
            .signature()
            .as_keychain()
            .is_some_and(|signature| key_auth.key_type != signature.signature.signature_type())
    {
        return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
            reason: "key authorization key_type does not match the keychain signature type".into(),
        }));
    }

    if (key_auth.is_admin || key_auth.account.is_some()) && !spec.is_t6() {
        return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
            reason: "T6 key authorization fields are not active before T6".into(),
        }));
    }
    if spec.is_t6()
        && key_auth
            .account
            .is_some_and(|account| account != aa.signer())
    {
        let reason = if key_auth.is_admin() {
            "admin key authorization account mismatch"
        } else {
            "key authorization account mismatch"
        };
        return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
            reason: reason.into(),
        }));
    }
    if key_auth.is_admin()
        && (key_auth.expiry.is_some()
            || key_auth.limits.is_some()
            || key_auth.allowed_calls.is_some())
    {
        return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
            reason: "admin key authorizations cannot carry expiry, limits, or call scopes".into(),
        }));
    }

    let signer = key_auth
        .recover_signer()
        .map_err(|_| invalid(TempoInvalidTransaction::KeyAuthorizationSignatureRecoveryFailed))?;
    if !spec.is_t6() && signer != aa.signer() {
        return Err(invalid(
            TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot {
                expected: aa.signer(),
                actual: signer,
            },
        ));
    }
    key_auth
        .validate_chain_id(chain_id, spec.is_t1c())
        .map_err(TempoInvalidTransaction::from)
        .map_err(invalid)?;

    if key_auth.has_witness() && !spec.is_t5() {
        return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
            reason: "key authorization witnesses are not active before T5".into(),
        }));
    }
    if !spec.is_t3() && key_auth.has_periodic_limits() {
        return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
            reason: "periodic token limits are not active before T3".into(),
        }));
    }
    if !spec.is_t3() && key_auth.has_call_scopes() {
        return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
            reason: "call scopes are not active before T3".into(),
        }));
    }

    if spec.is_t6() {
        if signer != aa.signer() && key_auth.account.is_none() {
            return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
                reason: "admin-signed key authorization account mismatch".into(),
            }));
        }
        if signer == aa.signer() && access_key.is_some() && !same_tx_auth_use {
            return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
                reason: "root-signed key authorization must use root transaction signature".into(),
            }));
        }
        if signer != aa.signer() {
            let Some(keychain_signature) = signed.signature().as_keychain() else {
                return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
                    reason: "admin-signed key authorization must be signed by transaction key"
                        .into(),
                }));
            };
            if access_key != Some(signer) {
                return Err(invalid(TempoInvalidTransaction::KeychainValidationFailed {
                    reason: "admin-signed key authorization must be signed by transaction key"
                        .into(),
                }));
            }
            if key_auth.signature.signature_type() != keychain_signature.signature.signature_type()
            {
                return Err(invalid(
                    TempoInvalidTransaction::KeychainValidationFailed {
                        reason: "admin-signed key authorization signature type does not match transaction key signature type".into(),
                    },
                ));
            }
        }
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct LoadedTxAccessKey {
    key_id: Address,
    key: AuthorizedKey,
}

#[derive(Clone, Debug, Default)]
struct KeychainState {
    access_key: Option<Address>,
    same_tx_authorization: bool,
    fee_key: Option<Address>,
    loaded_key: Option<LoadedTxAccessKey>,
}

fn keychain_error(error: TempoPrecompileError) -> HandlerError {
    match error {
        TempoPrecompileError::EvmError(code) => HandlerError::Fatal(code),
        TempoPrecompileError::Fatal(error) => HandlerError::Custom(error),
        error => invalid(TempoInvalidTransaction::KeychainValidationFailed {
            reason: format!("{error:?}"),
        }),
    }
}

fn prepare_keychain(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
    fee: TempoFeeContext,
) -> HandlerResult<KeychainState> {
    let signed = aa.inner();
    let tx = signed.tx();
    let Some(keychain_signature) = signed.signature().as_keychain() else {
        return Ok(KeychainState::default());
    };
    if keychain_signature.user_address != aa.signer() {
        return Err(invalid(
            TempoInvalidTransaction::KeychainUserAddressMismatch {
                user_address: keychain_signature.user_address,
                caller: aa.signer(),
            },
        ));
    }

    let access_key = access_key_id(aa)?.expect("keychain signature must have an access key");
    let key_authorization = tx.key_authorization.as_ref();
    let same_tx_authorization =
        key_authorization.is_some_and(|authorization| authorization.key_id == access_key);

    if same_tx_authorization {
        let authorization = key_authorization.expect("checked above");
        let fee_key = if !fee.collected.is_zero()
            && fee.fee_payer == aa.signer()
            && let Some(limits) = authorization.limits.as_ref()
        {
            let remaining = limits
                .iter()
                .rev()
                .find(|limit| limit.token == fee.fee_token)
                .map(|limit| limit.limit)
                .unwrap_or_default();
            if fee.collected > remaining {
                return Err(invalid(FeePaymentError::Other(
                    "SpendingLimitExceeded".into(),
                )));
            }
            Some(access_key)
        } else {
            None
        };
        return Ok(KeychainState {
            access_key: Some(access_key),
            same_tx_authorization,
            fee_key,
            loaded_key: None,
        });
    }

    let timestamp = host.block().timestamp.to::<u64>();
    let expected_signature_type = (key_authorization.is_some() || host.config_spec_id().is_t1())
        .then_some(u8::from(keychain_signature.signature.signature_type()));
    let loaded = StorageCtx::enter_evm_without_tip1060_accounting(host, || {
        let mut keychain = AccountKeychain::new();
        let key = keychain
            .validate_keychain_authorization(
                keychain_signature.user_address,
                access_key,
                timestamp,
                expected_signature_type,
            )
            .map_err(keychain_error)?;
        if key_authorization.is_some() && !key.is_admin {
            return Err(invalid(
                TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys,
            ));
        }
        keychain
            .set_transaction_key(access_key)
            .map_err(keychain_error)?;
        Ok::<_, HandlerError>(LoadedTxAccessKey {
            key_id: access_key,
            key,
        })
    })?;

    host.ext_mut().key_expiry = Some(loaded.key.expiry);
    let fee_key = loaded.key.enforce_limits.then_some(loaded.key_id);
    let state = KeychainState {
        access_key: Some(access_key),
        same_tx_authorization,
        fee_key,
        loaded_key: Some(loaded),
    };

    if host.config_spec_id().is_t6()
        && let Some(key_authorization) = key_authorization
    {
        let signer = key_authorization.recover_signer().map_err(|_| {
            invalid(TempoInvalidTransaction::KeyAuthorizationSignatureRecoveryFailed)
        })?;
        if signer != aa.signer() {
            let signature_type: u8 = key_authorization.signature.signature_type().into();
            let signer_is_admin = state.loaded_key.as_ref().is_some_and(|loaded| {
                loaded.key_id == signer
                    && loaded.key.signature_type as u8 == signature_type
                    && loaded.key.is_admin
            });
            if !signer_is_admin {
                return Err(invalid(
                    TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot {
                        expected: aa.signer(),
                        actual: signer,
                    },
                ));
            }
        }
    }

    Ok(state)
}

fn translate_allowed_calls(authorization: &SignedKeyAuthorization) -> Vec<PrecompileCallScope> {
    authorization
        .allowed_calls
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|scope| PrecompileCallScope {
            target: scope.target,
            selectorRules: scope
                .selector_rules
                .iter()
                .map(|rule| PrecompileSelectorRule {
                    selector: rule.selector.into(),
                    recipients: rule.recipients.clone(),
                })
                .collect(),
        })
        .collect()
}

fn apply_key_authorization(
    host: &mut Evm<'_, TempoEvmTypes>,
    aa: &TempoAaTx,
    fee: TempoFeeContext,
    state: &KeychainState,
    remaining_gas: u64,
) -> HandlerResult<u64> {
    let Some(authorization) = aa.inner().tx().key_authorization.as_ref() else {
        return Ok(0);
    };
    let spec = host.config_spec_id();
    let checkpoint = host.state().checkpoint();
    let features = host.version().features;
    let metered = spec.is_t1() && !spec.is_t1b();
    let (result, gas) = StorageCtx::enter_evm_without_tip1060_accounting_with_gas_limit(
        host,
        if metered { remaining_gas } else { u64::MAX },
        0,
        || {
            let mut keychain = AccountKeychain::new();
            let signature_type: PrecompileSignatureType = authorization.key_type.into();
            let restrictions = KeyRestrictions {
                expiry: authorization.expiry.map_or(u64::MAX, |expiry| expiry.get()),
                enforceLimits: authorization.limits.is_some(),
                limits: authorization
                    .limits
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(|limit| TokenLimit {
                        token: limit.token,
                        amount: limit.limit,
                        period: limit.period,
                    })
                    .collect(),
                allowAnyCalls: authorization.allowed_calls.is_none(),
                allowedCalls: translate_allowed_calls(authorization),
            };
            if authorization.is_admin() {
                keychain.authorize_admin_key(
                    aa.signer(),
                    authorization.key_id,
                    signature_type,
                    authorization.witness(),
                )?;
            } else {
                keychain.authorize_key(
                    aa.signer(),
                    authorization.key_id,
                    signature_type,
                    restrictions,
                    authorization.witness(),
                )?;
            }

            if state.same_tx_authorization {
                keychain.set_transaction_key(authorization.key_id)?;
                if !fee.collected.is_zero() {
                    keychain.authorize_transfer(fee.fee_payer, fee.fee_token, fee.collected)?;
                }
            }
            Ok::<_, TempoPrecompileError>(())
        },
    );

    match result {
        Ok(()) => {
            host.ext_mut().key_expiry = authorization.expiry.map(|expiry| expiry.get());
            Ok(if metered { gas.spent() } else { 0 })
        }
        Err(TempoPrecompileError::OutOfGas) if metered => {
            host.state_mut().rollback(checkpoint, features);
            Ok(u64::MAX)
        }
        Err(error) => {
            host.state_mut().rollback(checkpoint, features);
            Err(match error {
                TempoPrecompileError::EvmError(code) => HandlerError::Fatal(code),
                TempoPrecompileError::Fatal(error) => HandlerError::Custom(error),
                error => invalid(TempoInvalidTransaction::KeychainPrecompileError {
                    reason: error.to_string(),
                }),
            })
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct AppliedAuthorization {
    existed: bool,
    delegated_before_tx: bool,
    delegated_now: bool,
    clearing: bool,
}

fn apply_one_authorization(
    host: &mut Evm<'_, TempoEvmTypes>,
    authorization: &tempo_primitives::transaction::TempoSignedAuthorization,
) -> HandlerResult<Option<AppliedAuthorization>> {
    if !authorization.chain_id.is_zero()
        && authorization.chain_id != U256::from(host.version().chain_id)
    {
        return Ok(None);
    }
    if authorization.nonce == u64::MAX {
        return Ok(None);
    }
    let Ok(authority) = authorization.recover_authority() else {
        return Ok(None);
    };
    let mut account = host
        .state_mut()
        .account(&authority, false)
        .map_err(HandlerError::Fatal)?;
    account.warm();
    let existed = account.exists();
    let nonce = account.nonce();
    let code = account.load_code().map_err(HandlerError::Fatal)?;
    let delegated_now = !code.is_empty();
    if delegated_now && !code.is_eip7702() {
        return Ok(None);
    }
    if authorization.nonce != nonce {
        return Ok(None);
    }
    let delegated_before_tx = account
        .original_code()
        .map_err(HandlerError::Fatal)?
        .is_eip7702();
    let clearing = authorization.address.is_zero();
    account.set_delegation(authorization.address);
    Ok(Some(AppliedAuthorization {
        existed,
        delegated_before_tx,
        delegated_now,
        clearing,
    }))
}

fn apply_authorization_list(
    host: &mut Evm<'_, TempoEvmTypes>,
    authorizations: &[tempo_primitives::transaction::TempoSignedAuthorization],
    spec: TempoHardfork,
) -> HandlerResult<(u64, u64)> {
    let eip8037 = host.feature(EvmFeatures::EIP8037);
    let new_account = host.version().gas_params.new_account_state_gas();
    let auth_base = u64::from(host.version().gas_params.get(GasId::TxEip7702PerAuthState));
    let regular_per_auth = u64::from(host.version().gas_params.get(GasId::TxEip7702AuthRefund));
    let mut state_refund = 0u64;
    let mut regular_refund = 0u64;

    for authorization in authorizations
        .iter()
        .filter(|authorization| !(spec.is_t0() && authorization.signature().is_keychain()))
    {
        let Some(applied) = apply_one_authorization(host, authorization)? else {
            if eip8037 {
                state_refund = state_refund.saturating_add(new_account + auth_base);
                regular_refund = regular_refund.saturating_add(regular_per_auth);
            }
            continue;
        };

        if applied.existed {
            regular_refund = regular_refund.saturating_add(regular_per_auth);
        }
        if !eip8037 {
            continue;
        }
        let mut refund = 0u64;
        if applied.existed {
            refund = refund.saturating_add(new_account);
        }
        if applied.clearing {
            refund = refund.saturating_add(auth_base);
            if applied.delegated_now && !applied.delegated_before_tx {
                refund = refund.saturating_add(auth_base);
            }
        } else if applied.delegated_now || applied.delegated_before_tx {
            refund = refund.saturating_add(auth_base);
        }
        state_refund = state_refund.saturating_add(refund);
    }

    Ok((state_refund, regular_refund))
}

fn prevalidate_call_scopes(
    host: &mut Evm<'_, TempoEvmTypes>,
    caller: Address,
    access_key: Option<Address>,
    calls: &[tempo_primitives::transaction::Call],
    gas_limit: u64,
    reservoir: u64,
) -> HandlerResult<Option<MessageResult<TempoEvmTypes>>> {
    if !host.config_spec_id().is_t3() {
        return Ok(None);
    }
    let Some(access_key) = access_key else {
        return Ok(None);
    };

    let (validation, mut gas) =
        StorageCtx::enter_evm_with_gas_limit(host, gas_limit, reservoir, || {
            let keychain = AccountKeychain::new();
            for call in calls {
                keychain.validate_call_scope_for_transaction(
                    caller,
                    access_key,
                    &call.to,
                    call.input.as_ref(),
                )?;
            }
            Ok::<_, TempoPrecompileError>(())
        });
    let Err(error) = validation else {
        return Ok(None);
    };

    let (stop, output) = match error.into_precompile_result() {
        Err(PrecompileError::Revert(output)) => (InstrStop::Revert, output),
        Err(PrecompileError::Halt(_)) => {
            gas.set_remaining(0);
            (InstrStop::PrecompileOOG, Default::default())
        }
        Err(PrecompileError::Fatal(error)) => {
            return Err(HandlerError::Custom(error.to_string()));
        }
        Ok(_) => unreachable!("Tempo precompile errors cannot produce success"),
    };
    Ok(Some(MessageResult {
        stop,
        gas,
        output,
        ..MessageResult::default()
    }))
}

fn apply_nonce(
    host: &mut Evm<'_, TempoEvmTypes>,
    envelope: &TempoTxEnv,
    aa: &TempoAaTx,
) -> HandlerResult<u64> {
    let caller = aa.signer();
    let tx = aa.inner().tx();
    let spec = host.config_spec_id();
    let eip3607 = host.feature(EvmFeatures::EIP3607);
    let nonce_check = host.feature(EvmFeatures::NONCE_CHECK);
    let mut account = host
        .state_mut()
        .account(&caller, false)
        .map_err(HandlerError::Fatal)?;
    if eip3607 && account.code_hash() != KECCAK256_EMPTY {
        let code = account.load_code().map_err(HandlerError::Fatal)?;
        if !code.is_empty() && !code.is_eip7702() {
            return Err(HandlerError::RejectCallerWithCode);
        }
    }
    let protocol_nonce = account.nonce();
    if tx.nonce_key.is_zero() {
        if nonce_check && protocol_nonce != tx.nonce {
            return Err(HandlerError::InvalidNonce {
                expected: protocol_nonce,
                got: tx.nonce,
            });
        }
        if tx.calls.first().is_some_and(|call| call.to.is_call()) {
            account.bump_nonce();
        }
        return Ok(protocol_nonce);
    }
    drop(account);

    if tx.nonce_key == TEMPO_EXPIRING_NONCE_KEY && spec.is_t1() {
        if tx.nonce != 0 {
            return Err(invalid(TempoInvalidTransaction::ExpiringNonceNonceNotZero));
        }
        let valid_before = tx
            .valid_before
            .map(|value| value.get())
            .ok_or_else(|| invalid(TempoInvalidTransaction::ExpiringNonceMissingValidBefore))?;
        let replay_hash = if spec.is_t1b() {
            envelope.unique_tx_identifier()
        } else {
            envelope.tx_hash()
        };
        let timestamp = host.block().timestamp.to::<u64>();
        return StorageCtx::enter_evm_without_tip1060_accounting(host, || {
            let mut nonces = NonceManager::new();
            let previous_pointer = if let Some(index) = aa.expiring_nonce_idx() {
                let pointer = nonces.expiring_nonce_ring_ptr.read().map_err(|error| {
                    invalid(TempoInvalidTransaction::NonceManagerError(
                        error.to_string(),
                    ))
                })?;
                nonces
                    .expiring_nonce_ring_ptr
                    .write((pointer + index as u32) % EXPIRING_NONCE_SET_CAPACITY)
                    .map_err(|error| {
                        invalid(TempoInvalidTransaction::NonceManagerError(
                            error.to_string(),
                        ))
                    })?;
                Some(pointer)
            } else {
                None
            };
            nonces
                .check_and_mark_expiring_nonce(replay_hash, valid_before)
                .map_err(|error| {
                    if valid_before <= timestamp {
                        invalid(TempoInvalidTransaction::NonceManagerError(format!(
                            "expiring nonce transaction expired: valid_before ({valid_before}) <= block timestamp ({timestamp})"
                        )))
                    } else if valid_before
                        > timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS)
                    {
                        let max_allowed =
                            timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS);
                        invalid(TempoInvalidTransaction::NonceManagerError(format!(
                            "expiring nonce valid_before ({valid_before}) too far in the future: must be within {EXPIRING_NONCE_MAX_EXPIRY_SECS}s of block timestamp ({timestamp}), max allowed is {max_allowed}"
                        )))
                    } else {
                        invalid(TempoInvalidTransaction::NonceManagerError(error.to_string()))
                    }
                })?;
            if let Some(pointer) = previous_pointer {
                nonces
                    .expiring_nonce_ring_ptr
                    .write(pointer)
                    .map_err(|error| {
                        invalid(TempoInvalidTransaction::NonceManagerError(
                            error.to_string(),
                        ))
                    })?;
            }
            Ok::<_, HandlerError>(protocol_nonce)
        });
    }

    StorageCtx::enter_evm_without_tip1060_accounting(host, || {
        let mut nonces = NonceManager::new();
        if nonce_check {
            let state = nonces
                .get_nonce(getNonceCall {
                    account: caller,
                    nonceKey: tx.nonce_key,
                })
                .map_err(|error| {
                    invalid(TempoInvalidTransaction::NonceManagerError(
                        error.to_string(),
                    ))
                })?;
            match tx.nonce.cmp(&state) {
                Ordering::Less | Ordering::Greater => {
                    return Err(HandlerError::InvalidNonce {
                        expected: state,
                        got: tx.nonce,
                    });
                }
                Ordering::Equal => {}
            }
        }
        nonces
            .increment_nonce(caller, tx.nonce_key)
            .map_err(|error| {
                invalid(TempoInvalidTransaction::NonceManagerError(
                    error.to_string(),
                ))
            })?;
        Ok::<_, HandlerError>(protocol_nonce)
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "keeps batch execution state explicit"
)]
fn execute_batch(
    host: &mut Evm<'_, TempoEvmTypes>,
    caller: Address,
    access_key: Option<Address>,
    create_nonce: u64,
    gas_price: U256,
    gas_limit: u64,
    reservoir: u64,
    calls: &[tempo_primitives::transaction::Call],
    burn_create_nonce_on_failure: bool,
) -> HandlerResult<evm2::interpreter::MessageResult<TempoEvmTypes>> {
    let checkpoint = host.state().checkpoint();
    let features = host.version().features;
    if let Some(result) =
        prevalidate_call_scopes(host, caller, access_key, calls, gas_limit, reservoir)?
    {
        host.state_mut().rollback(checkpoint, features);
        return Ok(result);
    }
    let mut remaining = gas_limit;
    let mut reservoir = reservoir;
    let mut refund = 0i64;
    let mut state_gas = 0i64;
    let mut spilled_state_gas = 0u64;
    let mut final_result = None;
    let tx_env = TxEnv {
        origin: caller,
        gas_price,
        chain_id: U256::from(host.version().chain_id),
        ..TxEnv::default()
    };

    for call in calls {
        let (bytecode, mut message) = initial_message(
            host,
            caller,
            create_nonce,
            call.to,
            &call.input,
            call.value,
            remaining,
            reservoir,
        )?;
        let mut result = host.execute_message(&tx_env, bytecode, &mut message);
        if !result.is_success() {
            host.state_mut().rollback(checkpoint, features);
            if burn_create_nonce_on_failure && calls.first().is_some_and(|call| call.to.is_create())
            {
                host.state_mut()
                    .account(&caller, false)
                    .map_err(HandlerError::Fatal)?
                    .bump_nonce();
            }
            let restored_reservoir = result.gas.reservoir().saturating_add_signed(state_gas);
            result.gas =
                GasTracker::from_parts(gas_limit, result.gas.remaining(), restored_reservoir);
            return Ok(result);
        }
        refund = refund.saturating_add(result.gas.refunded());
        state_gas = state_gas.saturating_add(result.gas.state_gas_spent());
        spilled_state_gas = spilled_state_gas.saturating_add(result.gas.state_gas_spilled());
        remaining = result.gas.remaining();
        reservoir = result.gas.reservoir();
        final_result = Some(result);
    }

    let mut result = final_result.ok_or_else(|| {
        invalid(TempoInvalidTransaction::CallsValidation(
            "calls list cannot be empty",
        ))
    })?;
    result.gas = GasTracker::from_parts(gas_limit, remaining, reservoir);
    result.gas.record_refund(refund);
    result.gas.add_state_gas_spent(state_gas);
    result.gas.add_state_gas_spilled(spilled_state_gas);
    Ok(result)
}

fn is_subblock_fee_error(error: &HandlerError) -> bool {
    matches!(error, HandlerError::InsufficientFunds)
        || error
            .external_ref::<TempoInvalidTransaction>()
            .is_some_and(|error| {
                matches!(
                    error,
                    TempoInvalidTransaction::CollectFeePreTx(_)
                        | TempoInvalidTransaction::FeeTokenPaused { .. }
                )
            })
}

pub(super) fn handle(
    request: TxRequest<'_, '_, TempoEvmTypes, TempoAaTx>,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    let caller = request.tx.signer();
    let signed = request.tx.inner();
    let tx = signed.tx();
    let spec = request.host.config_spec_id();
    validate_calls(&tx.calls, !tx.tempo_authorization_list.is_empty())
        .map_err(TempoInvalidTransaction::from)
        .map_err(invalid)?;
    signed
        .signature()
        .validate_version(spec.is_t1c())
        .map_err(TempoInvalidTransaction::from)
        .map_err(invalid)?;
    for authorization in &tx.tempo_authorization_list {
        authorization
            .signature()
            .validate_version(spec.is_t1c())
            .map_err(TempoInvalidTransaction::from)
            .map_err(invalid)?;
    }
    validate_key_authorization(request.tx, request.host.version().chain_id, spec)?;
    if spec.is_t3()
        && signed.signature().is_keychain()
        && tx.calls.first().is_some_and(|call| call.to.is_create())
    {
        return Err(invalid(TempoInvalidTransaction::CallsValidation(
            "access-key transactions cannot use CREATE as the first call",
        )));
    }
    if tx.subblock_proposer().is_some()
        && (tx.key_authorization.is_some() || signed.signature().is_keychain())
    {
        return Err(invalid(
            TempoInvalidTransaction::KeychainOpInSubblockTransaction,
        ));
    }
    if tx.calls.iter().any(|call| !call.value.is_zero()) {
        return Err(invalid(
            TempoInvalidTransaction::ValueTransferNotAllowedInAATx,
        ));
    }
    let fee_payer = request
        .envelope
        .fee_payer()
        .map_err(|_| invalid(TempoInvalidTransaction::InvalidFeePayerSignature))?;
    if spec.is_t2() && tx.fee_payer_signature.is_some() && fee_payer == caller {
        return Err(invalid(TempoInvalidTransaction::SelfSponsoredFeePayer));
    }

    let max_fee = U256::from(tx.max_fee_per_gas);
    let priority_fee = U256::from(tx.max_priority_fee_per_gas);
    let gas_price =
        evm2::ethereum::effective_gas_price(max_fee, priority_fee, request.host.block().basefee);
    validate_priority_fee(request.host.version(), max_fee, priority_fee)?;
    validate_gas_price(
        request.host.version(),
        gas_price,
        request.host.block().basefee,
    )?;
    validate_chain_id(request.host.version(), Some(tx.chain_id), false)?;
    validate_tx_gas_limit_cap(request.host.version(), tx.gas_limit)?;
    validate_block_gas_limit(
        request.host.version(),
        tx.gas_limit,
        request.host.block().gas_limit,
    )?;
    validate_nonce_not_overflow(tx.nonce)?;
    for call in &tx.calls {
        validate_create_initcode(request.host.version(), call.to, &call.input)?;
    }
    let timestamp = request.host.block().timestamp.to::<u64>();
    validate_time_window(
        tx.valid_after
            .map(|value| value.get())
            .filter(|_| !request.host.ext().skip_valid_after_check),
        tx.valid_before.map(|value| value.get()),
        timestamp,
    )?;

    let (mut intrinsic, initial_state_gas, floor_gas) = intrinsic_gas(request.host, request.tx)?;
    validate_intrinsic_gas(tx.gas_limit, intrinsic, initial_state_gas)?;
    validate_floor_gas(tx.gas_limit, floor_gas)?;
    validate_regular_gas_limit_cap(request.host.version(), tx.gas_limit, intrinsic, floor_gas)?;

    warm_base_accounts(request.host, caller, tx.calls[0].to);
    for call in &tx.calls[1..] {
        if let TxKind::Call(address) = call.to {
            request.host.state_mut().prewarm(&address);
        }
    }
    warm_access_list(request.host, &tx.access_list);

    let create_nonce = apply_nonce(request.host, request.envelope, request.tx)?;
    let hook_context = TempoHandlerHooks::prepare_fee(request.host, request.envelope)?;
    let keychain = prepare_keychain(request.host, request.tx, hook_context)?;
    let fee_result = TempoHandlerHooks::collect_fee(
        request.host,
        hook_context,
        (hook_context.fee_payer == caller)
            .then_some(keychain.fee_key)
            .flatten(),
    );
    if let Err(error) = fee_result {
        if tx.subblock_proposer().is_some() && is_subblock_fee_error(&error) {
            return Ok(TxResult {
                status: false,
                total_gas_spent: tx.gas_limit.min(request.host.version().tx_gas_limit_cap),
                stop: InstrStop::PrecompileError,
                ..TxResult::default()
            });
        }
        return Err(error);
    }

    let key_auth_gas = apply_key_authorization(
        request.host,
        request.tx,
        hook_context,
        &keychain,
        tx.gas_limit
            .saturating_sub(intrinsic)
            .saturating_sub(initial_state_gas),
    )?;
    if key_auth_gas == u64::MAX
        || key_auth_gas
            > tx.gas_limit
                .saturating_sub(intrinsic)
                .saturating_sub(initial_state_gas)
    {
        let result = MessageResult {
            stop: InstrStop::OutOfGas,
            gas: GasTracker::new_spent_with_reservoir(tx.gas_limit.saturating_sub(intrinsic), 0),
            ..MessageResult::default()
        };
        return TempoHandlerHooks::settle_transaction(SettlementRequest {
            host: request.host,
            envelope: request.envelope,
            context: hook_context,
            gas: GasSettlement {
                caller,
                gas_price,
                gas_limit: tx.gas_limit,
                floor_gas,
                initial_state_gas,
                state_refund: 0,
                is_create: tx.calls[0].to.is_create(),
                result,
            },
        });
    }
    intrinsic = intrinsic.saturating_add(key_auth_gas);
    let (state_refund, regular_refund) =
        apply_authorization_list(request.host, &tx.tempo_authorization_list, spec)?;
    let (execution_gas, reservoir) = initial_gas_and_reservoir(
        request.host.version(),
        tx.gas_limit,
        intrinsic,
        initial_state_gas,
        state_refund,
    );
    let mut result = execute_batch(
        request.host,
        caller,
        keychain.access_key,
        create_nonce,
        gas_price,
        execution_gas,
        reservoir,
        &tx.calls,
        tx.nonce_key.is_zero(),
    )?;
    result
        .gas
        .record_refund(i64::try_from(regular_refund).unwrap_or(i64::MAX));
    TempoHandlerHooks::settle_transaction(SettlementRequest {
        host: request.host,
        envelope: request.envelope,
        context: hook_context,
        gas: GasSettlement {
            caller,
            gas_price,
            gas_limit: tx.gas_limit,
            floor_gas,
            initial_state_gas,
            state_refund,
            is_create: tx.calls[0].to.is_create(),
            result,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TempoBlockEnv, TempoEvmExt, TempoEvmTx, tempo_tx_registry};
    use alloy_consensus::transaction::Recovered;
    use alloy_eips::eip2930::{AccessList, AccessListItem};
    use alloy_primitives::{B256, Bytes, Signature};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use evm2::{
        ExecutionConfig, SpecId,
        evm::{InMemoryDB, precompile::NoPrecompiles},
    };
    use proptest::prelude::*;
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        test_util::TIP20Setup,
        tip20::{ITIP20, PAUSE_ROLE},
    };
    use tempo_primitives::{
        AASigned, TempoTransaction,
        subblock::TEMPO_SUBBLOCK_NONCE_KEY_PREFIX,
        transaction::{
            Call, CallScope, KeyAuthorization, KeychainSignature, SelectorRule, SignatureType,
            SignedKeyAuthorization, TempoSignedAuthorization, TokenLimit,
            tt_signature::{P256SignatureWithPreHash, PrimitiveSignature, WebAuthnSignature},
        },
    };

    const SIGNER: Address = Address::new([0x11; 20]);

    fn test_evm(spec: TempoHardfork) -> crate::TempoEvm<'static> {
        test_evm_with_amsterdam(spec, false)
    }

    fn test_evm_with_amsterdam(spec: TempoHardfork, amsterdam: bool) -> crate::TempoEvm<'static> {
        let mut version = tempo_chainspec::gas_params::version(SpecId::OSAKA, spec, amsterdam);
        version.chain_id = 1;
        let config = ExecutionConfig::for_spec_and_version(spec, version);
        Evm::new_with_execution_config_and_ext(
            config,
            spec,
            TempoBlockEnv::default(),
            tempo_tx_registry(SpecId::OSAKA),
            InMemoryDB::default(),
            NoPrecompiles::default(),
            TempoEvmExt::default(),
        )
    }

    fn secp256k1_signature() -> TempoSignature {
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()))
    }

    fn aa_env(transaction: TempoTransaction, signature: TempoSignature) -> TempoTxEnv {
        Recovered::new_unchecked(
            tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(transaction, signature)),
            SIGNER,
        )
        .into()
    }

    fn intrinsic(
        spec: TempoHardfork,
        transaction: TempoTransaction,
        signature: TempoSignature,
    ) -> HandlerResult<(u64, u64, u64)> {
        intrinsic_with_amsterdam(spec, false, transaction, signature)
    }

    fn intrinsic_with_amsterdam(
        spec: TempoHardfork,
        amsterdam: bool,
        transaction: TempoTransaction,
        signature: TempoSignature,
    ) -> HandlerResult<(u64, u64, u64)> {
        let evm = test_evm_with_amsterdam(spec, amsterdam);
        let env = aa_env(transaction, signature);
        intrinsic_gas(&evm, env.as_aa().unwrap())
    }

    fn call(input: Bytes) -> Call {
        Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input,
        }
    }

    fn key_authorization(num_limits: usize) -> SignedKeyAuthorization {
        let mut authorization =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO);
        if num_limits > 0 {
            authorization = authorization.with_limits(
                (0..num_limits)
                    .map(|index| TokenLimit {
                        token: Address::with_last_byte(index as u8),
                        limit: U256::from(1000),
                        period: 0,
                    })
                    .collect(),
            );
        }
        authorization.into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()))
    }

    fn generate_keypair() -> (PrivateKeySigner, Address) {
        let signer = PrivateKeySigner::random();
        let address = signer.address();
        (signer, address)
    }

    fn sign_key_authorization(
        signer: &PrivateKeySigner,
        authorization: KeyAuthorization,
    ) -> SignedKeyAuthorization {
        let signature_hash = authorization.signature_hash();
        authorization.into_signed(PrimitiveSignature::Secp256k1(
            signer
                .sign_hash_sync(&signature_hash)
                .expect("signing key authorization should succeed"),
        ))
    }

    fn validate_keychain_env(
        env: &TempoTxEnv,
        chain_id: u64,
        spec: TempoHardfork,
    ) -> HandlerResult<()> {
        validate_key_authorization(env.as_aa().unwrap(), chain_id, spec)
    }

    fn invalid_transaction(error: &HandlerError) -> Option<&TempoInvalidTransaction> {
        error.external_ref::<TempoInvalidTransaction>()
    }

    /// Build EVM + transaction with a keychain-signature AA tx.
    ///
    /// - `signature`: outer keychain signature; when `None` a default V2
    ///   keychain sig for `user` is used.
    /// - `seed_key`: when `true` the access key is pre-authorized in
    ///   keychain storage (existing-key path).
    fn make_evm(
        user: Address,
        access_key: Address,
        key_auth: Option<SignedKeyAuthorization>,
        spec: TempoHardfork,
        signature: Option<TempoSignature>,
        seed_key: bool,
    ) -> (crate::TempoEvm<'static>, TempoTxEnv) {
        let signature = signature.unwrap_or_else(|| {
            TempoSignature::Keychain(KeychainSignature::new(
                user,
                PrimitiveSignature::Secp256k1(Signature::test_signature()),
            ))
        });
        let env: TempoTxEnv = Recovered::new_unchecked(
            tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(
                TempoTransaction {
                    chain_id: 1,
                    fee_token: Some(tempo_contracts::precompiles::DEFAULT_FEE_TOKEN),
                    gas_limit: 1_000_000,
                    calls: vec![call(Bytes::new())],
                    key_authorization: key_auth,
                    ..Default::default()
                },
                signature,
            )),
            user,
        )
        .into();
        let env = env.with_simulation_overrides(B256::ZERO, None, Some(access_key));
        let mut evm = test_evm(spec);

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut kc = AccountKeychain::new();
            kc.initialize().unwrap();
            kc.set_transaction_key(Address::ZERO).unwrap();
            kc.set_tx_origin(user).unwrap();
            if seed_key {
                kc.authorize_key(
                    user,
                    access_key,
                    PrecompileSignatureType::Secp256k1,
                    KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                    None,
                )
                .unwrap();
            }
        });

        (evm, env)
    }

    fn validate_against_state(
        evm: &mut crate::TempoEvm<'static>,
        env: &TempoTxEnv,
    ) -> HandlerResult<()> {
        validate_against_state_with_fee(evm, env, U256::ZERO)
    }

    fn validate_against_state_with_fee(
        evm: &mut crate::TempoEvm<'static>,
        env: &TempoTxEnv,
        collected_fee: U256,
    ) -> HandlerResult<()> {
        let aa = env.as_aa().unwrap();
        validate_key_authorization(aa, evm.version().chain_id, evm.config_spec_id())?;
        let fee = TempoFeeContext {
            fee_payer: aa.signer(),
            fee_token: tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
            collected: collected_fee,
        };
        let state = prepare_keychain(evm, aa, fee)?;
        apply_key_authorization(evm, aa, fee, &state, u64::MAX)?;
        Ok(())
    }

    #[test]
    fn test_key_authorization_invalid_signature_rejected() {
        let (_, user) = generate_keypair();
        let key = Address::random();
        let (bad_signer, _) = generate_keypair();

        let signed = sign_key_authorization(
            &bad_signer,
            KeyAuthorization::unrestricted(1337, SignatureType::Secp256k1, key),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T2, None, true);

        assert!(matches!(
            validate_keychain_env(&env, 1, TempoHardfork::T2)
                .as_ref()
                .err()
                .and_then(|error| invalid_transaction(error)),
            Some(TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot { .. })
        ));
    }

    #[test]
    fn test_key_authorization_mismatched_key_id_rejected() {
        let (signer, user) = generate_keypair();
        let wrong_key = Address::random();
        let tx_key = Address::random();

        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1337, SignatureType::Secp256k1, wrong_key),
        );
        let (_, env) = make_evm(user, tx_key, Some(signed), TempoHardfork::T2, None, true);

        assert!(matches!(
            validate_keychain_env(&env, 1, TempoHardfork::T2)
                .as_ref()
                .err()
                .and_then(|error| invalid_transaction(error)),
            Some(TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys)
        ));
    }

    #[test]
    fn test_key_authorization_chain_id_wildcard() {
        for spec in [TempoHardfork::T1B, TempoHardfork::T2] {
            let (signer, user) = generate_keypair();
            let key = Address::random();
            let signed = sign_key_authorization(
                &signer,
                KeyAuthorization::unrestricted(0, SignatureType::Secp256k1, key),
            );
            let (_, env) = make_evm(user, key, Some(signed), spec, None, false);

            let result = validate_keychain_env(&env, 1, spec);
            if !spec.is_t1c() {
                assert!(
                    result.is_ok(),
                    "{spec:?}: chain_id=0 wildcard should be accepted pre-T1C, got: {result:?}"
                );
            } else {
                assert!(
                    result.is_err(),
                    "{spec:?}: chain_id=0 wildcard should be rejected post-T1C, got: {result:?}"
                );
            }
        }
    }

    #[test]
    fn test_key_authorization_chain_id_wrong_and_matching() {
        // Both pre-T1C and post-T1C: wrong chain_id rejected, matching accepted.
        for spec in [TempoHardfork::T1B, TempoHardfork::T2] {
            // Wrong chain_id → rejected
            let (signer, user) = generate_keypair();
            let key = Address::random();
            let signed = sign_key_authorization(
                &signer,
                KeyAuthorization::unrestricted(99_999, SignatureType::Secp256k1, key),
            );
            let (mut evm, env) = make_evm(user, key, Some(signed), spec, None, true);
            assert!(
                validate_against_state(&mut evm, &env).is_err(),
                "{spec:?}: wrong chain_id should be rejected"
            );

            // Matching chain_id (1 = default CfgEnv) → accepted
            let (signer, user) = generate_keypair();
            let key = Address::random();
            let signed = sign_key_authorization(
                &signer,
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key),
            );
            let (mut evm, env) = make_evm(user, key, Some(signed), spec, None, true);
            let result = validate_against_state(&mut evm, &env);
            assert!(
                !matches!(
                    result.as_ref().err().and_then(invalid_transaction),
                    Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                        if reason.contains("chain_id")
                ),
                "{spec:?}: matching chain_id should be accepted, got: {result:?}"
            );
        }
    }

    #[test]
    fn test_key_authorization_witness_rejected_before_t5() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .with_witness(B256::repeat_byte(0x53)),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T4, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T4);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("before T5")
            ),
            "witness-bearing key authorization should be rejected before T5, got: {result:?}"
        );
    }

    #[test]
    fn test_key_authorization_expiry_cached_for_pool_maintenance() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let expiry = u64::MAX - 1;

        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_expiry(expiry),
        );
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T2, None, false);

        let _ = validate_against_state(&mut evm, &env);
        assert_eq!(evm.ext().key_expiry, Some(expiry));
    }

    #[test]
    fn test_t5_key_authorization_witness_is_not_burned_in_state() {
        use tempo_precompiles::account_keychain::isKeyAuthorizationWitnessBurnedCall;

        let (signer, user) = generate_keypair();
        let key = Address::random();
        let witness = B256::repeat_byte(0x54);
        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_witness(witness),
        );
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T5, None, false);

        let result = validate_against_state(&mut evm, &env);
        assert!(
            result.is_ok(),
            "T5 witness authorization should pass: {result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let keychain = AccountKeychain::new();
            assert!(
                !keychain
                    .is_key_authorization_witness_burned(isKeyAuthorizationWitnessBurnedCall {
                        account: user,
                        witness,
                    })
                    .expect("witness read succeeds"),
                "T5 key authorization must not burn its witness"
            );
        });
    }

    #[test]
    fn test_t6_admin_key_authorization_fields_rejected_before_t6() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).into_admin(user),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T5, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T5);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("not active before T6")
            ),
            "admin key authorization fields should be rejected before T6, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_account_mismatch() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let wrong_account = Address::random();
        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .into_admin(wrong_account),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("account mismatch")
            ),
            "admin key authorization should be bound to tx.caller, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_root_admin_key_authorization_allows_omitted_account() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let mut key_auth = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key);
        key_auth.is_admin = true;
        assert_eq!(key_auth.account, None);

        let signed = sign_key_authorization(&signer, key_auth);
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "root-signed admin key authorization should pass stateless validation, got: {env_result:?}"
        );

        let result = validate_against_state(&mut evm, &env);
        assert!(
            result.is_ok(),
            "root-signed admin key authorization should not require account, got: {result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let keychain = AccountKeychain::new();
            assert!(
                keychain
                    .is_admin_key(user, key)
                    .expect("admin key status read succeeds"),
                "root-signed admin key should be registered as admin"
            );
        });
    }

    #[test]
    fn test_t6_root_signed_key_authorization_rejects_admin_keychain_submission() {
        let (root_signer, user) = generate_keypair();
        let (_, admin_key) = generate_keypair();
        let child_key = Address::random();
        let signed = sign_key_authorization(
            &root_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key),
        );
        let (_, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                env_result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("root transaction signature")
            ),
            "root-signed key authorization should require a root transaction signature, got: {env_result:?}"
        );
    }

    #[test]
    fn test_t6_root_key_authorization_rejects_account_mismatch() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let wrong_account = Address::random();
        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .with_account(wrong_account),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("key authorization account mismatch")
            ),
            "root-signed key authorization should be bound to tx.caller, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_restrictions() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .with_expiry(u64::MAX)
                .into_admin(user),
        );
        let (_, env) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("cannot carry expiry")
            ),
            "admin key authorization should reject restrictions, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_access_key_can_authorize_different_admin_key() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_authorization(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::WebAuthn, child_key).into_admin(user),
        );
        let (mut evm, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "admin access key authorization should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes admin key");
        });

        let result = validate_against_state(&mut evm, &env);
        assert!(
            result.is_ok(),
            "admin access key should authorize a different admin key, got: {result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let keychain = AccountKeychain::new();
            assert!(
                keychain
                    .is_admin_key(user, child_key)
                    .expect("admin key status read succeeds"),
                "child key should be registered as admin"
            );
        });
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_admin_signature_type_mismatch() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_authorization(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(user),
        );
        let (mut evm, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "admin-signed key authorization should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::WebAuthn, None)
                .expect("root authorizes WebAuthn admin key");
        });

        let result = validate_against_state(&mut evm, &env);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("SignatureTypeMismatch")
            ),
            "admin-signed key authorization should reject sidecar signature type mismatch, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_different_transaction_admin_key() {
        let (authorization_signer, authorization_admin_key) = generate_keypair();
        let (_, tx_admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_authorization(
            &authorization_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(user),
        );
        let (_, env) = make_evm(
            user,
            tx_admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("must be signed by transaction key")
            ),
            "admin-signed key authorization must use the transaction admin key; auth signer {authorization_admin_key}, tx signer {tx_admin_key}, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_access_key_non_admin_authorization_requires_account_binding() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_authorization(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key),
        );
        let (_, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("admin-signed key authorization account mismatch")
            ),
            "admin-signed non-admin authorization without account binding should fail in validate_env, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_access_key_non_admin_authorization_rejects_account_replay() {
        use tempo_precompiles::account_keychain::getKeyCall;

        let (admin_signer, admin_key) = generate_keypair();
        let alice = Address::random();
        let bob = Address::random();
        let child_key = Address::random();
        let signed = sign_key_authorization(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(alice),
        );

        let (mut alice_evm, alice_env) = make_evm(
            alice,
            admin_key,
            Some(signed.clone()),
            TempoHardfork::T6,
            None,
            false,
        );
        let alice_env_result = validate_keychain_env(&alice_env, 1, TempoHardfork::T6);
        assert!(
            alice_env_result.is_ok(),
            "account-bound authorization should pass Alice stateless validation, got: {alice_env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut alice_evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(alice, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes Alice admin key");
        });

        let alice_result = validate_against_state(&mut alice_evm, &alice_env);
        assert!(
            alice_result.is_ok(),
            "account-bound admin-signed non-admin authorization should pass for Alice, got: {alice_result:?}"
        );
        StorageCtx::enter_evm_without_tip1060_accounting(&mut alice_evm, || {
            let keychain = AccountKeychain::new();
            let key = keychain
                .get_key(getKeyCall {
                    account: alice,
                    keyId: child_key,
                })
                .expect("child key read succeeds");
            assert_eq!(key.keyId, child_key, "child key should be registered");
            assert!(
                !keychain
                    .is_admin_key(alice, child_key)
                    .expect("admin key status read succeeds"),
                "child key should not be admin"
            );
        });

        let (_, bob_env) = make_evm(bob, admin_key, Some(signed), TempoHardfork::T6, None, false);

        let bob_result = validate_keychain_env(&bob_env, 1, TempoHardfork::T6);
        assert!(
            matches!(
                bob_result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { reason })
                    if reason.contains("key authorization account mismatch")
            ),
            "Alice-bound authorization should not replay for Bob, got: {bob_result:?}"
        );
    }

    #[test]
    fn test_t6_admin_delegation_does_not_apply_child_fee_limit() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let gas_limit = 100_000;
        let fee = U256::from(gas_limit);
        let child_spending_limit = fee - U256::ONE;

        let signed = sign_key_authorization(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_limits(vec![TokenLimit {
                    token: tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
                    limit: child_spending_limit,
                    period: 60,
                }])
                .with_account(user),
        );
        let (mut evm, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "admin delegation should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes admin key");
        });

        let result = validate_against_state_with_fee(&mut evm, &env, fee);
        assert!(
            result.is_ok(),
            "admin delegation should not precharge fees against child key limits, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_delegation_preserves_admin_transaction_key() {
        use tempo_precompiles::account_keychain::getTransactionKeyCall;

        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_authorization(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(user),
        );
        let (mut evm, env) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = validate_keychain_env(&env, 1, TempoHardfork::T6);
        assert!(
            env_result.is_ok(),
            "admin delegation should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes admin key");
        });

        let result = validate_against_state(&mut evm, &env);
        assert!(
            result.is_ok(),
            "admin delegation should pass, got: {result:?}"
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let keychain = AccountKeychain::new();
            let transaction_key = keychain
                .get_transaction_key(getTransactionKeyCall {}, user)
                .expect("transaction key read succeeds");
            assert_eq!(
                transaction_key, admin_key,
                "admin delegation must preserve the signer key as transaction key"
            );
        });
    }

    #[test]
    fn test_same_tx_key_authorization_rejects_fee_above_new_limit_before_auth() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let gas_limit = 100_000;
        let fee = U256::from(gas_limit);
        let spending_limit = fee - U256::ONE;

        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_limits(vec![
                TokenLimit {
                    token: tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
                    limit: spending_limit,
                    period: 60,
                },
            ]),
        );
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T3, None, false);

        let result = validate_against_state_with_fee(&mut evm, &env, fee);

        assert!(
            matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::CollectFeePreTx(FeePaymentError::Other(reason)))
                    if reason.contains("SpendingLimitExceeded")
            ),
            "same-tx auth+use should reject fee above the new key limit before auth, got: {result:?}"
        );
        assert!(
            evm.logs()
                .iter()
                .all(|log| log.address != tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS),
            "fee-limit rejection must happen before key authorization emits events"
        );
    }

    #[test]
    fn test_stale_collected_fee_not_charged_to_zero_fee_same_tx_auth_use() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let stale_fee = U256::from(100_000);
        let spending_limit = stale_fee - U256::ONE;

        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_limits(vec![
                TokenLimit {
                    token: tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
                    limit: spending_limit,
                    period: 60,
                },
            ]),
        );
        let (mut evm, env) = make_evm(
            user,
            key,
            Some(signed.clone()),
            TempoHardfork::T3,
            None,
            false,
        );

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            TIP20Setup::path_usd(user)
                .with_issuer(user)
                .with_mint(user, stale_fee * U256::from(2))
                .apply()
                .expect("pathUSD setup succeeds");
        });

        let stale_env: TempoTxEnv = Recovered::new_unchecked(
            tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(
                TempoTransaction {
                    chain_id: 1,
                    fee_token: Some(tempo_contracts::precompiles::DEFAULT_FEE_TOKEN),
                    max_priority_fee_per_gas: 1_000_000_000_000,
                    max_fee_per_gas: 1_000_000_000_000,
                    gas_limit: 100_000,
                    calls: vec![call(Bytes::new())],
                    key_authorization: Some(signed),
                    ..Default::default()
                },
                TempoSignature::Keychain(KeychainSignature::new(
                    user,
                    PrimitiveSignature::Secp256k1(Signature::test_signature()),
                )),
            )),
            user,
        )
        .into();
        let stale_env = stale_env.with_simulation_overrides(B256::ZERO, None, Some(key));
        let stale_context = TempoHandlerHooks::prepare_fee(&mut evm, &stale_env).unwrap();
        assert_eq!(stale_context.collected, stale_fee);

        let context = TempoHandlerHooks::prepare_fee(&mut evm, &env).unwrap();
        assert_eq!(context.collected, U256::ZERO);

        let result = validate_against_state_with_fee(&mut evm, &env, U256::ZERO);

        assert!(
            result.is_ok(),
            "zero-fee same-tx auth/use must not charge stale fee, got: {result:?}"
        );
        assert_eq!(context.collected, U256::ZERO);
    }

    #[test]
    fn test_t3_scope_validation_moves_to_execution() {
        const CALL_SCOPE_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

        let caller = Address::repeat_byte(0x11);
        let access_key = Address::repeat_byte(0x22);
        let target = tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
        let calls = vec![Call {
            to: TxKind::Call(target),
            value: U256::ZERO,
            input: Bytes::from_static(&CALL_SCOPE_SELECTOR),
        }];
        let mut evm = test_evm(TempoHardfork::T3);

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();

            keychain.initialize().expect("keychain initialized");
            keychain
                .set_transaction_key(Address::ZERO)
                .expect("root key setup succeeds");
            keychain
                .set_tx_origin(caller)
                .expect("tx.origin setup succeeds");
            keychain
                .authorize_key(
                    caller,
                    access_key,
                    PrecompileSignatureType::Secp256k1,
                    KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: false,
                        allowedCalls: vec![PrecompileCallScope {
                            target,
                            selectorRules: vec![PrecompileSelectorRule {
                                selector: CALL_SCOPE_SELECTOR.into(),
                                recipients: vec![],
                            }],
                        }],
                    },
                    None,
                )
                .expect("access key authorization succeeds");
        });

        let env = aa_env(
            TempoTransaction {
                chain_id: 1,
                fee_token: Some(tempo_contracts::precompiles::DEFAULT_FEE_TOKEN),
                gas_limit: 1_000_000,
                calls: calls.clone(),
                ..Default::default()
            },
            TempoSignature::Keychain(KeychainSignature::new(
                caller,
                PrimitiveSignature::Secp256k1(Signature::test_signature()),
            )),
        )
        .with_simulation_overrides(B256::ZERO, None, Some(access_key));
        let keychain = prepare_keychain(
            &mut evm,
            env.as_aa().unwrap(),
            TempoFeeContext {
                fee_payer: caller,
                fee_token: tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
                collected: U256::ZERO,
            },
        )
        .expect("scope validation no longer runs during state validation");
        assert_eq!(keychain.access_key, Some(access_key));

        // EVM2 passes only the post-intrinsic execution budget into batch execution. A
        // transaction whose gas limit is exactly its intrinsic gas therefore has no gas left for
        // call-scope validation.
        let execution_gas = 0;
        let result =
            prevalidate_call_scopes(&mut evm, caller, Some(access_key), &calls, execution_gas, 0)
                .expect("scope validation should return a frame result")
                .expect("insufficient execution gas should halt");

        assert!(
            matches!(result.stop, InstrStop::PrecompileOOG),
            "expected scope validation to fail during execution with OOG, got: {:?}",
            result.stop
        );
        assert_eq!(
            result.gas.limit(),
            execution_gas,
            "batch OOG should report the full execution gas budget"
        );
        assert_eq!(
            result.gas.spent(),
            execution_gas,
            "batch OOG should consume the full execution gas budget"
        );
        assert_eq!(result.gas.refunded(), 0);
    }

    #[test]
    fn test_t3_scope_validation_returns_call_not_allowed_revert_data() {
        use alloy_sol_types::SolInterface;
        use tempo_contracts::precompiles::AccountKeychainError;

        const ALLOWED_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        const DENIED_SELECTOR: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];

        let caller = Address::repeat_byte(0x11);
        let access_key = Address::repeat_byte(0x22);
        let target = tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
        let calls = vec![Call {
            to: TxKind::Call(target),
            value: U256::ZERO,
            input: Bytes::from_static(&DENIED_SELECTOR),
        }];
        let mut evm = test_evm(TempoHardfork::T3);

        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut keychain = AccountKeychain::new();

            keychain.initialize().expect("keychain initialized");
            keychain
                .set_transaction_key(Address::ZERO)
                .expect("root key setup succeeds");
            keychain
                .set_tx_origin(caller)
                .expect("tx.origin setup succeeds");
            keychain
                .authorize_key(
                    caller,
                    access_key,
                    PrecompileSignatureType::Secp256k1,
                    KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: false,
                        allowedCalls: vec![PrecompileCallScope {
                            target,
                            selectorRules: vec![PrecompileSelectorRule {
                                selector: ALLOWED_SELECTOR.into(),
                                recipients: vec![],
                            }],
                        }],
                    },
                    None,
                )
                .expect("access key authorization succeeds");
        });

        let result =
            prevalidate_call_scopes(&mut evm, caller, Some(access_key), &calls, 1_000_000, 0)
                .expect("execution should return a frame result")
                .expect("denied call should revert");

        let expected_revert: Bytes = AccountKeychainError::call_not_allowed().abi_encode().into();

        assert_eq!(result.stop, InstrStop::Revert);
        assert_eq!(result.output, expected_revert);
        assert!(
            result.gas.spent() < 1_000_000,
            "prevalidate revert must not consume the full gas_limit"
        );
    }

    #[test]
    fn test_t3_scope_validation_empty_calls_returns_custom_error() {
        let err = validate_calls(&[], false)
            .map_err(TempoInvalidTransaction::from)
            .map_err(invalid)
            .expect_err("empty calls should return an error instead of panicking");

        assert!(matches!(
            invalid_transaction(&err),
            Some(TempoInvalidTransaction::CallsValidation(reason))
                if *reason == "calls list cannot be empty"
        ));
    }

    #[test]
    fn test_self_sponsored_fee_payer_rejected_post_t2() {
        let caller = Address::random();
        let invalid_token = Address::random();

        let env: TempoTxEnv = Recovered::new_unchecked(
            tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(
                TempoTransaction {
                    chain_id: 1,
                    fee_token: Some(invalid_token),
                    fee_payer_signature: Some(Signature::test_signature()),
                    gas_limit: 1_000_000,
                    calls: vec![call(Bytes::new())],
                    ..Default::default()
                },
                secp256k1_signature(),
            )),
            caller,
        )
        .into();
        let env = env.with_simulation_overrides(B256::ZERO, Some(caller), None);
        let mut evm = test_evm(TempoHardfork::T2);
        let result = handle(TxRequest {
            envelope: &env,
            tx: env.as_aa().unwrap(),
            host: &mut evm,
            _non_exhaustive: (),
        });
        assert!(matches!(
            result
                .as_ref()
                .err()
                .and_then(|error| invalid_transaction(error)),
            Some(TempoInvalidTransaction::SelfSponsoredFeePayer)
        ));
    }

    #[test]
    fn test_self_sponsored_fee_payer_not_rejected_pre_t4() {
        let caller = Address::random();
        let invalid_token = Address::random();

        let env: TempoTxEnv = Recovered::new_unchecked(
            tempo_primitives::TempoTxEnvelope::AA(AASigned::new_unhashed(
                TempoTransaction {
                    chain_id: 1,
                    fee_token: Some(invalid_token),
                    fee_payer_signature: Some(Signature::test_signature()),
                    gas_limit: 1_000_000,
                    calls: vec![call(Bytes::new())],
                    ..Default::default()
                },
                secp256k1_signature(),
            )),
            caller,
        )
        .into();
        let env = env.with_simulation_overrides(B256::ZERO, Some(caller), None);
        let mut evm = test_evm(TempoHardfork::T1C);
        let result = handle(TxRequest {
            envelope: &env,
            tx: env.as_aa().unwrap(),
            host: &mut evm,
            _non_exhaustive: (),
        });
        assert!(
            !matches!(
                result
                    .as_ref()
                    .err()
                    .and_then(|error| invalid_transaction(error)),
                Some(TempoInvalidTransaction::SelfSponsoredFeePayer)
            ),
            "self-sponsored fee payer must not be rejected before T2, got: {result:?}"
        );
    }

    #[test]
    fn test_keychain_version_rejection() {
        let caller = Address::random();

        // V1 (legacy) rejected post-T1C
        let v1 = TempoSignature::Keychain(KeychainSignature::new_v1(
            caller,
            PrimitiveSignature::Secp256k1(Signature::test_signature()),
        ));
        let (_, env) = make_evm(
            caller,
            Address::ZERO,
            None,
            TempoHardfork::T2,
            Some(v1),
            false,
        );
        assert!(
            env.as_aa()
                .unwrap()
                .inner()
                .signature()
                .validate_version(true)
                .is_err()
        );

        // V2 rejected pre-T1C
        let v2 = TempoSignature::Keychain(KeychainSignature::new(
            caller,
            PrimitiveSignature::Secp256k1(Signature::test_signature()),
        ));
        let (_, env) = make_evm(
            caller,
            Address::ZERO,
            None,
            TempoHardfork::T1B,
            Some(v2),
            false,
        );
        assert!(
            env.as_aa()
                .unwrap()
                .inner()
                .signature()
                .validate_version(false)
                .is_err()
        );
    }

    #[test]
    fn test_keychain_signature_with_valid_authorized_key() {
        let (mut evm, env) = make_evm(
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            None,
            TempoHardfork::T2,
            None,
            true,
        );

        let result = validate_against_state(&mut evm, &env);
        assert!(
            !matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(TempoInvalidTransaction::KeychainValidationFailed { .. })
            ),
            "Valid authorized key should pass, got: {result:?}"
        );
    }

    #[test]
    fn test_key_authorization_without_existing_key_passes() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_authorization(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key),
        );
        let (mut evm, env) = make_evm(user, key, Some(signed), TempoHardfork::T2, None, false);

        let result = validate_against_state(&mut evm, &env);
        assert!(
            !matches!(
                result.as_ref().err().and_then(invalid_transaction),
                Some(
                    TempoInvalidTransaction::KeychainValidationFailed { .. }
                        | TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys
                        | TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot { .. }
                        | TempoInvalidTransaction::KeychainPrecompileError { .. }
                )
            ),
            "Same-tx auth+use should pass when key does not exist, got: {result:?}"
        );
    }

    #[test]
    fn test_aa_gas_single_call_vs_normal_tx() {
        // Test that AA tx with secp256k1 and single call matches normal tx + per-call overhead
        let calldata = Bytes::from(vec![1, 2, 3, 4, 5]); // 5 non-zero bytes
        let to = Address::random();

        // Single call for AA
        let call = Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        // Calculate AA gas
        let (regular, state, _) = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls: vec![call],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        // Calculate expected gas using EVM2's function for equivalent normal tx
        let evm = test_evm(TempoHardfork::Genesis);
        let normal_tx_gas = evm2::ethereum::intrinsic_gas(
            evm.version(),
            SIGNER,
            TxKind::Call(to),
            &calldata,
            0,
            0,
            U256::ZERO,
        );

        // AA with secp256k1 + single call should match normal tx exactly
        assert_eq!(regular, normal_tx_gas);
        assert_eq!(state, 0, "AA CALL tx should not add initial state gas");
    }

    #[test]
    fn test_aa_gas_multiple_calls_overhead() {
        let calldata = Bytes::from(vec![1, 2, 3]); // 3 non-zero bytes

        let calls = vec![
            Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: calldata.clone(),
            },
            Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: calldata.clone(),
            },
            Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: calldata.clone(),
            },
        ];

        let evm = test_evm(TempoHardfork::Genesis);
        let cold_account = u64::from(evm.version().gas_params[GasId::WarmStorageReadCost])
            + u64::from(evm.version().gas_params[GasId::ColdAccountAdditionalCost]);
        let (regular, _, _) = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        // Calculate base gas for a single normal tx
        let base_tx_gas = 21_000 + calldata.len() as u64 * 16;

        // For 3 calls: base (21k) + 3*calldata + 2*per-call overhead (calls 2 and 3)
        // = 21k + 2*(calldata cost) + 2*COLD_ACCOUNT_ACCESS_COST
        let expected = base_tx_gas + 2 * (calldata.len() as u64 * 16) + 2 * cold_account;
        // Should charge per-call overhead for calls beyond the first
        assert_eq!(regular, expected);
    }

    #[test]
    fn test_aa_gas_p256_signature() {
        let calldata = Bytes::from(vec![1, 2]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        let signature =
            TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: B256::ZERO,
                s: B256::ZERO,
                pub_key_x: B256::ZERO,
                pub_key_y: B256::ZERO,
                pre_hash: false,
            }));
        let (regular, _, _) = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls: vec![call],
                ..Default::default()
            },
            signature,
        )
        .unwrap();

        // Calculate base gas for normal tx
        let base_gas = 21_000 + calldata.len() as u64 * 16;

        // Expected: normal tx + P256_VERIFY_GAS
        let expected = base_gas + P256_VERIFY_GAS;
        assert_eq!(regular, expected);
    }

    #[test]
    fn test_aa_gas_create_call() {
        let initcode = Bytes::from(vec![0x60, 0x80]); // 2 bytes

        let call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode.clone(),
        };

        let (regular, state, _) = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls: vec![call],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        // Calculate expected using EVM2's function for CREATE tx
        let evm = test_evm(TempoHardfork::Genesis);
        let base_gas = evm2::ethereum::intrinsic_gas(
            evm.version(),
            SIGNER,
            TxKind::Create,
            &initcode,
            0,
            0,
            U256::ZERO,
        );

        // AA CREATE should match normal CREATE exactly
        assert_eq!(regular, base_gas);
        assert_eq!(state, evm.version().gas_params.create_state_gas());
    }

    #[test]
    fn test_aa_gas_value_transfer() {
        let calldata = Bytes::from(vec![1]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::from(1000), // Non-zero value
            input: calldata,
        };

        let error = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls: vec![call],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap_err();
        assert!(matches!(
            error.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::ValueTransferNotAllowedInAATx)
        ));
    }

    #[test]
    fn test_zero_value_transfer() {
        assert!(
            intrinsic(
                TempoHardfork::Genesis,
                TempoTransaction {
                    calls: vec![call(Bytes::new())],
                    ..Default::default()
                },
                secp256k1_signature(),
            )
            .is_ok()
        );
    }

    #[test]
    fn test_aa_gas_access_list() {
        let evm = test_evm(TempoHardfork::Genesis);
        let address_cost = u64::from(evm.version().gas_params[GasId::TxAccessListAddressCost]);
        let storage_cost = u64::from(evm.version().gas_params[GasId::TxAccessListStorageKeyCost]);
        let (without, _, _) = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        let (with, _, _) = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                access_list: AccessList(vec![AccessListItem {
                    address: Address::repeat_byte(0x42),
                    storage_keys: vec![B256::ZERO, B256::repeat_byte(1)],
                }]),
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        assert_eq!(with - without, address_cost + 2 * storage_cost);
    }

    #[test]
    fn test_key_authorization_rlp_encoding() {
        use alloy_primitives::{Address, U256};
        use tempo_primitives::transaction::{KeyAuthorization, SignatureType, TokenLimit};

        // Create test data
        let chain_id = 1u64;
        let key_type = SignatureType::Secp256k1;
        let key_id = Address::random();
        let expiry = 1000u64;
        let limits = vec![
            TokenLimit {
                token: Address::random(),
                limit: U256::from(100),
                period: 0,
            },
            TokenLimit {
                token: Address::random(),
                limit: U256::from(200),
                period: 0,
            },
        ];

        // Compute hash using the helper function
        let hash1 = KeyAuthorization::unrestricted(chain_id, key_type, key_id)
            .with_expiry(expiry)
            .with_limits(limits.clone())
            .signature_hash();

        // Compute again to verify consistency
        let hash2 = KeyAuthorization::unrestricted(chain_id, key_type, key_id)
            .with_expiry(expiry)
            .with_limits(limits.clone())
            .signature_hash();

        assert_eq!(hash1, hash2, "Hash computation should be deterministic");

        // Verify that different chain_id produces different hash
        let hash3 = KeyAuthorization::unrestricted(2, key_type, key_id)
            .with_expiry(expiry)
            .with_limits(limits)
            .signature_hash();
        assert_ne!(
            hash1, hash3,
            "Different chain_id should produce different hash"
        );
    }

    #[test]
    fn test_aa_gas_floor_gas_prague() {
        let (_, _, floor) = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls: vec![call(Bytes::from(vec![1; 1_000]))],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        assert!(floor > 0);
    }

    #[test]
    fn test_key_authorization_gas_with_limits() {
        use tempo_primitives::transaction::{
            KeyAuthorization, SignatureType, SignedKeyAuthorization, TokenLimit,
        };

        // Helper to create key auth with N limits
        let create_key_auth = |num_limits: usize| -> SignedKeyAuthorization {
            let mut auth =
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random());
            if num_limits > 0 {
                auth = auth.with_limits(
                    (0..num_limits)
                        .map(|_| TokenLimit {
                            token: Address::random(),
                            limit: U256::from(1000),
                            period: 0,
                        })
                        .collect(),
                );
            }
            auth.into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ))
        };

        // Test 0 limits: base (27k) + ecrecover (3k) = 30,000
        let genesis = test_evm(TempoHardfork::Genesis);
        let (gas_0, state_0) = key_authorization_gas(
            &create_key_auth(0),
            &genesis,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        );
        assert_eq!(
            gas_0,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS,
            "0 limits should be 30,000"
        );
        assert_eq!(state_0, 0, "pre-T1B has no state gas");

        // Test 1 limit: 30,000 + 22,000 = 52,000
        let (gas_1, state_1) = key_authorization_gas(
            &create_key_auth(1),
            &genesis,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        );
        assert_eq!(
            gas_1,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + KEY_AUTH_PER_LIMIT_GAS,
            "1 limit should be 52,000"
        );
        assert_eq!(state_1, 0, "pre-T1B has no state gas");

        // Test 2 limits: 30,000 + 44,000 = 74,000
        let (gas_2, _) = key_authorization_gas(
            &create_key_auth(2),
            &genesis,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        );
        assert_eq!(
            gas_2,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 2 * KEY_AUTH_PER_LIMIT_GAS,
            "2 limits should be 74,000"
        );

        // Test 3 limits: 30,000 + 66,000 = 96,000
        let (gas_3, _) = key_authorization_gas(
            &create_key_auth(3),
            &genesis,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        );
        assert_eq!(
            gas_3,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 3 * KEY_AUTH_PER_LIMIT_GAS,
            "3 limits should be 96,000"
        );

        // T1B branch: gas = sig_gas + SLOAD + SSTORE * (1 + num_limits) + buffer
        let t1b_evm = test_evm(TempoHardfork::T1B);
        let t1b_gas_params = &t1b_evm.version().gas_params;
        let sstore = u64::from(t1b_gas_params.get(GasId::SstoreSetWithoutLoadCost));
        let sload = u64::from(t1b_gas_params.get(GasId::WarmStorageReadCost))
            + u64::from(t1b_gas_params.get(GasId::ColdStorageAdditionalCost));
        const BUFFER: u64 = 2_000;

        for num_limits in 0..=3 {
            let (gas, state_gas) =
                key_authorization_gas(&create_key_auth(num_limits), &t1b_evm, TempoHardfork::T1B);
            let expected = ECRECOVER_GAS + sload + sstore * (1 + num_limits as u64) + BUFFER;
            assert_eq!(gas, expected, "T1B with {num_limits} limits");
            assert_eq!(state_gas, 0, "T1B has no state gas");
        }

        let t3_evm = test_evm(TempoHardfork::T3);
        let t3_gas_params = &t3_evm.version().gas_params;
        let t3_sstore = u64::from(t3_gas_params.get(GasId::SstoreSetWithoutLoadCost));
        let t3_sload = u64::from(t3_gas_params.get(GasId::WarmStorageReadCost))
            + u64::from(t3_gas_params.get(GasId::ColdStorageAdditionalCost));

        for num_limits in 0..=3 {
            let num_sstores = 1 + 2 * num_limits as u64;
            let (gas, state_gas) =
                key_authorization_gas(&create_key_auth(num_limits), &t3_evm, TempoHardfork::T3);
            let expected = ECRECOVER_GAS + t3_sload + t3_sstore * num_sstores + BUFFER;
            assert_eq!(gas, expected, "T3 with {num_limits} limits");
            assert_eq!(state_gas, 0, "T3 has no state gas");
        }

        // T4 with T4 gas params: regular sstore = 19,900, state gas = 230,000 per SSTORE
        let t4_evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let t4_gas_params = &t4_evm.version().gas_params;
        let t4_sstore = u64::from(t4_gas_params.get(GasId::SstoreSetWithoutLoadCost));
        let t4_sload = u64::from(t4_gas_params.get(GasId::WarmStorageReadCost))
            + u64::from(t4_gas_params.get(GasId::ColdStorageAdditionalCost));
        let t4_sstore_state = u64::from(t4_gas_params.get(GasId::SstoreSetState));

        for num_limits in 0..=3 {
            let num_sstores = 1 + 2 * num_limits as u64;
            let (gas, state_gas) =
                key_authorization_gas(&create_key_auth(num_limits), &t4_evm, TempoHardfork::T4);
            let expected_state = t4_sstore_state * num_sstores;
            let expected = ECRECOVER_GAS
                + t4_sload
                + t4_sstore * num_sstores
                + BUFFER
                + 5_000
                + expected_state;
            assert_eq!(gas + state_gas, expected, "T4 with {num_limits} limits");
            assert_eq!(
                state_gas, expected_state,
                "T4 state gas with {num_limits} limits"
            );
        }

        let t5_evm = test_evm(TempoHardfork::T5);
        let t5_gas_params = &t5_evm.version().gas_params;
        let t5_sload = u64::from(t5_gas_params.get(GasId::WarmStorageReadCost))
            + u64::from(t5_gas_params.get(GasId::ColdStorageAdditionalCost));
        let base_t5_key_auth = create_key_auth(0);
        let mut witness_t5_key_auth = create_key_auth(0);
        witness_t5_key_auth.authorization = witness_t5_key_auth
            .authorization
            .with_witness(B256::repeat_byte(0x53));

        let (base_t5_gas, base_t5_state_gas) =
            key_authorization_gas(&base_t5_key_auth, &t5_evm, TempoHardfork::T5);
        let (witness_t5_gas, witness_t5_state_gas) =
            key_authorization_gas(&witness_t5_key_auth, &t5_evm, TempoHardfork::T5);

        assert_eq!(
            witness_t5_gas - base_t5_gas,
            t5_sload + KEY_AUTH_EXTRA_EVENT_BUFFER,
            "T5 witness adds one burned-witness SLOAD and one event"
        );
        assert_eq!(
            witness_t5_state_gas - base_t5_state_gas,
            0,
            "T5 witness authorization does not add state gas"
        );

        let t6_evm = test_evm(TempoHardfork::T6);
        let base_t6_key_auth = create_key_auth(0);
        let mut account_bound_t6_key_auth = create_key_auth(0);
        account_bound_t6_key_auth.authorization = account_bound_t6_key_auth
            .authorization
            .with_account(Address::random());
        let mut admin_t6_key_auth = create_key_auth(0);
        admin_t6_key_auth.authorization = admin_t6_key_auth
            .authorization
            .into_admin(Address::random());
        let mut unbound_admin_t6_key_auth = create_key_auth(0);
        unbound_admin_t6_key_auth.authorization.is_admin = true;

        let (base_t6_gas, base_t6_state_gas) =
            key_authorization_gas(&base_t6_key_auth, &t6_evm, TempoHardfork::T6);
        let (account_bound_t6_gas, account_bound_t6_state_gas) =
            key_authorization_gas(&account_bound_t6_key_auth, &t6_evm, TempoHardfork::T6);
        let (admin_t6_gas, admin_t6_state_gas) =
            key_authorization_gas(&admin_t6_key_auth, &t6_evm, TempoHardfork::T6);
        let (unbound_admin_t6_gas, unbound_admin_t6_state_gas) =
            key_authorization_gas(&unbound_admin_t6_key_auth, &t6_evm, TempoHardfork::T6);

        assert_eq!(
            account_bound_t6_gas - base_t6_gas,
            0,
            "T6 account-bound authorization does not add key authorization gas"
        );
        assert_eq!(
            admin_t6_gas - base_t6_gas,
            KEY_AUTH_EXTRA_EVENT_BUFFER,
            "T6 account-bound admin authorization charges one extra event buffer"
        );
        assert_eq!(
            admin_t6_gas - account_bound_t6_gas,
            KEY_AUTH_EXTRA_EVENT_BUFFER,
            "T6 admin authorization pays one extra event buffer over non-admin account-bound authorization"
        );
        assert_eq!(
            unbound_admin_t6_gas - base_t6_gas,
            KEY_AUTH_EXTRA_EVENT_BUFFER,
            "T6 root-signed admin authorization without account charges only the extra event buffer"
        );
        assert_eq!(
            account_bound_t6_state_gas, base_t6_state_gas,
            "T6 account binding does not add state gas"
        );
        assert_eq!(
            admin_t6_state_gas, base_t6_state_gas,
            "T6 admin authorization event buffer does not add state gas"
        );
        assert_eq!(
            unbound_admin_t6_state_gas, base_t6_state_gas,
            "T6 unbound admin authorization does not add state gas"
        );

        let scoped = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
            .with_allowed_calls(vec![tempo_primitives::transaction::CallScope {
                target: Address::random(),
                selector_rules: vec![tempo_primitives::transaction::SelectorRule {
                    selector: [0xa9, 0x05, 0x9c, 0xbb],
                    recipients: vec![Address::random(), Address::random()],
                }],
            }])
            .into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ));

        let (gas, state_gas) = key_authorization_gas(&scoped, &t3_evm, TempoHardfork::T3);
        let expected = ECRECOVER_GAS + t3_sload + t3_sstore * (1 + 12) + BUFFER;
        assert_eq!(
            gas, expected,
            "T3 scope writes should keep current main accounting"
        );
        assert_eq!(state_gas, 0, "T3 has no state gas");

        let (gas, state_gas) = key_authorization_gas(&scoped, &t4_evm, TempoHardfork::T4);
        // 1 key write + 12 scope slots = 13 SSTOREs:
        // account mode(1) + target insertion rows(3) + selector insertion rows(3)
        // + constrained selector recipient-length(1) + recipients values+positions(2*2).
        // The rounded surcharge adds 5k base + 7k per target + 7k per selector + 5k per
        // recipient, which keeps larger scope trees from being materially underpriced.
        let num_sstores = 1 + 12;
        let expected_state = t4_sstore_state * num_sstores;
        let expected =
            ECRECOVER_GAS + t4_sload + t4_sstore * num_sstores + BUFFER + 29_000 + expected_state;
        assert_eq!(
            gas + state_gas,
            expected,
            "T4 scope writes should be fully charged"
        );
        assert_eq!(state_gas, expected_state, "T4 scope state gas");
        let multi_scope =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
                .with_allowed_calls(vec![
                    tempo_primitives::transaction::CallScope {
                        target: Address::random(),
                        selector_rules: vec![
                            tempo_primitives::transaction::SelectorRule {
                                selector: [0xa9, 0x05, 0x9c, 0xbb],
                                recipients: vec![],
                            },
                            tempo_primitives::transaction::SelectorRule {
                                selector: [0x09, 0x5e, 0xa7, 0xb3],
                                recipients: vec![],
                            },
                        ],
                    },
                    tempo_primitives::transaction::CallScope {
                        target: Address::random(),
                        selector_rules: vec![],
                    },
                ])
                .into_signed(PrimitiveSignature::Secp256k1(
                    alloy_primitives::Signature::test_signature(),
                ));

        let (gas, state_gas) = key_authorization_gas(&multi_scope, &t3_evm, TempoHardfork::T3);
        let expected = ECRECOVER_GAS + t3_sload + t3_sstore * 14 + BUFFER;
        assert_eq!(
            gas, expected,
            "T3 scope writes should keep current main accounting"
        );
        assert_eq!(state_gas, 0, "T3 has no state gas");

        let (gas, state_gas) = key_authorization_gas(&multi_scope, &t4_evm, TempoHardfork::T4);
        let expected_state = t4_sstore_state * 12;
        let expected = ECRECOVER_GAS + t4_sload + t4_sstore * 12 + BUFFER + 33_000 + expected_state;
        assert_eq!(
            gas + state_gas,
            expected,
            "T4 scope writes should only charge storage-creating rows"
        );
        assert_eq!(state_gas, expected_state, "T4 scope state gas");
    }

    #[test]
    fn test_t4_key_authorization_matches_tip1016_sstore_regular_cost() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let authorization = key_authorization(0);
        let params = &evm.version().gas_params;
        let load = u64::from(params[GasId::WarmStorageReadCost])
            + u64::from(params[GasId::ColdStorageAdditionalCost]);
        let (regular, state) = key_authorization_gas(&authorization, &evm, TempoHardfork::T4);
        assert_eq!(
            regular
                - ECRECOVER_GAS
                - load
                - 2_000
                - call_scope_extra_gas(&authorization.authorization),
            20_000
        );
        assert_eq!(state, 230_000);
    }

    #[test]
    fn test_t7_key_authorization_intrinsic_includes_storage_credit_value() {
        let evm = test_evm(TempoHardfork::T7);
        let authorization = key_authorization(0);
        let params = &evm.version().gas_params;
        let load = u64::from(params[GasId::WarmStorageReadCost])
            + u64::from(params[GasId::ColdStorageAdditionalCost]);
        let (regular, state) = key_authorization_gas(&authorization, &evm, TempoHardfork::T7);
        assert_eq!(params[GasId::SstoreSetWithoutLoadCost], 5_000);
        assert_eq!(
            regular
                - ECRECOVER_GAS
                - load
                - 2_000
                - call_scope_extra_gas(&authorization.authorization),
            tempo_chainspec::constants::gas::SSTORE_CREATE_COST
        );
        assert_eq!(state, 0);
    }

    #[test]
    fn test_translate_allowed_calls_for_precompile_preserves_empty_nested_allow_all_lists() {
        let empty_selectors =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO)
                .with_allowed_calls(vec![CallScope {
                    target: Address::repeat_byte(1),
                    selector_rules: Vec::new(),
                }])
                .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let translated = translate_allowed_calls(&empty_selectors);
        assert_eq!(translated.len(), 1);
        assert!(translated[0].selectorRules.is_empty());

        let empty_recipients =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO)
                .with_allowed_calls(vec![CallScope {
                    target: Address::repeat_byte(1),
                    selector_rules: vec![SelectorRule {
                        selector: [0xa9, 0x05, 0x9c, 0xbb],
                        recipients: Vec::new(),
                    }],
                }])
                .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let translated = translate_allowed_calls(&empty_recipients);
        assert_eq!(translated.len(), 1);
        assert_eq!(translated[0].selectorRules.len(), 1);
        assert!(translated[0].selectorRules[0].recipients.is_empty());
    }

    #[test]
    fn test_key_authorization_gas_in_batch() {
        let transaction = TempoTransaction {
            calls: vec![call(Bytes::from_static(&[1, 2, 3]))],
            key_authorization: Some(key_authorization(2)),
            ..Default::default()
        };
        let (with, _, _) = intrinsic(
            TempoHardfork::Genesis,
            transaction.clone(),
            secp256k1_signature(),
        )
        .unwrap();
        let (without, _, _) = intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                key_authorization: None,
                ..transaction
            },
            secp256k1_signature(),
        )
        .unwrap();
        let expected_key_authorization_gas =
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 2 * KEY_AUTH_PER_LIMIT_GAS;
        assert_eq!(
            with - without,
            expected_key_authorization_gas,
            "key authorization should add exactly {expected_key_authorization_gas} gas to batch"
        );

        let evm = test_evm(TempoHardfork::Genesis);
        let expected_without = u64::from(evm.version().gas_params[GasId::TxBaseStipend])
            + 12 * u64::from(evm.version().gas_params[GasId::TxTokenCost]);
        assert_eq!(
            without, expected_without,
            "gas without key authorization should match expected"
        );
        assert_eq!(
            with,
            expected_without + expected_key_authorization_gas,
            "gas with key authorization should match expected"
        );
    }

    #[test]
    fn test_2d_nonce_gas_in_intrinsic_gas() {
        for spec in [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T1A,
            TempoHardfork::T1B,
            TempoHardfork::T2,
        ] {
            let gas = |nonce, nonce_key| {
                intrinsic(
                    spec,
                    TempoTransaction {
                        nonce,
                        nonce_key,
                        calls: vec![call(Bytes::new())],
                        ..Default::default()
                    },
                    secp256k1_signature(),
                )
                .unwrap()
            };
            assert_eq!(gas(5, U256::ZERO).0, 21_000);
            let new_key = gas(0, U256::ONE);
            let evm = test_evm(spec);
            assert_eq!(
                new_key.0 + new_key.1,
                21_000
                    + if spec.is_t1() {
                        u64::from(evm.version().gas_params[GasId::NewAccountCost])
                            + evm.version().gas_params.new_account_state_gas()
                    } else {
                        spec.gas_new_nonce_key()
                    }
            );
            assert_eq!(gas(5, U256::ONE).0, 21_000 + spec.gas_existing_nonce_key());
        }
    }

    #[test]
    fn test_t1_2d_nonce_key_charges_250k_gas() {
        let nonce_key = U256::from(42);
        let evm = test_evm(TempoHardfork::T1);
        let new_account_cost = u64::from(evm.version().gas_params[GasId::NewAccountCost]);
        assert_eq!(
            new_account_cost, 250_000,
            "T1 gas params should have 250k new_account_cost"
        );

        let (new_regular, new_state, _) = intrinsic(
            TempoHardfork::T1,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                nonce_key,
                nonce: 0,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        let (existing_regular, existing_state, _) = intrinsic(
            TempoHardfork::T1,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                nonce_key,
                nonce: 1,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        let gas_delta = new_regular + new_state - existing_regular - existing_state;
        let expected_delta = new_account_cost - TempoHardfork::T1.gas_existing_nonce_key();
        assert_eq!(
            gas_delta, expected_delta,
            "T1 gas difference between nonce=0 and nonce>0 should be {expected_delta}"
        );
        assert_ne!(
            gas_delta,
            TempoHardfork::T1.gas_new_nonce_key(),
            "T1 should not use the pre-T1 new nonce key gas for nonce=0 transactions"
        );

        let (regular_nonce_regular, regular_nonce_state, _) = intrinsic(
            TempoHardfork::T1,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                nonce: 0,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        assert_eq!(
            new_regular + new_state,
            regular_nonce_regular + regular_nonce_state,
            "nonce=0 should charge the same regardless of nonce_key"
        );
    }

    #[test]
    fn test_t1_existing_2d_nonce_key_charges_5k_gas() {
        let (regular, regular_state, _) = intrinsic(
            TempoHardfork::T1,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                nonce: 1,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        let (two_dimensional, two_dimensional_state, _) = intrinsic(
            TempoHardfork::T1,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                nonce_key: U256::from(99),
                nonce: 1,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();
        assert_eq!(
            two_dimensional + two_dimensional_state,
            21_000 + TempoHardfork::T1.gas_existing_nonce_key(),
            "T1 existing 2D nonce key should charge base plus existing nonce key gas"
        );
        assert_eq!(
            regular + regular_state,
            21_000,
            "T1 regular nonce should only charge base intrinsic gas"
        );
        assert_eq!(
            two_dimensional + two_dimensional_state - regular - regular_state,
            TempoHardfork::T1.gas_existing_nonce_key(),
            "difference between existing 2D and regular nonce should be existing nonce key gas"
        );
    }

    #[test]
    fn test_2d_nonce_gas_limit_validation() {
        for spec in [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T2,
        ] {
            for nonce in [0, 1] {
                let (regular, state, _) = intrinsic(
                    spec,
                    TempoTransaction {
                        nonce,
                        nonce_key: U256::ONE,
                        calls: vec![call(Bytes::new())],
                        ..Default::default()
                    },
                    secp256k1_signature(),
                )
                .unwrap();
                assert!(
                    evm2::ethereum::validate_intrinsic_gas(regular + state, regular, state,)
                        .is_ok()
                );
                assert!(
                    evm2::ethereum::validate_intrinsic_gas(regular + state - 1, regular, state,)
                        .is_err()
                );
            }
        }
    }

    /// TIP-1016: Standard CREATE tx should populate initial_state_gas with
    /// create_state_gas when state gas is enabled (T4+).
    /// Note: new_account_state_gas for the caller (nonce==0) is added later
    /// during state validation, not in the initial CREATE state gas.
    #[test]
    fn test_state_gas_standard_create_tx_populates_initial_state_gas() {
        // TIP-1016 is opt-in via EIP-8037; manually enable for this test.
        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let expected_state_gas = evm.version().gas_params.create_state_gas();
        let initial_state_gas = evm2::ethereum::create_initial_state_gas(evm.version(), true);

        assert!(
            expected_state_gas > 0,
            "State gas constants should be non-zero"
        );
        assert_eq!(
            initial_state_gas,
            expected_state_gas,
            "CREATE tx should have initial_state_gas = create_state_gas ({})",
            evm.version().gas_params.create_state_gas()
        );
    }

    /// TIP-1016: Standard CALL tx should have zero initial_state_gas.
    #[test]
    fn test_state_gas_standard_call_tx_zero_initial_state_gas() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let initial_state_gas = evm2::ethereum::create_initial_state_gas(evm.version(), false);

        assert_eq!(
            initial_state_gas, 0,
            "CALL tx should have zero initial_state_gas"
        );
    }

    /// TIP-1016: initial gas for a standard CREATE tx should include both the
    /// CREATE state charge and the nonce-zero caller account charge at T4.
    #[test]
    fn test_state_gas_validate_initial_tx_gas_create_t4() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let initial_state_gas = evm2::ethereum::create_initial_state_gas(evm.version(), true)
            + evm.version().gas_params.new_account_state_gas();

        // create_state_gas (from the CREATE intrinsic) + new_account_state_gas
        // (from Tempo's nonce==0 check for the caller)
        let expected_state_gas = evm.version().gas_params.create_state_gas()
            + evm.version().gas_params.new_account_state_gas();

        assert_eq!(
            initial_state_gas, expected_state_gas,
            "T4 CREATE tx with nonce==0 should have create_state_gas + new_account_state_gas"
        );
    }

    /// TIP-1016: When EIP-8037 is enabled, tx gas limit can exceed the cap.
    #[test]
    fn test_state_gas_tx_gas_limit_above_cap_allowed() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);

        // validate_env should pass even though gas_limit > cap
        let result = evm2::ethereum::validate_tx_gas_limit_cap(evm.version(), 60_000_000);
        assert!(
            result.is_ok(),
            "With EIP-8037 enabled, tx gas limit above cap should be allowed, got: {:?}",
            result.err()
        );
    }

    /// TIP-1016: When EIP-8037 is disabled (pre-T4), tx gas limit above cap is rejected.
    #[test]
    fn test_state_gas_tx_gas_limit_above_cap_rejected_pre_t4() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T1, false);

        // validate_env should reject: gas_limit > cap with state gas disabled
        let result = evm2::ethereum::validate_tx_gas_limit_cap(evm.version(), 60_000_000);
        assert!(
            result.is_err(),
            "With EIP-8037 disabled, tx gas limit above cap should be rejected"
        );
    }

    /// TIP-1016 regression: subblock fee-payment halt must not exceed the gas cap.
    #[test]
    fn test_subblock_fee_payment_halt_clamps_to_gas_cap_t4() {
        const CAP: u64 = 1 << 24;
        const TX_GAS_LIMIT: u64 = 60_000_000;

        let mut evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            TIP20Setup::path_usd(SIGNER).with_issuer(SIGNER).apply()
        })
        .expect("PATH USD setup succeeds");

        let env = aa_env(
            TempoTransaction {
                chain_id: 1,
                fee_token: Some(PATH_USD_ADDRESS),
                max_priority_fee_per_gas: 1,
                max_fee_per_gas: 1,
                gas_limit: TX_GAS_LIMIT,
                calls: vec![call(Bytes::new())],
                nonce_key: U256::from(TEMPO_SUBBLOCK_NONCE_KEY_PREFIX) << 248,
                ..Default::default()
            },
            secp256k1_signature(),
        );

        // Sanity: T4 must actually have the cap-skip enabled so tx_gas_limit > cap is legal.
        assert!(
            evm.feature(EvmFeatures::EIP8037),
            "T4 must enable EIP-8037 for this regression to apply"
        );
        assert_eq!(evm.version().tx_gas_limit_cap, CAP);

        let result = evm
            .transact(&env)
            .expect("subblock fee-payment failure must be converted to a halt, not a hard error")
            .detach()
            .result;

        assert!(!result.status);
        assert_eq!(result.stop, InstrStop::PrecompileError);
        assert_eq!(
            result.total_gas_spent, CAP,
            "regular gas charged on subblock fee-payment halt must be clamped to \
             tx_gas_limit_cap (got {} for tx.gas_limit={} cap={})",
            result.total_gas_spent, TX_GAS_LIMIT, CAP,
        );
        assert_eq!(result.state_gas_spent, 0, "halt reports zero state gas");
    }

    #[test]
    fn test_subblock_paused_fee_token_halts_as_fee_payment_failure() {
        const GAS_LIMIT: u64 = 300_000;

        let mut evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut token = TIP20Setup::path_usd(SIGNER)
                .with_issuer(SIGNER)
                .with_role(SIGNER, *PAUSE_ROLE)
                .apply()?;
            token.pause(SIGNER, ITIP20::pauseCall {})
        })
        .expect("paused PATH USD setup succeeds");

        let env = aa_env(
            TempoTransaction {
                chain_id: 1,
                fee_token: Some(PATH_USD_ADDRESS),
                max_priority_fee_per_gas: 1,
                max_fee_per_gas: 1,
                gas_limit: GAS_LIMIT,
                calls: vec![call(Bytes::new())],
                nonce_key: U256::from(TEMPO_SUBBLOCK_NONCE_KEY_PREFIX) << 248,
                ..Default::default()
            },
            secp256k1_signature(),
        );

        let result = evm
            .transact(&env)
            .expect("subblock paused fee-token failure must be converted to a halt")
            .detach()
            .result;

        assert!(!result.status);
        assert_eq!(result.stop, InstrStop::PrecompileError);
        assert_eq!(result.total_gas_spent, GAS_LIMIT);
        assert_eq!(result.state_gas_spent, 0, "halt reports zero state gas");
    }

    /// TIP-1016: Pre-T4 behavior unchanged. EIP-8037 is disabled and a CALL
    /// transaction has no initial state gas.
    #[test]
    fn test_state_gas_backward_compat_t1_no_state_gas_enabled() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T1, false);

        assert!(
            !evm.feature(EvmFeatures::EIP8037),
            "Pre-T4 should NOT have EIP-8037 enabled"
        );

        // CALL tx - no state gas in either case
        assert_eq!(
            evm2::ethereum::create_initial_state_gas(evm.version(), false),
            0
        );
    }

    /// TIP-1016: Standard tx with nonce==0 should track state gas on T4 only.
    #[test]
    fn test_state_gas_standard_tx_nonce_zero_t4() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let initial_state_gas = evm.version().gas_params.new_account_state_gas();

        assert_eq!(
            initial_state_gas,
            evm.version().gas_params.new_account_state_gas(),
            "T4 standard tx with nonce==0 should track new_account_state_gas"
        );
    }

    /// TIP-1016: Standard tx with nonce==0 should NOT track state gas on T1.
    #[test]
    fn test_state_gas_standard_tx_nonce_zero_t1_no_state_gas() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T1, false);
        let initial_state_gas = evm.version().gas_params.new_account_state_gas();

        assert_eq!(
            initial_state_gas, 0,
            "T1 standard tx with nonce==0 must NOT track state gas"
        );
    }

    /// TIP-1060: T7 removes the EIP-3529 one-fifth refund cap; pre-T7 keeps it.
    #[test]
    fn test_refund_cap_removed_on_t7() {
        // Refund (50k) deliberately exceeds one fifth of the gas used (100k / 5 = 20k).
        const SPENT: u64 = 100_000;
        const REFUND: i64 = 50_000;
        const CAPPED: u64 = SPENT / 5;

        let refunded_for_spec = |spec: TempoHardfork| -> u64 {
            let evm = test_evm(spec);
            let mut result = MessageResult::<TempoEvmTypes> {
                gas: GasTracker::new_spent_with_reservoir(SPENT, 0),
                ..MessageResult::default()
            };
            result.gas.record_refund(REFUND);
            result.final_refund(
                SPENT,
                u64::from(evm.version().gas_params[GasId::MaxRefundQuotient]),
            )
        };

        assert_eq!(
            refunded_for_spec(TempoHardfork::T6),
            CAPPED,
            "pre-T7 must cap the refund at one fifth of gas used"
        );
        assert_eq!(
            refunded_for_spec(TempoHardfork::T7),
            REFUND as u64,
            "T7 must credit the full refund, with no EIP-3529 cap"
        );
    }

    #[test]
    fn test_multicall_gas_refund_accounting() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const GAS_LIMIT: u64 = 1_000_000;
        const INTRINSIC_GAS: u64 = 21_000;
        // Mock call's gas: (CALL_0, CALL_1)
        const SPENT: (u64, u64) = (1000, 500);
        const REFUND: (i64, i64) = (100, 50);

        #[derive(Debug)]
        struct Runner {
            call_idx: AtomicUsize,
            outcomes: [(InstrStop, u64, i64); 2],
        }

        impl evm2::InterpreterRunner<TempoEvmTypes> for Runner {
            fn run<'frame, 'host>(
                &self,
                _config: &ExecutionConfig<TempoEvmTypes>,
                interpreter: &mut evm2::interpreter::Interpreter<'frame, 'host, TempoEvmTypes>,
                _host: &mut Evm<'host, TempoEvmTypes>,
            ) -> Option<InstrStop> {
                let (stop, spent, refund) =
                    self.outcomes[self.call_idx.fetch_add(1, Ordering::Relaxed)];
                interpreter
                    .gas_mut()
                    .tracker_mut()
                    .spend(spent)
                    .expect("mock call has enough gas");
                interpreter.gas_mut().tracker_mut().record_refund(refund);
                Some(stop)
            }
        }

        let mut evm = test_evm(TempoHardfork::Genesis);
        evm.set_interpreter_runner(Runner {
            call_idx: AtomicUsize::new(0),
            outcomes: [
                (InstrStop::Stop, SPENT.0, REFUND.0),
                (InstrStop::Stop, SPENT.1, REFUND.1),
            ],
        });

        let calls = vec![
            Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: Bytes::new(),
            },
            Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: Bytes::new(),
            },
        ];

        let result = execute_batch(
            &mut evm,
            SIGNER,
            None,
            0,
            U256::ZERO,
            GAS_LIMIT - INTRINSIC_GAS,
            0,
            &calls,
            false,
        )
        .expect("execute_batch should succeed");

        assert_eq!(
            INTRINSIC_GAS + result.gas.spent(),
            INTRINSIC_GAS + SPENT.0 + SPENT.1,
            "Total spent should be intrinsic_gas + sum of all calls' spent values"
        );
        assert_eq!(
            result.gas.refunded(),
            REFUND.0 + REFUND.1,
            "Total refund should be sum of all calls' refunded values"
        );
        assert_eq!(
            INTRINSIC_GAS + result.gas.used(),
            INTRINSIC_GAS + SPENT.0 + SPENT.1 - (REFUND.0 + REFUND.1) as u64,
            "used() should be spent - refund"
        );
    }

    /// TIP-1016: CREATE state gas is charged upfront and must be spent even if a later AA step reverts.
    #[test]
    fn test_state_gas_failed_batch_preserves_upfront_create_intrinsic_gas() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const TX_GAS_LIMIT: u64 = 1_000_000;
        const INTRINSIC_GAS: u64 = 21_000;
        const CALL_RESULTS: [(InstrStop, u64); 2] =
            [(InstrStop::Stop, 10_000), (InstrStop::Revert, 7_000)];

        #[derive(Debug)]
        struct Runner {
            call_idx: AtomicUsize,
        }

        impl evm2::InterpreterRunner<TempoEvmTypes> for Runner {
            fn run<'frame, 'host>(
                &self,
                _config: &ExecutionConfig<TempoEvmTypes>,
                interpreter: &mut evm2::interpreter::Interpreter<'frame, 'host, TempoEvmTypes>,
                _host: &mut Evm<'host, TempoEvmTypes>,
            ) -> Option<InstrStop> {
                let (stop, spent) = CALL_RESULTS[self.call_idx.fetch_add(1, Ordering::Relaxed)];
                interpreter
                    .gas_mut()
                    .tracker_mut()
                    .spend(spent)
                    .expect("mock call has enough gas");
                Some(stop)
            }
        }

        let mut evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        evm.set_interpreter_runner(Runner {
            call_idx: AtomicUsize::new(0),
        });
        let initial_state_gas = evm.version().gas_params.create_state_gas();
        let (gas_limit, reservoir) = initial_gas_and_reservoir(
            evm.version(),
            TX_GAS_LIMIT,
            INTRINSIC_GAS,
            initial_state_gas,
            0,
        );
        let calls = vec![
            Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: Bytes::from(vec![0x60, 0x80]),
            },
            Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: Bytes::new(),
            },
        ];

        let result = execute_batch(
            &mut evm,
            SIGNER,
            None,
            1,
            U256::ZERO,
            gas_limit,
            reservoir,
            &calls,
            true,
        )
        .expect("execute_batch should return a failed message result");

        let expected_spent = INTRINSIC_GAS
            + initial_state_gas
            + CALL_RESULTS.iter().map(|(_, spent)| spent).sum::<u64>();

        // Pays CREATE state gas + both call costs. CREATE is charged upfront via intrinsic gas, and NOT refunded.
        assert_eq!(result.stop, InstrStop::Revert);
        assert_eq!(
            TX_GAS_LIMIT - result.gas.remaining() - result.gas.reservoir(),
            expected_spent
        );
        assert_eq!(result.gas.remaining(), TX_GAS_LIMIT - expected_spent);
        assert_eq!(result.gas.state_gas_spent(), 0);
        assert_eq!(result.gas.reservoir(), 0);
    }

    /// TIP-1016: AA CREATE tx should populate initial_state_gas.
    #[test]
    fn test_state_gas_aa_create_tx_populates_initial_state_gas() {
        let initcode = Bytes::from(vec![0x60, 0x80]);

        let call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode,
        };

        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let (_, state, _) = intrinsic_with_amsterdam(
            TempoHardfork::T4,
            true,
            TempoTransaction {
                nonce: 1,
                calls: vec![call],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        let expected_state_gas = evm.version().gas_params.create_state_gas();

        assert_eq!(
            state, expected_state_gas,
            "AA CREATE tx should have initial_state_gas = create_state_gas"
        );
    }

    /// TIP-1016: AA CALL tx should have zero initial_state_gas.
    #[test]
    fn test_state_gas_aa_call_tx_zero_initial_state_gas() {
        let calldata = Bytes::from(vec![1, 2, 3]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata,
        };

        let (_, state, _) = intrinsic_with_amsterdam(
            TempoHardfork::T4,
            true,
            TempoTransaction {
                nonce: 1,
                calls: vec![call],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        assert_eq!(state, 0, "AA CALL tx should have zero initial_state_gas");
    }

    /// TIP-1016: AA batch with multiple calls including CREATE should track
    /// state gas for the CREATE call only.
    #[test]
    fn test_state_gas_aa_mixed_batch_create_and_call() {
        let calldata = Bytes::from(vec![1, 2, 3]);
        let initcode = Bytes::from(vec![0x60, 0x80]);

        let calls = vec![
            Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: calldata,
            },
            Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: initcode,
            },
        ];

        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let (_, state, _) = intrinsic_with_amsterdam(
            TempoHardfork::T4,
            true,
            TempoTransaction {
                nonce: 1,
                calls,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        // Only the CREATE call contributes state gas
        let expected_state_gas = evm.version().gas_params.create_state_gas();

        assert_eq!(
            state, expected_state_gas,
            "Mixed batch should have state gas only from CREATE call"
        );
    }

    /// TIP-1016: AA batch with multiple CREATE calls accumulates state gas.
    #[test]
    fn test_state_gas_aa_multiple_create_calls() {
        let initcode = Bytes::from(vec![0x60, 0x80]);

        let calls = vec![
            Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: initcode.clone(),
            },
            Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: initcode,
            },
        ];

        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let (_, state, _) = intrinsic_with_amsterdam(
            TempoHardfork::T4,
            true,
            TempoTransaction {
                nonce: 1,
                calls,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        // Two CREATE calls should accumulate state gas
        let per_create_state_gas = evm.version().gas_params.create_state_gas();

        assert_eq!(
            state,
            per_create_state_gas * 2,
            "Multiple CREATE calls should accumulate initial_state_gas"
        );
    }

    /// TIP-1016: In multi-call execution, per-call gas starts with no state gas
    /// charged, so state gas is only deducted once upfront by the AA intrinsic
    /// calculation, not per call.
    #[test]
    fn test_state_gas_multi_call_per_call_init_has_zero_state_gas() {
        let per_call_gas = GasTracker::new_with_regular_gas_and_reservoir(0, 0);
        assert_eq!(
            per_call_gas.state_gas_spent(),
            0,
            "Per-call init gas in multi-call must have zero initial_state_gas; state gas is deducted once upfront, not per call"
        );
    }

    /// TIP-1016: Multi-call corrected gas (success path) must use flattened
    /// reconstruction and must preserve accumulated state_gas_spent.
    #[test]
    fn test_state_gas_multi_call_corrected_gas_success_preserves_state_gas() {
        let gas_limit: u64 = 1_000_000;
        let total_gas_spent: u64 = 400_000;
        let accumulated_state_gas: i64 = 150_000;
        let accumulated_refund: i64 = 5_000;

        // Simulate flattened gas reconstruction (same pattern as execute_batch)
        let mut corrected_gas = GasTracker::from_parts(gas_limit, gas_limit - total_gas_spent, 0);
        corrected_gas.set_refunded(accumulated_refund);
        corrected_gas.add_state_gas_spent(accumulated_state_gas);

        assert_eq!(
            corrected_gas.spent(),
            total_gas_spent,
            "Flattened gas must have correct spent"
        );
        assert_eq!(
            corrected_gas.used(),
            total_gas_spent - accumulated_refund as u64,
            "Flattened gas must have correct used (spent - refunded)"
        );
        assert_eq!(
            corrected_gas.state_gas_spent(),
            accumulated_state_gas,
            "Corrected gas must preserve accumulated state_gas_spent"
        );
        assert_eq!(
            corrected_gas.reservoir(),
            0,
            "Flattened gas must have zero reservoir"
        );
    }

    /// TIP-1016: AA nonce==0 new account should track state gas in T4.
    #[test]
    fn test_state_gas_aa_nonce_zero_new_account() {
        let calls = vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::from(vec![1, 2, 3]),
        }];
        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let (_, state, _) = intrinsic_with_amsterdam(
            TempoHardfork::T4,
            true,
            TempoTransaction {
                nonce: 0,
                nonce_key: U256::ONE,
                calls,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        assert_eq!(
            state,
            evm.version().gas_params.new_account_state_gas(),
            "AA tx with nonce==0 should track new_account_state_gas in T4"
        );
    }

    /// TIP-1016: AA auth list entries with nonce==0 should track state gas.
    #[test]
    fn test_state_gas_aa_auth_list_nonce_zero() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T4, true);
        let (_, state, _) = intrinsic_with_amsterdam(
            TempoHardfork::T4,
            true,
            TempoTransaction {
                nonce: 1,
                calls: vec![call(Bytes::new())],
                tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                    alloy_eips::eip7702::Authorization {
                        chain_id: U256::ONE,
                        address: Address::repeat_byte(0x42),
                        nonce: 0,
                    },
                    secp256k1_signature(),
                )],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        // State gas = per-auth state gas (225k) + nonce==0 account creation state gas (225k)
        // Use hard-coded expected values to catch missing gas_params overrides.
        assert_eq!(
            state,
            225_000 + 225_000,
            "Auth list entry should track per-auth state gas (225k) + nonce==0 account creation state gas (225k)"
        );
        assert_eq!(evm.version().gas_params.eip7702_auth_state_gas(), 225_000);
        assert_eq!(evm.version().gas_params.new_account_state_gas(), 225_000);
    }

    /// TIP-1016: Auth list state gas (GasId 254) must be zero on T1.
    #[test]
    fn test_state_gas_auth_list_zero_on_t1() {
        let evm = test_evm_with_amsterdam(TempoHardfork::T1, false);
        assert_eq!(
            evm.version().gas_params.new_account_state_gas(),
            0,
            "Auth account creation state gas must be zero on T1"
        );

        let (_, state, _) = intrinsic_with_amsterdam(
            TempoHardfork::T1,
            false,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                    alloy_eips::eip7702::Authorization {
                        chain_id: U256::ONE,
                        address: Address::repeat_byte(0x42),
                        nonce: 0,
                    },
                    secp256k1_signature(),
                )],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        assert_eq!(
            state, 0,
            "T1 auth list nonce==0 should have zero initial_state_gas"
        );
    }

    /// TIP-1016: `initial_total_gas >= initial_state_gas` invariant must hold for
    /// AA CREATE calls. Without this, execution computes the regular initial gas
    /// as zero, giving the transaction its full gas_limit for free.
    #[test]
    fn test_state_gas_aa_create_total_gas_includes_state_gas() {
        let initcode = Bytes::from(vec![0x60, 0x80]);

        let call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode,
        };

        let (regular, state, _) = intrinsic_with_amsterdam(
            TempoHardfork::T4,
            true,
            TempoTransaction {
                calls: vec![call],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        let initial_total_gas = regular + state;
        assert!(
            initial_total_gas >= state,
            "invariant violated: initial_total_gas ({initial_total_gas}) < initial_state_gas ({state})",
        );
    }

    /// TIP-1016: `initial_total_gas >= initial_state_gas` invariant must hold
    /// when AA auth-list entries with nonce==0 add account-creation state gas.
    #[test]
    fn test_state_gas_aa_auth_nonce_zero_total_gas_includes_state_gas() {
        let (regular, state, _) = intrinsic_with_amsterdam(
            TempoHardfork::T4,
            true,
            TempoTransaction {
                calls: vec![call(Bytes::new())],
                tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                    alloy_eips::eip7702::Authorization {
                        chain_id: U256::ONE,
                        address: Address::repeat_byte(0x42),
                        nonce: 0,
                    },
                    secp256k1_signature(),
                )],
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap();

        let initial_total_gas = regular + state;
        assert!(
            initial_total_gas >= state,
            "invariant violated: initial_total_gas ({initial_total_gas}) < initial_state_gas ({state})",
        );
    }

    fn arb_opt_timestamp() -> impl Strategy<Value = Option<u64>> {
        prop_oneof![Just(None), any::<u64>().prop_map(Some)]
    }

    fn compute_aa_gas(calls: Vec<Call>) -> u64 {
        intrinsic(
            TempoHardfork::Genesis,
            TempoTransaction {
                calls,
                ..Default::default()
            },
            secp256k1_signature(),
        )
        .unwrap()
        .0
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn proptest_validate_time_window_correctness(
            valid_after in arb_opt_timestamp(),
            valid_before in arb_opt_timestamp(),
            block_timestamp in any::<u64>(),
        ) {
            let result = validate_time_window(valid_after, valid_before, block_timestamp);
            prop_assert_eq!(
                result.is_ok(),
                valid_after.is_none_or(|after| block_timestamp >= after)
                    && valid_before.is_none_or(|before| block_timestamp < before)
            );
        }

        #[test]
        fn proptest_validate_time_window_none_always_valid(block_timestamp in any::<u64>()) {
            prop_assert!(validate_time_window(None, None, block_timestamp).is_ok());
        }

        #[test]
        fn proptest_validate_time_window_zero_after_equivalent_to_none(
            valid_before in arb_opt_timestamp(),
            block_timestamp in any::<u64>(),
        ) {
            prop_assert_eq!(
                validate_time_window(Some(0), valid_before, block_timestamp).is_ok(),
                validate_time_window(None, valid_before, block_timestamp).is_ok()
            );
        }

        #[test]
        fn proptest_validate_time_window_empty_window(
            valid_after in 1u64..=u64::MAX,
            offset in 0u64..1000,
        ) {
            let valid_before = valid_after.saturating_sub(offset);
            prop_assert!(
                validate_time_window(Some(valid_after), Some(valid_before), valid_after).is_err()
            );
        }

        #[test]
        fn proptest_signature_gas_ordering(webauthn_data_len in 0usize..1000) {
            let secp = PrimitiveSignature::Secp256k1(Signature::test_signature());
            let p256 = PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: B256::ZERO,
                s: B256::ZERO,
                pub_key_x: B256::ZERO,
                pub_key_y: B256::ZERO,
                pre_hash: false,
            });
            let webauthn = PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r: B256::ZERO,
                s: B256::ZERO,
                pub_key_x: B256::ZERO,
                pub_key_y: B256::ZERO,
                webauthn_data: Bytes::from(vec![0; webauthn_data_len]),
            });
            prop_assert!(primitive_signature_gas(&secp) <= primitive_signature_gas(&p256));
            prop_assert!(primitive_signature_gas(&p256) <= primitive_signature_gas(&webauthn));
        }

        #[test]
        fn proptest_gas_monotonicity_calldata_nonzero(
            first in 0usize..1000,
            second in 0usize..1000,
        ) {
            let first_gas = compute_aa_gas(vec![call(Bytes::from(vec![1; first]))]);
            let second_gas = compute_aa_gas(vec![call(Bytes::from(vec![1; second]))]);
            prop_assert_eq!(first_gas.cmp(&second_gas), first.cmp(&second));
        }

        #[test]
        fn proptest_gas_monotonicity_calldata_zero(
            first in 0usize..1000,
            second in 0usize..1000,
        ) {
            let first_gas = compute_aa_gas(vec![call(Bytes::from(vec![0; first]))]);
            let second_gas = compute_aa_gas(vec![call(Bytes::from(vec![0; second]))]);
            prop_assert_eq!(first_gas.cmp(&second_gas), first.cmp(&second));
        }

        #[test]
        fn proptest_zero_bytes_cheaper_than_nonzero(len in 1usize..1000) {
            prop_assert!(
                compute_aa_gas(vec![call(Bytes::from(vec![0; len]))])
                    < compute_aa_gas(vec![call(Bytes::from(vec![1; len]))])
            );
        }

        #[test]
        fn proptest_mixed_calldata_gas_bounded(len in 1usize..500, ratio in 0u8..=100) {
            let mixed = (0..len)
                .map(|index| u8::from(index * 100 / len < ratio as usize))
                .collect::<Vec<_>>();
            let mixed = compute_aa_gas(vec![call(Bytes::from(mixed))]);
            let zero = compute_aa_gas(vec![call(Bytes::from(vec![0; len]))]);
            let nonzero = compute_aa_gas(vec![call(Bytes::from(vec![1; len]))]);
            prop_assert!(zero <= mixed && mixed <= nonzero);
        }

        #[test]
        fn proptest_gas_monotonicity_call_count(first in 1usize..10, second in 1usize..10) {
            let calls = |count| (0..count).map(|_| call(Bytes::new())).collect();
            prop_assert_eq!(
                compute_aa_gas(calls(first)).cmp(&compute_aa_gas(calls(second))),
                first.cmp(&second)
            );
        }

        #[test]
        fn proptest_gas_aa_secp256k1_exact_bounds(num_calls in 1usize..5) {
            let evm = test_evm(TempoHardfork::Genesis);
            let cold_account = u64::from(evm.version().gas_params[GasId::WarmStorageReadCost])
                + u64::from(evm.version().gas_params[GasId::ColdAccountAdditionalCost]);
            prop_assert_eq!(
                compute_aa_gas((0..num_calls).map(|_| call(Bytes::new())).collect()),
                21_000 + cold_account * num_calls.saturating_sub(1) as u64
            );
        }

        #[test]
        fn proptest_first_call_returns_first_for_aa(num_calls in 1usize..10) {
            let env = aa_env(
                TempoTransaction {
                    calls: (0..num_calls)
                        .map(|index| Call {
                            to: TxKind::Call(Address::with_last_byte(index as u8)),
                            value: U256::ZERO,
                            input: Bytes::from(vec![index as u8; index + 1]),
                        })
                        .collect(),
                    ..Default::default()
                },
                secp256k1_signature(),
            );
            prop_assert_eq!(
                env.evm_tx().calls().next(),
                Some((TxKind::Call(Address::ZERO), &Bytes::from_static(&[0])))
            );
        }

        #[test]
        fn proptest_first_call_empty_aa(_dummy in 0u8..1) {
            let env = aa_env(TempoTransaction::default(), secp256k1_signature());
            prop_assert!(env.evm_tx().calls().next().is_none());
        }

        #[test]
        fn proptest_first_call_non_aa(calldata_len in 0usize..100) {
            let input = Bytes::from(vec![0xab; calldata_len]);
            let transaction = alloy_consensus::TxLegacy {
                to: TxKind::Call(Address::repeat_byte(0x42)),
                input: input.clone(),
                ..Default::default()
            };
            let transaction = TempoEvmTx::from(Recovered::new_unchecked(
                tempo_primitives::TempoTxEnvelope::Legacy(alloy_consensus::Signed::new_unhashed(
                    transaction,
                    Signature::test_signature(),
                )),
                SIGNER,
            ));
            prop_assert_eq!(
                transaction.calls().next(),
                Some((TxKind::Call(Address::repeat_byte(0x42)), &input))
            );
        }

        #[test]
        fn proptest_key_auth_gas_monotonic_limits(
            first in 0usize..10,
            second in 0usize..10,
        ) {
            for spec in [TempoHardfork::Genesis, TempoHardfork::T1B] {
                let evm = test_evm(spec);
                let first_gas = key_authorization_gas(&key_authorization(first), &evm, spec).0;
                let second_gas = key_authorization_gas(&key_authorization(second), &evm, spec).0;
                prop_assert_eq!(first_gas.cmp(&second_gas), first.cmp(&second));
            }
        }

        #[test]
        fn proptest_key_auth_gas_minimum(sig_type in 0u8..3, num_limits in 0usize..5) {
            let signature = match sig_type {
                0 => PrimitiveSignature::Secp256k1(Signature::test_signature()),
                1 => PrimitiveSignature::P256(P256SignatureWithPreHash {
                    r: B256::ZERO,
                    s: B256::ZERO,
                    pub_key_x: B256::ZERO,
                    pub_key_y: B256::ZERO,
                    pre_hash: false,
                }),
                _ => PrimitiveSignature::WebAuthn(WebAuthnSignature {
                    r: B256::ZERO,
                    s: B256::ZERO,
                    pub_key_x: B256::ZERO,
                    pub_key_y: B256::ZERO,
                    webauthn_data: Bytes::new(),
                }),
            };
            let mut authorization =
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO);
            if num_limits > 0 {
                authorization = authorization.with_limits(
                    (0..num_limits)
                        .map(|index| TokenLimit {
                            token: Address::with_last_byte(index as u8),
                            limit: U256::from(1000),
                            period: 0,
                        })
                        .collect(),
                );
            }
            let authorization = authorization.into_signed(signature);

            let genesis = test_evm(TempoHardfork::Genesis);
            let (gas, _) = key_authorization_gas(
                &authorization,
                &genesis,
                TempoHardfork::Genesis,
            );
            prop_assert!(gas >= KEY_AUTH_BASE_GAS + ECRECOVER_GAS);

            let t1b = test_evm(TempoHardfork::T1B);
            let params = &t1b.version().gas_params;
            let minimum = ECRECOVER_GAS
                + u64::from(params[GasId::WarmStorageReadCost])
                + u64::from(params[GasId::ColdStorageAdditionalCost])
                + u64::from(params[GasId::SstoreSetWithoutLoadCost]);
            prop_assert!(
                key_authorization_gas(&authorization, &t1b, TempoHardfork::T1B).0 >= minimum
            );
        }
    }
}
