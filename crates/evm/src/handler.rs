//! Tempo EVM Handler implementation.

mod config;

pub use self::config::{
    FeeTokenResolver, ProtocolFeeManager, TempoBlockEnv, TempoBlockExt, TempoConfig,
    TempoConfigSelector, TempoEvmExt, TempoEvmTypes, TempoFeeManager, TempoTxResultExt,
    build_tempo_evm, tempo_execution_config, tempo_tx_registry,
};
use self::config::{TempoFeeContext, TempoHandlerHooks, invalid};
use crate::{FeePaymentError, TempoAaTx, TempoInvalidTransaction, TempoTxEnv};
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
    evm::handler::{GasSettlement, TxHandlerHooks},
    interpreter::{GasTracker, Host, InstrStop, MessageResult},
    precompiles::PrecompileError,
    registry::{HandlerError, HandlerResult, TxRequest},
    version::{GasId, GasParams},
};
use std::cmp::Ordering;
use tempo_chainspec::{constants::gas::STORAGE_CREDIT_VALUE, hardfork::TempoHardfork};
use tempo_contracts::precompiles::IAccountKeychain::SignatureType as PrecompileSignatureType;
use tempo_precompiles::{
    ECRECOVER_GAS,
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

/// Additional gas for P256 signature verification
/// P256 precompile cost (6900 from EIP-7951) + 1100 for 129 bytes extra signature size - ecrecover savings (3000)
const P256_VERIFY_GAS: u64 = 5_000;

const COLD_SLOAD_COST: u64 = 2_100;
const STANDARD_TOKEN_COST: u64 = 4;
const WARM_SSTORE_RESET: u64 = 2_900;

/// Additional gas for Keychain signatures (key validation overhead: COLD_SLOAD_COST + 900 processing)
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST + 900;

/// Base gas for KeyAuthorization (22k storage + 5k buffer), signature gas added at runtime
const KEY_AUTH_BASE_GAS: u64 = 27_000;

/// Gas per spending limit in KeyAuthorization
const KEY_AUTH_PER_LIMIT_GAS: u64 = 22_000;

/// Rounded buffer for each extra LOG3/no-data event emitted by key authorizations.
const KEY_AUTH_EXTRA_EVENT_BUFFER: u64 = 1_500;

/// Gas cost for expiring nonce transactions (replay check + insert).
///
/// See [TIP-1009] for full specification.
///
/// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
///
/// Operations charged:
/// - 2 cold SLOADs: `seen[tx_hash]`, `ring[idx]` (unique slots per tx)
/// - 1 warm SLOAD: `seen[old_hash]` (warm because we just read `ring[idx]` which points to it)
/// - 3 SSTOREs at RESET price: `seen[old_hash]=0`, `ring[idx]=tx_hash`, `seen[tx_hash]=valid_before`
///
/// Excluded from gas calculation:
/// - `ring_ptr` SLOAD/SSTORE: Accessed by almost every expiring nonce tx in a block, so
///   amortized cost approaches ~200 gas. May be moved out of EVM storage in the future.
///
/// Why SSTORE_RESET (2,900) instead of SSTORE_SET (20,000) for `seen[tx_hash]`:
/// - SSTORE_SET cost exists to penalize permanent state growth
/// - Expiring nonce data is ephemeral: evicted within 30 seconds, fixed-size buffer (300k)
/// - No permanent state growth, so the 20k penalty doesn't apply
///
/// Total: 2*2100 + 100 + 3*2900 = 13,000 gas
const EXPIRING_NONCE_GAS: u64 = 2 * COLD_SLOAD_COST + 100 + 3 * WARM_SSTORE_RESET;

fn calldata_tokens(input: &[u8]) -> u64 {
    input
        .iter()
        .map(|byte| if *byte == 0 { 1 } else { 4 })
        .sum()
}

/// Calculates the gas cost for verifying a primitive signature.
///
/// Returns the additional gas required beyond the base transaction cost:
/// - Secp256k1: 0 (already included in base 21k)
/// - P256: 5000 gas
/// - WebAuthn: 5000 gas + calldata cost for webauthn_data
#[inline]
fn primitive_signature_verification_gas(signature: &PrimitiveSignature) -> u64 {
    match signature {
        PrimitiveSignature::Secp256k1(_) => 0,
        PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
        PrimitiveSignature::WebAuthn(webauthn_sig) => {
            P256_VERIFY_GAS + calldata_tokens(&webauthn_sig.webauthn_data) * STANDARD_TOKEN_COST
        }
    }
}

/// Calculates the gas cost for verifying an AA signature.
///
/// For Keychain signatures, adds key validation overhead to the inner signature cost
/// Returns the additional gas required beyond the base transaction cost.
#[inline]
fn tempo_signature_verification_gas(signature: &TempoSignature) -> u64 {
    match signature {
        TempoSignature::Primitive(prim_sig) => primitive_signature_verification_gas(prim_sig),
        TempoSignature::Keychain(keychain_sig) => {
            // Keychain = inner signature + key validation overhead (SLOAD + processing)
            primitive_signature_verification_gas(&keychain_sig.signature) + KEYCHAIN_VALIDATION_GAS
        }
    }
}

/// Counts the scope storage rows that pay the dynamic SSTORE-set path for the active spec.
///
/// T3 keeps the broader all-persisted-rows accounting from current main. T4 narrows this to rows
/// that actually create storage, so repeated same-tx set length rewrites no longer count as fresh
/// SSTORE-set rows. The helper bookkeeping around scope persistence is charged separately via a
/// rounded surcharge.
fn call_scope_storage_slots(
    auth: &tempo_primitives::transaction::KeyAuthorization,
    spec: tempo_chainspec::hardfork::TempoHardfork,
) -> u64 {
    match auth.allowed_calls.as_ref() {
        None => 0,
        Some(scopes) if scopes.is_empty() => 1,
        Some(scopes) => {
            let is_t4 = spec.is_t4();
            let mut selector_sets = 0u64;
            let mut selectors = 0u64;
            let mut constrained_selectors = 0u64;
            let mut recipients = 0u64;

            for scope in scopes {
                if is_t4 && !scope.selector_rules.is_empty() {
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

            if is_t4 {
                // Storage-creating rows only:
                // - account mode write: 1
                // - target set values+positions: +2 per target, plus one length slot for the set
                // - selector set values+positions: +2 per selector, plus one length slot per
                //   target that persists selectors
                // - recipient-constrained selectors persist one recipient set length slot each
                // - recipient set values+positions: +2 per recipient
                1 + scopes.len() as u64 * 2
                    + 1
                    + selectors * 2
                    + selector_sets
                    + constrained_selectors
                    + recipients * 2
            } else {
                // All persisted rows:
                // - account mode write: 1
                // - each target insertion: 3
                // - each selector insertion: 3
                // - recipient-constrained selectors also write recipient set length: +1 per
                //   selector
                // - recipient set values+positions: +2 per recipient
                1 + scopes.len() as u64 * 3 + selectors * 3 + constrained_selectors + recipients * 2
            }
        }
    }
}

/// Charges the unpriced scope-helper bookkeeping for T4 key authorizations.
/// The dynamic SSTORE rows are already counted by `call_scope_storage_slots()`. What remains is the
/// helper work around them: clearing the empty scope tree for fresh keys, target/set maintenance,
/// selector/set maintenance, and recipient-set writes. We use rounded constants here because the
/// goal is to stop the undercharge without mirroring every storage helper exactly.
///
/// The chosen values intentionally round upward:
/// - base 5k covers the always-run empty-tree clear and restricted/unrestricted mode bookkeeping,
/// - 7k per target and 7k per selector cover the set-maintenance work around each scope layer,
/// - 5k per recipient covers the extra recipient-set persistence.
///
/// The objective is to stay roughly aligned with authorization pricing while avoiding materially low
/// charges on larger scope trees, even if that means slight overcharging in simpler cases.
///
/// TODO: Refactor intrinsic gas accounting so this and the other intrinsic surcharges come from one
/// shared model instead of per-feature heuristics.
fn call_scope_extra_gas(auth: &tempo_primitives::transaction::KeyAuthorization) -> u64 {
    const BASE_SCOPE_GAS: u64 = 5_000;
    const TARGET_SCOPE_GAS: u64 = 7_000;
    const SELECTOR_SCOPE_GAS: u64 = 7_000;
    const RECIPIENT_SCOPE_GAS: u64 = 5_000;

    let Some(scopes) = auth.allowed_calls.as_ref() else {
        return BASE_SCOPE_GAS;
    };

    let num_targets = scopes.len() as u64;
    let num_selectors = scopes
        .iter()
        .map(|scope| scope.selector_rules.len() as u64)
        .sum::<u64>();
    let num_recipients = scopes
        .iter()
        .flat_map(|scope| &scope.selector_rules)
        .map(|rule| rule.recipients.len() as u64)
        .sum::<u64>();

    BASE_SCOPE_GAS
        + TARGET_SCOPE_GAS.saturating_mul(num_targets)
        + SELECTOR_SCOPE_GAS.saturating_mul(num_selectors)
        + RECIPIENT_SCOPE_GAS.saturating_mul(num_recipients)
}

/// Calculates the intrinsic gas cost for a KeyAuthorization.
///
/// This is charged before execution as part of transaction validation.
///
/// Pre-T1B: Gas = BASE (27k) + signature verification + (22k per spending limit)
///   On T1/T1A this was double-charged alongside the gas-metered precompile call.
///
/// T1B+: Gas = signature verification + SLOAD (existing key check) +
///   SSTORE (write key) + N × SSTORE (per spending limit)
///   This is the sole gas accounting — the precompile runs with unlimited gas.
///
/// Returns `(total_gas, state_gas)` where `total_gas` includes the state gas portion.
/// On T4+, each storage-creating SSTORE contributes `sstore_set_state_gas` to state gas
/// per TIP-1016.
#[inline]
fn calculate_key_authorization_gas(
    key_auth: &tempo_primitives::transaction::SignedKeyAuthorization,
    gas_params: &GasParams,
    spec: TempoHardfork,
) -> (u64, u64) {
    // All signature types pay ECRECOVER_GAS (3k) as the baseline since
    // primitive_signature_verification_gas assumes ecrecover is already in base 21k.
    // For KeyAuthorization, we're doing an additional signature verification.
    let sig_gas = ECRECOVER_GAS + primitive_signature_verification_gas(&key_auth.signature);

    let num_limits = key_auth
        .authorization
        .limits
        .as_ref()
        .map(|limits| limits.len() as u64)
        .unwrap_or(0);

    if spec.is_t1b() {
        // T1B+: Accurate gas matching actual precompile storage operations.
        // authorize_key does: 1 SLOAD (read existing key) + 1 SSTORE (write key)
        //   + N SSTOREs (one per spending limit) + 2k buffer (TSTORE + keccak + event)
        // T5 witness and T6 admin authorizations emit additional LOG3 events with no data.
        const BUFFER: u64 = 2_000;
        let sload_cost = u64::from(gas_params.get(GasId::WarmStorageReadCost))
            + u64::from(gas_params.get(GasId::ColdStorageAdditionalCost));

        let limit_slots = if spec.is_t3() {
            // T3 periodic limits write 2 storage slots per token:
            // spending_limits[token].remaining + packed {max, period, period_end}
            num_limits.saturating_mul(2)
        } else {
            num_limits
        };

        let has_t5_witness = key_auth.has_witness();
        let mut num_sstores = 1 + limit_slots;

        if spec.is_t3() {
            num_sstores += call_scope_storage_slots(&key_auth.authorization, spec);
        }

        let mut sstore_cost = u64::from(gas_params.get(GasId::SstoreSetWithoutLoadCost));
        if spec.is_t7() {
            // T7 exposes only the SSTORE residual in the gas table. Since key-auth storage is
            // intrinsic-only, we must also add the creditable portion here.
            sstore_cost = sstore_cost.saturating_add(STORAGE_CREDIT_VALUE);
        }
        let mut regular_gas = sig_gas + sload_cost + sstore_cost * num_sstores + BUFFER;

        if has_t5_witness {
            regular_gas += sload_cost + KEY_AUTH_EXTRA_EVENT_BUFFER;
        }

        if spec.is_t6() && key_auth.is_admin() {
            regular_gas += KEY_AUTH_EXTRA_EVENT_BUFFER;
        }

        // T4+: include extra gas for call scopes configuration
        if spec.is_t4() {
            regular_gas += call_scope_extra_gas(&key_auth.authorization);
        }

        // TIP-1016: each storage-creating SSTORE also incurs state gas.
        let state_gas =
            u64::from(gas_params.get(GasId::SstoreSetState)).saturating_mul(num_sstores);

        (regular_gas, state_gas)
    } else {
        // Pre-T1B: Original heuristic constants
        (
            KEY_AUTH_BASE_GAS + sig_gas + num_limits * KEY_AUTH_PER_LIMIT_GAS,
            0,
        )
    }
}

#[cfg(test)]
fn key_authorization_gas(
    authorization: &tempo_primitives::transaction::SignedKeyAuthorization,
    host: &Evm<'_, TempoEvmTypes>,
    spec: TempoHardfork,
) -> (u64, u64) {
    calculate_key_authorization_gas(authorization, &host.version().gas_params, spec)
}

/// Calculates intrinsic gas for an AA transaction batch using EVM2 gas parameters.
///
/// This includes:
/// - Base 21k stipend (once for the transaction)
/// - Signature verification gas (P256: 5k, WebAuthn: 5k + webauthn_data)
/// - Per-call account access cost (COLD_ACCOUNT_ACCESS_COST * calls.len())
/// - Per-call input data gas (calldata tokens * 4 gas)
/// - Per-call CREATE costs (if applicable):
///   - Additional 32k base (CREATE constant)
///   - Initcode analysis gas (2 per 32-byte chunk, Shanghai+)
/// - Check that value transfer is zero.
/// - Access list costs (shared across batch)
/// - Key authorization costs (if present):
///   - Pre-T1B: 27k base + 3k ecrecover + 22k per spending limit
///   - T1B+: ecrecover + SLOAD + SSTORE × (1 + N limits)
/// - Floor gas calculation (EIP-7623, Prague+)
fn intrinsic_gas(host: &Evm<'_, TempoEvmTypes>, aa: &TempoAaTx) -> HandlerResult<(u64, u64, u64)> {
    let signed = aa.inner();
    let tx = signed.tx();
    let spec = host.config_spec_id();
    let params = &host.version().gas_params;
    // 1. Base stipend (21k, once per transaction)
    let mut regular = u64::from(params.get(GasId::TxBaseStipend));
    let mut state = 0u64;
    let mut tokens = 0u64;

    // 2. Signature verification gas
    regular = regular.saturating_add(tempo_signature_verification_gas(signed.signature()));

    // 3. Per-call overhead: cold account access
    // if the `to` address has not appeared in the call batch before.
    let cold_account = u64::from(params.get(GasId::WarmStorageReadCost))
        + u64::from(params.get(GasId::ColdAccountAdditionalCost));
    regular = regular
        .saturating_add(cold_account.saturating_mul(tx.calls.len().saturating_sub(1) as u64));

    // 4. Authorization list costs (EIP-7702)
    // TIP-1016: Track state gas portion of per-auth cost (225k on T4, 0 pre-T4).
    // Add signature verification costs for each authorization
    // No need for v1 fork check as gas_params would be zero
    for authorization in &tx.tempo_authorization_list {
        regular = regular
            .saturating_add(u64::from(params.get(GasId::TxEip7702PerEmptyAccountCost)))
            .saturating_add(tempo_signature_verification_gas(authorization.signature()));
        state = state.saturating_add(params.eip7702_auth_state_gas());
        if spec.is_t1() && authorization.nonce == 0 {
            // TIP-1000: Storage pricing updates for launch
            // EIP-7702 authorisation list entries with `auth_list.nonce == 0` require an additional 250,000 gas.
            regular = regular.saturating_add(u64::from(params.get(GasId::NewAccountCost)));
            state = state.saturating_add(params.new_account_state_gas());
        }
    }

    // 5. Key authorization costs (if present)
    if let Some(authorization) = &tx.key_authorization {
        let (auth_regular, auth_state) =
            calculate_key_authorization_gas(authorization, params, spec);
        regular = regular.saturating_add(auth_regular);
        state = state.saturating_add(auth_state);
    }

    // 6. Per-call costs
    for call in &tx.calls {
        // Note: Transaction value is not allowed in AA transactions as there is no balances in accounts yet.
        // Check added in https://github.com/tempoxyz/tempo/pull/759
        if !call.value.is_zero() {
            return Err(invalid(
                TempoInvalidTransaction::ValueTransferNotAllowedInAATx,
            ));
        }
        // 4a. Calldata gas using EVM2's token pricing.
        tokens = tokens.saturating_add(calldata_tokens(&call.input));
        if call.to.is_create() {
            // 4b. CREATE-specific costs
            // CREATE costs 500,000 gas in TIP-1000 (T1), 32,000 before
            regular = regular
                .saturating_add(u64::from(params.get(GasId::Create)))
                .saturating_add(params.initcode_cost(call.input.len()));
            // TIP-1016: Track predictable state gas for CREATE calls
            state = state.saturating_add(params.create_state_gas());
        }
    }
    regular =
        regular.saturating_add(tokens.saturating_mul(u64::from(params.get(GasId::TxTokenCost))));

    // 5. Access list costs using the configured gas parameters
    let (accounts, storage_keys) = access_list_counts(&tx.access_list);
    regular = regular
        .saturating_add(
            accounts.saturating_mul(u64::from(params.get(GasId::TxAccessListAddressCost))),
        )
        .saturating_add(
            storage_keys.saturating_mul(u64::from(params.get(GasId::TxAccessListStorageKeyCost))),
        );

    // 6. Floor gas using EVM2 gas parameters
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

fn nonce_intrinsic_gas(host: &Evm<'_, TempoEvmTypes>, aa: &TempoAaTx) -> (u64, u64) {
    let tx = aa.inner().tx();
    let spec = host.config_spec_id();
    let params = &host.version().gas_params;

    if tx.nonce_key == TEMPO_EXPIRING_NONCE_KEY && spec.is_t1() {
        (EXPIRING_NONCE_GAS, 0)
    } else if spec.is_t1() && tx.nonce == 0 {
        // TIP-1000: Storage pricing updates for launch
        // Tempo transactions with any `nonce_key` and `nonce == 0` require an additional 250,000 gas
        (
            u64::from(params.get(GasId::NewAccountCost)),
            params.new_account_state_gas(),
        )
    } else if !tx.nonce_key.is_zero() {
        // Existing 2D nonce key usage (nonce > 0)
        // TIP-1000 Invariant 3: existing state updates must charge +5,000 gas
        (
            if tx.nonce == 0 {
                spec.gas_new_nonce_key()
            } else {
                spec.gas_existing_nonce_key()
            },
            0,
        )
    } else {
        (0, 0)
    }
}

/// Validates time window for AA transactions
///
/// AA transactions can have optional validBefore and validAfter fields:
/// - validAfter: Transaction can only be included after this timestamp
/// - validBefore: Transaction can only be included before this timestamp
///
/// This ensures transactions are only valid within a specific time window.
fn validate_time_window(
    valid_after: Option<u64>,
    valid_before: Option<u64>,
    timestamp: u64,
) -> HandlerResult<()> {
    // Validate validAfter constraint
    if let Some(valid_after) = valid_after
        && timestamp < valid_after
    {
        return Err(invalid(TempoInvalidTransaction::ValidAfter {
            current: timestamp,
            valid_after,
        }));
    }
    // Validate validBefore constraint
    // IMPORTANT: must be aligned with `RecoveredSubBlock::has_expired_transactions`.
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
pub(super) struct KeychainState {
    pub(super) access_key: Option<Address>,
    same_tx_authorization: bool,
    pub(super) fee_key: Option<Address>,
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

    // The user_address is the root account this transaction is being executed for.
    // This should match tx.caller (which comes from recover_signer on the outer signature).
    // Sanity check: user_address should match tx.caller
    if keychain_signature.user_address != aa.signer() {
        return Err(invalid(
            TempoInvalidTransaction::KeychainUserAddressMismatch {
                user_address: keychain_signature.user_address,
                caller: aa.signer(),
            },
        ));
    }

    // Use override_key_id if provided (for gas estimation), otherwise recover from signature.
    let access_key = access_key_id(aa)?.expect("keychain signature must have an access key");
    let key_authorization = tx.key_authorization.as_ref();

    // Classify whether this keychain-signed tx is using the same access key that the
    // inline authorization registers.
    let same_tx_authorization =
        key_authorization.is_some_and(|authorization| authorization.key_id == access_key);

    if same_tx_authorization {
        // Same-tx auth+use path: the access key does not exist in storage yet, so the fee
        // check must use the inline limits directly. `collectFeePreTx` cannot enforce this
        // because `transaction_key` is intentionally not set until after authorization.
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

    // Existing-key path:
    // - ordinary keychain txs must validate the acting access key before fees are paid
    // - T6 delegated key authorizations also validate the acting key here, then reuse
    //   the loaded admin/signature-type facts below when the sidecar signer is the same key
    let timestamp = host.block().timestamp.to::<u64>();

    // Extract the signature type from the inner signature to validate it matches
    // the key_type stored in the keychain. This prevents using a signature of one
    // type to authenticate as a key registered with a different type.
    // Only validate signature type on T1+ to maintain backward compatibility
    // with historical blocks during re-execution.
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
            // T6 adds admin delegation: a keychain signer may authorize a different
            // child key only if the acting transaction key is itself an active admin key.
            return Err(invalid(
                TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys,
            ));
        }
        // Set the transaction key in the keychain precompile.
        // The TIP20 precompile will read this during fee collection and
        // execution to enforce spending limits for existing keys.
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

    // T6 stateless signer/account checks run in `validate_env`. This state-aware phase only
    // proves that a non-root sidecar signer is an active admin key for the caller account.
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

fn translate_allowed_calls_for_precompile(
    authorization: &SignedKeyAuthorization,
) -> Vec<PrecompileCallScope> {
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

    // If the transaction includes a KeyAuthorization, validate and authorize the key
    // only after fee collection has succeeded. This pre-execution write is deliberately
    // outside the later user-call batch checkpoint, so same-transaction authorize-and-use
    // keeps the newly registered key even if scoped-call prevalidation or execution fails.
    let spec = host.config_spec_id();
    let checkpoint = host.state().checkpoint();
    let features = host.version().features;
    // T1/T1A: Apply gas metering for the keychain precompile call.
    // Pre-T1 and T1B+: Use unlimited gas.
    // T1B+ disables gas metering here because gas is already accounted for
    // in intrinsic gas via `calculate_key_authorization_gas`. Running with
    // unlimited gas also eliminates the OOG path that caused the CREATE
    // nonce replay vulnerability (protocol nonce not bumped on OOG).
    let metered = spec.is_t1() && !spec.is_t1b();
    let (result, gas) = StorageCtx::enter_evm_without_tip1060_accounting_with_gas_limit(
        host,
        if metered { remaining_gas } else { u64::MAX },
        // It's ok to set reservoir to 0 because pre-T1B it doesn't matter and post-T1B we have unlimited gas anyway.
        0,
        || {
            let mut keychain = AccountKeychain::new();
            // Convert signature type to precompile SignatureType enum
            // Use the key_type field which specifies the type of key being authorized
            let signature_type: PrecompileSignatureType = authorization.key_type.into();
            let restrictions = KeyRestrictions {
                // Handle expiry: None means never expires (store as u64::MAX)
                expiry: authorization.expiry.map_or(u64::MAX, |expiry| expiry.get()),
                // Handle limits: None means unlimited spending (enforce_limits=false)
                // Some([]) means no spending allowed (enforce_limits=true)
                // Some([...]) means specific limits (enforce_limits=true)
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
                allowedCalls: translate_allowed_calls_for_precompile(authorization),
            };
            // Call precompile to authorize the key (same phase as nonce increment).
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

            // If this is a same tx auth+use, set the transient key_id to the newly authorized
            // key and decrement the fee from its spending limit. Admin delegation must keep the
            // actual signer as the transaction key.
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
            // Cache inline key authorization expiry.
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

    // Call-scope matching scales with batch size, so it runs under a metered storage provider.
    // This keeps unpaid transaction validation bounded while still failing before the first
    // user call executes.
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
        // Protocol nonce (nonce_key == 0)
        // Bump the nonce for calls. Nonce for CREATE will be bumped in `make_create_frame`.
        // This applies uniformly to both standard and AA transactions - we only bump here
        // for CALLs, letting make_create_frame handle the nonce for CREATE operations.
        if tx.calls.first().is_some_and(|call| call.to.is_call()) {
            account.bump_nonce();
        }
        return Ok(protocol_nonce);
    }
    drop(account);

    if tx.nonce_key == TEMPO_EXPIRING_NONCE_KEY && spec.is_t1() {
        // Expiring nonce transaction replay protection:
        // - Pre-T1B: use tx_hash for backwards-compatible behavior.
        // - T1B+: use the sender-scoped tx identifier (keccak256(encode_for_signing || sender))
        //   to prevent replay via different fee payer signatures.
        // Expiring nonce txs must have nonce == 0
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

    // 2D nonce transaction
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

/// Provides atomic batch execution for AA transactions with multiple calls:
/// 1. Creates a checkpoint before executing any calls
/// 2. Executes each call sequentially, updating gas tracking
/// 3. If ANY call fails, reverts ALL state changes atomically
/// 4. If all calls succeed, commits ALL state changes atomically
///
/// The atomicity is guaranteed by the checkpoint/revert/commit mechanism:
/// - Each individual call creates its own internal checkpoint
/// - The outer checkpoint (created here) captures state before any calls execute
/// - Reverting the outer checkpoint undoes all nested changes
///
/// This checkpoint only covers user-call execution. Inline key authorization attached to the
/// transaction is applied earlier during validation/pre-execution and intentionally remains
/// persisted if scope prevalidation fails here or if a later user call reverts the batch.
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
    // Create checkpoint for atomic execution - captures state before any calls
    let checkpoint = host.state().checkpoint();
    let features = host.version().features;
    if let Some(result) =
        prevalidate_call_scopes(host, caller, access_key, calls, gas_limit, reservoir)?
    {
        host.state_mut().rollback(checkpoint, features);
        return Ok(result);
    }
    if calls.first().is_some_and(|call| call.to.is_create()) {
        host.state_mut()
            .account(&caller, false)
            .map_err(HandlerError::Fatal)?
            .bump_nonce();
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
        // Check if call succeeded
        if !result.is_success() {
            // Revert checkpoint - rolls back ALL state changes from all executed calls.
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
        // Call succeeded - accumulate gas usage, refunds, and state gas
        refund = refund.saturating_add(result.gas.refunded());
        state_gas = state_gas.saturating_add(result.gas.state_gas_spent());
        spilled_state_gas = spilled_state_gas.saturating_add(result.gas.state_gas_spilled());
        // Update gas limit and reservoir to remaining values
        remaining = result.gas.remaining();
        reservoir = result.gas.reservoir();
        final_result = Some(result);
    }

    // All calls succeeded - keep the checkpointed state changes and normalize batch gas.
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

/// Validates and executes an AA transaction using Tempo's custom transaction lifecycle.
///
/// Performs standard validation plus AA-specific checks:
/// - Priority fee validation (EIP-1559)
/// - Time window validation (validAfter/validBefore)
fn handle(
    request: TxRequest<'_, '_, TempoEvmTypes, TempoAaTx>,
) -> HandlerResult<TxResult<TempoEvmTypes>> {
    let caller = request.tx.signer();
    let signed = request.tx.inner();
    let tx = signed.tx();
    let spec = request.host.config_spec_id();

    // Validate AA transaction structure (calls list, CREATE rules)
    validate_calls(&tx.calls, !tx.tempo_authorization_list.is_empty())
        .map_err(TempoInvalidTransaction::from)
        .map_err(invalid)?;
    // Validate keychain signature version (outer + authorization list).
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
    validate_key_authorization(request.tx.inner(), request.host.version().chain_id, spec)?;
    // Access-key CREATE is a cheap structural rejection that does not depend on any
    // per-call scope walk or state mutation. Rejecting it here keeps validation work
    // constant and avoids entering CREATE execution paths that require special protocol-
    // nonce preservation on failure.
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
    // All accounts have zero balance so transfer of value is not possible.
    // Check added in https://github.com/tempoxyz/tempo/pull/759
    if tx.calls.iter().any(|call| !call.value.is_zero()) {
        return Err(invalid(
            TempoInvalidTransaction::ValueTransferNotAllowedInAATx,
        ));
    }
    // Validate the fee payer signature
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
    // First perform standard validation (header + transaction environment)
    // This validates: chain_id, gas limits, tx type support, and fee fields.
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
    // Validate time window for AA transactions
    let timestamp = request.host.block().timestamp.to::<u64>();
    validate_time_window(
        tx.valid_after
            .map(|value| value.get())
            .filter(|_| !request.host.ext().skip_valid_after_check),
        tx.valid_before.map(|value| value.get()),
        timestamp,
    )?;

    // Route to the AA gas calculation and validation path.
    let (mut intrinsic, mut initial_state_gas, floor_gas) =
        intrinsic_gas(request.host, request.tx.inner())?;
    let (nonce_gas, nonce_state_gas) = nonce_intrinsic_gas(request.host, request.tx.inner());

    // add additional gas for CREATE tx with 2d nonce and account nonce is 0.
    // This case would create a new account for caller.
    // We only check first call of the transaction because CREATE is only allowed
    // to appear as the first call in the batch (validated in `validate_calls`)
    if !tx.nonce_key.is_zero()
        && tx.calls.first().is_some_and(|call| call.to.is_create())
        && request
            .host
            .state_mut()
            .account_info_untracked(&caller)
            .map_err(HandlerError::Fatal)?
            .is_none_or(|account| account.nonce == 0)
    {
        intrinsic = intrinsic.saturating_add(u64::from(
            request.host.version().gas_params[GasId::NewAccountCost],
        ));
        initial_state_gas = initial_state_gas
            .saturating_add(request.host.version().gas_params.new_account_state_gas());
    }

    // For T0+, include 2D nonce gas in validation (charged upfront)
    // For pre-T0 (Genesis), 2D nonce gas is added AFTER validation to allow transactions
    // with gas_limit < intrinsic + nonce_2d_gas to pass validation, but the gas is still
    // charged during execution via init_and_floor_gas (not evm.initial_gas)
    if spec.is_t0() {
        intrinsic = intrinsic.saturating_add(nonce_gas);
        initial_state_gas = initial_state_gas.saturating_add(nonce_state_gas);
    }

    // Validate gas limit is sufficient for initial gas.
    // initial_total_gas already includes initial_state_gas as a subset,
    // so no need to add state gas separately.
    validate_intrinsic_gas(tx.gas_limit, intrinsic, initial_state_gas)?;
    validate_floor_gas(tx.gas_limit, floor_gas)?;

    // For pre-T0 (Genesis), add 2D nonce gas after validation
    // This gas will be charged via init_and_floor_gas, not evm.initial_gas
    if !spec.is_t0() {
        intrinsic = intrinsic.saturating_add(nonce_gas);
        initial_state_gas = initial_state_gas.saturating_add(nonce_state_gas);
    }
    validate_regular_gas_limit_cap(request.host.version(), tx.gas_limit, intrinsic, floor_gas)?;

    warm_base_accounts(request.host, caller, tx.calls[0].to);
    for call in &tx.calls[1..] {
        if let TxKind::Call(address) = call.to {
            request.host.state_mut().prewarm(&address);
        }
    }
    warm_access_list(request.host, &tx.access_list);

    // Collect fees for the transaction.
    let fee_context = TempoHandlerHooks::resolve_fee_context(request.host, request.envelope)?;

    let create_nonce = apply_nonce(request.host, request.envelope, request.tx.inner())?;

    // For Keychain signatures, validate the acting access key before fee collection when it
    // already exists. Same-tx auth+use is the exception: that key is registered only after fees
    // are collected, so fee-limit validation uses the inline authorization payload instead.
    let keychain = prepare_keychain(request.host, request.tx.inner(), fee_context)?;
    let fee_result = if request.host.feature(EvmFeatures::FEE_CHARGE) {
        TempoHandlerHooks::collect_fee(
            request.host,
            fee_context,
            (fee_context.fee_payer == caller)
                .then_some(keychain.fee_key)
                .flatten(),
        )
    } else {
        Ok(())
    };
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
        request.tx.inner(),
        fee_context,
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
        return TempoHandlerHooks::settle_transaction(
            request.host,
            request.envelope,
            GasSettlement {
                caller,
                gas_price,
                gas_limit: tx.gas_limit,
                floor_gas,
                initial_state_gas,
                state_refund: 0,
                is_create: tx.calls[0].to.is_create(),
                result,
            },
        );
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
    TempoHandlerHooks::settle_transaction(
        request.host,
        request.envelope,
        GasSettlement {
            caller,
            gas_price,
            gas_limit: tx.gas_limit,
            floor_gas,
            initial_state_gas,
            state_refund,
            is_create: tx.calls[0].to.is_create(),
            result,
        },
    )
}

#[cfg(test)]
fn translate_allowed_calls(authorization: &SignedKeyAuthorization) -> Vec<PrecompileCallScope> {
    translate_allowed_calls_for_precompile(authorization)
}

#[cfg(test)]
mod tests;
