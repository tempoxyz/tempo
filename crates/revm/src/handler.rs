//! Tempo EVM Handler implementation.

use std::{
    cmp::Ordering,
    fmt::Debug,
    sync::{Arc, OnceLock},
};

use alloy_primitives::{Address, TxKind, U256};
use reth_evm::{EvmError, EvmInternals};
use revm::{
    Database,
    context::{
        Block, Cfg, ContextTr, JournalTr, LocalContextTr, Transaction, TransactionType,
        journaled_state::account::JournaledAccountTr,
        result::{EVMError, ExecutionResult, InvalidTransaction, ResultGas},
        transaction::{AccessListItem, AccessListItemTr},
    },
    context_interface::cfg::{GasId, GasParams},
    handler::{
        EvmTr, FrameResult, FrameTr, Handler, MainnetHandler, post_execution,
        pre_execution::{self, apply_auth_list, calculate_caller_fee},
        precompile_output_to_interpreter_result, validation,
    },
    inspector::{Inspector, InspectorHandler},
    interpreter::{
        CallOutcome, CreateOutcome, Gas, InitialAndFloorGas,
        gas::{
            COLD_SLOAD_COST, STANDARD_TOKEN_COST, WARM_SSTORE_RESET,
            get_tokens_in_calldata_istanbul,
        },
        interpreter::EthInterpreter,
    },
    precompile::PrecompileError,
};
use tempo_chainspec::constants::gas::STORAGE_CREDIT_VALUE;
use tempo_contracts::precompiles::{
    IAccountKeychain::SignatureType as PrecompileSignatureType, TIPFeeAMMError,
};
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
    storage::{
        Handler as _, PrecompileStorageProvider, StorageActions, StorageCtx,
        evm::EvmPrecompileStorageProvider,
    },
    tip20::{ITIP20::InsufficientBalance, TIP20Error, TIP20Token},
    tip20_channel_reserve::TIP20ChannelReserve,
};
use tempo_primitives::{
    TempoAddressExt,
    transaction::{
        PrimitiveSignature, SignatureType, TEMPO_EXPIRING_NONCE_KEY, TempoSignature,
        calc_gas_balance_spending, validate_calls,
    },
};

use crate::{
    ProtocolFeeContext, TempoBatchCallEnv, TempoEvm, TempoInvalidTransaction, TempoTxEnv,
    error::{FeePaymentError, TempoHaltReason},
    evm::TempoContext,
    gas_credits,
};

/// Additional gas for P256 signature verification
/// P256 precompile cost (6900 from EIP-7951) + 1100 for 129 bytes extra signature size - ecrecover savings (3000)
const P256_VERIFY_GAS: u64 = 5_000;

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
pub const EXPIRING_NONCE_GAS: u64 = 2 * COLD_SLOAD_COST + 100 + 3 * WARM_SSTORE_RESET;

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
            let tokens = get_tokens_in_calldata_istanbul(&webauthn_sig.webauthn_data);
            P256_VERIFY_GAS + tokens * STANDARD_TOKEN_COST
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

#[derive(Debug, Clone)]
struct LoadedTxAccessKey {
    key_id: Address,
    key: AuthorizedKey,
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

/// Rewrites a failed batch step's gas accounting to match whole-transaction semantics.
///
/// `frame_result` initially only reflects the final failed step. For atomic AA batches we surface
/// one top-level transaction result instead, so the gas field must be normalized to the full tx
/// budget. Reverts preserve the exact gas spent across prior successful steps plus the failed step,
/// while halts such as OOG consume the entire remaining transaction budget.
///
/// NOTE: in AA batches, non-refundable state-gas charges that are known upfront, are already
/// included in `initial_state_gas`, so this only refunds per-step execution state gas on failure.
fn normalize_failed_batch_result_gas(
    frame_result: &mut FrameResult,
    final_gas_limit: u64,
    accumulated_state_gas_spent: i64,
) {
    // Create new Gas with correct limit, because Gas does not have a set_limit method
    // (the frame_result limit only covers the failed step).
    let mut corrected_gas = Gas::new_spent_with_reservoir(final_gas_limit, 0);
    if frame_result.instruction_result().is_revert() {
        corrected_gas.erase_cost(frame_result.gas().remaining());
    }
    // No refunds when batch fails and all state is reverted.
    corrected_gas.set_refund(0);
    // No state gas spending for failed calls
    corrected_gas.set_state_gas_spent(0);
    // Reservoir and state gas are refunded on failure
    corrected_gas.set_reservoir(
        frame_result
            .gas()
            .reservoir()
            .saturating_add_signed(accumulated_state_gas_spent)
            .saturating_add_signed(frame_result.gas().state_gas_spent()),
    );
    *frame_result.gas_mut() = corrected_gas;
}

fn translate_allowed_calls_for_precompile(
    key_auth: &tempo_primitives::transaction::SignedKeyAuthorization,
) -> Vec<PrecompileCallScope> {
    let Some(scopes) = key_auth.allowed_calls.as_ref() else {
        return Vec::new();
    };

    scopes
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
    spec: tempo_chainspec::hardfork::TempoHardfork,
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
        let sload_cost =
            gas_params.warm_storage_read_cost() + gas_params.cold_storage_additional_cost();

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

        let mut sstore_cost = gas_params.get(GasId::sstore_set_without_load_cost());
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
        let state_gas = gas_params
            .get(GasId::sstore_set_state_gas())
            .saturating_mul(num_sstores);

        (regular_gas, state_gas)
    } else {
        // Pre-T1B: Original heuristic constants
        (
            KEY_AUTH_BASE_GAS + sig_gas + num_limits * KEY_AUTH_PER_LIMIT_GAS,
            0,
        )
    }
}

/// Tempo EVM [`Handler`] implementation with Tempo specific modifications:
///
/// Fees are paid in fee tokens instead of account balance.
#[derive(Debug)]
pub struct TempoEvmHandler<DB, I> {
    /// Phantom data to avoid type inference issues.
    _phantom: core::marker::PhantomData<(DB, I)>,
}

impl<DB, I> TempoEvmHandler<DB, I> {
    /// Create a new [`TempoEvmHandler`] handler instance
    pub fn new() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<DB: alloy_evm::Database, I> TempoEvmHandler<DB, I> {
    fn seed_precompile_tx_context(
        &self,
        evm: &mut TempoEvm<DB, I>,
    ) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
        let ctx = evm.ctx_mut();
        let channel_open_context_hash = ctx.tx.channel_open_context_hash();

        // Seed transient precompile transaction context for both regular execution and RPC
        // simulations (`eth_call` / `eth_estimateGas`) that go through handler execution.
        StorageCtx::enter_evm(
            &mut ctx.journaled_state,
            &ctx.block,
            &ctx.cfg,
            &ctx.tx,
            StorageActions::disabled(),
            || {
                let mut keychain = AccountKeychain::new();
                keychain.set_tx_origin(ctx.tx.caller())?;

                if let Some(channel_open_context_hash) = channel_open_context_hash {
                    let mut channel_reserve = TIP20ChannelReserve::new();
                    channel_reserve.set_channel_open_context_hash(channel_open_context_hash)?;
                }

                Ok::<(), TempoPrecompileError>(())
            },
        )
        .map_err(|e| EVMError::Custom(e.to_string()))
    }
}

impl<DB, I> TempoEvmHandler<DB, I>
where
    DB: alloy_evm::Database,
{
    fn prevalidate_keychain_call_scopes(
        &self,
        evm: &mut TempoEvm<DB, I>,
        calls: &[tempo_primitives::transaction::Call],
        remaining_gas: &mut u64,
        reservoir: u64,
    ) -> Result<Option<FrameResult>, EVMError<DB::Error, TempoInvalidTransaction>> {
        let spec = *evm.ctx().cfg().spec();
        if !spec.is_t3() {
            return Ok(None);
        }

        // Call-scope matching scales with batch size, so it runs under a metered storage provider.
        // This keeps unpaid transaction validation bounded while still failing before the first
        // user call executes.

        let (access_key_addr, user_address) = {
            let ctx = evm.ctx();
            let tx = ctx.tx();
            let Some(tempo_tx_env) = tx.tempo_tx_env.as_ref() else {
                return Ok(None);
            };
            let Some(keychain_sig) = tempo_tx_env.signature.as_keychain() else {
                return Ok(None);
            };

            let access_key_addr = if let Some(override_key_id) = tempo_tx_env.override_key_id {
                override_key_id
            } else {
                keychain_sig
                    .key_id(&tempo_tx_env.signature_hash)
                    .map_err(|_| {
                        EVMError::Custom(
                            "keychain access key recovery failed after validation".into(),
                        )
                    })?
            };

            (access_key_addr, keychain_sig.user_address)
        };
        let Some(kind) = calls.first().map(|call| call.to) else {
            return Err(EVMError::Custom(
                "AA transactions must contain at least one call".into(),
            ));
        };

        // It's fine to set reservoir to 0 because this won't create any state.
        let actions = evm.actions.clone();
        let (validation, gas_used) = StorageCtx::enter_ctx_with_gas_limit(
            evm.ctx_mut(),
            *remaining_gas,
            reservoir,
            actions,
            || {
                let keychain = AccountKeychain::default();
                for call in calls {
                    keychain.validate_call_scope_for_transaction(
                        user_address,
                        access_key_addr,
                        &call.to,
                        call.input.as_ref(),
                    )?;
                }
                Ok::<(), TempoPrecompileError>(())
            },
        );

        match validation {
            Ok(()) => {
                *remaining_gas = remaining_gas.saturating_sub(gas_used);
                Ok(None)
            }
            Err(err) => match err.into_precompile_result(gas_used, reservoir) {
                Ok(output) => {
                    let interpreter_result =
                        precompile_output_to_interpreter_result(output, *remaining_gas);

                    let frame_result = if kind.is_call() {
                        FrameResult::Call(CallOutcome::new(interpreter_result, 0..0))
                    } else {
                        FrameResult::Create(CreateOutcome::new(interpreter_result, None))
                    };

                    Ok(Some(frame_result))
                }
                Err(PrecompileError::Fatal(err)) => Err(EVMError::Custom(err)),
                Err(err) => Err(EVMError::Custom(err.to_string())),
            },
        }
    }

    /// Generic single-call execution that works with both standard and inspector exec loops.
    ///
    /// This is the core implementation that both `execute_single_call` and inspector-aware
    /// execution can use by providing the appropriate exec loop function.
    fn execute_single_call_with<F>(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        gas_limit: u64,
        reservoir: u64,
        mut run_loop: F,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        F: FnMut(
            &mut Self,
            &mut TempoEvm<DB, I>,
            <<TempoEvm<DB, I> as EvmTr>::Frame as FrameTr>::FrameInit,
        ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>,
    {
        // Create first frame action
        let first_frame_input = self.first_frame_input(evm, gas_limit, reservoir)?;

        // Run execution loop (standard or inspector)
        let mut frame_result = run_loop(self, evm, first_frame_input)?;

        // Handle last frame result
        self.last_frame_result(evm, reservoir, &mut frame_result)?;

        Ok(frame_result)
    }

    /// Executes a standard single-call transaction using the default handler logic.
    ///
    /// This calls the same helper methods used by the default [`Handler::execution`] implementation.
    fn execute_single_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        gas_limit: u64,
        reservoir: u64,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>> {
        self.execute_single_call_with(evm, gas_limit, reservoir, Self::run_exec_loop)
    }

    /// Generic multi-call execution that works with both standard and inspector exec loops.
    ///
    /// This is the core implementation for atomic batch execution that both `execute_multi_call`
    /// and inspector-aware execution can use by providing the appropriate single-call function.
    ///
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
    fn execute_multi_call_with<F>(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        mut remaining_gas: u64,
        mut reservoir: u64,
        calls: Vec<tempo_primitives::transaction::Call>,
        mut execute_single: F,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        F: FnMut(
            &mut Self,
            &mut TempoEvm<DB, I>,
            u64,
            u64,
        ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>,
    {
        // Create checkpoint for atomic execution - captures state before any calls
        let checkpoint = evm.ctx().journal_mut().checkpoint();
        let mut accumulated_gas_refund = 0i64;
        let mut accumulated_state_gas_spent = 0i64;

        // Store original TxEnv values to restore after batch execution
        let original_kind = evm.ctx().tx().kind();
        let original_value = evm.ctx().tx().value();
        let original_data = evm.ctx().tx().input().clone();
        let original_gas_limit = evm.ctx().tx().gas_limit();

        let mut final_result = None;

        if let Some(mut frame_result) =
            self.prevalidate_keychain_call_scopes(evm, &calls, &mut remaining_gas, reservoir)?
        {
            // This path only runs for keychain batches that already passed the structural CREATE
            // rejection in validation, so there is no first-call CREATE nonce to preserve here.
            normalize_failed_batch_result_gas(
                &mut frame_result,
                evm.ctx().tx().gas_limit(),
                accumulated_state_gas_spent,
            );
            return Ok(frame_result);
        }

        for call in calls.iter() {
            // Update TxEnv to point to this specific call
            {
                let tx = &mut evm.ctx().tx;
                tx.inner.kind = call.to;
                tx.inner.value = call.value;
                tx.inner.data = call.input.clone();
                tx.inner.gas_limit = remaining_gas;
            }

            // Execute call with NO additional initial gas (already deducted upfront in validation)
            let frame_result = execute_single(self, evm, remaining_gas, reservoir);

            // Restore original TxEnv immediately after execution, even if execution failed
            {
                let tx = &mut evm.ctx().tx;
                tx.inner.kind = original_kind;
                tx.inner.value = original_value;
                tx.inner.data = original_data.clone();
                tx.inner.gas_limit = original_gas_limit;
            }

            let mut frame_result = frame_result?;

            // Check if call succeeded
            if !frame_result.instruction_result().is_ok() {
                // Revert checkpoint - rolls back ALL state changes from all executed calls.
                evm.ctx().journal_mut().checkpoint_revert(checkpoint);

                // For AA transactions with CREATE as the first call, the nonce was bumped by
                // make_create_frame during execution. Since checkpoint_revert rolled that back,
                // we need to manually bump the nonce here to ensure it persists even on failure.
                //
                // However, this only applies when using the protocol nonce (nonce_key == 0).
                // When using 2D nonces (nonce_key != 0), replay protection is handled by the
                // NonceManager, and the protocol nonce is only used for CREATE address derivation.
                // Since the CREATE reverted, no contract was deployed, so the address wasn't
                // "claimed" and we don't need to burn the protocol nonce.
                let uses_protocol_nonce = evm
                    .ctx()
                    .tx()
                    .tempo_tx_env
                    .as_ref()
                    .map(|aa| aa.nonce_key.is_zero())
                    .unwrap_or(true);

                if uses_protocol_nonce && calls.first().map(|c| c.to.is_create()).unwrap_or(false) {
                    let caller = evm.ctx().tx().caller();
                    if let Ok(mut caller_acc) =
                        evm.ctx().journal_mut().load_account_with_code_mut(caller)
                    {
                        caller_acc.data.bump_nonce();
                    }
                }

                normalize_failed_batch_result_gas(
                    &mut frame_result,
                    evm.ctx().tx().gas_limit(),
                    accumulated_state_gas_spent,
                );

                return Ok(frame_result);
            }

            // Call succeeded - accumulate gas usage, refunds, and state gas
            accumulated_gas_refund =
                accumulated_gas_refund.saturating_add(frame_result.gas().refunded());
            accumulated_state_gas_spent =
                accumulated_state_gas_spent.saturating_add(frame_result.gas().state_gas_spent());

            // Update gas limit and reservoir to remaining values
            remaining_gas = frame_result.gas().remaining();
            reservoir = frame_result.gas().reservoir();

            final_result = Some(frame_result);
        }

        // All calls succeeded - commit checkpoint to finalize ALL state changes
        evm.ctx().journal_mut().checkpoint_commit();

        // Fix gas accounting for the entire batch
        let mut result =
            final_result.ok_or_else(|| EVMError::Custom("No calls executed".into()))?;

        // Create new Gas with correct limit, because Gas does not have a set_limit method
        // (the frame_result has the limit from just the last call)
        let mut corrected_gas = Gas::new(evm.ctx().tx().gas_limit());
        corrected_gas.set_remaining(result.gas().remaining());
        corrected_gas.set_refund(accumulated_gas_refund);
        corrected_gas.set_state_gas_spent(accumulated_state_gas_spent);
        corrected_gas.set_reservoir(reservoir);

        *result.gas_mut() = corrected_gas;

        Ok(result)
    }

    /// Executes a multi-call AA transaction atomically.
    fn execute_multi_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        gas_limit: u64,
        reservoir: u64,
        calls: Vec<tempo_primitives::transaction::Call>,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>> {
        self.execute_multi_call_with(evm, gas_limit, reservoir, calls, Self::execute_single_call)
    }

    /// Executes a standard single-call transaction with inspector support.
    ///
    /// This is the inspector-aware version of execute_single_call that uses
    /// inspect_run_exec_loop instead of run_exec_loop.
    fn inspect_execute_single_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        gas_limit: u64,
        reservoir: u64,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        I: Inspector<TempoContext<DB>, EthInterpreter>,
    {
        self.execute_single_call_with(evm, gas_limit, reservoir, Self::inspect_run_exec_loop)
    }

    /// Executes a multi-call AA transaction atomically with inspector support.
    ///
    /// This is the inspector-aware version of execute_multi_call that uses
    /// inspect_execute_single_call instead of execute_single_call.
    fn inspect_execute_multi_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        gas_limit: u64,
        reservoir: u64,
        calls: Vec<tempo_primitives::transaction::Call>,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        I: Inspector<TempoContext<DB>, EthInterpreter>,
    {
        self.execute_multi_call_with(
            evm,
            gas_limit,
            reservoir,
            calls,
            Self::inspect_execute_single_call,
        )
    }
}

impl<DB, I> Default for TempoEvmHandler<DB, I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<DB, I> Handler for TempoEvmHandler<DB, I>
where
    DB: alloy_evm::Database,
{
    type Evm = TempoEvm<DB, I>;
    type Error = EVMError<DB::Error, TempoInvalidTransaction>;
    type HaltReason = TempoHaltReason;

    /// Overridden execution method that handles AA vs standard transactions.
    ///
    /// Dispatches based on transaction type:
    /// - AA transactions (type 0x5): Use batch execution path with calls field
    /// - All other transactions: Use standard single-call execution
    #[inline]
    fn execution(
        &mut self,
        evm: &mut Self::Evm,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<FrameResult, Self::Error> {
        let spec = evm.ctx_ref().cfg().spec();
        let tx = evm.tx();

        if let Some(oog) = check_gas_limit(*spec, tx, init_and_floor_gas) {
            return Ok(oog);
        }

        let (gas_limit, reservoir) = evm.initial_gas_and_reservoir(init_and_floor_gas);

        if let Some(tempo_tx_env) = evm.ctx().tx().tempo_tx_env.as_ref() {
            let calls = tempo_tx_env.aa_calls.clone();
            self.execute_multi_call(evm, gas_limit, reservoir, calls)
        } else {
            self.execute_single_call(evm, gas_limit, reservoir)
        }
    }

    /// Applies Tempo-specific post-execution accounting before the standard gas refund flow.
    #[inline]
    fn post_execution(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut FrameResult,
        init_and_floor_gas: InitialAndFloorGas,
        eip7702_gas_refund: i64,
    ) -> Result<ResultGas, Self::Error> {
        if exec_result.instruction_result().is_ok() {
            gas_credits::apply_refund(evm, exec_result.gas_mut())?;
        }
        self.refund(evm, exec_result, eip7702_gas_refund);

        let result_gas = post_execution::build_result_gas(
            exec_result.instruction_result().is_halt(),
            exec_result.gas(),
            init_and_floor_gas,
        );

        self.eip7623_check_gas_floor(evm, exec_result, init_and_floor_gas);
        self.reimburse_caller(evm, exec_result)?;
        self.reward_beneficiary(evm, exec_result)?;

        Ok(result_gas)
    }

    /// Applies gas refunds, dropping the EIP-3529 one-fifth refund cap on T7+.
    ///
    /// TIP-1060 removes the standard EVM refund cap: the `Refund`-mode
    /// storage-credit settlement refund and the preserved baseline SSTORE
    /// refunds are credited to the transaction's gas refund counter in full,
    /// regardless of the transaction's gas used. Pre-T7 keeps the standard
    /// capped behavior (`Gas::set_final_refund`).
    #[inline]
    fn refund(&self, evm: &mut Self::Evm, exec_result: &mut FrameResult, eip7702_refund: i64) {
        let spec = evm.ctx.cfg.spec;
        let gas = exec_result.gas_mut();
        if spec.is_t7() {
            // No cap: leave the accumulated refund counter untouched after
            // recording the EIP-7702 auth refund.
            gas.record_refund(eip7702_refund);
        } else {
            post_execution::refund(spec.into(), gas, eip7702_refund);
        }
    }

    /// Take logs from the Journal if outcome is Halt Or Revert.
    #[inline]
    fn execution_result(
        &mut self,
        evm: &mut Self::Evm,
        result: <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
        result_gas: ResultGas,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        evm.clear();

        MainnetHandler::default()
            .execution_result(evm, result, result_gas)
            .map(|result| result.map_haltreason(Into::into))
    }

    /// Override apply_eip7702_auth_list to support AA transactions with authorization lists.
    ///
    /// The default implementation only processes authorization lists for TransactionType::Eip7702 (0x04).
    /// This override extends support to AA transactions (type 0x76) by checking for the presence
    /// of an aa_authorization_list in the tempo_tx_env.
    #[inline]
    fn apply_eip7702_auth_list(
        &self,
        evm: &mut Self::Evm,
        _init_and_floor_gas: &mut InitialAndFloorGas,
    ) -> Result<u64, Self::Error> {
        let ctx = &mut evm.ctx;
        let spec = ctx.cfg.spec;

        // Check if this is an AA transaction with an authorization list
        let has_aa_auth_list = ctx
            .tx
            .tempo_tx_env
            .as_ref()
            .map(|aa_env| !aa_env.tempo_authorization_list.is_empty())
            .unwrap_or(false);

        let refunded_accounts = if has_aa_auth_list {
            let tempo_tx_env = ctx.tx.tempo_tx_env.as_ref().unwrap();

            apply_auth_list::<_, Self::Error>(
                ctx.cfg.chain_id,
                tempo_tx_env
                    .tempo_authorization_list
                    .iter()
                    // T0 hardfork: skip keychain signatures in auth list processing
                    .filter(|auth| !(spec.is_t0() && auth.signature().is_keychain())),
                &mut ctx.journaled_state,
            )?
            .0
        } else {
            apply_auth_list::<_, Self::Error>(
                ctx.cfg.chain_id,
                ctx.tx.authorization_list(),
                &mut ctx.journaled_state,
            )?
            .0
        };

        let refunded_gas = ctx
            .cfg
            .gas_params
            .tx_eip7702_auth_refund_regular()
            .saturating_mul(refunded_accounts);

        Ok(refunded_gas)
    }

    #[inline]
    fn validate_against_state_and_deduct_caller(
        &self,
        evm: &mut Self::Evm,
        init_gas: &mut InitialAndFloorGas,
    ) -> Result<(), Self::Error> {
        self.seed_precompile_tx_context(evm)?;

        let actions = evm.actions.clone();
        let fee_manager = evm.fee_manager.clone();
        let block = &evm.inner.ctx.block;
        let tx = &evm.inner.ctx.tx;
        let cfg = &evm.inner.ctx.cfg;
        let journal = &mut evm.inner.ctx.journaled_state;

        let fee_payer = tx.fee_payer().expect("pre-validated in `validate_env`");
        let fee_token = fee_manager
            .get_fee_token(journal, tx, fee_payer, cfg.spec, actions.clone())
            .map_err(|err| EVMError::Custom(err.to_string()))?;

        evm.fee_token = Some(fee_token);

        // Always validate TIP20 prefix to prevent panics in get_token_balance.
        // This is a protocol-level check since validators could bypass initial validation.
        if !fee_token.is_tip20() {
            return Err(TempoInvalidTransaction::FeeTokenNotTip20 { address: fee_token }.into());
        }

        // Skip fee token validation when the transaction is free and not part of a subblock.
        // The TIP20 prefix is already validated above.
        if !tx.max_balance_spending()?.is_zero() || tx.is_subblock_transaction() {
            fee_manager.validate_fee_token(journal, fee_token, cfg.spec, actions.clone())?;
        }

        // Load the fee payer balance
        let account_balance = get_token_balance(journal, fee_token, fee_payer)?;

        // Load caller's account
        let mut caller_account = journal.load_account_with_code_mut(tx.caller())?.data;

        let nonce_key = tx
            .tempo_tx_env
            .as_ref()
            .map(|aa| aa.nonce_key)
            .unwrap_or_default();

        let spec = cfg.spec();

        // Only treat as expiring nonce if T1 is active, otherwise treat as regular 2D nonce
        let is_expiring_nonce = nonce_key == TEMPO_EXPIRING_NONCE_KEY && spec.is_t1();

        // Validate account nonce and code (EIP-3607) using upstream helper
        pre_execution::validate_account_nonce_and_code(
            &caller_account.account().info,
            tx.nonce(),
            cfg.is_eip3607_disabled(),
            // skip nonce check if 2D nonce or expiring nonce is used
            cfg.is_nonce_check_disabled() || !nonce_key.is_zero(),
        )?;

        // modify account nonce and touch the account.
        caller_account.touch();

        // add additional gas for CREATE tx with 2d nonce and account nonce is 0.
        // This case would create a new account for caller.
        // We only check first call of the transaction because CREATE is only allowed
        // to appear as the first call in the batch (validated in `validate_calls`)
        if !nonce_key.is_zero()
            && tx.first_call().is_some_and(|(kind, _)| kind.is_create())
            && caller_account.nonce() == 0
        {
            init_gas.initial_regular_gas += cfg.gas_params.get(GasId::new_account_cost());
            init_gas.initial_state_gas += cfg.gas_params.new_account_state_gas();

            // do the gas limit check again (include state gas for T4+).
            if tx.gas_limit() < init_gas.initial_total_gas() {
                return Err(InvalidTransaction::CallGasCostMoreThanGasLimit {
                    gas_limit: tx.gas_limit(),
                    initial_gas: init_gas.initial_total_gas(),
                }
                .into());
            }

            // Validate that regular gas does not exceed the cap.
            if cfg.is_amsterdam_eip8037_enabled()
                && init_gas.initial_regular_gas().max(init_gas.floor_gas) > cfg.tx_gas_limit_cap()
            {
                return Err(InvalidTransaction::GasFloorMoreThanGasLimit {
                    gas_floor: init_gas.initial_regular_gas(),
                    gas_limit: cfg.tx_gas_limit_cap(),
                }
                .into());
            }
        }

        if is_expiring_nonce {
            // Expiring nonce transaction replay protection:
            // - Pre-T1B: use tx_hash for backwards-compatible behavior.
            // - T1B+: use the sender-scoped tx identifier (keccak256(encode_for_signing || sender))
            //   to prevent replay via different fee payer signatures.
            let tempo_tx_env = tx
                .tempo_tx_env
                .as_ref()
                .ok_or(TempoInvalidTransaction::ExpiringNonceMissingTxEnv)?;

            // Expiring nonce txs must have nonce == 0
            if tx.nonce() != 0 {
                return Err(TempoInvalidTransaction::ExpiringNonceNonceNotZero.into());
            }

            let replay_hash = if spec.is_t1b() {
                tx.unique_tx_identifier()
                    .ok_or(TempoInvalidTransaction::ExpiringNonceMissingTxEnv)?
            } else {
                tempo_tx_env.tx_hash
            };
            let valid_before = tempo_tx_env
                .valid_before
                .ok_or(TempoInvalidTransaction::ExpiringNonceMissingValidBefore)?;

            let block_timestamp = block.timestamp().saturating_to::<u64>();
            StorageCtx::enter_evm_without_tip1060_accounting(
                journal,
                block,
                cfg,
                tx,
                actions.clone(),
                || {
                    let mut nonce_manager = NonceManager::new();

                    let prev_ptr = if let Some(expiring_nonce_idx) = tempo_tx_env.expiring_nonce_idx
                    {
                        let ptr = nonce_manager
                            .expiring_nonce_ring_ptr
                            .read()
                            .map_err(|err| EVMError::Custom(err.to_string()))?;

                        let next = (ptr + expiring_nonce_idx as u32) % EXPIRING_NONCE_SET_CAPACITY;

                        nonce_manager
                            .expiring_nonce_ring_ptr
                            .write(next)
                            .map_err(|err| EVMError::Custom(err.to_string()))?;

                        Some(ptr)
                    } else {
                        None
                    };

                    nonce_manager
                    .check_and_mark_expiring_nonce(replay_hash, valid_before)
                    .map_err(|err| match err {
                        TempoPrecompileError::Fatal(err) => EVMError::Custom(err),
                        TempoPrecompileError::NonceError(
                            tempo_contracts::precompiles::NonceError::InvalidExpiringNonceExpiry(_),
                        ) => {
                            let max_allowed =
                                block_timestamp.saturating_add(EXPIRING_NONCE_MAX_EXPIRY_SECS);
                            if valid_before <= block_timestamp {
                                TempoInvalidTransaction::NonceManagerError(format!(
                                    "expiring nonce transaction expired: valid_before ({valid_before}) <= block timestamp ({block_timestamp})"
                                ))
                                .into()
                            } else {
                                TempoInvalidTransaction::NonceManagerError(format!(
                                    "expiring nonce valid_before ({valid_before}) too far in the future: must be within {EXPIRING_NONCE_MAX_EXPIRY_SECS}s of block timestamp ({block_timestamp}), max allowed is {max_allowed}"
                                ))
                                .into()
                            }
                        }
                        err => TempoInvalidTransaction::NonceManagerError(err.to_string()).into(),
                    })?;

                    if let Some(prev_ptr) = prev_ptr {
                        nonce_manager
                            .expiring_nonce_ring_ptr
                            .write(prev_ptr)
                            .map_err(|err| EVMError::Custom(err.to_string()))?;
                    }

                    Ok::<_, EVMError<DB::Error, TempoInvalidTransaction>>(())
                },
            )?;
        } else if !nonce_key.is_zero() {
            // 2D nonce transaction
            StorageCtx::enter_evm_without_tip1060_accounting(
                journal,
                block,
                cfg,
                tx,
                actions.clone(),
                || {
                    let mut nonce_manager = NonceManager::new();

                    if !cfg.is_nonce_check_disabled() {
                        let tx_nonce = tx.nonce();
                        let state = nonce_manager
                            .get_nonce(getNonceCall {
                                account: tx.caller(),
                                nonceKey: nonce_key,
                            })
                            .map_err(|err| match err {
                                TempoPrecompileError::Fatal(err) => EVMError::Custom(err),
                                err => TempoInvalidTransaction::NonceManagerError(err.to_string())
                                    .into(),
                            })?;

                        match tx_nonce.cmp(&state) {
                            Ordering::Greater => {
                                return Err(InvalidTransaction::NonceTooHigh {
                                    tx: tx_nonce,
                                    state,
                                }
                                .into());
                            }
                            Ordering::Less => {
                                return Err(InvalidTransaction::NonceTooLow {
                                    tx: tx_nonce,
                                    state,
                                }
                                .into());
                            }
                            _ => {}
                        }
                    }

                    // Always increment nonce for AA transactions with non-zero nonce keys.
                    nonce_manager
                        .increment_nonce(tx.caller(), nonce_key)
                        .map_err(|err| match err {
                            TempoPrecompileError::Fatal(err) => EVMError::Custom(err),
                            err => {
                                TempoInvalidTransaction::NonceManagerError(err.to_string()).into()
                            }
                        })?;

                    Ok::<_, EVMError<DB::Error, TempoInvalidTransaction>>(())
                },
            )?;
        } else {
            // Protocol nonce (nonce_key == 0)
            // Bump the nonce for calls. Nonce for CREATE will be bumped in `make_create_frame`.
            // This applies uniformly to both standard and AA transactions - we only bump here
            // for CALLs, letting make_create_frame handle the nonce for CREATE operations.
            if tx.kind().is_call() {
                caller_account.bump_nonce();
            }
        }

        // calculate the new balance after the fee is collected.
        let new_balance = calculate_caller_fee(account_balance, tx, block, cfg)?;
        // doing max to avoid underflow as new_balance can be more than account
        // balance if `cfg.is_balance_check_disabled()` is true.
        let gas_balance_spending = core::cmp::max(account_balance, new_balance) - new_balance;

        // Note: Signature verification happens during recover_signer() before entering the pool
        // Note: Transaction parameter validation (priority fee, time window) happens in validate_env()

        // For Keychain signatures, validate the acting access key before fee collection when it
        // already exists. Same-tx auth+use is the exception: that key is registered only after fees
        // are collected, so fee-limit validation uses the inline authorization payload instead.
        let mut loaded_tx_access_key = None;
        // Access key whose fee-token spending limit was debited during fee collection, if any.
        let mut keychain_fee_key = None;
        let mut same_tx_key_authorization_use = false;
        if let Some(tempo_tx_env) = tx.tempo_tx_env.as_ref()
            && let Some(keychain_sig) = tempo_tx_env.signature.as_keychain()
        {
            // The user_address is the root account this transaction is being executed for.
            // This should match tx.caller (which comes from recover_signer on the outer signature).
            let user_address = &keychain_sig.user_address;

            // Sanity check: user_address should match tx.caller
            if *user_address != tx.caller {
                return Err(TempoInvalidTransaction::KeychainUserAddressMismatch {
                    user_address: *user_address,
                    caller: tx.caller,
                }
                .into());
            }

            // Use override_key_id if provided (for gas estimation), otherwise recover from signature.
            let access_key_addr = if let Some(override_key_id) = tempo_tx_env.override_key_id {
                override_key_id
            } else {
                keychain_sig
                    .key_id(&tempo_tx_env.signature_hash)
                    .map_err(|_| TempoInvalidTransaction::AccessKeyRecoveryFailed)?
            };

            let key_auth = tempo_tx_env.key_authorization.as_ref();
            // Classify whether this keychain-signed tx is using the same access key that the
            // inline authorization registers.
            same_tx_key_authorization_use =
                key_auth.is_some_and(|key_auth| access_key_addr == key_auth.key_id);

            if same_tx_key_authorization_use {
                let key_auth = key_auth.expect("same-tx auth/use requires inline authorization");

                // Same-tx auth+use path: the access key does not exist in storage yet, so the fee
                // check must use the inline limits directly. `collectFeePreTx` cannot enforce this
                // because `transaction_key` is intentionally not set until after authorization.
                if !gas_balance_spending.is_zero()
                    && fee_payer == tx.caller
                    && let Some(limits) = key_auth.limits.as_ref()
                {
                    let remaining = limits
                        .iter()
                        .rev()
                        .find(|limit| limit.token == fee_token)
                        .map(|limit| limit.limit)
                        .unwrap_or_default();

                    if gas_balance_spending > remaining {
                        return Err(
                            FeePaymentError::Other("SpendingLimitExceeded".to_string()).into()
                        );
                    }

                    keychain_fee_key = Some(key_auth.key_id);
                }
            } else {
                // Existing-key path:
                // - ordinary keychain txs must validate the acting access key before fees are paid
                // - T6 delegated key authorizations also validate the acting key here, then reuse
                //   the loaded admin/signature-type facts below when the sidecar signer is the same key
                let loaded_key = StorageCtx::enter_precompile(
                    journal,
                    block,
                    cfg,
                    tx,
                    actions.clone(),
                    |mut keychain: AccountKeychain| {
                        // Extract the signature type from the inner signature to validate it matches
                        // the key_type stored in the keychain. This prevents using a signature of one
                        // type to authenticate as a key registered with a different type.
                        // Only validate signature type on T1+ to maintain backward compatibility
                        // with historical blocks during re-execution.
                        let tx_sig_type = keychain_sig.signature.signature_type().into();
                        let sig_type = (key_auth.is_some() || spec.is_t1()).then_some(tx_sig_type);

                        let key = keychain
                            .validate_keychain_authorization(
                                *user_address,
                                access_key_addr,
                                block.timestamp().to::<u64>(),
                                sig_type,
                            )
                            .map_err(|e| TempoInvalidTransaction::KeychainValidationFailed {
                                reason: format!("{e:?}"),
                            })?;

                        // T6 adds admin delegation: a keychain signer may authorize a different
                        // child key only if the acting transaction key is itself an active admin key.
                        if key_auth.is_some() && !key.is_admin {
                            return Err(
                                TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys.into()
                            );
                        }

                        // Set the transaction key in the keychain precompile.
                        // The TIP20 precompile will read this during fee collection and
                        // execution to enforce spending limits for existing keys.
                        keychain
                            .set_transaction_key(access_key_addr)
                            .map_err(|e| EVMError::Custom(e.to_string()))?;

                        Ok::<_, EVMError<_, TempoInvalidTransaction>>(LoadedTxAccessKey {
                            key_id: access_key_addr,
                            key,
                        })
                    },
                )?;

                evm.key_expiry = Some(loaded_key.key.expiry);
                keychain_fee_key = loaded_key.key.enforce_limits.then_some(loaded_key.key_id);
                loaded_tx_access_key = Some(loaded_key);
            }
        }

        // T6 stateless signer/account checks run in `validate_env`. This state-aware phase only
        // proves that a non-root sidecar signer is an active admin key for the caller account.
        if cfg.spec.is_t6()
            && let Some(tempo_tx_env) = tx.tempo_tx_env.as_ref()
            && let Some(key_auth) = tempo_tx_env.key_authorization.as_ref()
        {
            let auth_signer = key_auth
                .recover_signer()
                .map_err(|_| TempoInvalidTransaction::KeyAuthorizationSignatureRecoveryFailed)?;

            if auth_signer != tx.caller {
                let key_auth_sig_type: u8 = key_auth.signature.signature_type().into();
                let signer_is_admin = match loaded_tx_access_key {
                    Some(loaded_key)
                        if loaded_key.key_id == auth_signer
                            && (loaded_key.key.signature_type as u8) == key_auth_sig_type =>
                    {
                        loaded_key.key.is_admin
                    }
                    Some(_) | None => {
                        return Err(TempoInvalidTransaction::KeychainValidationFailed {
                            reason:
                                "admin-signed key authorization must be signed by transaction key"
                                    .to_string(),
                        }
                        .into());
                    }
                };

                if !signer_is_admin {
                    return Err(TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot {
                        expected: tx.caller,
                        actual: auth_signer,
                    }
                    .into());
                }
            }
        }

        // Collect fees for the transaction.
        if !gas_balance_spending.is_zero() {
            let checkpoint = journal.checkpoint();

            let skip_liquidity_check = evm.skip_liquidity_check;
            let result = fee_manager.collect_fee_pre_tx(
                ProtocolFeeContext {
                    journal,
                    block_env: block,
                    cfg,
                    tx_env: tx,
                    actions: actions.clone(),
                },
                fee_payer,
                fee_token,
                gas_balance_spending,
                block.beneficiary(),
                skip_liquidity_check,
            );

            if let Err(err) = result {
                // Revert the journal to checkpoint before `collectFeePreTx` call if something went wrong.
                journal.checkpoint_revert(checkpoint);

                // Map fee collection errors to transaction validation errors since they
                // indicate the transaction cannot be included (e.g., insufficient liquidity
                // in FeeAMM pool for fee swaps)
                return Err(match err {
                    TempoPrecompileError::TIPFeeAMMError(
                        TIPFeeAMMError::InsufficientLiquidity(_),
                    ) => {
                        let validator_token = fee_manager
                            .get_validator_token(
                                journal,
                                block.beneficiary(),
                                cfg.spec,
                                StorageActions::disabled(),
                            )
                            .ok();

                        FeePaymentError::InsufficientAmmLiquidity {
                            user_token: validator_token.map(|_| fee_token),
                            validator_token,
                            fee: gas_balance_spending,
                        }
                        .into()
                    }

                    TempoPrecompileError::TIP20(TIP20Error::InsufficientBalance(
                        InsufficientBalance { available, .. },
                    )) => FeePaymentError::InsufficientFeeTokenBalance {
                        fee: gas_balance_spending,
                        balance: available,
                    }
                    .into(),

                    TempoPrecompileError::TIP20(TIP20Error::ContractPaused(_)) => {
                        TempoInvalidTransaction::FeeTokenPaused { address: fee_token }.into()
                    }

                    TempoPrecompileError::Fatal(e) => EVMError::Custom(e),

                    _ => FeePaymentError::Other(err.to_string()).into(),
                });
            }

            if cfg.spec.is_t7() {
                let keychain_fee_key = if fee_payer == tx.caller {
                    keychain_fee_key
                } else {
                    None
                };
                evm.non_creditable_slots.borrow_mut().initialize(
                    fee_payer,
                    fee_token,
                    keychain_fee_key,
                );
            }

            journal.checkpoint_commit();
            evm.collected_fee = gas_balance_spending;
        }

        // If the transaction includes a KeyAuthorization, validate and authorize the key
        // only after fee collection has succeeded. This pre-execution write is deliberately
        // outside the later user-call batch checkpoint, so same-transaction authorize-and-use
        // keeps the newly registered key even if scoped-call prevalidation or execution fails.
        if let Some(tempo_tx_env) = tx.tempo_tx_env.as_ref()
            && let Some(key_auth) = &tempo_tx_env.key_authorization
        {
            let keychain_checkpoint = if spec.is_t1() {
                Some(journal.checkpoint())
            } else {
                None
            };

            let amsterdam_eip8037_enabled = cfg.enable_amsterdam_eip8037;
            let internals = EvmInternals::new(journal, block, cfg, tx);

            // T1/T1A: Apply gas metering for the keychain precompile call.
            // Pre-T1 and T1B+: Use unlimited gas.
            // T1B+ disables gas metering here because gas is already accounted for
            // in intrinsic gas via `calculate_key_authorization_gas`. Running with
            // unlimited gas also eliminates the OOG path that caused the CREATE
            // nonce replay vulnerability (protocol nonce not bumped on OOG).
            let gas_limit = if spec.is_t1() && !spec.is_t1b() {
                tx.gas_limit() - init_gas.initial_total_gas()
            } else {
                u64::MAX
            };

            // Create gas_params with only sstore increase for key authorization
            let gas_params = if spec.is_t1() {
                static TABLE: OnceLock<GasParams> = OnceLock::new();
                // only enabled SSTORE and warm storage read gas params for T1 fork in keychain.
                TABLE
                    .get_or_init(|| {
                        let mut table = [0u64; 256];
                        table[GasId::sstore_set_without_load_cost().as_usize()] =
                            cfg.gas_params.get(GasId::sstore_set_without_load_cost());
                        table[GasId::warm_storage_read_cost().as_usize()] =
                            cfg.gas_params.get(GasId::warm_storage_read_cost());
                        GasParams::new(Arc::new(table))
                    })
                    .clone()
            } else {
                cfg.gas_params.clone()
            };

            // It's ok to set reservoir to 0 because pre-T1B it doesn't matter and post-T1B we have unlimited gas anyway.
            let mut provider = EvmPrecompileStorageProvider::new(
                internals,
                gas_limit,
                0,
                cfg.spec,
                amsterdam_eip8037_enabled,
                false,
                gas_params,
            )
            .with_actions(actions.clone());
            provider.set_tip1060_storage_credits(false);

            // The core logic of setting up thread-local storage is here.
            let out_of_gas = StorageCtx::enter(&mut provider, || {
                let mut keychain = AccountKeychain::default();
                let access_key_addr = key_auth.key_id;

                // Convert signature type to precompile SignatureType enum
                // Use the key_type field which specifies the type of key being authorized
                let signature_type = match key_auth.key_type {
                    SignatureType::Secp256k1 => PrecompileSignatureType::Secp256k1,
                    SignatureType::P256 => PrecompileSignatureType::P256,
                    SignatureType::WebAuthn => PrecompileSignatureType::WebAuthn,
                };

                // Handle expiry: None means never expires (store as u64::MAX)
                let expiry = key_auth.expiry.map_or(u64::MAX, |expiry| expiry.get());

                // Handle limits: None means unlimited spending (enforce_limits=false)
                // Some([]) means no spending allowed (enforce_limits=true)
                // Some([...]) means specific limits (enforce_limits=true)
                let enforce_limits = key_auth.limits.is_some();
                let precompile_limits: Vec<TokenLimit> = key_auth
                    .limits
                    .as_ref()
                    .map(|limits| {
                        limits
                            .iter()
                            .map(|limit| TokenLimit {
                                token: limit.token,
                                amount: limit.limit,
                                period: limit.period,
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                let allow_any_calls = key_auth.allowed_calls.is_none();
                let precompile_allowed_calls = translate_allowed_calls_for_precompile(key_auth);

                let config = KeyRestrictions {
                    expiry,
                    enforceLimits: enforce_limits,
                    limits: precompile_limits,
                    allowAnyCalls: allow_any_calls,
                    allowedCalls: precompile_allowed_calls,
                };

                // Call precompile to authorize the key (same phase as nonce increment).
                let result = if key_auth.is_admin() {
                    keychain.authorize_admin_key(
                        tx.caller,
                        access_key_addr,
                        signature_type,
                        key_auth.witness(),
                    )
                } else {
                    keychain.authorize_key(
                        tx.caller,
                        access_key_addr,
                        signature_type,
                        config,
                        key_auth.witness(),
                    )
                };

                match result {
                    // all is good, we can do execution.
                    Ok(_) => Ok(false),
                    // on out of gas we are skipping execution but not invalidating the transaction.
                    Err(TempoPrecompileError::OutOfGas) => Ok(true),
                    Err(TempoPrecompileError::Fatal(err)) => Err(EVMError::Custom(err)),
                    Err(err) => Err(TempoInvalidTransaction::KeychainPrecompileError {
                        reason: err.to_string(),
                    }
                    .into()),
                }
            })?;

            let gas_used = provider.gas_used();
            drop(provider);

            // Cache inline key authorization expiry.
            if let Some(expiry) = key_auth.expiry {
                evm.key_expiry = Some(expiry.get());
            }

            // activated only on T1/T1A fork.
            // T1B+: Skip adding precompile gas to initial_gas since it is already
            // accounted for in intrinsic gas. The precompile runs with unlimited gas
            // on T1B+ so out_of_gas is never true.
            if let Some(keychain_checkpoint) = keychain_checkpoint {
                if spec.is_t1b() {
                    journal.checkpoint_commit();
                } else if out_of_gas {
                    init_gas.initial_regular_gas = u64::MAX;
                    journal.checkpoint_revert(keychain_checkpoint);
                } else {
                    init_gas.initial_regular_gas += gas_used;
                    journal.checkpoint_commit();
                };
            }

            // If this is a same tx auth+use, set the transient key_id to the newly authorized
            // key and decrement the fee from its spending limit. Admin delegation must keep the
            // actual signer as the transaction key.
            if same_tx_key_authorization_use {
                StorageCtx::enter_evm_without_tip1060_accounting(
                    journal,
                    block,
                    cfg,
                    tx,
                    actions,
                    || {
                        let mut keychain = AccountKeychain::new();
                        keychain
                            .set_transaction_key(key_auth.key_id)
                            .map_err(|e| EVMError::Custom(e.to_string()))?;

                        if evm.collected_fee.is_zero() {
                            return Ok(());
                        }

                        keychain
                            .authorize_transfer(fee_payer, fee_token, evm.collected_fee)
                            .map_err(|err| match err {
                                TempoPrecompileError::Fatal(err) => EVMError::Custom(err),
                                err => FeePaymentError::Other(err.to_string()).into(),
                            })
                    },
                )?;
            }
        }

        Ok(())
    }

    fn reimburse_caller(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut FrameResult,
    ) -> Result<(), Self::Error> {
        let actions = evm.actions.clone();
        let fee_manager = evm.fee_manager.clone();
        let context = &mut evm.inner.ctx;
        let tx = context.tx();
        let basefee = u128::from(context.block().basefee());
        let effective_gas_price = tx.effective_gas_price(basefee);
        let gas = exec_result.gas();

        let actual_spending = calc_gas_balance_spending(
            gas.used().saturating_sub(gas.reservoir()),
            effective_gas_price,
        );
        let refund_amount = tx.effective_balance_spending(
            context.block.basefee.into(),
            context.block.blob_gasprice().unwrap_or_default(),
        )? - tx.value
            - actual_spending;

        // Skip `collectFeePostTx` call if the initial fee collected in
        // `collectFeePreTx` was zero, but spending is non-zero.
        //
        // This is normally unreachable unless the gas price was increased mid-transaction,
        // which is only possible when there are some EVM customizations involved (e.g Foundry EVM).
        if context.cfg.disable_fee_charge
            && evm.collected_fee.is_zero()
            && !actual_spending.is_zero()
        {
            return Ok(());
        }

        let (journal, block, tx) = (&mut context.journaled_state, &context.block, &context.tx);
        let beneficiary = context.block.beneficiary();

        let credited = if !actual_spending.is_zero() || !refund_amount.is_zero() {
            let fee_payer = tx.fee_payer().expect("pre-validated in `validate_env`");
            let fee_token = evm
                .fee_token
                .expect("set in `validate_against_state_and_deduct_caller`");
            fee_manager
                .collect_fee_post_tx(
                    ProtocolFeeContext {
                        journal,
                        block_env: block,
                        cfg: &context.cfg,
                        tx_env: tx,
                        actions,
                    },
                    fee_payer,
                    actual_spending,
                    refund_amount,
                    fee_token,
                    beneficiary,
                )
                .map_err(|e| EVMError::Custom(format!("{e:?}")))?
        } else {
            U256::ZERO
        };

        // Stash the per-tx credit so `TempoBlockExecutor` can surface it on `TempoTxResult`
        // for payload scoring. Reset to zero on every tx entry below in `validate_env`.
        evm.validator_fee = credited;
        Ok(())
    }

    #[inline]
    fn reward_beneficiary(
        &self,
        _evm: &mut Self::Evm,
        _exec_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        // Fee handling (refunds and swaps) are done in `reimburse_caller()` via `collectFeePostTx`.
        // Validators call distributeFees() to claim their accumulated fees.
        Ok(())
    }

    /// Validates transaction environment with custom handling for AA transactions.
    ///
    /// Performs standard validation plus AA-specific checks:
    /// - Priority fee validation (EIP-1559)
    /// - Time window validation (validAfter/validBefore)
    #[inline]
    fn validate_env(&self, evm: &mut Self::Evm) -> Result<(), Self::Error> {
        // Reset per-tx fee state.
        evm.collected_fee = U256::ZERO;
        evm.validator_fee = U256::ZERO;
        evm.non_creditable_slots.borrow_mut().clear();

        // Validate the fee payer signature
        let fee_payer = evm.ctx.tx.fee_payer()?;

        if evm.ctx.cfg.spec.is_t2()
            && evm.ctx.tx.has_fee_payer_signature()
            && fee_payer == evm.ctx.tx.caller()
        {
            return Err(TempoInvalidTransaction::SelfSponsoredFeePayer.into());
        }

        // All accounts have zero balance so transfer of value is not possible.
        // Check added in https://github.com/tempoxyz/tempo/pull/759
        if !evm.ctx.tx.value().is_zero() {
            return Err(TempoInvalidTransaction::ValueTransferNotAllowed.into());
        }

        // First perform standard validation (header + transaction environment)
        // This validates: prevrandao, excess_blob_gas, chain_id, gas limits, tx type support, etc.
        validation::validate_env::<_, Self::Error>(evm.ctx())?;

        // AA-specific validations
        let cfg = &evm.inner.cfg;
        let tx = &evm.inner.tx;

        if let Some(aa_env) = tx.tempo_tx_env.as_ref() {
            // Validate AA transaction structure (calls list, CREATE rules)
            validate_calls(
                &aa_env.aa_calls,
                !aa_env.tempo_authorization_list.is_empty(),
            )
            .map_err(TempoInvalidTransaction::from)?;

            // Access-key CREATE is a cheap structural rejection that does not depend on any
            // per-call scope walk or state mutation. Rejecting it here keeps validation work
            // constant and avoids entering CREATE execution paths that require special protocol-
            // nonce preservation on failure.
            if cfg.spec().is_t3()
                && aa_env.signature.is_keychain()
                && aa_env
                    .aa_calls
                    .first()
                    .is_some_and(|call| call.to.is_create())
            {
                return Err(TempoInvalidTransaction::CallsValidation(
                    "access-key transactions cannot use CREATE as the first call",
                )
                .into());
            }

            // Validate keychain signature version (outer + authorization list).
            aa_env
                .signature
                .validate_version(cfg.spec().is_t1c())
                .map_err(TempoInvalidTransaction::from)?;
            for auth in &aa_env.tempo_authorization_list {
                auth.signature()
                    .validate_version(cfg.spec().is_t1c())
                    .map_err(TempoInvalidTransaction::from)?;
            }

            let has_keychain_fields =
                aa_env.key_authorization.is_some() || aa_env.signature.is_keychain();

            if aa_env.subblock_transaction && has_keychain_fields {
                return Err(TempoInvalidTransaction::KeychainOpInSubblockTransaction.into());
            }

            if let Some(key_auth) = &aa_env.key_authorization {
                // Check if this TX is using a Keychain signature (access key). Non-admin access
                // keys cannot authorize other keys; T6 admin keys can.
                let mut same_tx_auth_use = false;
                if let Some(keychain_sig) = aa_env.signature.as_keychain() {
                    // Use override_key_id if provided (for gas estimation), otherwise recover from signature
                    let access_key_addr = if let Some(override_key_id) = aa_env.override_key_id {
                        override_key_id
                    } else {
                        // Get the access key address (recovered during Tx->TxEnv conversion and cached)
                        keychain_sig
                            .key_id(&aa_env.signature_hash)
                            .map_err(|_| TempoInvalidTransaction::AccessKeyRecoveryFailed)?
                    };

                    same_tx_auth_use = access_key_addr == key_auth.key_id;
                    if !same_tx_auth_use && !cfg.spec.is_t6() {
                        return Err(
                            TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys.into()
                        );
                    }

                    if same_tx_auth_use
                        && cfg.spec.is_t3()
                        && key_auth.key_type != keychain_sig.signature.signature_type()
                    {
                        return Err(TempoInvalidTransaction::KeychainValidationFailed {
                                reason: "key authorization key_type does not match the keychain signature type"
                                    .to_string(),
                            }
                            .into());
                    }
                }

                if (key_auth.is_admin || key_auth.account.is_some()) && !cfg.spec.is_t6() {
                    return Err(TempoInvalidTransaction::KeychainValidationFailed {
                        reason: "T6 key authorization fields are not active before T6".to_string(),
                    }
                    .into());
                }

                if cfg.spec.is_t6() && key_auth.account.is_some_and(|account| account != tx.caller)
                {
                    // T6 allows existing admin keys to sign `KeyAuthorization`s for an
                    // account. Any named account must match the transaction caller so the
                    // signed payload cannot be replayed against another account where the
                    // same admin key is also authorized.
                    let reason = if key_auth.is_admin() {
                        "admin key authorization account mismatch"
                    } else {
                        "key authorization account mismatch"
                    };

                    return Err(TempoInvalidTransaction::KeychainValidationFailed {
                        reason: reason.to_string(),
                    }
                    .into());
                }

                if key_auth.is_admin()
                    && (key_auth.expiry.is_some()
                        || key_auth.limits.is_some()
                        || key_auth.allowed_calls.is_some())
                {
                    return Err(TempoInvalidTransaction::KeychainValidationFailed {
                        reason:
                            "admin key authorizations cannot carry expiry, limits, or call scopes"
                                .to_string(),
                    }
                    .into());
                }

                if !cfg.spec.is_t6() {
                    let auth_signer = key_auth.recover_signer().map_err(|_| {
                        TempoInvalidTransaction::KeyAuthorizationSignatureRecoveryFailed
                    })?;

                    if auth_signer != tx.caller {
                        return Err(TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot {
                            expected: tx.caller,
                            actual: auth_signer,
                        }
                        .into());
                    }
                }

                // Validate KeyAuthorization chain_id.
                // T1C+: chain_id must exactly match (wildcard 0 is no longer allowed).
                // Pre-T1C: chain_id == 0 allows replay on any chain (wildcard).
                key_auth
                    .validate_chain_id(cfg.chain_id(), cfg.spec.is_t1c())
                    .map_err(TempoInvalidTransaction::from)?;

                if key_auth.has_witness() && !cfg.spec.is_t5() {
                    return Err(TempoInvalidTransaction::KeychainValidationFailed {
                        reason: "key authorization witnesses are not active before T5".to_string(),
                    }
                    .into());
                }

                // T3 gates all TIP-1011 fields. Before activation, transaction semantics must stay
                // unchanged, so periodic limits and call scopes are rejected.
                if !cfg.spec.is_t3() {
                    if key_auth.has_periodic_limits() {
                        return Err(TempoInvalidTransaction::KeychainValidationFailed {
                            reason: "periodic token limits are not active before T3".to_string(),
                        }
                        .into());
                    }

                    if key_auth.has_call_scopes() {
                        return Err(TempoInvalidTransaction::KeychainValidationFailed {
                            reason: "call scopes are not active before T3".to_string(),
                        }
                        .into());
                    }
                }

                if cfg.spec.is_t6() {
                    let auth_signer = key_auth.recover_signer().map_err(|_| {
                        TempoInvalidTransaction::KeyAuthorizationSignatureRecoveryFailed
                    })?;
                    if auth_signer != tx.caller && key_auth.account.is_none() {
                        return Err(TempoInvalidTransaction::KeychainValidationFailed {
                            reason: "admin-signed key authorization account mismatch".to_string(),
                        }
                        .into());
                    }

                    if auth_signer == tx.caller
                        && aa_env.signature.is_keychain()
                        && !same_tx_auth_use
                    {
                        return Err(TempoInvalidTransaction::KeychainValidationFailed {
                            reason:
                                "root-signed key authorization must use root transaction signature"
                                    .to_string(),
                        }
                        .into());
                    }

                    if auth_signer != tx.caller {
                        let Some(keychain_sig) = aa_env.signature.as_keychain() else {
                            return Err(TempoInvalidTransaction::KeychainValidationFailed {
                                reason:
                                    "admin-signed key authorization must be signed by transaction key"
                                        .to_string(),
                            }
                            .into());
                        };

                        let access_key_addr = if let Some(override_key_id) = aa_env.override_key_id
                        {
                            override_key_id
                        } else {
                            keychain_sig
                                .key_id(&aa_env.signature_hash)
                                .map_err(|_| TempoInvalidTransaction::AccessKeyRecoveryFailed)?
                        };

                        if access_key_addr != auth_signer {
                            return Err(TempoInvalidTransaction::KeychainValidationFailed {
                                reason:
                                    "admin-signed key authorization must be signed by transaction key"
                                        .to_string(),
                            }
                            .into());
                        }

                        if key_auth.signature.signature_type()
                            != keychain_sig.signature.signature_type()
                        {
                            return Err(TempoInvalidTransaction::KeychainValidationFailed {
                                reason:
                                    "admin-signed key authorization signature type does not match transaction key signature type"
                                        .to_string(),
                            }
                            .into());
                        }
                    }
                }

                // Cache inline key authorization expiry.
                if let Some(expiry) = key_auth.expiry {
                    evm.key_expiry = Some(expiry.get());
                }
            }

            // Validate priority fee for AA transactions using revm's validate_priority_fee_tx
            let base_fee = if cfg.is_base_fee_check_disabled() {
                None
            } else {
                Some(u128::from(evm.ctx_ref().block().basefee()))
            };

            validation::validate_priority_fee_tx(
                tx.max_fee_per_gas(),
                tx.max_priority_fee_per_gas().unwrap_or_default(),
                base_fee,
                cfg.is_priority_fee_check_disabled(),
            )?;

            // Validate time window for AA transactions
            let block_timestamp = evm.ctx_ref().block().timestamp().saturating_to();
            let valid_after = aa_env.valid_after.filter(|_| !evm.skip_valid_after_check);
            validate_time_window(valid_after, aa_env.valid_before, block_timestamp)?;
        }

        Ok(())
    }

    /// Calculates initial gas costs with custom handling for AA transactions.
    ///
    /// AA transactions have variable intrinsic gas based on signature type:
    /// - secp256k1 (64/65 bytes): Standard 21k base
    /// - P256 (129 bytes): 21k base + 5k for P256 verification
    /// - WebAuthn (>129 bytes): 21k base + 5k + calldata gas for variable data
    #[inline]
    fn validate_initial_tx_gas(
        &self,
        evm: &mut Self::Evm,
    ) -> Result<InitialAndFloorGas, Self::Error> {
        let tx = evm.ctx_ref().tx();
        let spec = evm.ctx_ref().cfg().spec();
        let gas_params = evm.ctx_ref().cfg().gas_params();
        let gas_limit = tx.gas_limit();

        // Route to appropriate gas calculation and validation based on transaction type
        let mut init_gas = if tx.tempo_tx_env.is_some() {
            // AA transaction - use batch gas calculation (includes validation)
            validate_aa_initial_tx_gas(evm)?
        } else {
            let mut acc = 0;
            let mut storage = 0;
            // legacy is only tx type that does not have access list.
            if tx.tx_type() != TransactionType::Legacy {
                (acc, storage) = tx
                    .access_list()
                    .map(|al| {
                        al.fold((0, 0), |(acc, storage), item| {
                            (acc + 1, storage + item.storage_slots().count())
                        })
                    })
                    .unwrap_or_default();
            };
            let mut init_gas = gas_params.initial_tx_gas(
                tx.input(),
                tx.kind().is_create(),
                acc as u64,
                storage as u64,
                tx.authorization_list_len() as u64,
            );
            // TIP-1000: Storage pricing updates for launch
            // EIP-7702 authorisation list entries with `auth_list.nonce == 0` require an additional 250,000 gas.
            // no need for v1 fork check as gas_params would be zero
            for auth in tx.authorization_list() {
                if spec.is_t1() && auth.nonce == 0 {
                    init_gas.initial_regular_gas += gas_params.get(GasId::new_account_cost());
                    init_gas.initial_state_gas += gas_params.new_account_state_gas();
                }
            }

            // TIP-1000: Storage pricing updates for launch
            // Transactions with any `nonce_key` and `nonce == 0` require an additional 250,000 gas.
            if spec.is_t1() && tx.nonce == 0 {
                // Add both execution and state portions to initial_total_gas
                // (revm's invariant: initial_total_gas >= initial_state_gas)
                init_gas.initial_regular_gas += gas_params.get(GasId::new_account_cost());
                init_gas.initial_state_gas += gas_params.new_account_state_gas();
            }

            // Validate gas limit is sufficient for initial gas
            if gas_limit < init_gas.initial_total_gas() {
                return Err(InvalidTransaction::CallGasCostMoreThanGasLimit {
                    gas_limit,
                    initial_gas: init_gas.initial_total_gas(),
                }
                .into());
            }

            init_gas
        };

        if evm.ctx.cfg.is_eip7623_disabled() {
            init_gas.floor_gas = 0u64;
        }

        // Validate floor gas (Prague+)
        if gas_limit < init_gas.floor_gas {
            return Err(InvalidTransaction::GasFloorMoreThanGasLimit {
                gas_limit,
                gas_floor: init_gas.floor_gas,
            }
            .into());
        }

        // Validate that regular gas does not exceed the cap.
        if evm.ctx.cfg.is_amsterdam_eip8037_enabled()
            && init_gas.initial_regular_gas().max(init_gas.floor_gas)
                > evm.ctx.cfg.tx_gas_limit_cap()
        {
            return Err(InvalidTransaction::GasFloorMoreThanGasLimit {
                gas_floor: init_gas.initial_regular_gas(),
                gas_limit: evm.ctx.cfg.tx_gas_limit_cap(),
            }
            .into());
        }

        Ok(init_gas)
    }

    fn catch_error(
        &self,
        evm: &mut Self::Evm,
        error: Self::Error,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        evm.clear();

        // For subblock transactions that failed `collectFeePreTx` call we catch error and treat such transactions as valid.
        if evm.ctx.tx.is_subblock_transaction()
            && let Some(
                TempoInvalidTransaction::CollectFeePreTx(_)
                | TempoInvalidTransaction::FeeTokenPaused { .. }
                | TempoInvalidTransaction::EthInvalidTransaction(
                    InvalidTransaction::LackOfFundForMaxFee { .. },
                ),
            ) = error.as_invalid_tx_err()
        {
            // Commit the transaction.
            //
            // `collectFeePreTx` call will happen after the nonce bump so this will only commit the nonce increment.
            evm.ctx.journaled_state.commit_tx();

            evm.ctx().local_mut().clear();
            evm.frame_stack().clear();

            // On fee payment failure, treat the transaction as a halt that consumed entire regular gas limit.
            let total_spent = core::cmp::min(evm.ctx.tx.gas_limit, evm.ctx.cfg.tx_gas_limit_cap());

            Ok(ExecutionResult::Halt {
                reason: TempoHaltReason::SubblockTxFeePayment,
                logs: Default::default(),
                gas: ResultGas::new_with_state_gas(total_spent, 0, 0, 0),
            })
        } else {
            MainnetHandler::default()
                .catch_error(evm, error)
                .map(|result| result.map_haltreason(Into::into))
        }
    }
}

impl<DB, I> TempoEvmHandler<DB, I>
where
    DB: alloy_evm::Database,
{
    /// Runs the full transaction validation pipeline without executing the transaction.
    ///
    /// Returns a [`ValidationContext`] with context relevant for the transaction pool.
    pub fn validate_transaction(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
    ) -> Result<ValidationContext, EVMError<DB::Error, TempoInvalidTransaction>> {
        let mut init_and_floor_gas = self.validate(evm)?;
        self.pre_execution(evm, &mut init_and_floor_gas)?;
        let result = ValidationContext {
            fee_token: evm
                .fee_token
                .expect("set in `validate_against_state_and_deduct_caller`"),
            key_expiry: evm.key_expiry,
        };
        evm.clear();
        Ok(result)
    }
}

/// Context returned by [`TempoEvmHandler::validate_transaction`] with resolved
/// fee token and key expiry information for use by the transaction pool.
#[derive(Debug, Clone)]
pub struct ValidationContext {
    /// The resolved fee token address used to pay for this transaction.
    pub fee_token: Address,
    /// The expiry timestamp of the access key used by this transaction.
    /// Populated for keychain-signed transactions or transactions carrying a KeyAuthorization.
    pub key_expiry: Option<u64>,
}

/// Calculates intrinsic gas for an AA transaction batch using revm helpers.
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
pub fn calculate_aa_batch_intrinsic_gas<'a>(
    aa_env: &TempoBatchCallEnv,
    gas_params: &GasParams,
    access_list: Option<impl Iterator<Item = &'a AccessListItem>>,
    spec: tempo_chainspec::hardfork::TempoHardfork,
) -> Result<InitialAndFloorGas, TempoInvalidTransaction> {
    let calls = &aa_env.aa_calls;
    let signature = &aa_env.signature;
    let authorization_list = &aa_env.tempo_authorization_list;
    let key_authorization = aa_env.key_authorization.as_ref();
    let mut gas = InitialAndFloorGas::default();

    // 1. Base stipend (21k, once per transaction)
    gas.initial_regular_gas += gas_params.tx_base_stipend();

    // 2. Signature verification gas
    gas.initial_regular_gas += tempo_signature_verification_gas(signature);

    let cold_account_cost =
        gas_params.warm_storage_read_cost() + gas_params.cold_account_additional_cost();

    // 3. Per-call overhead: cold account access
    // if the `to` address has not appeared in the call batch before.
    gas.initial_regular_gas += cold_account_cost * calls.len().saturating_sub(1) as u64;

    // 4. Authorization list costs (EIP-7702)
    let num_auths = authorization_list.len() as u64;
    gas.initial_regular_gas +=
        num_auths * gas_params.get(GasId::tx_eip7702_per_empty_account_cost());
    // TIP-1016: Track state gas portion of per-auth cost (225k on T4, 0 pre-T4).
    gas.initial_state_gas += num_auths * gas_params.tx_eip7702_state_gas();

    // Add signature verification costs for each authorization
    // No need for v1 fork check as gas_params would be zero
    for auth in authorization_list {
        gas.initial_regular_gas += tempo_signature_verification_gas(auth.signature());
        // TIP-1000: Storage pricing updates for launch
        // EIP-7702 authorisation list entries with `auth_list.nonce == 0` require an additional 250,000 gas.
        if spec.is_t1() && auth.nonce == 0 {
            gas.initial_regular_gas += gas_params.get(GasId::new_account_cost());
            gas.initial_state_gas += gas_params.new_account_state_gas();
        }
    }

    // 5. Key authorization costs (if present)
    if let Some(key_auth) = key_authorization {
        let (key_auth_regular_gas, key_auth_state_gas) =
            calculate_key_authorization_gas(key_auth, gas_params, spec);
        gas.initial_regular_gas += key_auth_regular_gas;
        gas.initial_state_gas += key_auth_state_gas;
    }

    // 6. Per-call costs
    let mut total_tokens = 0u64;

    for call in calls {
        // 4a. Calldata gas using revm helper
        let tokens = get_tokens_in_calldata_istanbul(&call.input);
        total_tokens += tokens;

        // 4b. CREATE-specific costs
        if call.to.is_create() {
            // CREATE costs 500,000 gas in TIP-1000 (T1), 32,000 before
            gas.initial_regular_gas += gas_params.create_cost();

            // EIP-3860: Initcode analysis gas using revm helper
            gas.initial_regular_gas += gas_params.tx_initcode_cost(call.input.len());

            // TIP-1016: Track predictable state gas for CREATE calls
            gas.initial_state_gas += gas_params.create_state_gas();
        }

        // Note: Transaction value is not allowed in AA transactions as there is no balances in accounts yet.
        // Check added in https://github.com/tempoxyz/tempo/pull/759
        if !call.value.is_zero() {
            return Err(TempoInvalidTransaction::ValueTransferNotAllowedInAATx);
        }

        // 4c. Value transfer cost using revm constant
        // left here for future reference.
        if !call.value.is_zero() && call.to.is_call() {
            gas.initial_regular_gas += gas_params.get(GasId::transfer_value_cost()); // 9000 gas
        }
    }

    gas.initial_regular_gas += total_tokens * gas_params.tx_token_cost();

    // 5. Access list costs using revm constants
    if let Some(access_list) = access_list {
        let (accounts, storages) = access_list.fold((0, 0), |(acc_count, storage_count), item| {
            (acc_count + 1, storage_count + item.storage_slots().count())
        });
        gas.initial_regular_gas += accounts * gas_params.tx_access_list_address_cost(); // 2400 per account
        gas.initial_regular_gas += storages as u64 * gas_params.tx_access_list_storage_key_cost(); // 1900 per storage
    }

    // 6. Floor gas using revm helper
    gas.floor_gas = gas_params.tx_floor_cost_with_tokens(total_tokens); // tokens * 10 + 21000

    Ok(gas)
}

/// Validates and calculates initial transaction gas for AA transactions.
///
/// Calculates intrinsic gas based on:
/// - Signature type (secp256k1: 21k, P256: 26k, WebAuthn: 26k + calldata)
/// - Batch call costs (per-call overhead, calldata, CREATE, value transfers)
fn validate_aa_initial_tx_gas<DB, I>(
    evm: &TempoEvm<DB, I>,
) -> Result<InitialAndFloorGas, EVMError<DB::Error, TempoInvalidTransaction>>
where
    DB: alloy_evm::Database,
{
    let (_, tx, cfg, _, _, _, _) = evm.ctx_ref().all();
    let gas_limit = tx.gas_limit();
    let gas_params = cfg.gas_params();
    let spec = *cfg.spec();

    // This function should only be called for AA transactions
    let aa_env = tx
        .tempo_tx_env
        .as_ref()
        .expect("validate_aa_initial_tx_gas called for non-AA transaction");

    let calls = &aa_env.aa_calls;

    // Validate all CREATE calls' initcode size upfront (EIP-3860)
    let max_initcode_size = evm.ctx_ref().cfg().max_initcode_size();
    for call in calls {
        if call.to.is_create() && call.input.len() > max_initcode_size {
            return Err(InvalidTransaction::CreateInitCodeSizeLimit.into());
        }
    }

    // Calculate batch intrinsic gas using helper
    let mut batch_gas =
        calculate_aa_batch_intrinsic_gas(aa_env, gas_params, tx.access_list(), spec)?;

    let mut nonce_2d_gas = 0;

    // Calculate 2D nonce gas if nonce_key is non-zero
    // If tx nonce is 0, it's a new key (0 -> 1 transition), otherwise existing key
    if spec.is_t1() {
        if aa_env.nonce_key == TEMPO_EXPIRING_NONCE_KEY {
            // Calculate nonce gas based on nonce type:
            // - Expiring nonce (nonce_key == MAX, T1 active): ring buffer + seen mapping operations
            // - 2D nonce (nonce_key != 0): SLOAD + SSTORE for nonce increment
            // - Regular nonce (nonce_key == 0): no additional gas
            batch_gas.initial_regular_gas += EXPIRING_NONCE_GAS;
        } else if tx.nonce == 0 {
            // TIP-1000: Storage pricing updates for launch
            // Tempo transactions with any `nonce_key` and `nonce == 0` require an additional 250,000 gas
            batch_gas.initial_regular_gas += gas_params.get(GasId::new_account_cost());
            batch_gas.initial_state_gas += gas_params.new_account_state_gas();
        } else if !aa_env.nonce_key.is_zero() {
            // Existing 2D nonce key usage (nonce > 0)
            // TIP-1000 Invariant 3: existing state updates must charge +5,000 gas
            batch_gas.initial_regular_gas += spec.gas_existing_nonce_key();
        }
    } else if let Some(aa_env) = &tx.tempo_tx_env
        && !aa_env.nonce_key.is_zero()
    {
        nonce_2d_gas = if tx.nonce() == 0 {
            spec.gas_new_nonce_key()
        } else {
            spec.gas_existing_nonce_key()
        };
    };

    // For T0+, include 2D nonce gas in validation (charged upfront)
    // For pre-T0 (Genesis), 2D nonce gas is added AFTER validation to allow transactions
    // with gas_limit < intrinsic + nonce_2d_gas to pass validation, but the gas is still
    // charged during execution via init_and_floor_gas (not evm.initial_gas)
    if spec.is_t0() {
        batch_gas.initial_regular_gas += nonce_2d_gas;
    }

    // Validate gas limit is sufficient for initial gas.
    // initial_total_gas already includes initial_state_gas as a subset,
    // so no need to add state gas separately.
    if gas_limit < batch_gas.initial_total_gas() {
        return Err(InvalidTransaction::CallGasCostMoreThanGasLimit {
            gas_limit,
            initial_gas: batch_gas.initial_total_gas(),
        }
        .into());
    }

    // For pre-T0 (Genesis), add 2D nonce gas after validation
    // This gas will be charged via init_and_floor_gas, not evm.initial_gas
    if !spec.is_t0() {
        batch_gas.initial_regular_gas += nonce_2d_gas;
    }

    Ok(batch_gas)
}

/// IMPORTANT: the caller must ensure `token` is a valid TIP20Token address.
pub fn get_token_balance<JOURNAL>(
    journal: &mut JOURNAL,
    token: Address,
    sender: Address,
) -> Result<U256, <JOURNAL::Database as Database>::Error>
where
    JOURNAL: JournalTr,
{
    // Address has already been validated as having TIP20 prefix
    journal.load_account(token)?;
    let balance_slot = TIP20Token::from_address(token)
        .expect("TIP20 prefix already validated")
        .balances[sender]
        .slot();
    let balance = journal.sload(token, balance_slot)?.data;

    Ok(balance)
}

impl<DB, I> InspectorHandler for TempoEvmHandler<DB, I>
where
    DB: alloy_evm::Database,
    I: Inspector<TempoContext<DB>>,
{
    type IT = EthInterpreter;

    /// Overridden execution method with inspector support that handles AA vs standard transactions.
    #[inline]
    fn inspect_execution(
        &mut self,
        evm: &mut Self::Evm,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<FrameResult, Self::Error> {
        let spec = evm.ctx_ref().cfg().spec();
        let tx = evm.tx();

        if let Some(oog) = check_gas_limit(*spec, tx, init_and_floor_gas) {
            return Ok(oog);
        }

        let (gas_limit, reservoir) = evm.initial_gas_and_reservoir(init_and_floor_gas);

        if let Some(tempo_tx_env) = evm.ctx().tx().tempo_tx_env.as_ref() {
            let calls = tempo_tx_env.aa_calls.clone();
            self.inspect_execute_multi_call(evm, gas_limit, reservoir, calls)
        } else {
            self.inspect_execute_single_call(evm, gas_limit, reservoir)
        }
    }
}

/// Helper function to create a frame result for an out of gas error.
///
/// Use native fn when new revm version is released.
#[inline]
fn oog_frame_result(kind: TxKind, gas_limit: u64) -> FrameResult {
    if kind.is_call() {
        FrameResult::new_call_oog(gas_limit, 0..0, 0)
    } else {
        FrameResult::new_create_oog(gas_limit, 0)
    }
}

/// Checks if gas limit is sufficient and returns OOG frame result if not.
///
/// For T0+, validates gas limit covers intrinsic gas. For pre-T0, skips check
/// to maintain backward compatibility.
#[inline]
fn check_gas_limit(
    spec: tempo_chainspec::hardfork::TempoHardfork,
    tx: &TempoTxEnv,
    adjusted_gas: &InitialAndFloorGas,
) -> Option<FrameResult> {
    if spec.is_t0() && tx.gas_limit() < adjusted_gas.initial_total_gas() {
        let kind = *tx
            .first_call()
            .expect("we already checked that there is at least one call in aa tx")
            .0;
        return Some(oog_frame_result(kind, tx.gas_limit()));
    }
    None
}

/// Validates time window for AA transactions
///
/// AA transactions can have optional validBefore and validAfter fields:
/// - validAfter: Transaction can only be included after this timestamp
/// - validBefore: Transaction can only be included before this timestamp
///
/// This ensures transactions are only valid within a specific time window.
pub fn validate_time_window(
    valid_after: Option<u64>,
    valid_before: Option<u64>,
    block_timestamp: u64,
) -> Result<(), TempoInvalidTransaction> {
    // Validate validAfter constraint
    if let Some(after) = valid_after
        && block_timestamp < after
    {
        return Err(TempoInvalidTransaction::ValidAfter {
            current: block_timestamp,
            valid_after: after,
        });
    }

    // Validate validBefore constraint
    // IMPORTANT: must be aligned with `RecoveredSubBlock::has_expired_transactions`.
    if let Some(before) = valid_before
        && block_timestamp >= before
    {
        return Err(TempoInvalidTransaction::ValidBefore {
            current: block_timestamp,
            valid_before: before,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests;
