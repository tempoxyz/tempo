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
        result::{EVMError, ExecutionResult, InvalidTransaction},
        transaction::{AccessListItem, AccessListItemTr},
    },
    context_interface::cfg::{GasId, GasParams},
    handler::{
        EvmTr, FrameResult, FrameTr, Handler, MainnetHandler,
        pre_execution::{self, apply_auth_list, calculate_caller_fee},
        validation,
    },
    inspector::{Inspector, InspectorHandler},
    interpreter::{
        Gas, InitialAndFloorGas,
        gas::{
            COLD_SLOAD_COST, STANDARD_TOKEN_COST, WARM_SSTORE_RESET,
            get_tokens_in_calldata_istanbul,
        },
        interpreter::EthInterpreter,
    },
};
use tempo_contracts::precompiles::{
    IAccountKeychain::SignatureType as PrecompileSignatureType, TIPFeeAMMError,
};
use tempo_precompiles::{
    account_keychain::{AccountKeychain, TokenLimit, authorizeKeyCall},
    error::TempoPrecompileError,
    nonce::{EXPIRING_NONCE_MAX_EXPIRY_SECS, INonce::getNonceCall, NonceManager},
    storage::{PrecompileStorageProvider, StorageCtx, evm::EvmPrecompileStorageProvider},
    tip_fee_manager::TipFeeManager,
    tip20::{ITIP20::InsufficientBalance, TIP20Error, TIP20Token, is_tip20_prefix},
};
use tempo_primitives::transaction::{
    PrimitiveSignature, SignatureType, TEMPO_EXPIRING_NONCE_KEY, TempoSignature,
    calc_gas_balance_spending, validate_calls,
};

use crate::{
    TempoBatchCallEnv, TempoEvm, TempoInvalidTransaction, TempoTxEnv,
    common::TempoStateAccess,
    error::{FeePaymentError, TempoHaltReason},
    evm::TempoContext,
    gas_params::TempoGasParams,
};

/// Additional gas for P256 signature verification
/// P256 precompile cost (6900 from EIP-7951) + 1100 for 129 bytes extra signature size - ecrecover savings (3000)
const P256_VERIFY_GAS: u64 = 5_000;

/// Gas cost for ecrecover signature verification (used by KeyAuthorization)
const ECRECOVER_GAS: u64 = 3_000;

/// Additional gas for Keychain signatures (key validation overhead: COLD_SLOAD_COST + 900 processing)
const KEYCHAIN_VALIDATION_GAS: u64 = COLD_SLOAD_COST + 900;

/// Base gas for KeyAuthorization (22k storage + 5k buffer), signature gas added at runtime
const KEY_AUTH_BASE_GAS: u64 = 27_000;

/// Gas per spending limit in KeyAuthorization
const KEY_AUTH_PER_LIMIT_GAS: u64 = 22_000;

/// Gas cost for expiring nonce transactions (replay check + insert).
///
/// See TIP-1009 for full specification.
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
#[inline]
fn calculate_key_authorization_gas(
    key_auth: &tempo_primitives::transaction::SignedKeyAuthorization,
    gas_params: &GasParams,
    spec: tempo_chainspec::hardfork::TempoHardfork,
) -> u64 {
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
        const BUFFER: u64 = 2_000;
        let sstore_cost = gas_params.get(GasId::sstore_set_without_load_cost());
        let sload_cost =
            gas_params.warm_storage_read_cost() + gas_params.cold_storage_additional_cost();

        sig_gas + sload_cost + sstore_cost * (1 + num_limits) + BUFFER
    } else {
        // Pre-T1B: Original heuristic constants
        KEY_AUTH_BASE_GAS + sig_gas + num_limits * KEY_AUTH_PER_LIMIT_GAS
    }
}

/// Computes the adjusted initial gas for AA transaction execution.
///
/// For T1+: Uses `evm_initial_gas` which includes key_authorization gas tracking.
/// For pre-T1: Uses `init_and_floor_gas` directly to maintain backward compatibility,
/// since pre-T1 doesn't have key_authorization gas tracking and Genesis has special
/// handling where nonce_2d_gas is added to init_and_floor_gas but not to evm.initial_gas.
#[inline]
fn adjusted_initial_gas(
    spec: tempo_chainspec::hardfork::TempoHardfork,
    evm_initial_gas: u64,
    init_and_floor_gas: &InitialAndFloorGas,
) -> InitialAndFloorGas {
    if spec.is_t1() {
        InitialAndFloorGas::new(evm_initial_gas, init_and_floor_gas.floor_gas)
    } else {
        *init_and_floor_gas
    }
}

/// Tempo EVM [`Handler`] implementation with Tempo specific modifications:
///
/// Fees are paid in fee tokens instead of account balance.
#[derive(Debug)]
pub struct TempoEvmHandler<DB, I> {
    /// Fee token used for the transaction.
    fee_token: Address,
    /// Fee payer for the transaction.
    fee_payer: Address,
    /// Phantom data to avoid type inference issues.
    _phantom: core::marker::PhantomData<(DB, I)>,
}

impl<DB, I> TempoEvmHandler<DB, I> {
    /// Create a new [`TempoEvmHandler`] handler instance
    pub fn new() -> Self {
        Self {
            fee_token: Address::default(),
            fee_payer: Address::default(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<DB: alloy_evm::Database, I> TempoEvmHandler<DB, I> {
    /// Loads the fee token and fee payer from the transaction environment.
    ///
    /// Resolves and validates the fee fields used by Tempo's fee system:
    /// - Fee payer: determined from the transaction
    /// - Fee token: resolved via the journaled state and validated (TIP20 prefix + USD currency)
    ///
    /// Must be called before `validate_against_state_and_deduct_caller`, which uses the
    /// loaded fee fields for balance checks.
    ///
    /// Called by [`Handler::run`] and [`InspectorHandler::inspect_run`]. Exposed for consumers
    /// like `FoundryHandler` that override `inspect_run` but still need Tempo fee setup.
    pub fn load_fee_fields(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
    ) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
        let ctx = evm.ctx_mut();

        self.fee_payer = ctx.tx.fee_payer()?;
        self.fee_token = ctx
            .journaled_state
            .get_fee_token(&ctx.tx, self.fee_payer, ctx.cfg.spec)
            .map_err(|err| EVMError::Custom(err.to_string()))?;

        // Always validate TIP20 prefix to prevent panics in get_token_balance.
        // This is a protocol-level check since validators could bypass initial validation.
        if !is_tip20_prefix(self.fee_token) {
            return Err(TempoInvalidTransaction::InvalidFeeToken(self.fee_token).into());
        }

        // Skip USD currency check for cases when the transaction is free and is not a part of a subblock.
        // Since we already validated the TIP20 prefix above, we only need to check the USD currency.
        if (!ctx.tx.max_balance_spending()?.is_zero() || ctx.tx.is_subblock_transaction())
            && !ctx
                .journaled_state
                .is_tip20_usd(ctx.cfg.spec, self.fee_token)
                .map_err(|err| EVMError::Custom(err.to_string()))?
        {
            return Err(TempoInvalidTransaction::InvalidFeeToken(self.fee_token).into());
        }

        Ok(())
    }
}

impl<DB, I> TempoEvmHandler<DB, I>
where
    DB: alloy_evm::Database,
{
    /// Generic single-call execution that works with both standard and inspector exec loops.
    ///
    /// This is the core implementation that both `execute_single_call` and inspector-aware
    /// execution can use by providing the appropriate exec loop function.
    fn execute_single_call_with<F>(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
        mut run_loop: F,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        F: FnMut(
            &mut Self,
            &mut TempoEvm<DB, I>,
            <<TempoEvm<DB, I> as EvmTr>::Frame as FrameTr>::FrameInit,
        ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>,
    {
        let gas_limit = evm.ctx().tx().gas_limit() - init_and_floor_gas.initial_gas;

        // Create first frame action
        let first_frame_input = self.first_frame_input(evm, gas_limit)?;

        // Run execution loop (standard or inspector)
        let mut frame_result = run_loop(self, evm, first_frame_input)?;

        // Handle last frame result
        self.last_frame_result(evm, &mut frame_result)?;

        Ok(frame_result)
    }

    /// Executes a standard single-call transaction using the default handler logic.
    ///
    /// This calls the same helper methods used by the default [`Handler::execution`] implementation.
    fn execute_single_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>> {
        self.execute_single_call_with(evm, init_and_floor_gas, Self::run_exec_loop)
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
    fn execute_multi_call_with<F>(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
        calls: Vec<tempo_primitives::transaction::Call>,
        mut execute_single: F,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        F: FnMut(
            &mut Self,
            &mut TempoEvm<DB, I>,
            &InitialAndFloorGas,
        ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>,
    {
        // Create checkpoint for atomic execution - captures state before any calls
        let checkpoint = evm.ctx().journal_mut().checkpoint();

        let gas_limit = evm.ctx().tx().gas_limit();
        let mut remaining_gas = gas_limit - init_and_floor_gas.initial_gas;
        let mut accumulated_gas_refund = 0i64;

        // Store original TxEnv values to restore after batch execution
        let original_kind = evm.ctx().tx().kind();
        let original_value = evm.ctx().tx().value();
        let original_data = evm.ctx().tx().input().clone();

        let mut final_result = None;

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
            let zero_init_gas = InitialAndFloorGas::new(0, 0);
            let frame_result = execute_single(self, evm, &zero_init_gas);

            // Restore original TxEnv immediately after execution, even if execution failed
            {
                let tx = &mut evm.ctx().tx;
                tx.inner.kind = original_kind;
                tx.inner.value = original_value;
                tx.inner.data = original_data.clone();
                tx.inner.gas_limit = gas_limit;
            }

            let mut frame_result = frame_result?;

            // Check if call succeeded
            let instruction_result = frame_result.instruction_result();
            if !instruction_result.is_ok() {
                // Revert checkpoint - rolls back ALL state changes from ALL calls
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

                // Include gas from all previous successful calls + failed call
                let gas_spent_by_failed_call = frame_result.gas().spent();
                let total_gas_spent = (gas_limit - remaining_gas) + gas_spent_by_failed_call;

                // Create new Gas with correct limit, because Gas does not have a set_limit method
                // (the frame_result has the limit from just the last call)
                let mut corrected_gas = Gas::new(gas_limit);
                if instruction_result.is_revert() {
                    corrected_gas.set_spent(total_gas_spent);
                } else {
                    corrected_gas.spend_all();
                }
                corrected_gas.set_refund(0); // No refunds when batch fails and all state is reverted
                *frame_result.gas_mut() = corrected_gas;

                return Ok(frame_result);
            }

            // Call succeeded - accumulate gas usage and refunds
            let gas_spent = frame_result.gas().spent();
            let gas_refunded = frame_result.gas().refunded();

            accumulated_gas_refund = accumulated_gas_refund.saturating_add(gas_refunded);
            // Subtract only execution gas (intrinsic gas already deducted upfront)
            remaining_gas = remaining_gas.saturating_sub(gas_spent);

            final_result = Some(frame_result);
        }

        // All calls succeeded - commit checkpoint to finalize ALL state changes
        evm.ctx().journal_mut().checkpoint_commit();

        // Fix gas accounting for the entire batch
        let mut result =
            final_result.ok_or_else(|| EVMError::Custom("No calls executed".into()))?;

        let total_gas_spent = gas_limit - remaining_gas;

        // Create new Gas with correct limit, because Gas does not have a set_limit method
        // (the frame_result has the limit from just the last call)
        let mut corrected_gas = Gas::new(gas_limit);
        corrected_gas.set_spent(total_gas_spent);
        corrected_gas.set_refund(accumulated_gas_refund);
        *result.gas_mut() = corrected_gas;

        Ok(result)
    }

    /// Executes a multi-call AA transaction atomically.
    fn execute_multi_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
        calls: Vec<tempo_primitives::transaction::Call>,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>> {
        self.execute_multi_call_with(evm, init_and_floor_gas, calls, Self::execute_single_call)
    }

    /// Executes a standard single-call transaction with inspector support.
    ///
    /// This is the inspector-aware version of execute_single_call that uses
    /// inspect_run_exec_loop instead of run_exec_loop.
    fn inspect_execute_single_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        I: Inspector<TempoContext<DB>, EthInterpreter>,
    {
        self.execute_single_call_with(evm, init_and_floor_gas, Self::inspect_run_exec_loop)
    }

    /// Executes a multi-call AA transaction atomically with inspector support.
    ///
    /// This is the inspector-aware version of execute_multi_call that uses
    /// inspect_execute_single_call instead of execute_single_call.
    fn inspect_execute_multi_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
        calls: Vec<tempo_primitives::transaction::Call>,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        I: Inspector<TempoContext<DB>, EthInterpreter>,
    {
        self.execute_multi_call_with(
            evm,
            init_and_floor_gas,
            calls,
            Self::inspect_execute_single_call,
        )
    }

    /// Inspector-aware execution with a custom exec loop for standard (non-AA) transactions.
    ///
    /// Dispatches based on transaction type:
    /// - AA transactions (type 0x76): Use batch execution path with calls field
    /// - All other transactions: Use standard single-call execution
    ///
    /// This mirrors the logic in [`Handler::execution`] but uses inspector-aware execution methods.
    ///
    /// Additionally, delegates the standard single-call execution to the `exec_loop` closure.
    /// This allows downstream consumers like the `FoundryHandler` to inject custom execution
    /// loop logic (such as CREATE2 factory routing) while preserving all Tempo-specific
    /// behavior as a single source of truth.
    pub fn inspect_execution_with<F>(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
        mut exec_loop: F,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        F: FnMut(
            &mut Self,
            &mut TempoEvm<DB, I>,
            <<TempoEvm<DB, I> as EvmTr>::Frame as FrameTr>::FrameInit,
        ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>,
        I: Inspector<TempoContext<DB>, EthInterpreter>,
    {
        let spec = *evm.ctx_ref().cfg().spec();
        let adjusted_gas = adjusted_initial_gas(spec, evm.initial_gas, init_and_floor_gas);

        let tx = evm.tx();

        if let Some(oog) = check_gas_limit(spec, tx, &adjusted_gas) {
            return Ok(oog);
        }

        if let Some(tempo_tx_env) = tx.tempo_tx_env.as_ref() {
            let calls = tempo_tx_env.aa_calls.clone();
            return self.inspect_execute_multi_call(evm, &adjusted_gas, calls);
        }

        self.execute_single_call_with(evm, &adjusted_gas, &mut exec_loop)
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

    #[inline]
    fn run(
        &mut self,
        evm: &mut Self::Evm,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        self.load_fee_fields(evm)?;

        // Standard handler flow - execution() handles single vs multi-call dispatch
        match self.run_without_catch_error(evm) {
            Ok(output) => Ok(output),
            Err(err) => self.catch_error(evm, err),
        }
    }

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
        let adjusted_gas = adjusted_initial_gas(*spec, evm.initial_gas, init_and_floor_gas);
        let tx = evm.tx();

        if let Some(oog) = check_gas_limit(*spec, tx, &adjusted_gas) {
            return Ok(oog);
        }

        if let Some(tempo_tx_env) = tx.tempo_tx_env.as_ref() {
            let calls = tempo_tx_env.aa_calls.clone();
            self.execute_multi_call(evm, &adjusted_gas, calls)
        } else {
            self.execute_single_call(evm, &adjusted_gas)
        }
    }

    /// Take logs from the Journal if outcome is Halt Or Revert.
    #[inline]
    fn execution_result(
        &mut self,
        evm: &mut Self::Evm,
        result: <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        evm.logs.clear();
        // reset initial gas to 0 to avoid gas limit check errors
        evm.initial_gas = 0;
        if !result.instruction_result().is_ok() {
            evm.logs = evm.journal_mut().take_logs();
        }

        MainnetHandler::default()
            .execution_result(evm, result)
            .map(|result| result.map_haltreason(Into::into))
    }

    /// Override apply_eip7702_auth_list to support AA transactions with authorization lists.
    ///
    /// The default implementation only processes authorization lists for TransactionType::Eip7702 (0x04).
    /// This override extends support to AA transactions (type 0x76) by checking for the presence
    /// of an aa_authorization_list in the tempo_tx_env.
    #[inline]
    fn apply_eip7702_auth_list(&self, evm: &mut Self::Evm) -> Result<u64, Self::Error> {
        let ctx = evm.ctx();
        let spec = *ctx.cfg().spec();

        // Check if this is an AA transaction with an authorization list
        let has_aa_auth_list = ctx
            .tx()
            .tempo_tx_env
            .as_ref()
            .map(|aa_env| !aa_env.tempo_authorization_list.is_empty())
            .unwrap_or(false);

        // If it's an AA transaction with authorization list, we need to apply it manually
        // since the default implementation only checks for TransactionType::Eip7702
        let refunded_gas = if has_aa_auth_list {
            let chain_id = ctx.cfg().chain_id();

            let (tx, journal) = evm.ctx().tx_journal_mut();

            let tempo_tx_env = tx.tempo_tx_env.as_ref().unwrap();

            apply_auth_list::<_, Self::Error>(
                chain_id,
                tempo_tx_env
                    .tempo_authorization_list
                    .iter()
                    // T0 hardfork: skip keychain signatures in auth list processing
                    .filter(|auth| !(spec.is_t0() && auth.signature().is_keychain())),
                journal,
            )?
        } else {
            // For standard EIP-7702 transactions, use the default implementation
            pre_execution::apply_eip7702_auth_list::<_, Self::Error>(evm.ctx())?
        };

        // TIP-1000: State Creation Cost Increase
        // Authorization lists: There is no refund if the account already exists
        if spec.is_t1() {
            return Ok(0);
        }

        Ok(refunded_gas)
    }

    #[inline]
    fn validate_against_state_and_deduct_caller(
        &self,
        evm: &mut Self::Evm,
    ) -> Result<(), Self::Error> {
        let block = &evm.inner.ctx.block;
        let tx = &evm.inner.ctx.tx;
        let cfg = &evm.inner.ctx.cfg;
        let journal = &mut evm.inner.ctx.journaled_state;

        // Set tx.origin in the keychain's transient storage for spending limit checks.
        // This must be done for ALL transactions so precompiles can access it.
        StorageCtx::enter_evm(journal, block, cfg, tx, || {
            let mut keychain = AccountKeychain::new();
            keychain.set_tx_origin(tx.caller())
        })
        .map_err(|e| EVMError::Custom(e.to_string()))?;

        // TIP-1007: Set the fee token in transient storage so contracts can read it
        // via `IFeeManager.getFeeToken()` during execution.
        if cfg.spec().is_t2() {
            let fee_token = self.fee_token;
            StorageCtx::enter_evm(journal, block, cfg, tx, || {
                TipFeeManager::new().set_fee_token(fee_token)
            })
            .map_err(|e| EVMError::Custom(e.to_string()))?;
        }

        // Validate fee token has TIP20 prefix before loading balance.
        // This prevents panics in get_token_balance for invalid fee tokens.
        // Note: Full fee token validation (currency check) happens in load_fee_fields,
        // but is skipped for free non-subblock transactions. This prefix check ensures
        // we don't panic even for those cases.
        if !is_tip20_prefix(self.fee_token) {
            return Err(TempoInvalidTransaction::InvalidFeeToken(self.fee_token).into());
        }

        // Load the fee payer balance
        let account_balance = get_token_balance(journal, self.fee_token, self.fee_payer)?;

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
        if !nonce_key.is_zero() && tx.kind().is_create() && caller_account.nonce() == 0 {
            evm.initial_gas += cfg.gas_params().get(GasId::new_account_cost());

            // do the gas limit check again.
            if tx.gas_limit() < evm.initial_gas {
                return Err(TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
                    gas_limit: tx.gas_limit(),
                    intrinsic_gas: evm.initial_gas,
                }
                .into());
            }
        }

        if is_expiring_nonce {
            // Expiring nonce transaction replay protection:
            // - Pre-T1B: use tx_hash for backwards-compatible behavior.
            // - T1B+: use expiring_nonce_hash (keccak256(encode_for_signing || sender))
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
                tempo_tx_env
                    .expiring_nonce_hash
                    .ok_or(TempoInvalidTransaction::ExpiringNonceMissingTxEnv)?
            } else {
                tempo_tx_env.tx_hash
            };
            let valid_before = tempo_tx_env
                .valid_before
                .ok_or(TempoInvalidTransaction::ExpiringNonceMissingValidBefore)?;

            let block_timestamp = block.timestamp().saturating_to::<u64>();
            StorageCtx::enter_evm(journal, block, cfg, tx, || {
                let mut nonce_manager = NonceManager::new();

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

                Ok::<_, EVMError<DB::Error, TempoInvalidTransaction>>(())
            })?;
        } else if !nonce_key.is_zero() {
            // 2D nonce transaction
            StorageCtx::enter_evm(journal, block, cfg, tx, || {
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
                            err => {
                                TempoInvalidTransaction::NonceManagerError(err.to_string()).into()
                            }
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
                        err => TempoInvalidTransaction::NonceManagerError(err.to_string()).into(),
                    })?;

                Ok::<_, EVMError<DB::Error, TempoInvalidTransaction>>(())
            })?;
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

        // If the transaction includes a KeyAuthorization, validate and authorize the key
        if let Some(tempo_tx_env) = tx.tempo_tx_env.as_ref()
            && let Some(key_auth) = &tempo_tx_env.key_authorization
        {
            // Check if this TX is using a Keychain signature (access key)
            // Access keys cannot authorize new keys UNLESS it's the same key being authorized (same-tx auth+use)
            if let Some(keychain_sig) = tempo_tx_env.signature.as_keychain() {
                // Use override_key_id if provided (for gas estimation), otherwise recover from signature
                let access_key_addr = if let Some(override_key_id) = tempo_tx_env.override_key_id {
                    override_key_id
                } else {
                    // Get the access key address (recovered during Tx->TxEnv conversion and cached)
                    keychain_sig
                        .key_id(&tempo_tx_env.signature_hash)
                        .map_err(|_| TempoInvalidTransaction::AccessKeyRecoveryFailed)?
                };

                // Only allow if authorizing the same key that's being used (same-tx auth+use)
                if access_key_addr != key_auth.key_id {
                    return Err(TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys.into());
                }
            }

            // Validate that the KeyAuthorization is signed by the root account
            let root_account = &tx.caller;

            // Recover the signer of the KeyAuthorization
            let auth_signer = key_auth
                .recover_signer()
                .map_err(|_| TempoInvalidTransaction::KeyAuthorizationSignatureRecoveryFailed)?;

            // Verify the KeyAuthorization is signed by the root account
            if auth_signer != *root_account {
                return Err(TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot {
                    expected: *root_account,
                    actual: auth_signer,
                }
                .into());
            }

            // Validate KeyAuthorization chain_id (following EIP-7702 pattern)
            // chain_id == 0 allows replay on any chain (wildcard)
            let expected_chain_id = cfg.chain_id();
            if key_auth.chain_id != 0 && key_auth.chain_id != expected_chain_id {
                return Err(TempoInvalidTransaction::KeyAuthorizationChainIdMismatch {
                    expected: expected_chain_id,
                    got: key_auth.chain_id,
                }
                .into());
            }

            let keychain_checkpoint = if spec.is_t1() {
                Some(journal.checkpoint())
            } else {
                None
            };

            let internals = EvmInternals::new(journal, block, cfg, tx);

            // T1/T1A: Apply gas metering for the keychain precompile call.
            // Pre-T1 and T1B+: Use unlimited gas.
            // T1B+ disables gas metering here because gas is already accounted for
            // in intrinsic gas via `calculate_key_authorization_gas`. Running with
            // unlimited gas also eliminates the OOG path that caused the CREATE
            // nonce replay vulnerability (protocol nonce not bumped on OOG).
            let gas_limit = if spec.is_t1() && !spec.is_t1b() {
                tx.gas_limit() - evm.initial_gas
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

            let mut provider = EvmPrecompileStorageProvider::new(
                internals, gas_limit, cfg.spec, false, gas_params,
            );

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
                let expiry = key_auth.expiry.unwrap_or(u64::MAX);

                // Validate expiry is not in the past
                let current_timestamp = block.timestamp().saturating_to::<u64>();
                if expiry <= current_timestamp {
                    return Err(TempoInvalidTransaction::AccessKeyExpiryInPast {
                        expiry,
                        current_timestamp,
                    }
                    .into());
                }

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
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Create the authorize key call
                let authorize_call = authorizeKeyCall {
                    keyId: access_key_addr,
                    signatureType: signature_type,
                    expiry,
                    enforceLimits: enforce_limits,
                    limits: precompile_limits,
                };

                // Call precompile to authorize the key (same phase as nonce increment)
                match keychain.authorize_key(*root_account, authorize_call) {
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

            // activated only on T1/T1A fork.
            // T1B+: Skip adding precompile gas to initial_gas since it is already
            // accounted for in intrinsic gas. The precompile runs with unlimited gas
            // on T1B+ so out_of_gas is never true.
            if let Some(keychain_checkpoint) = keychain_checkpoint {
                if spec.is_t1b() {
                    journal.checkpoint_commit();
                } else if out_of_gas {
                    evm.initial_gas = u64::MAX;
                    journal.checkpoint_revert(keychain_checkpoint);
                } else {
                    evm.initial_gas += gas_used;
                    journal.checkpoint_commit();
                };
            }
        }

        // For Keychain signatures, validate that the keychain is authorized in the precompile
        // UNLESS this transaction also includes a KeyAuthorization (same-tx auth+use case)
        if let Some(tempo_tx_env) = tx.tempo_tx_env.as_ref()
            && let Some(keychain_sig) = tempo_tx_env.signature.as_keychain()
        {
            // Use override_key_id if provided (for gas estimation), otherwise recover from signature
            let access_key_addr = if let Some(override_key_id) = tempo_tx_env.override_key_id {
                override_key_id
            } else {
                // The user_address is the root account this transaction is being executed for
                // This should match tx.caller (which comes from recover_signer on the outer signature)
                let user_address = &keychain_sig.user_address;

                // Sanity check: user_address should match tx.caller
                if *user_address != tx.caller {
                    return Err(TempoInvalidTransaction::KeychainUserAddressMismatch {
                        user_address: *user_address,
                        caller: tx.caller,
                    }
                    .into());
                }

                // Get the access key address (recovered during pool validation and cached)
                keychain_sig
                    .key_id(&tempo_tx_env.signature_hash)
                    .map_err(|_| TempoInvalidTransaction::AccessKeyRecoveryFailed)?
            };

            // Check if this transaction includes a KeyAuthorization for the same key
            // If so, skip keychain validation here - the key was just validated and authorized
            let is_authorizing_this_key = tempo_tx_env
                .key_authorization
                .as_ref()
                .map(|key_auth| key_auth.key_id == access_key_addr)
                .unwrap_or(false);

            // Always need to set the transaction key for Keychain signatures
            StorageCtx::enter_precompile(
                journal,
                block,
                cfg,
                tx,
                |mut keychain: AccountKeychain| {
                    // Skip keychain validation when authorizing this key in the same tx
                    if !is_authorizing_this_key {
                        // Validate that user_address has authorized this access key in the keychain
                        let user_address = &keychain_sig.user_address;

                        // Extract the signature type from the inner signature to validate it matches
                        // the key_type stored in the keychain. This prevents using a signature of one
                        // type to authenticate as a key registered with a different type.
                        // Only validate signature type on T1+ to maintain backward compatibility
                        // with historical blocks during re-execution.
                        let sig_type = spec
                            .is_t1()
                            .then_some(keychain_sig.signature.signature_type().into());

                        keychain
                            .validate_keychain_authorization(
                                *user_address,
                                access_key_addr,
                                block.timestamp().to::<u64>(),
                                sig_type,
                            )
                            .map_err(|e| TempoInvalidTransaction::KeychainValidationFailed {
                                reason: format!("{e:?}"),
                            })?;
                    }

                    // Set the transaction key in the keychain precompile
                    // This marks that the current transaction is using an access key
                    // The TIP20 precompile will read this during execution to enforce spending limits
                    keychain
                        .set_transaction_key(access_key_addr)
                        .map_err(|e| EVMError::Custom(e.to_string()))
                },
            )?;
        }

        // Short-circuit if there is no spending for this transaction and `collectFeePreTx`
        // call will not collect any fees.
        if gas_balance_spending.is_zero() {
            return Ok(());
        }

        let checkpoint = journal.checkpoint();

        let result = StorageCtx::enter_evm(journal, &block, cfg, tx, || {
            TipFeeManager::new().collect_fee_pre_tx(
                self.fee_payer,
                self.fee_token,
                gas_balance_spending,
                block.beneficiary(),
            )
        });

        if let Err(err) = result {
            // Revert the journal to checkpoint before `collectFeePreTx` call if something went wrong.
            journal.checkpoint_revert(checkpoint);

            // Map fee collection errors to transaction validation errors since they
            // indicate the transaction cannot be included (e.g., insufficient liquidity
            // in FeeAMM pool for fee swaps)
            Err(match err {
                TempoPrecompileError::TIPFeeAMMError(TIPFeeAMMError::InsufficientLiquidity(_)) => {
                    FeePaymentError::InsufficientAmmLiquidity {
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

                TempoPrecompileError::Fatal(e) => EVMError::Custom(e),

                _ => FeePaymentError::Other(err.to_string()).into(),
            })
        } else {
            journal.checkpoint_commit();
            evm.collected_fee = gas_balance_spending;

            Ok(())
        }
    }

    fn reimburse_caller(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        // Call collectFeePostTx on TipFeeManager precompile
        let context = &mut evm.inner.ctx;
        let tx = context.tx();
        let basefee = context.block().basefee() as u128;
        let effective_gas_price = tx.effective_gas_price(basefee);
        let gas = exec_result.gas();

        let actual_spending = calc_gas_balance_spending(gas.used(), effective_gas_price);
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

        // Create storage provider and fee manager
        let (journal, block, tx) = (&mut context.journaled_state, &context.block, &context.tx);
        let beneficiary = context.block.beneficiary();

        StorageCtx::enter_evm(&mut *journal, block, &context.cfg, tx, || {
            let mut fee_manager = TipFeeManager::new();

            if !actual_spending.is_zero() || !refund_amount.is_zero() {
                // Call collectFeePostTx (handles both refund and fee queuing)
                fee_manager
                    .collect_fee_post_tx(
                        self.fee_payer,
                        actual_spending,
                        refund_amount,
                        self.fee_token,
                        beneficiary,
                    )
                    .map_err(|e| EVMError::Custom(format!("{e:?}")))?;
            }

            Ok(())
        })
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
        // All accounts have zero balance so transfer of value is not possible.
        // Check added in https://github.com/tempoxyz/tempo/pull/759
        if !evm.ctx.tx.value().is_zero() {
            return Err(TempoInvalidTransaction::ValueTransferNotAllowed.into());
        }

        // First perform standard validation (header + transaction environment)
        // This validates: prevrandao, excess_blob_gas, chain_id, gas limits, tx type support, etc.
        validation::validate_env::<_, Self::Error>(evm.ctx())?;

        // AA-specific validations
        let cfg = evm.ctx_ref().cfg();
        let tx = evm.ctx_ref().tx();

        if let Some(aa_env) = tx.tempo_tx_env.as_ref() {
            // Validate AA transaction structure (calls list, CREATE rules)
            validate_calls(
                &aa_env.aa_calls,
                !aa_env.tempo_authorization_list.is_empty(),
            )
            .map_err(TempoInvalidTransaction::from)?;

            let has_keychain_fields =
                aa_env.key_authorization.is_some() || aa_env.signature.is_keychain();

            if aa_env.subblock_transaction && has_keychain_fields {
                return Err(TempoInvalidTransaction::KeychainOpInSubblockTransaction.into());
            }

            // Validate priority fee for AA transactions using revm's validate_priority_fee_tx
            let base_fee = if cfg.is_base_fee_check_disabled() {
                None
            } else {
                Some(evm.ctx_ref().block().basefee() as u128)
            };

            validation::validate_priority_fee_tx(
                tx.max_fee_per_gas(),
                tx.max_priority_fee_per_gas().unwrap_or_default(),
                base_fee,
                cfg.is_priority_fee_check_disabled(),
            )?;

            // Validate time window for AA transactions
            let block_timestamp = evm.ctx_ref().block().timestamp().saturating_to();
            validate_time_window(aa_env.valid_after, aa_env.valid_before, block_timestamp)?;
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
        let init_gas = if tx.tempo_tx_env.is_some() {
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
                if auth.nonce == 0 {
                    init_gas.initial_gas += gas_params.tx_tip1000_auth_account_creation_cost();
                }
            }

            // TIP-1000: Storage pricing updates for launch
            // Transactions with any `nonce_key` and `nonce == 0` require an additional 250,000 gas.
            if spec.is_t1() && tx.nonce == 0 {
                init_gas.initial_gas += gas_params.get(GasId::new_account_cost());
            }

            if evm.ctx.cfg.is_eip7623_disabled() {
                init_gas.floor_gas = 0u64;
            }

            // Validate gas limit is sufficient for initial gas
            if gas_limit < init_gas.initial_gas {
                return Err(TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
                    gas_limit,
                    intrinsic_gas: init_gas.initial_gas,
                }
                .into());
            }

            // Validate floor gas (Prague+)
            if !evm.ctx.cfg.is_eip7623_disabled() && gas_limit < init_gas.floor_gas {
                return Err(TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
                    gas_limit,
                    intrinsic_gas: init_gas.floor_gas,
                }
                .into());
            }

            init_gas
        };

        // used to calculate key_authorization gas spending limit.
        evm.initial_gas = init_gas.initial_gas;

        Ok(init_gas)
    }

    fn catch_error(
        &self,
        evm: &mut Self::Evm,
        error: Self::Error,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        // reset initial gas to 0 to avoid gas limit check errors
        evm.initial_gas = 0;

        // For subblock transactions that failed `collectFeePreTx` call we catch error and treat such transactions as valid.
        if evm.ctx.tx.is_subblock_transaction()
            && let Some(
                TempoInvalidTransaction::CollectFeePreTx(_)
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

            Ok(ExecutionResult::Halt {
                reason: TempoHaltReason::SubblockTxFeePayment,
                gas_used: 0,
            })
        } else {
            MainnetHandler::default()
                .catch_error(evm, error)
                .map(|result| result.map_haltreason(Into::into))
        }
    }
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
    gas.initial_gas += gas_params.tx_base_stipend();

    // 2. Signature verification gas
    gas.initial_gas += tempo_signature_verification_gas(signature);

    let cold_account_cost =
        gas_params.warm_storage_read_cost() + gas_params.cold_account_additional_cost();

    // 3. Per-call overhead: cold account access
    // if the `to` address has not appeared in the call batch before.
    gas.initial_gas += cold_account_cost * calls.len().saturating_sub(1) as u64;

    // 4. Authorization list costs (EIP-7702)
    gas.initial_gas +=
        authorization_list.len() as u64 * gas_params.tx_eip7702_per_empty_account_cost();

    // Add signature verification costs for each authorization
    // No need for v1 fork check as gas_params would be zero
    for auth in authorization_list {
        gas.initial_gas += tempo_signature_verification_gas(auth.signature());
        // TIP-1000: Storage pricing updates for launch
        // EIP-7702 authorisation list entries with `auth_list.nonce == 0` require an additional 250,000 gas.
        if auth.nonce == 0 {
            gas.initial_gas += gas_params.tx_tip1000_auth_account_creation_cost();
        }
    }

    // 5. Key authorization costs (if present)
    if let Some(key_auth) = key_authorization {
        gas.initial_gas += calculate_key_authorization_gas(key_auth, gas_params, spec);
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
            gas.initial_gas += gas_params.create_cost();

            // EIP-3860: Initcode analysis gas using revm helper
            gas.initial_gas += gas_params.tx_initcode_cost(call.input.len());
        }

        // Note: Transaction value is not allowed in AA transactions as there is no balances in accounts yet.
        // Check added in https://github.com/tempoxyz/tempo/pull/759
        if !call.value.is_zero() {
            return Err(TempoInvalidTransaction::ValueTransferNotAllowedInAATx);
        }

        // 4c. Value transfer cost using revm constant
        // left here for future reference.
        if !call.value.is_zero() && call.to.is_call() {
            gas.initial_gas += gas_params.get(GasId::transfer_value_cost()); // 9000 gas
        }
    }

    gas.initial_gas += total_tokens * gas_params.tx_token_cost();

    // 5. Access list costs using revm constants
    if let Some(access_list) = access_list {
        let (accounts, storages) = access_list.fold((0, 0), |(acc_count, storage_count), item| {
            (acc_count + 1, storage_count + item.storage_slots().count())
        });
        gas.initial_gas += accounts * gas_params.tx_access_list_address_cost(); // 2400 per account
        gas.initial_gas += storages as u64 * gas_params.tx_access_list_storage_key_cost(); // 1900 per storage
    }

    // 6. Floor gas using revm helper
    gas.floor_gas = gas_params.tx_floor_cost(total_tokens); // tokens * 10 + 21000

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
            batch_gas.initial_gas += EXPIRING_NONCE_GAS;
        } else if tx.nonce == 0 {
            // TIP-1000: Storage pricing updates for launch
            // Tempo transactions with any `nonce_key` and `nonce == 0` require an additional 250,000 gas
            batch_gas.initial_gas += gas_params.get(GasId::new_account_cost());
        } else if !aa_env.nonce_key.is_zero() {
            // Existing 2D nonce key usage (nonce > 0)
            // TIP-1000 Invariant 3: existing state updates must charge +5,000 gas
            batch_gas.initial_gas += spec.gas_existing_nonce_key();
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

    if evm.ctx.cfg.is_eip7623_disabled() {
        batch_gas.floor_gas = 0u64;
    }

    // For T0+, include 2D nonce gas in validation (charged upfront)
    // For pre-T0 (Genesis), 2D nonce gas is added AFTER validation to allow transactions
    // with gas_limit < intrinsic + nonce_2d_gas to pass validation, but the gas is still
    // charged during execution via init_and_floor_gas (not evm.initial_gas)
    if spec.is_t0() {
        batch_gas.initial_gas += nonce_2d_gas;
    }

    // Validate gas limit is sufficient for initial gas
    if gas_limit < batch_gas.initial_gas {
        return Err(TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
            gas_limit,
            intrinsic_gas: batch_gas.initial_gas,
        }
        .into());
    }

    // For pre-T0 (Genesis), add 2D nonce gas after validation
    // This gas will be charged via init_and_floor_gas, not evm.initial_gas
    if !spec.is_t0() {
        batch_gas.initial_gas += nonce_2d_gas;
    }

    // Validate floor gas (Prague+)
    if !evm.ctx.cfg.is_eip7623_disabled() && gas_limit < batch_gas.floor_gas {
        return Err(TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
            gas_limit,
            intrinsic_gas: batch_gas.floor_gas,
        }
        .into());
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

    fn inspect_run(
        &mut self,
        evm: &mut Self::Evm,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        self.load_fee_fields(evm)?;

        match self.inspect_run_without_catch_error(evm) {
            Ok(output) => Ok(output),
            Err(e) => self.catch_error(evm, e),
        }
    }

    /// Overridden execution method with inspector support that handles AA vs standard transactions.
    ///
    /// Delegates to [`inspect_execution_with`](TempoEvmHandler::inspect_execution_with) with
    /// the default [`inspect_run_exec_loop`](Self::inspect_run_exec_loop).
    #[inline]
    fn inspect_execution(
        &mut self,
        evm: &mut Self::Evm,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<FrameResult, Self::Error> {
        self.inspect_execution_with(evm, init_and_floor_gas, Self::inspect_run_exec_loop)
    }
}

/// Helper function to create a frame result for an out of gas error.
///
/// Use native fn when new revm version is released.
#[inline]
fn oog_frame_result(kind: TxKind, gas_limit: u64) -> FrameResult {
    if kind.is_call() {
        FrameResult::new_call_oog(gas_limit, 0..0)
    } else {
        FrameResult::new_create_oog(gas_limit)
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
    if spec.is_t0() && tx.gas_limit() < adjusted_gas.initial_gas {
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
    // IMPORTANT: must be aligned with `fn has_expired_transactions` in `tempo-payload-builder`.
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
mod tests {
    use super::*;
    use crate::{TempoBlockEnv, TempoTxEnv, evm::TempoEvm, tx::TempoBatchCallEnv};
    use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
    use proptest::prelude::*;
    use revm::{
        Context, Journal, MainContext,
        context::CfgEnv,
        database::{CacheDB, EmptyDB},
        handler::Handler,
        interpreter::{gas::COLD_ACCOUNT_ACCESS_COST, instructions::utility::IntoU256},
        primitives::hardfork::SpecId,
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
    use tempo_precompiles::{PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
    use tempo_primitives::transaction::{
        Call, TempoSignature,
        tt_signature::{P256SignatureWithPreHash, WebAuthnSignature},
    };

    fn create_test_journal() -> Journal<CacheDB<EmptyDB>> {
        let db = CacheDB::new(EmptyDB::default());
        Journal::new(db)
    }

    #[test]
    fn test_invalid_fee_token_rejected() {
        // Test that an invalid fee token (non-TIP20 address) is rejected with InvalidFeeToken error
        // rather than panicking. This validates the check in load_fee_fields that guards against
        // invalid tokens reaching get_token_balance.
        let invalid_token = Address::random(); // Random address won't have TIP20 prefix
        assert!(
            !is_tip20_prefix(invalid_token),
            "Test requires a non-TIP20 address"
        );

        let mut handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::default();

        // Set up tx with the invalid token as fee_token
        let tx_env = TempoTxEnv {
            fee_token: Some(invalid_token),
            ..Default::default()
        };

        let mut evm: TempoEvm<CacheDB<EmptyDB>, ()> = TempoEvm::new(
            Context::mainnet()
                .with_db(CacheDB::new(EmptyDB::default()))
                .with_block(TempoBlockEnv::default())
                .with_cfg(Default::default())
                .with_tx(tx_env),
            (),
        );

        let result = handler.load_fee_fields(&mut evm);

        assert!(
            matches!(
                result,
                Err(EVMError::Transaction(TempoInvalidTransaction::InvalidFeeToken(addr))) if addr == invalid_token
            ),
            "Should reject invalid fee token with InvalidFeeToken error"
        );
    }

    #[test]
    fn test_get_token_balance() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        // Use PATH_USD_ADDRESS which has the TIP20 prefix
        let token = PATH_USD_ADDRESS;
        let account = Address::random();
        let expected_balance = U256::random();

        // Set up initial balance
        let balance_slot = TIP20Token::from_address(token)?.balances[account].slot();
        journal.load_account(token)?;
        journal
            .sstore(token, balance_slot, expected_balance)
            .unwrap();

        let balance = get_token_balance(&mut journal, token, account)?;
        assert_eq!(balance, expected_balance);

        Ok(())
    }

    #[test]
    fn test_get_fee_token() -> eyre::Result<()> {
        let journal = create_test_journal();
        let mut ctx: TempoContext<_> = Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::default()))
            .with_block(TempoBlockEnv::default())
            .with_cfg(Default::default())
            .with_tx(TempoTxEnv::default())
            .with_new_journal(journal);
        let user = Address::random();
        ctx.tx.inner.caller = user;
        let validator = Address::random();
        ctx.block.beneficiary = validator;
        let user_fee_token = Address::random();
        let validator_fee_token = Address::random();
        let tx_fee_token = Address::random();

        // Set validator token
        let validator_slot = TipFeeManager::new().validator_tokens[validator].slot();
        ctx.journaled_state.load_account(TIP_FEE_MANAGER_ADDRESS)?;
        ctx.journaled_state
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                validator_slot,
                validator_fee_token.into_u256(),
            )
            .unwrap();

        {
            let fee_token = ctx
                .journaled_state
                .get_fee_token(&ctx.tx, user, ctx.cfg.spec)?;
            assert_eq!(DEFAULT_FEE_TOKEN, fee_token);
        }

        // Set user token
        let user_slot = TipFeeManager::new().user_tokens[user].slot();
        ctx.journaled_state
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                user_slot,
                user_fee_token.into_u256(),
            )
            .unwrap();

        {
            let fee_token = ctx
                .journaled_state
                .get_fee_token(&ctx.tx, user, ctx.cfg.spec)?;
            assert_eq!(user_fee_token, fee_token);
        }

        // Set tx fee token
        ctx.tx.fee_token = Some(tx_fee_token);
        let fee_token = ctx
            .journaled_state
            .get_fee_token(&ctx.tx, user, ctx.cfg.spec)?;
        assert_eq!(tx_fee_token, fee_token);

        Ok(())
    }

    #[test]
    fn test_aa_gas_single_call_vs_normal_tx() {
        use crate::TempoBatchCallEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{Call, TempoSignature};
        let gas_params = GasParams::default();

        // Test that AA tx with secp256k1 and single call matches normal tx + per-call overhead
        let calldata = Bytes::from(vec![1, 2, 3, 4, 5]); // 5 non-zero bytes
        let to = Address::random();

        // Single call for AA
        let call = Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        let aa_env = TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )), // dummy secp256k1 sig
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        // Calculate AA gas
        let spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let aa_gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            &gas_params,
            None::<std::iter::Empty<&AccessListItem>>, // no access list
            spec,
        )
        .unwrap();

        // Calculate expected gas using revm's function for equivalent normal tx
        let normal_tx_gas = calculate_initial_tx_gas(
            spec.into(),
            &calldata,
            false, // not create
            0,     // no access list accounts
            0,     // no access list storage
            0,     // no authorization list
        );

        // AA with secp256k1 + single call should match normal tx exactly
        assert_eq!(aa_gas.initial_gas, normal_tx_gas.initial_gas);
    }

    #[test]
    fn test_aa_gas_multiple_calls_overhead() {
        use crate::TempoBatchCallEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{Call, TempoSignature};

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

        let aa_env = TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: calls,
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            &GasParams::default(),
            None::<std::iter::Empty<&AccessListItem>>,
            spec,
        )
        .unwrap();

        // Calculate base gas for a single normal tx
        let base_tx_gas = calculate_initial_tx_gas(spec.into(), &calldata, false, 0, 0, 0);

        // For 3 calls: base (21k) + 3*calldata + 2*per-call overhead (calls 2 and 3)
        // = 21k + 2*(calldata cost) + 2*COLD_ACCOUNT_ACCESS_COST
        let expected = base_tx_gas.initial_gas
            + 2 * (calldata.len() as u64 * 16)
            + 2 * COLD_ACCOUNT_ACCESS_COST;
        // Should charge per-call overhead for calls beyond the first
        assert_eq!(gas.initial_gas, expected,);
    }

    #[test]
    fn test_aa_gas_p256_signature() {
        use crate::TempoBatchCallEnv;
        use alloy_primitives::{B256, Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{
            Call, TempoSignature, tt_signature::P256SignatureWithPreHash,
        };

        let spec = SpecId::CANCUN;
        let calldata = Bytes::from(vec![1, 2]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        let aa_env = TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::P256(
                P256SignatureWithPreHash {
                    r: B256::ZERO,
                    s: B256::ZERO,
                    pub_key_x: B256::ZERO,
                    pub_key_y: B256::ZERO,
                    pre_hash: false,
                },
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            &GasParams::default(),
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        )
        .unwrap();

        // Calculate base gas for normal tx
        let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

        // Expected: normal tx + P256_VERIFY_GAS
        let expected = base_gas.initial_gas + P256_VERIFY_GAS;
        assert_eq!(gas.initial_gas, expected,);
    }

    #[test]
    fn test_aa_gas_create_call() {
        use crate::TempoBatchCallEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{Call, TempoSignature};

        let spec = SpecId::CANCUN; // Post-Shanghai
        let initcode = Bytes::from(vec![0x60, 0x80]); // 2 bytes

        let call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode.clone(),
        };

        let aa_env = TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            &GasParams::default(),
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        )
        .unwrap();

        // Calculate expected using revm's function for CREATE tx
        let base_gas = calculate_initial_tx_gas(
            spec, &initcode, true, // is_create = true
            0, 0, 0,
        );

        // AA CREATE should match normal CREATE exactly
        assert_eq!(gas.initial_gas, base_gas.initial_gas,);
    }

    #[test]
    fn test_aa_gas_value_transfer() {
        use crate::TempoBatchCallEnv;
        use alloy_primitives::{Bytes, TxKind};
        use tempo_primitives::transaction::{Call, TempoSignature};

        let calldata = Bytes::from(vec![1]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::from(1000), // Non-zero value
            input: calldata,
        };

        let aa_env = TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let res = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            &GasParams::default(),
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        );

        assert_eq!(
            res.unwrap_err(),
            TempoInvalidTransaction::ValueTransferNotAllowedInAATx
        );
    }

    #[test]
    fn test_aa_gas_access_list() {
        use crate::TempoBatchCallEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{Call, TempoSignature};

        let spec = SpecId::CANCUN;
        let calldata = Bytes::from(vec![]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        let aa_env = TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        // Test without access list
        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            &GasParams::default(),
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        )
        .unwrap();

        // Calculate expected using revm's function
        let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

        // Expected: normal tx
        assert_eq!(gas.initial_gas, base_gas.initial_gas,);
    }

    #[test]
    fn test_key_authorization_rlp_encoding() {
        use alloy_primitives::{Address, U256};
        use tempo_primitives::transaction::{
            SignatureType, TokenLimit, key_authorization::KeyAuthorization,
        };

        // Create test data
        let chain_id = 1u64;
        let key_type = SignatureType::Secp256k1;
        let key_id = Address::random();
        let expiry = 1000u64;
        let limits = vec![
            TokenLimit {
                token: Address::random(),
                limit: U256::from(100),
            },
            TokenLimit {
                token: Address::random(),
                limit: U256::from(200),
            },
        ];

        // Compute hash using the helper function
        let hash1 = KeyAuthorization {
            chain_id,
            key_type,
            key_id,
            expiry: Some(expiry),
            limits: Some(limits.clone()),
        }
        .signature_hash();

        // Compute again to verify consistency
        let hash2 = KeyAuthorization {
            chain_id,
            key_type,
            key_id,
            expiry: Some(expiry),
            limits: Some(limits.clone()),
        }
        .signature_hash();

        assert_eq!(hash1, hash2, "Hash computation should be deterministic");

        // Verify that different chain_id produces different hash
        let hash3 = KeyAuthorization {
            chain_id: 2,
            key_type,
            key_id,
            expiry: Some(expiry),
            limits: Some(limits),
        }
        .signature_hash();
        assert_ne!(
            hash1, hash3,
            "Different chain_id should produce different hash"
        );
    }

    #[test]
    fn test_aa_gas_floor_gas_prague() {
        use crate::TempoBatchCallEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{Call, TempoSignature};

        let spec = SpecId::PRAGUE;
        let calldata = Bytes::from(vec![1, 2, 3, 4, 5]); // 5 non-zero bytes

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        let aa_env = TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            &GasParams::default(),
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        )
        .unwrap();

        // Calculate expected floor gas using revm's function
        let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

        // Floor gas should match revm's calculation for same calldata
        assert_eq!(
            gas.floor_gas, base_gas.floor_gas,
            "Should calculate floor gas for Prague matching revm"
        );
    }

    /// This test will start failing once we get the balance transfer enabled
    /// PR that introduced [`TempoInvalidTransaction::ValueTransferNotAllowed`] https://github.com/tempoxyz/tempo/pull/759
    #[test]
    fn test_zero_value_transfer() -> eyre::Result<()> {
        use crate::TempoEvm;

        // Create a test context with a transaction that has a non-zero value
        let ctx = Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::default()))
            .with_block(Default::default())
            .with_cfg(Default::default())
            .with_tx(TempoTxEnv::default());
        let mut evm = TempoEvm::new(ctx, ());

        // Set a non-zero value on the transaction
        evm.ctx.tx.inner.value = U256::from(1000);

        // Create the handler
        let handler = TempoEvmHandler::<_, ()>::new();

        // Call validate_env and expect it to fail with ValueTransferNotAllowed
        let result = handler.validate_env(&mut evm);

        if let Err(EVMError::Transaction(err)) = result {
            assert_eq!(err, TempoInvalidTransaction::ValueTransferNotAllowed);
        } else {
            panic!("Expected ValueTransferNotAllowed error");
        }

        Ok(())
    }

    #[test]
    fn test_key_authorization_gas_with_limits() {
        use tempo_primitives::transaction::{
            KeyAuthorization, SignatureType, SignedKeyAuthorization, TokenLimit,
        };

        // Helper to create key auth with N limits
        let create_key_auth = |num_limits: usize| -> SignedKeyAuthorization {
            let limits = if num_limits == 0 {
                None
            } else {
                Some(
                    (0..num_limits)
                        .map(|_| TokenLimit {
                            token: Address::random(),
                            limit: U256::from(1000),
                        })
                        .collect(),
                )
            };

            SignedKeyAuthorization {
                authorization: KeyAuthorization {
                    chain_id: 1,
                    key_type: SignatureType::Secp256k1,
                    key_id: Address::random(),
                    expiry: None,
                    limits,
                },
                signature: PrimitiveSignature::Secp256k1(
                    alloy_primitives::Signature::test_signature(),
                ),
            }
        };

        // Test 0 limits: base (27k) + ecrecover (3k) = 30,000
        let gas_0 = calculate_key_authorization_gas(
            &create_key_auth(0),
            &GasParams::default(),
            tempo_chainspec::hardfork::TempoHardfork::default(),
        );
        assert_eq!(
            gas_0,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS,
            "0 limits should be 30,000"
        );

        // Test 1 limit: 30,000 + 22,000 = 52,000
        let gas_1 = calculate_key_authorization_gas(
            &create_key_auth(1),
            &GasParams::default(),
            tempo_chainspec::hardfork::TempoHardfork::default(),
        );
        assert_eq!(
            gas_1,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + KEY_AUTH_PER_LIMIT_GAS,
            "1 limit should be 52,000"
        );

        // Test 2 limits: 30,000 + 44,000 = 74,000
        let gas_2 = calculate_key_authorization_gas(
            &create_key_auth(2),
            &GasParams::default(),
            tempo_chainspec::hardfork::TempoHardfork::default(),
        );
        assert_eq!(
            gas_2,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 2 * KEY_AUTH_PER_LIMIT_GAS,
            "2 limits should be 74,000"
        );

        // Test 3 limits: 30,000 + 66,000 = 96,000
        let gas_3 = calculate_key_authorization_gas(
            &create_key_auth(3),
            &GasParams::default(),
            tempo_chainspec::hardfork::TempoHardfork::default(),
        );
        assert_eq!(
            gas_3,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 3 * KEY_AUTH_PER_LIMIT_GAS,
            "3 limits should be 96,000"
        );

        // T1B branch: gas = sig_gas + SLOAD + SSTORE * (1 + num_limits) + buffer
        let t1b_gas_params = crate::gas_params::tempo_gas_params(TempoHardfork::T1B);
        let sstore =
            t1b_gas_params.get(revm::context_interface::cfg::GasId::sstore_set_without_load_cost());
        let sload =
            t1b_gas_params.warm_storage_read_cost() + t1b_gas_params.cold_storage_additional_cost();
        const BUFFER: u64 = 2_000;

        for num_limits in 0..=3 {
            let gas = calculate_key_authorization_gas(
                &create_key_auth(num_limits),
                &t1b_gas_params,
                TempoHardfork::T1B,
            );
            let expected = ECRECOVER_GAS + sload + sstore * (1 + num_limits as u64) + BUFFER;
            assert_eq!(gas, expected, "T1B with {num_limits} limits");
        }
    }

    #[test]
    fn test_key_authorization_gas_in_batch() {
        use crate::TempoBatchCallEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{
            Call, KeyAuthorization, SignatureType, SignedKeyAuthorization, TempoSignature,
            TokenLimit,
        };

        let calldata = Bytes::from(vec![1, 2, 3]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        // Create key authorization with 2 limits
        let key_auth: SignedKeyAuthorization = SignedKeyAuthorization {
            authorization: KeyAuthorization {
                chain_id: 1,
                key_type: SignatureType::Secp256k1,
                key_id: Address::random(),
                expiry: None,
                limits: Some(vec![
                    TokenLimit {
                        token: Address::random(),
                        limit: U256::from(1000),
                    },
                    TokenLimit {
                        token: Address::random(),
                        limit: U256::from(2000),
                    },
                ]),
            },
            signature: PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature()),
        };

        let aa_env_with_key_auth = TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call.clone()],
            key_authorization: Some(key_auth),
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let aa_env_without_key_auth = TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        // Calculate gas WITH key authorization
        let gas_with_key_auth = calculate_aa_batch_intrinsic_gas(
            &aa_env_with_key_auth,
            &GasParams::default(),
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        )
        .unwrap();

        // Calculate gas WITHOUT key authorization
        let gas_without_key_auth = calculate_aa_batch_intrinsic_gas(
            &aa_env_without_key_auth,
            &GasParams::default(),
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        )
        .unwrap();

        // Expected key auth gas: 30,000 (base + ecrecover) + 2 * 22,000 (limits) = 74,000
        let expected_key_auth_gas = KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 2 * KEY_AUTH_PER_LIMIT_GAS;

        assert_eq!(
            gas_with_key_auth.initial_gas - gas_without_key_auth.initial_gas,
            expected_key_auth_gas,
            "Key authorization should add exactly {expected_key_auth_gas} gas to batch",
        );

        // Also verify absolute values
        let spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let base_tx_gas = calculate_initial_tx_gas(spec.into(), &calldata, false, 0, 0, 0);
        let expected_without = base_tx_gas.initial_gas; // no cold access for single call
        let expected_with = expected_without + expected_key_auth_gas;

        assert_eq!(
            gas_without_key_auth.initial_gas, expected_without,
            "Gas without key auth should match expected"
        );
        assert_eq!(
            gas_with_key_auth.initial_gas, expected_with,
            "Gas with key auth should match expected"
        );
    }

    #[test]
    fn test_2d_nonce_gas_in_intrinsic_gas() {
        use crate::gas_params::tempo_gas_params;
        use revm::{context_interface::cfg::GasId, handler::Handler};

        const BASE_INTRINSIC_GAS: u64 = 21_000;

        for spec in [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T1A,
            TempoHardfork::T1B,
            TempoHardfork::T2,
        ] {
            let gas_params = tempo_gas_params(spec);

            let make_evm = |nonce: u64, nonce_key: U256| {
                let journal = Journal::new(CacheDB::new(EmptyDB::default()));
                let mut cfg = CfgEnv::<TempoHardfork>::default();
                cfg.spec = spec;
                cfg.gas_params = gas_params.clone();
                let ctx = Context::mainnet()
                    .with_db(CacheDB::new(EmptyDB::default()))
                    .with_block(TempoBlockEnv::default())
                    .with_cfg(cfg)
                    .with_tx(TempoTxEnv {
                        inner: revm::context::TxEnv {
                            gas_limit: 1_000_000,
                            nonce,
                            ..Default::default()
                        },
                        tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                            aa_calls: vec![Call {
                                to: TxKind::Call(Address::random()),
                                value: U256::ZERO,
                                input: Bytes::new(),
                            }],
                            nonce_key,
                            ..Default::default()
                        })),
                        ..Default::default()
                    })
                    .with_new_journal(journal);
                TempoEvm::<_, ()>::new(ctx, ())
            };

            let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();

            // Case 1: Protocol nonce (nonce_key == 0, nonce > 0) - no additional gas
            {
                let mut evm = make_evm(5, U256::ZERO);
                let gas = handler.validate_initial_tx_gas(&mut evm).unwrap();
                assert_eq!(
                    gas.initial_gas, BASE_INTRINSIC_GAS,
                    "{spec:?}: protocol nonce (nonce_key=0, nonce>0) should have no extra gas"
                );
            }

            // Case 2: nonce_key != 0, nonce == 0
            {
                let expected = if spec.is_t1() {
                    // T1+: any nonce==0 charges new_account_cost (250k)
                    BASE_INTRINSIC_GAS + gas_params.get(GasId::new_account_cost())
                } else {
                    // Pre-T1: charges gas_new_nonce_key for new 2D key
                    BASE_INTRINSIC_GAS + spec.gas_new_nonce_key()
                };
                let mut evm = make_evm(0, U256::from(42));
                let gas = handler.validate_initial_tx_gas(&mut evm).unwrap();
                assert_eq!(
                    gas.initial_gas, expected,
                    "{spec:?}: nonce_key!=0, nonce==0 gas mismatch"
                );
            }

            // Case 3: Existing 2D nonce key (nonce_key != 0, nonce > 0)
            {
                let mut evm = make_evm(5, U256::from(42));
                let gas = handler.validate_initial_tx_gas(&mut evm).unwrap();
                assert_eq!(
                    gas.initial_gas,
                    BASE_INTRINSIC_GAS + spec.gas_existing_nonce_key(),
                    "{spec:?}: existing 2D nonce key gas mismatch"
                );
            }
        }
    }

    #[test]
    fn test_2d_nonce_gas_limit_validation() {
        use crate::gas_params::tempo_gas_params;
        use revm::{context_interface::cfg::GasId, handler::Handler};

        const BASE_INTRINSIC_GAS: u64 = 21_000;

        for spec in [
            TempoHardfork::Genesis,
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T2,
        ] {
            let gas_params = tempo_gas_params(spec);

            // Build spec-specific test cases: (gas_limit, nonce, expected_result)
            let nonce_zero_gas = if spec.is_t1() {
                gas_params.get(GasId::new_account_cost())
            } else {
                spec.gas_new_nonce_key()
            };

            let cases = if spec.is_t0() {
                vec![
                    (BASE_INTRINSIC_GAS + 10_000, 0u64, false), // Insufficient for nonce==0
                    (BASE_INTRINSIC_GAS + nonce_zero_gas, 0, true), // Exactly sufficient for nonce==0
                    (BASE_INTRINSIC_GAS + spec.gas_existing_nonce_key(), 1, true), // Exactly sufficient for existing key
                ]
            } else {
                // Genesis: nonce gas is added AFTER validation, so lower gas_limit still passes
                vec![
                    (BASE_INTRINSIC_GAS + 10_000, 0u64, true), // Passes validation (nonce gas added after)
                    (BASE_INTRINSIC_GAS + nonce_zero_gas, 0, true), // Also passes
                    (BASE_INTRINSIC_GAS + spec.gas_existing_nonce_key(), 1, true), // Also passes
                    (BASE_INTRINSIC_GAS - 1, 0, false),        // Below base intrinsic gas
                ]
            };

            for (gas_limit, nonce, should_succeed) in cases {
                let journal = Journal::new(CacheDB::new(EmptyDB::default()));
                let mut cfg = CfgEnv::<TempoHardfork>::default();
                cfg.spec = spec;
                cfg.gas_params = gas_params.clone();
                let ctx = Context::mainnet()
                    .with_db(CacheDB::new(EmptyDB::default()))
                    .with_block(TempoBlockEnv::default())
                    .with_cfg(cfg)
                    .with_tx(TempoTxEnv {
                        inner: revm::context::TxEnv {
                            gas_limit,
                            nonce,
                            ..Default::default()
                        },
                        tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                            aa_calls: vec![Call {
                                to: TxKind::Call(Address::random()),
                                value: U256::ZERO,
                                input: Bytes::new(),
                            }],
                            nonce_key: U256::from(1), // Non-zero to trigger 2D nonce gas
                            ..Default::default()
                        })),
                        ..Default::default()
                    })
                    .with_new_journal(journal);

                let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
                let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();
                let result = handler.validate_initial_tx_gas(&mut evm);

                if should_succeed {
                    assert!(
                        result.is_ok(),
                        "{spec:?}: gas_limit={gas_limit}, nonce={nonce}: expected success but got error"
                    );
                } else {
                    let err = result.expect_err(&format!(
                        "{spec:?}: gas_limit={gas_limit}, nonce={nonce}: should fail"
                    ));
                    assert!(
                        matches!(
                            err.as_invalid_tx_err(),
                            Some(TempoInvalidTransaction::InsufficientGasForIntrinsicCost { .. })
                        ),
                        "Expected InsufficientGasForIntrinsicCost, got: {err:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_multicall_gas_refund_accounting() {
        use crate::evm::TempoEvm;
        use alloy_primitives::{Bytes, TxKind};
        use revm::{
            Context, Journal,
            context::CfgEnv,
            database::{CacheDB, EmptyDB},
            handler::FrameResult,
            interpreter::{CallOutcome, Gas, InstructionResult, InterpreterResult},
        };
        use tempo_primitives::transaction::Call;

        const GAS_LIMIT: u64 = 1_000_000;
        const INTRINSIC_GAS: u64 = 21_000;
        // Mock call's gas: (CALL_0, CALL_1)
        const SPENT: (u64, u64) = (1000, 500);
        const REFUND: (i64, i64) = (100, 50);

        // Create minimal EVM context
        let db = CacheDB::new(EmptyDB::default());
        let journal = Journal::new(db);
        let ctx = Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::default()))
            .with_block(TempoBlockEnv::default())
            .with_cfg(CfgEnv::default())
            .with_tx(TempoTxEnv {
                inner: revm::context::TxEnv {
                    gas_limit: GAS_LIMIT,
                    ..Default::default()
                },
                ..Default::default()
            })
            .with_new_journal(journal);

        let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
        let mut handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();

        // Create mock calls
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

        let (mut call_idx, calls_gas) = (0, [(SPENT.0, REFUND.0), (SPENT.1, REFUND.1)]);
        let result = handler.execute_multi_call_with(
            &mut evm,
            &InitialAndFloorGas::new(INTRINSIC_GAS, 0),
            calls,
            |_handler, _evm, _gas| {
                let (spent, refund) = calls_gas[call_idx];
                call_idx += 1;

                // Create gas with specific spent and refund values
                let mut gas = Gas::new(GAS_LIMIT);
                gas.set_spent(spent);
                gas.record_refund(refund);

                // Mock successful frame result
                Ok(FrameResult::Call(CallOutcome::new(
                    InterpreterResult::new(InstructionResult::Stop, Bytes::new(), gas),
                    0..0,
                )))
            },
        );

        let result = result.expect("execute_multi_call_with should succeed");
        let final_gas = result.gas();

        assert_eq!(
            final_gas.spent(),
            INTRINSIC_GAS + SPENT.0 + SPENT.1,
            "Total spent should be intrinsic_gas + sum of all calls' spent values"
        );
        assert_eq!(
            final_gas.refunded(),
            REFUND.0 + REFUND.1,
            "Total refund should be sum of all calls' refunded values"
        );
        assert_eq!(
            final_gas.used(),
            INTRINSIC_GAS + SPENT.0 + SPENT.1 - (REFUND.0 + REFUND.1) as u64,
            "used() should be spent - refund"
        );
    }

    /// Strategy for optional u64 timestamps.
    fn arb_opt_timestamp() -> impl Strategy<Value = Option<u64>> {
        prop_oneof![Just(None), any::<u64>().prop_map(Some)]
    }

    /// Helper to create a secp256k1 signature for testing gas calculations.
    ///
    /// Note: We use a test signature rather than real valid/invalid signatures because
    /// these gas calculation functions only depend on the signature *type* (Secp256k1,
    /// P256, WebAuthn), not on cryptographic validity. Signature verification happens
    /// separately during `recover_signer()` before transactions enter the pool.
    fn secp256k1_sig() -> TempoSignature {
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ))
    }

    /// Helper to create a TempoBatchCallEnv with specified calls.
    fn make_aa_env(calls: Vec<Call>) -> TempoBatchCallEnv {
        TempoBatchCallEnv {
            signature: secp256k1_sig(),
            aa_calls: calls,
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        }
    }

    /// Helper to create a single-call TempoBatchCallEnv with given calldata.
    fn make_single_call_env(calldata: Bytes) -> TempoBatchCallEnv {
        make_aa_env(vec![Call {
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            input: calldata,
        }])
    }

    /// Helper to create a multi-call TempoBatchCallEnv with N empty calls.
    fn make_multi_call_env(num_calls: usize) -> TempoBatchCallEnv {
        make_aa_env(
            (0..num_calls)
                .map(|_| Call {
                    to: TxKind::Call(Address::ZERO),
                    value: U256::ZERO,
                    input: Bytes::new(),
                })
                .collect(),
        )
    }

    /// Helper to compute AA batch gas with no access list.
    fn compute_aa_gas(env: &TempoBatchCallEnv) -> InitialAndFloorGas {
        calculate_aa_batch_intrinsic_gas(
            env,
            &GasParams::default(),
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_chainspec::hardfork::TempoHardfork::default(),
        )
        .unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        /// Property: validate_time_window returns Ok if (after <= ts < before)
        #[test]
        fn proptest_validate_time_window_correctness(
            valid_after in arb_opt_timestamp(),
            valid_before in arb_opt_timestamp(),
            block_timestamp in any::<u64>(),
        ) {
            let result = validate_time_window(valid_after, valid_before, block_timestamp);

            let after_ok = valid_after.is_none_or(|after| block_timestamp >= after);
            let before_ok = valid_before.is_none_or(|before| block_timestamp < before);
            let expected_valid = after_ok && before_ok;

            prop_assert_eq!(result.is_ok(), expected_valid,
                "valid_after={:?}, valid_before={:?}, block_ts={}, result={:?}",
                valid_after, valid_before, block_timestamp, result);
        }

        /// Property: validate_time_window with None constraints always succeeds
        #[test]
        fn proptest_validate_time_window_none_always_valid(block_timestamp in any::<u64>()) {
            prop_assert!(validate_time_window(None, None, block_timestamp).is_ok());
        }

        /// Property: validate_time_window with valid_after=0 is equivalent to None
        ///
        /// This tests the equivalence property: Some(0) and None for valid_after should produce
        /// identical results regardless of what valid_before is. We intentionally don't constrain
        /// valid_before because we're testing that the equivalence holds in all cases (both when
        /// valid_before causes success and when it causes failure).
        #[test]
        fn proptest_validate_time_window_zero_after_equivalent_to_none(
            valid_before in arb_opt_timestamp(),
            block_timestamp in any::<u64>(),
        ) {
            let with_zero = validate_time_window(Some(0), valid_before, block_timestamp);
            let with_none = validate_time_window(None, valid_before, block_timestamp);
            prop_assert_eq!(with_zero.is_ok(), with_none.is_ok());
        }

        /// Property: validate_time_window - if before <= after, the window is empty
        #[test]
        fn proptest_validate_time_window_empty_window(
            valid_after in 1u64..=u64::MAX,
            offset in 0u64..1000u64,
        ) {
            let valid_before = valid_after.saturating_sub(offset);
            let result = validate_time_window(Some(valid_after), Some(valid_before), valid_after);
            prop_assert!(result.is_err(), "Empty window should reject all timestamps");
        }

        /// Property: signature gas ordering is consistent: secp256k1 <= p256 <= webauthn
        #[test]
        fn proptest_signature_gas_ordering(webauthn_data_len in 0usize..1000) {
            let secp_sig = PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature());
            let p256_sig = PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO, pre_hash: false,
            });
            let webauthn_sig = PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO,
                webauthn_data: Bytes::from(vec![0u8; webauthn_data_len]),
            });

            let secp_gas = primitive_signature_verification_gas(&secp_sig);
            let p256_gas = primitive_signature_verification_gas(&p256_sig);
            let webauthn_gas = primitive_signature_verification_gas(&webauthn_sig);

            prop_assert!(secp_gas <= p256_gas, "secp256k1 should be <= p256");
            prop_assert!(p256_gas <= webauthn_gas, "p256 should be <= webauthn");
        }

        /// Property: gas calculation monotonicity - more calldata means more gas (non-zero bytes)
        /// Non-zero bytes cost 16 gas each, so monotonicity holds for uniform non-zero calldata.
        #[test]
        fn proptest_gas_monotonicity_calldata_nonzero(
            calldata_len1 in 0usize..1000,
            calldata_len2 in 0usize..1000,
        ) {
            let gas1 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len1])));
            let gas2 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len2])));

            if calldata_len1 <= calldata_len2 {
                prop_assert!(gas1.initial_gas <= gas2.initial_gas,
                    "More calldata should mean more gas: len1={}, gas1={}, len2={}, gas2={}",
                    calldata_len1, gas1.initial_gas, calldata_len2, gas2.initial_gas);
            } else {
                prop_assert!(gas1.initial_gas >= gas2.initial_gas,
                    "Less calldata should mean less gas: len1={}, gas1={}, len2={}, gas2={}",
                    calldata_len1, gas1.initial_gas, calldata_len2, gas2.initial_gas);
            }
        }

        /// Property: gas calculation monotonicity - more calldata means more gas (zero bytes)
        /// Zero bytes cost 4 gas each, so monotonicity holds for uniform zero calldata.
        #[test]
        fn proptest_gas_monotonicity_calldata_zero(
            calldata_len1 in 0usize..1000,
            calldata_len2 in 0usize..1000,
        ) {
            let gas1 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len1])));
            let gas2 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len2])));

            if calldata_len1 <= calldata_len2 {
                prop_assert!(gas1.initial_gas <= gas2.initial_gas,
                    "More zero-byte calldata should mean more gas: len1={}, gas1={}, len2={}, gas2={}",
                    calldata_len1, gas1.initial_gas, calldata_len2, gas2.initial_gas);
            } else {
                prop_assert!(gas1.initial_gas >= gas2.initial_gas,
                    "Less zero-byte calldata should mean less gas: len1={}, gas1={}, len2={}, gas2={}",
                    calldata_len1, gas1.initial_gas, calldata_len2, gas2.initial_gas);
            }
        }

        /// Property: zero-byte calldata costs less gas than non-zero byte calldata of same length.
        /// Zero bytes cost 4 gas each, non-zero bytes cost 16 gas each.
        #[test]
        fn proptest_zero_bytes_cheaper_than_nonzero(calldata_len in 1usize..1000) {
            let zero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len])));
            let nonzero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len])));

            prop_assert!(zero_gas.initial_gas < nonzero_gas.initial_gas,
                "Zero-byte calldata should cost less: len={}, zero_gas={}, nonzero_gas={}",
                calldata_len, zero_gas.initial_gas, nonzero_gas.initial_gas);
        }

        /// Property: mixed calldata gas is bounded by all-zero and all-nonzero extremes.
        /// Gas for mixed calldata should be between gas for all-zero and all-nonzero of same length.
        #[test]
        fn proptest_mixed_calldata_gas_bounded(
            calldata_len in 1usize..500,
            nonzero_ratio in 0u8..=100,
        ) {
            // Create mixed calldata where nonzero_ratio% of bytes are non-zero
            let calldata: Vec<u8> = (0..calldata_len)
                .map(|i| if (i * 100 / calldata_len) < nonzero_ratio as usize { 1u8 } else { 0u8 })
                .collect();

            let mixed_gas = compute_aa_gas(&make_single_call_env(Bytes::from(calldata)));
            let zero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len])));
            let nonzero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len])));

            prop_assert!(mixed_gas.initial_gas >= zero_gas.initial_gas,
                "Mixed calldata gas should be >= all-zero gas: mixed={}, zero={}",
                mixed_gas.initial_gas, zero_gas.initial_gas);
            prop_assert!(mixed_gas.initial_gas <= nonzero_gas.initial_gas,
                "Mixed calldata gas should be <= all-nonzero gas: mixed={}, nonzero={}",
                mixed_gas.initial_gas, nonzero_gas.initial_gas);
        }

        /// Property: gas calculation monotonicity - more calls means more gas
        #[test]
        fn proptest_gas_monotonicity_call_count(
            num_calls1 in 1usize..10,
            num_calls2 in 1usize..10,
        ) {
            let gas1 = compute_aa_gas(&make_multi_call_env(num_calls1));
            let gas2 = compute_aa_gas(&make_multi_call_env(num_calls2));

            if num_calls1 <= num_calls2 {
                prop_assert!(gas1.initial_gas <= gas2.initial_gas,
                    "More calls should mean more gas: calls1={}, gas1={}, calls2={}, gas2={}",
                    num_calls1, gas1.initial_gas, num_calls2, gas2.initial_gas);
            } else {
                prop_assert!(gas1.initial_gas >= gas2.initial_gas,
                    "Fewer calls should mean less gas: calls1={}, gas1={}, calls2={}, gas2={}",
                    num_calls1, gas1.initial_gas, num_calls2, gas2.initial_gas);
            }
        }

        /// Property: AA batch gas with Secp256k1 signature equals exactly 21k base + cold access
        ///
        /// For minimal AA transactions (Secp256k1 sig, no calldata, no access list):
        /// - Base: 21,000 (same base stipend as regular transactions)
        /// - Plus: COLD_ACCOUNT_ACCESS_COST per additional call beyond the first
        ///
        /// AA transactions use the same 21k base as regular transactions because
        /// Secp256k1 signature verification adds 0 extra gas. Other signature types
        /// (P256, WebAuthn) add 5,000+ gas beyond this base.
        #[test]
        fn proptest_gas_aa_secp256k1_exact_bounds(num_calls in 1usize..5) {
            let gas = compute_aa_gas(&make_multi_call_env(num_calls));

            // Expected exactly: 21k base + cold account access for each additional call
            let expected = 21_000 + COLD_ACCOUNT_ACCESS_COST * (num_calls.saturating_sub(1) as u64);
            prop_assert_eq!(gas.initial_gas, expected,
                "Gas {} should equal expected {} for {} calls (21k + {}*COLD_ACCOUNT_ACCESS_COST)",
                gas.initial_gas, expected, num_calls, num_calls.saturating_sub(1));
        }

        /// Property: first_call returns the first call for AA transactions with any number of calls
        #[test]
        fn proptest_first_call_returns_first_for_aa(num_calls in 1usize..10) {
            let calls: Vec<Call> = (0..num_calls)
                .map(|i| Call {
                    to: TxKind::Call(Address::with_last_byte(i as u8)),
                    value: U256::ZERO,
                    input: Bytes::from(vec![i as u8; i + 1]),
                })
                .collect();

            let expected_addr = Address::with_last_byte(0);
            let expected_input = vec![0u8; 1];

            let tx_env = TempoTxEnv {
                inner: revm::context::TxEnv::default(),
                tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                    aa_calls: calls,
                    signature: secp256k1_sig(),
                    signature_hash: B256::ZERO,
                    ..Default::default()
                })),
                ..Default::default()
            };

            let first = tx_env.first_call();
            prop_assert!(first.is_some(), "first_call should return Some for non-empty AA calls");

            let (kind, input) = first.unwrap();
            prop_assert_eq!(*kind, TxKind::Call(expected_addr), "Should return first call's address");
            prop_assert_eq!(input, expected_input.as_slice(), "Should return first call's input");
        }

        /// Property: first_call returns None for AA transaction with zero calls
        #[test]
        fn proptest_first_call_empty_aa(_dummy in 0u8..1) {
            let tx_env = TempoTxEnv {
                inner: revm::context::TxEnv::default(),
                tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                    aa_calls: vec![],
                    signature: secp256k1_sig(),
                    signature_hash: B256::ZERO,
                    ..Default::default()
                })),
                ..Default::default()
            };

            prop_assert!(tx_env.first_call().is_none(), "first_call should return None for empty AA calls");
        }

        /// Property: first_call returns inner tx data for non-AA transactions
        #[test]
        fn proptest_first_call_non_aa(calldata_len in 0usize..100) {
            let calldata = Bytes::from(vec![0xab_u8; calldata_len]);
            let target = Address::random();

            let tx_env = TempoTxEnv {
                inner: revm::context::TxEnv {
                    kind: TxKind::Call(target),
                    data: calldata.clone(),
                    ..Default::default()
                },
                tempo_tx_env: None,
                ..Default::default()
            };

            let first = tx_env.first_call();
            prop_assert!(first.is_some(), "first_call should return Some for non-AA tx");

            let (kind, input) = first.unwrap();
            prop_assert_eq!(*kind, TxKind::Call(target), "Should return inner tx kind");
            prop_assert_eq!(input, calldata.as_ref(), "Should return inner tx data");
        }

        /// Property: calculate_key_authorization_gas is monotonic in number of limits
        #[test]
        fn proptest_key_auth_gas_monotonic_limits(
            num_limits1 in 0usize..10,
            num_limits2 in 0usize..10,
        ) {
            use tempo_primitives::transaction::{
                SignatureType, SignedKeyAuthorization,
                key_authorization::KeyAuthorization,
                TokenLimit as PrimTokenLimit,
            };

            let make_key_auth = |num_limits: usize| -> SignedKeyAuthorization {
                let limits = if num_limits == 0 {
                    None
                } else {
                    Some((0..num_limits).map(|i| PrimTokenLimit {
                        token: Address::with_last_byte(i as u8),
                        limit: U256::from(1000),
                    }).collect())
                };

                SignedKeyAuthorization {
                    authorization: KeyAuthorization {
                        chain_id: 1,
                        key_type: SignatureType::Secp256k1,
                        key_id: Address::ZERO,
                        expiry: None,
                        limits,
                    },
                    signature: PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature()),
                }
            };

            // Test both pre-T1B and T1B branches
            for (gas_params, spec) in [
                (GasParams::default(), tempo_chainspec::hardfork::TempoHardfork::default()),
                (crate::gas_params::tempo_gas_params(TempoHardfork::T1B), TempoHardfork::T1B),
            ] {
                let gas1 = calculate_key_authorization_gas(&make_key_auth(num_limits1), &gas_params, spec);
                let gas2 = calculate_key_authorization_gas(&make_key_auth(num_limits2), &gas_params, spec);

                if num_limits1 <= num_limits2 {
                    prop_assert!(gas1 <= gas2,
                        "{spec:?}: More limits should mean more gas: limits1={}, gas1={}, limits2={}, gas2={}",
                        num_limits1, gas1, num_limits2, gas2);
                } else {
                    prop_assert!(gas1 >= gas2,
                        "{spec:?}: Fewer limits should mean less gas: limits1={}, gas1={}, limits2={}, gas2={}",
                        num_limits1, gas1, num_limits2, gas2);
                }
            }
        }

        /// Property: calculate_key_authorization_gas minimum is KEY_AUTH_BASE_GAS + ECRECOVER_GAS
        #[test]
        fn proptest_key_auth_gas_minimum(
            sig_type in 0u8..3,
            num_limits in 0usize..5,
        ) {
            use tempo_primitives::transaction::{
                SignatureType, SignedKeyAuthorization,
                key_authorization::KeyAuthorization,
                TokenLimit as PrimTokenLimit,
            };

            let signature = match sig_type {
                0 => PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature()),
                1 => PrimitiveSignature::P256(P256SignatureWithPreHash {
                    r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO, pre_hash: false,
                }),
                _ => PrimitiveSignature::WebAuthn(WebAuthnSignature {
                    r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO,
                    webauthn_data: Bytes::new(),
                }),
            };

            let key_auth = SignedKeyAuthorization {
                authorization: KeyAuthorization {
                    chain_id: 1,
                    key_type: SignatureType::Secp256k1,
                    key_id: Address::ZERO,
                    expiry: None,
                    limits: if num_limits == 0 { None } else {
                        Some((0..num_limits).map(|i| PrimTokenLimit {
                            token: Address::with_last_byte(i as u8),
                            limit: U256::from(1000),
                        }).collect())
                    },
                },
                signature,
            };

            // Pre-T1B: minimum is KEY_AUTH_BASE_GAS + ECRECOVER_GAS
            let gas = calculate_key_authorization_gas(&key_auth, &GasParams::default(), tempo_chainspec::hardfork::TempoHardfork::default());
            let min_gas = KEY_AUTH_BASE_GAS + ECRECOVER_GAS;
            prop_assert!(gas >= min_gas,
                "Pre-T1B: Key auth gas should be at least {min_gas}, got {gas}");

            // T1B: minimum is ECRECOVER_GAS + sload + sstore (0 limits)
            let t1b_params = crate::gas_params::tempo_gas_params(TempoHardfork::T1B);
            let gas_t1b = calculate_key_authorization_gas(&key_auth, &t1b_params, TempoHardfork::T1B);
            let sstore = t1b_params.get(revm::context_interface::cfg::GasId::sstore_set_without_load_cost());
            let sload = t1b_params.warm_storage_read_cost() + t1b_params.cold_storage_additional_cost();
            let min_t1b = ECRECOVER_GAS + sload + sstore;
            prop_assert!(gas_t1b >= min_t1b,
                "T1B: Key auth gas should be at least {min_t1b}, got {gas_t1b}");
        }
    }

    /// Test that T1 hardfork correctly charges 250k gas for nonce == 0.
    ///
    /// This test validates TIP-1000's requirement:
    /// "Tempo transactions with any `nonce_key` and `nonce == 0` require an additional 250,000 gas"
    ///
    /// The test proves the audit finding (claiming only 22,100 gas is charged) is a false positive
    /// by using delta-based assertions: gas(nonce=0) - gas(nonce>0) == new_account_cost.
    #[test]
    fn test_t1_2d_nonce_key_charges_250k_gas() {
        use crate::gas_params::tempo_gas_params;
        use revm::{context_interface::cfg::GasId, handler::Handler};

        // Deterministic test addresses
        const TEST_TARGET: Address = Address::new([0xAA; 20]);
        const TEST_NONCE_KEY: U256 = U256::from_limbs([42, 0, 0, 0]);
        const SPEC: TempoHardfork = TempoHardfork::T1;
        const NEW_NONCE_KEY_GAS: u64 = SPEC.gas_new_nonce_key();
        const EXISTING_NONCE_KEY_GAS: u64 = SPEC.gas_existing_nonce_key();

        // Create T1 config with TIP-1000 gas params
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = SPEC;
        cfg.gas_params = tempo_gas_params(TempoHardfork::T1);

        // Get the expected new_account_cost dynamically from gas params
        let new_account_cost = cfg.gas_params.get(GasId::new_account_cost());
        assert_eq!(
            new_account_cost, 250_000,
            "T1 gas params should have 250k new_account_cost"
        );

        // Helper to create EVM context for testing
        let make_evm = |cfg: CfgEnv<TempoHardfork>, nonce: u64, nonce_key: U256| {
            let journal = Journal::new(CacheDB::new(EmptyDB::default()));
            let ctx = Context::mainnet()
                .with_db(CacheDB::new(EmptyDB::default()))
                .with_block(TempoBlockEnv::default())
                .with_cfg(cfg)
                .with_tx(TempoTxEnv {
                    inner: revm::context::TxEnv {
                        gas_limit: 1_000_000,
                        nonce,
                        ..Default::default()
                    },
                    tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                        aa_calls: vec![Call {
                            to: TxKind::Call(TEST_TARGET),
                            value: U256::ZERO,
                            input: Bytes::new(),
                        }],
                        nonce_key,
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .with_new_journal(journal);
            TempoEvm::<_, ()>::new(ctx, ())
        };

        // Case 1: nonce == 0 with 2D nonce key -> should include new_account_cost
        let mut evm_nonce_zero = make_evm(cfg.clone(), 0, TEST_NONCE_KEY);
        let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();
        let gas_nonce_zero = handler
            .validate_initial_tx_gas(&mut evm_nonce_zero)
            .unwrap();

        // Case 2: nonce > 0 with same 2D nonce key -> should charge EXISTING_NONCE_KEY_GAS (5k)
        // This tests that existing 2D nonce keys are charged 5k gas per TIP-1000 Invariant 3
        let mut evm_nonce_five = make_evm(cfg.clone(), 5, TEST_NONCE_KEY);
        let gas_nonce_five = handler
            .validate_initial_tx_gas(&mut evm_nonce_five)
            .unwrap();

        // Delta-based assertion: the difference should be new_account_cost - EXISTING_NONCE_KEY_GAS
        // nonce=0 charges 250k (new account), nonce>0 charges 5k (existing key update)
        let gas_delta = gas_nonce_zero.initial_gas - gas_nonce_five.initial_gas;
        let expected_delta = new_account_cost - EXISTING_NONCE_KEY_GAS;
        assert_eq!(
            gas_delta, expected_delta,
            "T1 gas difference between nonce=0 and nonce>0 should be {expected_delta} (new_account_cost - EXISTING_NONCE_KEY_GAS), got {gas_delta}"
        );

        // Verify it's NOT using the pre-T1 NEW_NONCE_KEY_GAS (22,100)
        assert_ne!(
            gas_delta, NEW_NONCE_KEY_GAS,
            "T1 should NOT use pre-T1 NEW_NONCE_KEY_GAS ({NEW_NONCE_KEY_GAS}) for nonce=0 transactions"
        );

        // Case 3: nonce == 0 with regular nonce (nonce_key=0) -> same +250k charge
        let mut evm_regular_nonce = make_evm(cfg, 0, U256::ZERO);
        let gas_regular = handler
            .validate_initial_tx_gas(&mut evm_regular_nonce)
            .unwrap();

        assert_eq!(
            gas_nonce_zero.initial_gas, gas_regular.initial_gas,
            "nonce=0 should charge the same regardless of nonce_key (2D vs regular)"
        );
    }

    /// Test that T1 hardfork correctly charges 5k gas for existing 2D nonce keys (nonce > 0).
    ///
    /// This test validates TIP-1000 Invariant 3:
    /// "SSTORE operations that modify existing non-zero state (non-zero to non-zero)
    /// MUST continue to charge 5,000 gas"
    ///
    /// When using an existing 2D nonce key (nonce_key != 0 && nonce > 0), the nonce value
    /// transitions from N to N+1 (non-zero to non-zero), which must charge EXISTING_NONCE_KEY_GAS.
    #[test]
    fn test_t1_existing_2d_nonce_key_charges_5k_gas() {
        use crate::gas_params::tempo_gas_params;
        use revm::handler::Handler;

        const BASE_INTRINSIC_GAS: u64 = 21_000;
        const TEST_TARGET: Address = Address::new([0xBB; 20]);
        const TEST_NONCE_KEY: U256 = U256::from_limbs([99, 0, 0, 0]);
        const SPEC: TempoHardfork = TempoHardfork::T1;
        const EXISTING_NONCE_KEY_GAS: u64 = SPEC.gas_existing_nonce_key();

        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = SPEC;
        cfg.gas_params = tempo_gas_params(TempoHardfork::T1);

        let make_evm = |cfg: CfgEnv<TempoHardfork>, nonce: u64, nonce_key: U256| {
            let journal = Journal::new(CacheDB::new(EmptyDB::default()));
            let ctx = Context::mainnet()
                .with_db(CacheDB::new(EmptyDB::default()))
                .with_block(TempoBlockEnv::default())
                .with_cfg(cfg)
                .with_tx(TempoTxEnv {
                    inner: revm::context::TxEnv {
                        gas_limit: 1_000_000,
                        nonce,
                        ..Default::default()
                    },
                    tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                        aa_calls: vec![Call {
                            to: TxKind::Call(TEST_TARGET),
                            value: U256::ZERO,
                            input: Bytes::new(),
                        }],
                        nonce_key,
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .with_new_journal(journal);
            TempoEvm::<_, ()>::new(ctx, ())
        };

        let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();

        // Case 1: Existing 2D nonce key (nonce > 0) should charge EXISTING_NONCE_KEY_GAS
        let mut evm_existing_key = make_evm(cfg.clone(), 5, TEST_NONCE_KEY);
        let gas_existing = handler
            .validate_initial_tx_gas(&mut evm_existing_key)
            .unwrap();

        assert_eq!(
            gas_existing.initial_gas,
            BASE_INTRINSIC_GAS + EXISTING_NONCE_KEY_GAS,
            "T1 existing 2D nonce key (nonce>0) should charge BASE + EXISTING_NONCE_KEY_GAS ({EXISTING_NONCE_KEY_GAS})"
        );

        // Case 2: Regular nonce (nonce_key = 0) with nonce > 0 should NOT charge extra gas
        let mut evm_regular = make_evm(cfg, 5, U256::ZERO);
        let gas_regular = handler.validate_initial_tx_gas(&mut evm_regular).unwrap();

        assert_eq!(
            gas_regular.initial_gas, BASE_INTRINSIC_GAS,
            "T1 regular nonce (nonce_key=0, nonce>0) should only charge BASE intrinsic gas"
        );

        // Verify the delta between 2D and regular nonce is exactly EXISTING_NONCE_KEY_GAS
        let gas_delta = gas_existing.initial_gas - gas_regular.initial_gas;
        assert_eq!(
            gas_delta, EXISTING_NONCE_KEY_GAS,
            "Difference between existing 2D nonce and regular nonce should be EXISTING_NONCE_KEY_GAS ({EXISTING_NONCE_KEY_GAS})"
        );
    }
}
