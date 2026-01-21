//! Tempo EVM Handler implementation.

use std::{cmp::Ordering, fmt::Debug};

use alloy_primitives::{Address, U256};
use reth_evm::EvmError;
use revm::{
    Database,
    context::{
        Block, Cfg, ContextTr, JournalTr, LocalContextTr, Transaction,
        journaled_state::account::JournaledAccountTr,
        result::{EVMError, ExecutionResult, InvalidTransaction},
        transaction::{AccessListItem, AccessListItemTr},
    },
    handler::{
        EvmTr, FrameResult, FrameTr, Handler, MainnetHandler,
        pre_execution::{self, apply_auth_list, calculate_caller_fee},
        validation,
    },
    inspector::{Inspector, InspectorHandler},
    interpreter::{
        Gas, InitialAndFloorGas,
        gas::{
            ACCESS_LIST_ADDRESS, ACCESS_LIST_STORAGE_KEY, CALLVALUE, COLD_ACCOUNT_ACCESS_COST,
            COLD_SLOAD_COST, CREATE, INITCODE_WORD_COST, SSTORE_SET, STANDARD_TOKEN_COST,
            TOTAL_COST_FLOOR_PER_TOKEN, WARM_SSTORE_RESET, get_tokens_in_calldata_istanbul,
        },
        interpreter::EthInterpreter,
    },
    primitives::eip7702,
};
use tempo_contracts::precompiles::{
    IAccountKeychain::SignatureType as PrecompileSignatureType, TIPFeeAMMError,
};
use tempo_precompiles::{
    account_keychain::{AccountKeychain, TokenLimit, authorizeKeyCall},
    error::TempoPrecompileError,
    nonce::{INonce::getNonceCall, NonceManager},
    storage::StorageCtx,
    tip_fee_manager::TipFeeManager,
    tip20::{ITIP20::InsufficientBalance, TIP20Error, TIP20Token, is_tip20_prefix},
};
use tempo_primitives::transaction::{
    PrimitiveSignature, SignatureType, TempoSignature, calc_gas_balance_spending, validate_calls,
};

use crate::{
    TempoBatchCallEnv, TempoEvm, TempoInvalidTransaction,
    common::TempoStateAccess,
    error::{FeePaymentError, TempoHaltReason},
    evm::TempoContext,
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

/// Gas cost for using an existing 2D nonce key (cold SLOAD + warm SSTORE reset)
pub const EXISTING_NONCE_KEY_GAS: u64 = COLD_SLOAD_COST + WARM_SSTORE_RESET;

/// Gas cost for using a new 2D nonce key (cold SLOAD + SSTORE set for 0 -> non-zero)
pub const NEW_NONCE_KEY_GAS: u64 = COLD_SLOAD_COST + SSTORE_SET;

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
/// Gas = BASE (27k) + signature verification + (22k per spending limit)
#[inline]
fn calculate_key_authorization_gas(
    key_auth: &tempo_primitives::transaction::SignedKeyAuthorization,
) -> u64 {
    // All signature types pay ECRECOVER_GAS (3k) as the baseline since
    // primitive_signature_verification_gas assumes ecrecover is already in base 21k.
    // For KeyAuthorization, we're doing an additional signature verification.
    let sig_gas = ECRECOVER_GAS + primitive_signature_verification_gas(&key_auth.signature);

    // Per-limit storage gas
    let limits_gas = key_auth
        .authorization
        .limits
        .as_ref()
        .map(|limits| limits.len() as u64 * KEY_AUTH_PER_LIMIT_GAS)
        .unwrap_or(0);

    // Total: base (27k) + sig verification + limits
    KEY_AUTH_BASE_GAS + sig_gas + limits_gas
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
    fn load_fee_fields(
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
    /// This calls the same helper methods used by the default Handler::execution() implementation.
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
        // Check if this is an AA transaction by checking for tempo_tx_env
        if let Some(tempo_tx_env) = evm.ctx().tx().tempo_tx_env.as_ref() {
            // AA transaction - use batch execution with calls field
            let calls = tempo_tx_env.aa_calls.clone();
            self.execute_multi_call(evm, init_and_floor_gas, calls)
        } else {
            // Standard transaction - use single-call execution
            self.execute_single_call(evm, init_and_floor_gas)
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

        // Check if this is an AA transaction with an authorization list
        let has_aa_auth_list = ctx
            .tx()
            .tempo_tx_env
            .as_ref()
            .map(|aa_env| !aa_env.tempo_authorization_list.is_empty())
            .unwrap_or(false);

        // If it's an AA transaction with authorization list, we need to apply it manually
        // since the default implementation only checks for TransactionType::Eip7702
        if has_aa_auth_list {
            let chain_id = ctx.cfg().chain_id();
            let spec = *ctx.cfg().spec();

            let (tx, journal) = evm.ctx().tx_journal_mut();

            let tempo_tx_env = tx.tempo_tx_env.as_ref().unwrap();

            let refunded_gas = apply_auth_list::<_, Self::Error>(
                chain_id,
                tempo_tx_env
                    .tempo_authorization_list
                    .iter()
                    // T0 hardfork: skip keychain signatures in auth list processing
                    .filter(|auth| !(spec.is_t0() && auth.signature().is_keychain())),
                journal,
            )?;
            return Ok(refunded_gas);
        }

        // For standard EIP-7702 transactions, use the default implementation
        pre_execution::apply_eip7702_auth_list(evm.ctx())
    }

    #[inline]
    fn validate_against_state_and_deduct_caller(
        &self,
        evm: &mut Self::Evm,
    ) -> Result<(), Self::Error> {
        let (block, tx, cfg, journal, _, _) = evm.ctx().all_mut();

        // Set tx.origin in the keychain's transient storage for spending limit checks.
        // This must be done for ALL transactions so precompiles can access it.
        StorageCtx::enter_evm(journal, block, cfg, tx, || {
            let mut keychain = AccountKeychain::new();
            keychain.set_tx_origin(tx.caller())
        })
        .map_err(|e| EVMError::Custom(e.to_string()))?;

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

        // Validate account nonce and code (EIP-3607) using upstream helper
        pre_execution::validate_account_nonce_and_code(
            &caller_account.account().info,
            tx.nonce(),
            cfg.is_eip3607_disabled(),
            // skip nonce check if 2D nonce is used
            cfg.is_nonce_check_disabled() || !nonce_key.is_zero(),
        )?;

        // modify account nonce and touch the account.
        caller_account.touch();

        if !nonce_key.is_zero() {
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
            // Bump the nonce for calls. Nonce for CREATE will be bumped in `make_create_frame`.
            // This applies uniformly to both standard and AA transactions - we only bump here
            // for CALLs, letting make_create_frame handle the nonce for CREATE operations.
            if tx.kind().is_call() {
                caller_account.bump_nonce();
            }
        }

        // calculate the new balance after the fee is collected.
        let new_balance = calculate_caller_fee(account_balance, tx, block, cfg)?;
        // doing max to avoid underflow as new_balance can be more than
        // account balance if `cfg.is_balance_check_disabled()` is true.
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

            // Now authorize the key in the precompile
            StorageCtx::enter_precompile(
                journal,
                block,
                cfg,
                tx,
                |mut keychain: AccountKeychain| {
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
                    keychain
                        .authorize_key(*root_account, authorize_call)
                        .map_err(|err| match err {
                            TempoPrecompileError::Fatal(err) => EVMError::Custom(err),
                            err => TempoInvalidTransaction::KeychainPrecompileError {
                                reason: err.to_string(),
                            }
                            .into(),
                        })
                },
            )?;
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
                        keychain
                            .validate_keychain_authorization(
                                *user_address,
                                access_key_addr,
                                block.timestamp().to::<u64>(),
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

        // Route to appropriate gas calculation based on transaction type
        if tx.tempo_tx_env.is_some() {
            // AA transaction - use batch gas calculation
            validate_aa_initial_tx_gas(evm)
        } else {
            // Standard transaction - use default revm validation
            let spec = evm.ctx_ref().cfg().spec().into();
            Ok(validation::validate_initial_tx_gas(
                tx,
                spec,
                evm.ctx.cfg.is_eip7623_disabled(),
            )?)
        }
    }

    fn catch_error(
        &self,
        evm: &mut Self::Evm,
        error: Self::Error,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
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
/// - Key authorization costs (if present): 30k/32k base + 22k per spending limit
/// - Floor gas calculation (EIP-7623, Prague+)
pub fn calculate_aa_batch_intrinsic_gas<'a>(
    aa_env: &TempoBatchCallEnv,
    access_list: Option<impl Iterator<Item = &'a AccessListItem>>,
) -> Result<InitialAndFloorGas, TempoInvalidTransaction> {
    let calls = &aa_env.aa_calls;
    let signature = &aa_env.signature;
    let authorization_list = &aa_env.tempo_authorization_list;
    let key_authorization = aa_env.key_authorization.as_ref();
    let mut gas = InitialAndFloorGas::default();

    // 1. Base stipend (21k, once per transaction)
    gas.initial_gas += 21_000;

    // 2. Signature verification gas
    gas.initial_gas += tempo_signature_verification_gas(signature);

    // 3. Per-call overhead: cold account access for additional calls beyond the first.
    gas.initial_gas += COLD_ACCOUNT_ACCESS_COST * calls.len().saturating_sub(1) as u64;

    // 4. Authorization list costs (EIP-7702)
    gas.initial_gas += authorization_list.len() as u64 * eip7702::PER_EMPTY_ACCOUNT_COST;
    // Add signature verification costs for each authorization
    for auth in authorization_list {
        gas.initial_gas += tempo_signature_verification_gas(auth.signature());
    }

    // 5. Key authorization costs (if present)
    if let Some(key_auth) = key_authorization {
        gas.initial_gas += calculate_key_authorization_gas(key_auth);
    }

    // 6. Per-call costs
    let mut total_tokens = 0u64;

    for call in calls {
        // 4a. Calldata gas using revm helper
        let tokens = get_tokens_in_calldata_istanbul(&call.input);
        total_tokens += tokens;

        // 4b. CREATE-specific costs
        if call.to.is_create() {
            // CREATE costs 32000 additional gas
            gas.initial_gas += CREATE; // 32000 gas

            // EIP-3860: Initcode analysis gas (2 gas per 32-byte word)
            let num_words = call.input.len().div_ceil(32);
            gas.initial_gas += num_words as u64 * INITCODE_WORD_COST;
        }

        // Note: Transaction value is not allowed in AA transactions as there is no balances in accounts yet.
        // Check added in https://github.com/tempoxyz/tempo/pull/759
        if !call.value.is_zero() {
            return Err(TempoInvalidTransaction::ValueTransferNotAllowedInAATx);
        }

        // 4c. Value transfer cost using revm constant
        // left here for future reference.
        if !call.value.is_zero() && call.to.is_call() {
            gas.initial_gas += CALLVALUE; // 9000 gas
        }
    }

    gas.initial_gas += total_tokens * STANDARD_TOKEN_COST;

    // 5. Access list costs using revm constants
    if let Some(access_list) = access_list {
        let (accounts, storages) =
            access_list.fold((0u64, 0u64), |(acc_count, storage_count), item| {
                (
                    acc_count + 1,
                    storage_count + item.storage_slots().count() as u64,
                )
            });
        gas.initial_gas += accounts * ACCESS_LIST_ADDRESS; // 2400 per account
        gas.initial_gas += storages * ACCESS_LIST_STORAGE_KEY; // 1900 per storage
    }

    // 6. Floor gas calculation (tokens * 10 + 21000)
    gas.floor_gas = total_tokens * TOTAL_COST_FLOOR_PER_TOKEN + 21_000;

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
    let tx = evm.ctx_ref().tx();
    let spec = *evm.ctx_ref().cfg().spec();

    // This function should only be called for AA transactions
    let aa_env = tx
        .tempo_tx_env
        .as_ref()
        .expect("validate_aa_initial_tx_gas called for non-AA transaction");

    let calls = &aa_env.aa_calls;
    let gas_limit = tx.gas_limit();

    // Validate all CREATE calls' initcode size upfront (EIP-3860)
    let max_initcode_size = evm.ctx_ref().cfg().max_initcode_size();
    for call in calls {
        if call.to.is_create() && call.input.len() > max_initcode_size {
            return Err(InvalidTransaction::CreateInitCodeSizeLimit.into());
        }
    }

    // Calculate batch intrinsic gas using helper
    let mut batch_gas = calculate_aa_batch_intrinsic_gas(aa_env, tx.access_list())?;

    // Calculate 2D nonce gas if nonce_key is non-zero
    // If tx nonce is 0, it's a new key (0 -> 1 transition), otherwise existing key
    let nonce_2d_gas = if !aa_env.nonce_key.is_zero() {
        if tx.nonce() == 0 {
            // New key - cold SLOAD + SSTORE set (0 -> non-zero)
            NEW_NONCE_KEY_GAS
        } else {
            // Existing key - cold SLOAD + warm SSTORE reset
            EXISTING_NONCE_KEY_GAS
        }
    } else {
        0
    };

    if evm.ctx.cfg.is_eip7623_disabled() {
        batch_gas.floor_gas = 0u64;
    }

    // For T0+, include 2D nonce gas in the validation
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

    // For pre-T0, add 2D nonce gas after validation
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
    /// Dispatches based on transaction type:
    /// - AA transactions (type 0x76): Use batch execution path with calls field
    /// - All other transactions: Use standard single-call execution
    ///
    /// This mirrors the logic in Handler::execution but uses inspector-aware execution methods.
    #[inline]
    fn inspect_execution(
        &mut self,
        evm: &mut Self::Evm,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<FrameResult, Self::Error> {
        // Check if this is an AA transaction by checking for tempo_tx_env
        let evm_ctx = evm.ctx();
        if let Some(tempo_tx_env) = evm_ctx.tx().tempo_tx_env.as_ref() {
            // AA transaction - use batch execution with calls field
            let calls = tempo_tx_env.aa_calls.clone();
            self.inspect_execute_multi_call(evm, init_and_floor_gas, calls)
        } else {
            // Standard transaction - use single-call execution
            self.inspect_execute_single_call(evm, init_and_floor_gas)
        }
    }
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
            None::<std::iter::Empty<&AccessListItem>>, // no access list
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
        let gas =
            calculate_aa_batch_intrinsic_gas(&aa_env, None::<std::iter::Empty<&AccessListItem>>)
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

        let gas =
            calculate_aa_batch_intrinsic_gas(&aa_env, None::<std::iter::Empty<&AccessListItem>>)
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

        let gas =
            calculate_aa_batch_intrinsic_gas(&aa_env, None::<std::iter::Empty<&AccessListItem>>)
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

        let res =
            calculate_aa_batch_intrinsic_gas(&aa_env, None::<std::iter::Empty<&AccessListItem>>);

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
        let gas =
            calculate_aa_batch_intrinsic_gas(&aa_env, None::<std::iter::Empty<&AccessListItem>>)
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

        let gas =
            calculate_aa_batch_intrinsic_gas(&aa_env, None::<std::iter::Empty<&AccessListItem>>)
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
        let gas_0 = calculate_key_authorization_gas(&create_key_auth(0));
        assert_eq!(
            gas_0,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS,
            "0 limits should be 30,000"
        );

        // Test 1 limit: 30,000 + 22,000 = 52,000
        let gas_1 = calculate_key_authorization_gas(&create_key_auth(1));
        assert_eq!(
            gas_1,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + KEY_AUTH_PER_LIMIT_GAS,
            "1 limit should be 52,000"
        );

        // Test 2 limits: 30,000 + 44,000 = 74,000
        let gas_2 = calculate_key_authorization_gas(&create_key_auth(2));
        assert_eq!(
            gas_2,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 2 * KEY_AUTH_PER_LIMIT_GAS,
            "2 limits should be 74,000"
        );

        // Test 3 limits: 30,000 + 66,000 = 96,000
        let gas_3 = calculate_key_authorization_gas(&create_key_auth(3));
        assert_eq!(
            gas_3,
            KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 3 * KEY_AUTH_PER_LIMIT_GAS,
            "3 limits should be 96,000"
        );
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
        let key_auth = SignedKeyAuthorization {
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
            None::<std::iter::Empty<&AccessListItem>>,
        )
        .unwrap();

        // Calculate gas WITHOUT key authorization
        let gas_without_key_auth = calculate_aa_batch_intrinsic_gas(
            &aa_env_without_key_auth,
            None::<std::iter::Empty<&AccessListItem>>,
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
        use revm::handler::Handler;

        // Base intrinsic gas for AA tx with one call (no 2D nonce)
        const BASE_INTRINSIC_GAS: u64 = 21_000;

        // Test case 1: Protocol nonce (nonce_key == 0) - no additional gas
        {
            let db = CacheDB::new(EmptyDB::default());
            let journal = Journal::new(db);
            let cfg = CfgEnv::<TempoHardfork>::default();
            let ctx = Context::mainnet()
                .with_db(CacheDB::new(EmptyDB::default()))
                .with_block(TempoBlockEnv::default())
                .with_cfg(cfg)
                .with_tx(TempoTxEnv {
                    inner: revm::context::TxEnv {
                        gas_limit: 100_000,
                        ..Default::default()
                    },
                    tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                        aa_calls: vec![Call {
                            to: TxKind::Call(Address::random()),
                            value: U256::ZERO,
                            input: Bytes::new(),
                        }],
                        nonce_key: U256::ZERO, // Protocol nonce
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .with_new_journal(journal);

            let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
            let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();
            let gas = handler.validate_initial_tx_gas(&mut evm).unwrap();
            assert_eq!(gas.initial_gas, BASE_INTRINSIC_GAS);
        }

        // Test case 2: New 2D nonce key (nonce_key != 0, tx_nonce == 0)
        {
            let db = CacheDB::new(EmptyDB::default());
            let journal = Journal::new(db);
            let cfg = CfgEnv::<TempoHardfork>::default();
            let ctx = Context::mainnet()
                .with_db(CacheDB::new(EmptyDB::default()))
                .with_block(TempoBlockEnv::default())
                .with_cfg(cfg)
                .with_tx(TempoTxEnv {
                    inner: revm::context::TxEnv {
                        gas_limit: 100_000,
                        nonce: 0, // First use of this key
                        ..Default::default()
                    },
                    tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                        aa_calls: vec![Call {
                            to: TxKind::Call(Address::random()),
                            value: U256::ZERO,
                            input: Bytes::new(),
                        }],
                        nonce_key: U256::from(42), // Non-zero nonce key
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .with_new_journal(journal);

            let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
            let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();
            let gas = handler.validate_initial_tx_gas(&mut evm).unwrap();
            assert_eq!(gas.initial_gas, BASE_INTRINSIC_GAS + NEW_NONCE_KEY_GAS);
        }

        // Test case 3: Existing 2D nonce key (nonce_key != 0, tx_nonce > 0)
        {
            let db = CacheDB::new(EmptyDB::default());
            let journal = Journal::new(db);
            let cfg = CfgEnv::<TempoHardfork>::default();
            let ctx = Context::mainnet()
                .with_db(CacheDB::new(EmptyDB::default()))
                .with_block(TempoBlockEnv::default())
                .with_cfg(cfg)
                .with_tx(TempoTxEnv {
                    inner: revm::context::TxEnv {
                        gas_limit: 100_000,
                        nonce: 5, // Existing key (nonce > 0)
                        ..Default::default()
                    },
                    tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                        aa_calls: vec![Call {
                            to: TxKind::Call(Address::random()),
                            value: U256::ZERO,
                            input: Bytes::new(),
                        }],
                        nonce_key: U256::from(42), // Non-zero nonce key
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .with_new_journal(journal);

            let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
            let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();
            let gas = handler.validate_initial_tx_gas(&mut evm).unwrap();
            assert_eq!(gas.initial_gas, BASE_INTRINSIC_GAS + EXISTING_NONCE_KEY_GAS);
        }
    }

    #[test]
    fn test_2d_nonce_gas_limit_validation() {
        use revm::handler::Handler;

        const BASE_INTRINSIC_GAS: u64 = 21_000;

        // Test cases: (gas_limit, nonce, expected_result)
        // With new 2D nonce key (tx_nonce == 0), need BASE + NEW_NONCE_KEY_GAS
        let cases = [
            (BASE_INTRINSIC_GAS + 10_000, 0, false), // Insufficient for new 2D nonce
            (BASE_INTRINSIC_GAS + NEW_NONCE_KEY_GAS, 0, true), // Exactly sufficient for new key
            (BASE_INTRINSIC_GAS + EXISTING_NONCE_KEY_GAS, 1, true), // Exactly sufficient for existing key
        ];

        for (gas_limit, nonce, should_succeed) in cases {
            let db = CacheDB::new(EmptyDB::default());
            let journal = Journal::new(db);
            let cfg = CfgEnv::<TempoHardfork>::default();
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
                    "gas_limit={gas_limit}, nonce={nonce}: expected success but got error"
                );
            } else {
                let err = result.expect_err(&format!(
                    "gas_limit={gas_limit}, nonce={nonce}: should fail"
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

        const GAS_LIMIT: u64 = 100_000;
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
        calculate_aa_batch_intrinsic_gas(env, None::<std::iter::Empty<&AccessListItem>>).unwrap()
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

            let gas1 = calculate_key_authorization_gas(&make_key_auth(num_limits1));
            let gas2 = calculate_key_authorization_gas(&make_key_auth(num_limits2));

            if num_limits1 <= num_limits2 {
                prop_assert!(gas1 <= gas2,
                    "More limits should mean more gas: limits1={}, gas1={}, limits2={}, gas2={}",
                    num_limits1, gas1, num_limits2, gas2);
            } else {
                prop_assert!(gas1 >= gas2,
                    "Fewer limits should mean less gas: limits1={}, gas1={}, limits2={}, gas2={}",
                    num_limits1, gas1, num_limits2, gas2);
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

            let gas = calculate_key_authorization_gas(&key_auth);

            // Minimum gas is BASE + ECRECOVER (secp256k1 adds 0 to ECRECOVER)
            let min_gas = KEY_AUTH_BASE_GAS + ECRECOVER_GAS;
            prop_assert!(gas >= min_gas,
                "Key auth gas should be at least {} (base + ecrecover), got {}",
                min_gas, gas);
        }
    }
}
