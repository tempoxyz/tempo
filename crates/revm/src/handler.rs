//! Tempo EVM Handler implementation.

use std::{cmp::Ordering, fmt::Debug};

use alloy_primitives::{Address, B256, U256, b256};
use reth_evm::EvmError;
use revm::{
    Database,
    context::{
        Block, Cfg, ContextTr, JournalTr, LocalContextTr, Transaction,
        result::{EVMError, ExecutionResult, InvalidTransaction},
        transaction::{AccessListItem, AccessListItemTr},
    },
    handler::{
        EvmTr, FrameResult, FrameTr, Handler, MainnetHandler,
        pre_execution::{self, calculate_caller_fee},
        validation,
    },
    inspector::{Inspector, InspectorHandler},
    interpreter::{
        Gas, InitialAndFloorGas,
        gas::{
            ACCESS_LIST_ADDRESS, ACCESS_LIST_STORAGE_KEY, CALLVALUE, COLD_ACCOUNT_ACCESS_COST,
            COLD_SLOAD_COST, CREATE, SSTORE_SET, STANDARD_TOKEN_COST, WARM_SSTORE_RESET,
            calc_tx_floor_cost, get_tokens_in_calldata, initcode_cost,
        },
        interpreter::EthInterpreter,
    },
    primitives::eip7702,
    state::Bytecode,
};
use tempo_contracts::{
    DEFAULT_7702_DELEGATE_ADDRESS,
    precompiles::{IAccountKeychain::SignatureType as PrecompileSignatureType, TIPFeeAMMError},
};
use tempo_precompiles::{
    account_keychain::{AccountKeychain, TokenLimit, authorizeKeyCall},
    error::TempoPrecompileError,
    nonce::{INonce::getNonceCall, NonceManager},
    storage::StorageCtx,
    tip_fee_manager::TipFeeManager,
    tip20::{self, ITIP20::InsufficientBalance, TIP20Error, TIP20Token},
};
use tempo_primitives::transaction::{
    PrimitiveSignature, SignatureType, TempoSignature, calc_gas_balance_spending,
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
const EXISTING_NONCE_KEY_GAS: u64 = COLD_SLOAD_COST + WARM_SSTORE_RESET;

/// Gas cost for using a new 2D nonce key (cold SLOAD + SSTORE set for 0 -> non-zero)
const NEW_NONCE_KEY_GAS: u64 = COLD_SLOAD_COST + SSTORE_SET;

/// Hashed account code of default 7702 delegate deployment
const DEFAULT_7702_DELEGATE_CODE_HASH: B256 =
    b256!("e7b3e4597bdbdd0cc4eb42f9b799b580f23068f54e472bb802cb71efb1570482");

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
            let tokens = get_tokens_in_calldata(&webauthn_sig.webauthn_data, true);
            P256_VERIFY_GAS + tokens * STANDARD_TOKEN_COST
        }
    }
}

/// Calculates the gas cost for verifying an AA signature.
///
/// For Keychain signatures, adds key validation overhead to the inner signature cost
/// (only post-AllegroModerato hardfork).
/// Returns the additional gas required beyond the base transaction cost.
#[inline]
fn tempo_signature_verification_gas(
    signature: &TempoSignature,
    spec: tempo_chainspec::hardfork::TempoHardfork,
) -> u64 {
    match signature {
        TempoSignature::Primitive(prim_sig) => primitive_signature_verification_gas(prim_sig),
        TempoSignature::Keychain(keychain_sig) => {
            // Keychain = inner signature + key validation overhead (SLOAD + processing)
            // Post-AllegroModerato: add KEYCHAIN_VALIDATION_GAS for key validation
            let base_gas = primitive_signature_verification_gas(&keychain_sig.signature);
            if spec.is_allegro_moderato() {
                base_gas + KEYCHAIN_VALIDATION_GAS
            } else {
                base_gas
            }
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

/// Calculates the gas cost for 2D nonce usage.
///
/// Gas schedule (post-AllegroModerato):
/// - Protocol nonce (key 0): 0 gas (no additional cost)
/// - Existing user key (nonce > 0): 5,000 gas (cold SLOAD + warm SSTORE reset)
/// - New user key (nonce == 0): 22,100 gas (cold SLOAD + SSTORE set)
#[inline]
fn calculate_2d_nonce_gas(
    nonce_manager: &NonceManager,
    caller: Address,
    nonce_key: U256,
) -> Result<u64, TempoPrecompileError> {
    // Protocol nonce (key 0) - no additional cost
    if nonce_key.is_zero() {
        return Ok(0);
    }

    // Get current nonce for this key
    let current_nonce = nonce_manager.get_nonce(getNonceCall {
        account: caller,
        nonceKey: nonce_key,
    })?;

    if current_nonce > 0 {
        // Existing key - cold SLOAD + warm SSTORE reset
        Ok(EXISTING_NONCE_KEY_GAS)
    } else {
        // New key - cold SLOAD + SSTORE set (0 -> non-zero)
        Ok(NEW_NONCE_KEY_GAS)
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
    fn load_fee_fields(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
    ) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
        let ctx = evm.ctx_mut();

        self.fee_payer = ctx.tx.fee_payer()?;
        self.fee_token = ctx
            .journaled_state
            .get_fee_token(&ctx.tx, ctx.block.beneficiary, self.fee_payer, ctx.cfg.spec)
            .map_err(|err| EVMError::Custom(err.to_string()))?;

        // Skip fee token validity check for cases when the transaction is free and is not a part of a subblock.
        if (!ctx.tx.max_balance_spending()?.is_zero() || ctx.tx.is_subblock_transaction())
            && !ctx
                .journaled_state
                .is_valid_fee_token(self.fee_token, ctx.cfg.spec)
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

                // Include gas from all previous successful calls + failed call
                let gas_used_by_failed_call = frame_result.gas().used();
                let total_gas_used = (gas_limit - remaining_gas) + gas_used_by_failed_call;

                // Create new Gas with correct limit, because Gas does not have a set_limit method
                // (the frame_result has the limit from just the last call)
                let mut corrected_gas = Gas::new(gas_limit);
                if instruction_result.is_revert() {
                    corrected_gas.set_spent(total_gas_used);
                } else {
                    corrected_gas.spend_all();
                }
                corrected_gas.set_refund(0); // No refunds when batch fails and all state is reverted
                *frame_result.gas_mut() = corrected_gas;

                return Ok(frame_result);
            }

            // Call succeeded - accumulate gas usage and refunds
            let gas_used = frame_result.gas().used();
            let gas_refunded = frame_result.gas().refunded();

            accumulated_gas_refund = accumulated_gas_refund.saturating_add(gas_refunded);
            // Subtract only execution gas (intrinsic gas already deducted upfront)
            remaining_gas = remaining_gas.saturating_sub(gas_used);

            final_result = Some(frame_result);
        }

        // All calls succeeded - commit checkpoint to finalize ALL state changes
        evm.ctx().journal_mut().checkpoint_commit();

        // Fix gas accounting for the entire batch
        let mut result =
            final_result.ok_or_else(|| EVMError::Custom("No calls executed".into()))?;

        let total_gas_used = gas_limit - remaining_gas;

        // Create new Gas with correct limit, because Gas does not have a set_limit method
        // (the frame_result has the limit from just the last call)
        let mut corrected_gas = Gas::new(gas_limit);
        corrected_gas.set_spent(total_gas_used);
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
        // Add 2D nonce gas to the initial gas
        let adjusted_gas = InitialAndFloorGas::new(
            init_and_floor_gas.initial_gas + evm.nonce_2d_gas,
            init_and_floor_gas.floor_gas,
        );

        // Check if this is an AA transaction by checking for tempo_tx_env
        if let Some(tempo_tx_env) = evm.ctx().tx().tempo_tx_env.as_ref() {
            // AA transaction - use batch execution with calls field
            let calls = tempo_tx_env.aa_calls.clone();
            self.execute_multi_call(evm, &adjusted_gas, calls)
        } else {
            // Standard transaction - use single-call execution
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
            // TODO(@rakita) could we have a helper function for this logic in revm?
            // For AA transactions, we need to apply the authorization list ourselves
            // because pre_execution::apply_eip7702_auth_list returns early for non-0x04 tx types

            let chain_id = ctx.cfg().chain_id();
            let (tx, journal) = evm.ctx().tx_journal_mut();

            let tempo_tx_env = tx.tempo_tx_env.as_ref().unwrap();
            let mut refunded_accounts = 0;

            for authorization in &tempo_tx_env.tempo_authorization_list {
                let Some(authority) = authorization.authority() else {
                    // invalid signature, we need to skip
                    continue;
                };

                // 1. Verify the chain id is either 0 or the chain's current ID.
                let auth_chain_id = authorization.chain_id;
                if !auth_chain_id.is_zero() && auth_chain_id != U256::from(chain_id) {
                    continue;
                }

                // 2. Verify the `nonce` is less than `2**64 - 1`.
                if authorization.nonce == u64::MAX {
                    continue;
                }

                // 3. Add `authority` to `accessed_addresses` (warm the account)
                let mut authority_acc = journal.load_account_with_code_mut(authority)?;

                // 4. Verify the code of `authority` is either empty or already delegated.
                if let Some(bytecode) = &authority_acc.info.code {
                    // if it is not empty and it is not eip7702
                    if !bytecode.is_empty() && !bytecode.is_eip7702() {
                        continue;
                    }
                }

                // 5. Verify the nonce of `authority` is equal to `nonce`.
                if authorization.nonce != authority_acc.info.nonce {
                    continue;
                }

                // 6. Add gas refund if authority already exists
                if !(authority_acc.is_empty()
                    && authority_acc.is_loaded_as_not_existing_not_touched())
                {
                    refunded_accounts += 1;
                }

                // 7. Set the code of `authority` to be `0xef0100 || address`. This is a delegation designation.
                //  * As a special case, if `address` is `0x0000000000000000000000000000000000000000` do not write the designation.
                //    Clear the accounts code and reset the account's code hash to the empty hash `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
                // 8. Increase the nonce of `authority` by one.
                authority_acc.delegate(*authorization.address());
            }

            let refunded_gas =
                refunded_accounts * (eip7702::PER_EMPTY_ACCOUNT_COST - eip7702::PER_AUTH_BASE_COST);
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
        StorageCtx::enter_evm(journal, block, cfg, || {
            let mut keychain = AccountKeychain::new();
            keychain.set_tx_origin(tx.caller())
        })
        .map_err(|e| EVMError::Custom(e.to_string()))?;

        // Load the fee payer balance
        let account_balance = get_token_balance(journal, self.fee_token, self.fee_payer)?;

        // Load caller's account
        let mut caller_account = journal.load_account_with_code_mut(tx.caller())?.data;

        if caller_account.info.has_no_code_and_nonce() {
            caller_account.set_code(
                DEFAULT_7702_DELEGATE_CODE_HASH,
                Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS),
            );
        }

        let nonce_key = tx
            .tempo_tx_env
            .as_ref()
            .map(|aa| aa.nonce_key)
            .unwrap_or_default();

        // Validate account nonce and code (EIP-3607) using upstream helper
        pre_execution::validate_account_nonce_and_code(
            &caller_account.info,
            tx.nonce(),
            cfg.is_eip3607_disabled(),
            // skip nonce check if 2D nonce is used
            cfg.is_nonce_check_disabled() || !nonce_key.is_zero(),
        )?;

        // modify account nonce and touch the account.
        caller_account.touch();

        let nonce_2d_gas;

        if !nonce_key.is_zero() {
            nonce_2d_gas = StorageCtx::enter_evm(journal, block, cfg, || {
                let mut nonce_manager = NonceManager::new();

                // Calculate 2D nonce gas (only post-AllegroModerato)
                let gas = if cfg.spec.is_allegro_moderato() {
                    calculate_2d_nonce_gas(&nonce_manager, tx.caller(), nonce_key).map_err(
                        |err| match err {
                            TempoPrecompileError::Fatal(err) => EVMError::Custom(err),
                            err => {
                                TempoInvalidTransaction::NonceManagerError(err.to_string()).into()
                            }
                        },
                    )?
                } else {
                    0
                };

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
                            return Err(TempoInvalidTransaction::EthInvalidTransaction(
                                InvalidTransaction::NonceTooHigh {
                                    tx: tx_nonce,
                                    state,
                                },
                            )
                            .into());
                        }
                        Ordering::Less => {
                            return Err(TempoInvalidTransaction::EthInvalidTransaction(
                                InvalidTransaction::NonceTooLow {
                                    tx: tx_nonce,
                                    state,
                                },
                            )
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

                Ok::<_, EVMError<DB::Error, TempoInvalidTransaction>>(gas)
            })?;
        } else {
            nonce_2d_gas = 0;
            // Bump the nonce for calls. Nonce for CREATE will be bumped in `make_create_frame`.
            //
            // Always bump nonce for AA transactions.
            if tx.tempo_tx_env.is_some() || tx.kind().is_call() {
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
                        .map_err(|_| {
                            EVMError::Transaction(
                            TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                                reason:
                                    "Failed to recover access key address from Keychain signature"
                                        .to_string(),
                            },
                        )
                        })?
                };

                // Only allow if authorizing the same key that's being used (same-tx auth+use)
                if access_key_addr != key_auth.key_id {
                    return Err(EVMError::Transaction(
                            TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                                reason: "Access keys cannot authorize other keys. Only the root key can authorize new keys.".to_string(),
                            },
                        ));
                }
            }

            // Validate that the KeyAuthorization is signed by the root account
            let root_account = &tx.caller;

            // Recover the signer of the KeyAuthorization
            let auth_signer = key_auth.recover_signer().map_err(|_| {
                EVMError::Transaction(TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                    reason: "Failed to recover signer from KeyAuthorization signature".to_string(),
                })
            })?;

            // Verify the KeyAuthorization is signed by the root account
            if auth_signer != *root_account {
                return Err(EVMError::Transaction(
                    TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                        reason: format!(
                            "KeyAuthorization must be signed by root account {root_account}, but was signed by {auth_signer}",
                        ),
                    },
                ));
            }

            // Validate KeyAuthorization chain_id (following EIP-7702 pattern)
            // chain_id == 0 allows replay on any chain (wildcard)
            let expected_chain_id = cfg.chain_id();
            if key_auth.chain_id != 0 && key_auth.chain_id != expected_chain_id {
                return Err(EVMError::Transaction(
                    TempoInvalidTransaction::KeyAuthorizationChainIdMismatch {
                        expected: expected_chain_id,
                        got: key_auth.chain_id,
                    },
                ));
            }

            // Now authorize the key in the precompile
            StorageCtx::enter_precompile(journal, block, cfg, |mut keychain: AccountKeychain| {
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
                    return Err(EVMError::Transaction(
                        TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                            reason: format!(
                                "Key expiry {expiry} is in the past (current timestamp: {current_timestamp})"
                            ),
                        },
                    ));
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
                        err => TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                            reason: err.to_string(),
                        }
                        .into(),
                    })
            })?;
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
                    return Err(EVMError::Transaction(
                        TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                            reason: format!(
                                "Keychain user_address {} does not match transaction caller {}",
                                user_address, tx.caller
                            ),
                        },
                    ));
                }

                // Get the access key address (recovered during pool validation and cached)
                keychain_sig
                    .key_id(&tempo_tx_env.signature_hash)
                    .map_err(|_| {
                        EVMError::Transaction(
                            TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                                reason: "Failed to recover access key address from inner signature"
                                    .to_string(),
                            },
                        )
                    })?
            };

            // Check if this transaction includes a KeyAuthorization for the same key
            // If so, skip keychain validation here - the key was just validated and authorized
            let is_authorizing_this_key = tempo_tx_env
                .key_authorization
                .as_ref()
                .map(|key_auth| key_auth.key_id == access_key_addr)
                .unwrap_or(false);

            // Always need to set the transaction key for Keychain signatures
            StorageCtx::enter_precompile(journal, block, cfg, |mut keychain: AccountKeychain| {
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
                        .map_err(|e| {
                            EVMError::Transaction(
                                TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                                    reason: format!("Keychain validation failed: {e:?}"),
                                },
                            )
                        })?;
                }

                // Set the transaction key in the keychain precompile
                // This marks that the current transaction is using an access key
                // The TIP20 precompile will read this during execution to enforce spending limits
                keychain
                    .set_transaction_key(access_key_addr)
                    .map_err(|e| EVMError::Custom(e.to_string()))
            })?;
        }

        if gas_balance_spending.is_zero() {
            return Ok(());
        }

        let checkpoint = journal.checkpoint();

        let result = StorageCtx::enter_evm(journal, &block, cfg, || {
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
                )) => EVMError::Transaction(
                    FeePaymentError::InsufficientFeeTokenBalance {
                        fee: gas_balance_spending,
                        balance: available,
                    }
                    .into(),
                ),

                TempoPrecompileError::Fatal(e) => EVMError::Custom(e),

                _ => EVMError::Transaction(FeePaymentError::Other(err.to_string()).into()),
            })
        } else {
            journal.checkpoint_commit();
            evm.collected_fee = gas_balance_spending;
            evm.nonce_2d_gas = nonce_2d_gas;

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

        // Calculate actual used and refund amounts
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
        let (journal, block) = (&mut context.journaled_state, &context.block);
        let beneficiary = block.beneficiary();

        StorageCtx::enter_evm(&mut *journal, block, &context.cfg, || {
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
        // Pre-AllegroModerato: fee handling (refunds and queuing) done in reimburse_caller via collectFeePostTx.
        // The actual swap and transfer to validator happens in executeBlock at the end of block processing.
        //
        // Post-AllegroModerato: fees are collected and swapped immediately in collectFeePreTx.
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
            let has_keychain_fields =
                aa_env.key_authorization.is_some() || aa_env.signature.is_keychain();

            // Validate that keychain operations are only supported after Allegretto
            if has_keychain_fields && !cfg.spec.is_allegretto() {
                return Err(TempoInvalidTransaction::KeychainOpBeforeAllegretto.into());
            }

            if aa_env.subblock_transaction {
                if !cfg.spec.is_allegretto() {
                    if tx.max_fee_per_gas() > 0 {
                        return Err(
                            TempoInvalidTransaction::SubblockTransactionMustHaveZeroFee.into()
                        );
                    }
                } else if has_keychain_fields {
                    return Err(TempoInvalidTransaction::KeychainOpInSubblockTransaction.into());
                }
            }

            // Validate priority fee for AA transactions using revm's validate_priority_fee_tx
            //
            // Skip basefee check for subblock transactions pre-Allegretto as they must always be free.
            let base_fee = if cfg.is_base_fee_check_disabled()
                || (aa_env.subblock_transaction && !cfg.spec.is_allegretto())
            {
                None
            } else {
                Some(evm.ctx_ref().block().basefee() as u128)
            };

            validation::validate_priority_fee_tx(
                tx.max_fee_per_gas(),
                tx.max_priority_fee_per_gas().unwrap_or_default(),
                base_fee,
                cfg.is_priority_fee_check_disabled(),
            )
            .map_err(TempoInvalidTransaction::EthInvalidTransaction)?;

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
    fn validate_initial_tx_gas(&self, evm: &Self::Evm) -> Result<InitialAndFloorGas, Self::Error> {
        let tx = evm.ctx_ref().tx();

        // Route to appropriate gas calculation based on transaction type
        if tx.tempo_tx_env.is_some() {
            // AA transaction - use batch gas calculation
            validate_aa_initial_tx_gas(evm)
        } else {
            // Standard transaction - use default revm validation
            let spec = evm.ctx_ref().cfg().spec().into();
            Ok(
                validation::validate_initial_tx_gas(tx, spec, evm.ctx.cfg.is_eip7623_disabled())
                    .map_err(TempoInvalidTransaction::EthInvalidTransaction)?,
            )
        }
    }

    fn catch_error(
        &self,
        evm: &mut Self::Evm,
        error: Self::Error,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        // For subblock transactions that failed `collectFeePreTx` call we catch error and treat such transactions as valid.
        if evm.ctx.tx.is_subblock_transaction()
            && evm.cfg.spec.is_allegretto()
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
/// - Key authorization costs (if present, post-AllegroModerato): 30k/32k base + 22k per spending limit
/// - Floor gas calculation (EIP-7623, Prague+)
fn calculate_aa_batch_intrinsic_gas<'a>(
    aa_env: &TempoBatchCallEnv,
    access_list: Option<impl Iterator<Item = &'a AccessListItem>>,
    spec: tempo_chainspec::hardfork::TempoHardfork,
) -> Result<InitialAndFloorGas, TempoInvalidTransaction> {
    let calls = &aa_env.aa_calls;
    let signature = &aa_env.signature;
    let authorization_list = &aa_env.tempo_authorization_list;
    let key_authorization = aa_env.key_authorization.as_ref();
    let mut gas = InitialAndFloorGas::default();

    // 1. Base stipend (21k, once per transaction)
    gas.initial_gas += 21_000;

    // 2. Signature verification gas
    gas.initial_gas += tempo_signature_verification_gas(signature, spec);

    // 3. Per-call overhead: cold account access
    // if the `to` address has not appeared in the call batch before.
    gas.initial_gas += COLD_ACCOUNT_ACCESS_COST * calls.len() as u64;

    // 4. Authorization list costs (EIP-7702)
    gas.initial_gas += authorization_list.len() as u64 * eip7702::PER_EMPTY_ACCOUNT_COST;
    // Add signature verification costs for each authorization
    for auth in authorization_list {
        gas.initial_gas += tempo_signature_verification_gas(auth.signature(), spec);
    }

    // 5. Key authorization costs (if present, post-AllegroModerato)
    if spec.is_allegro_moderato()
        && let Some(key_auth) = key_authorization
    {
        gas.initial_gas += calculate_key_authorization_gas(key_auth);
    }

    // 6. Per-call costs
    let mut total_tokens = 0u64;

    for call in calls {
        // 4a. Calldata gas using revm helper
        let tokens = get_tokens_in_calldata(&call.input, true);
        total_tokens += tokens;

        // 4b. CREATE-specific costs
        if call.to.is_create() {
            // CREATE costs 32000 additional gas
            gas.initial_gas += CREATE; // 32000 gas

            // EIP-3860: Initcode analysis gas using revm helper
            gas.initial_gas += initcode_cost(call.input.len());
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

    // 6. Floor gas  using revm helper
    gas.floor_gas = calc_tx_floor_cost(total_tokens); // tokens * 10 + 21000

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
            return Err(EVMError::Transaction(
                TempoInvalidTransaction::EthInvalidTransaction(
                    InvalidTransaction::CreateInitCodeSizeLimit,
                ),
            ));
        }
    }

    // Calculate batch intrinsic gas using helper
    let spec = evm.ctx_ref().cfg().spec();
    let mut batch_gas = calculate_aa_batch_intrinsic_gas(aa_env, tx.access_list(), spec)?;

    if evm.ctx.cfg.is_eip7623_disabled() {
        batch_gas.floor_gas = 0u64;
    }

    // Validate gas limit is sufficient for initial gas
    if gas_limit < batch_gas.initial_gas {
        return Err(TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
            gas_limit,
            intrinsic_gas: batch_gas.initial_gas,
        }
        .into());
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
    // Address has already been validated
    let token_id = tip20::address_to_token_id_unchecked(token);

    journal.load_account(token)?;
    let balance_slot = TIP20Token::new(token_id).balances.at(sender).slot();
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
        // Add 2D nonce gas to the initial gas (calculated in validate_against_state_and_deduct_caller)
        let adjusted_gas = InitialAndFloorGas::new(
            init_and_floor_gas.initial_gas + evm.nonce_2d_gas,
            init_and_floor_gas.floor_gas,
        );

        // Check if this is an AA transaction by checking for tempo_tx_env
        if let Some(tempo_tx_env) = evm.ctx().tx().tempo_tx_env.as_ref() {
            // AA transaction - use batch execution with calls field
            let calls = tempo_tx_env.aa_calls.clone();
            self.inspect_execute_multi_call(evm, &adjusted_gas, calls)
        } else {
            // Standard transaction - use single-call execution
            self.inspect_execute_single_call(evm, &adjusted_gas)
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
    use crate::{TempoBlockEnv, TempoTxEnv};
    use alloy_primitives::{Address, U256};
    use revm::{
        Context, Journal, MainContext,
        context::CfgEnv,
        database::{CacheDB, EmptyDB},
        interpreter::instructions::utility::IntoU256,
        primitives::hardfork::SpecId,
        state::Account,
    };
    use std::convert::Infallible;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::{DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, TIP_FEE_MANAGER_ADDRESS};

    fn create_test_journal() -> Journal<CacheDB<EmptyDB>> {
        let db = CacheDB::new(EmptyDB::default());
        Journal::new(db)
    }

    #[test]
    fn test_get_token_balance() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        let token = Address::random();
        let account = Address::random();
        let expected_balance = U256::random();

        // Set up initial balance
        let token_id = tip20::address_to_token_id_unchecked(token);
        let balance_slot = TIP20Token::new(token_id).balances.at(account).slot();
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
        let validator_slot = TipFeeManager::new().validator_tokens.at(validator).slot();
        ctx.journaled_state.load_account(TIP_FEE_MANAGER_ADDRESS)?;
        ctx.journaled_state
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                validator_slot,
                validator_fee_token.into_u256(),
            )
            .unwrap();

        {
            let fee_token =
                ctx.journaled_state
                    .get_fee_token(&ctx.tx, validator, user, ctx.cfg.spec)?;
            assert_eq!(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, fee_token);
        }

        // Set user token
        let user_slot = TipFeeManager::new().user_tokens.at(user).slot();
        ctx.journaled_state
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                user_slot,
                user_fee_token.into_u256(),
            )
            .unwrap();

        {
            let fee_token =
                ctx.journaled_state
                    .get_fee_token(&ctx.tx, validator, user, ctx.cfg.spec)?;
            assert_eq!(user_fee_token, fee_token);
        }

        // Set tx fee token
        ctx.tx.fee_token = Some(tx_fee_token);
        let fee_token =
            ctx.journaled_state
                .get_fee_token(&ctx.tx, validator, user, ctx.cfg.spec)?;
        assert_eq!(tx_fee_token, fee_token);

        Ok(())
    }

    #[test]
    fn test_delegate_code_hash() {
        let mut account = Account::default();
        account
            .info
            .set_code(Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS));
        assert_eq!(account.info.code_hash, DEFAULT_7702_DELEGATE_CODE_HASH);
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

        // AA should be: normal tx + per-call overhead (COLD_ACCOUNT_ACCESS_COST)
        let expected_initial = normal_tx_gas.initial_gas + COLD_ACCOUNT_ACCESS_COST;
        assert_eq!(
            aa_gas.initial_gas, expected_initial,
            "AA secp256k1 single call should match normal tx + per-call overhead"
        );
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
            None::<std::iter::Empty<&AccessListItem>>,
            spec,
        )
        .unwrap();

        // Calculate base gas for a single normal tx
        let base_tx_gas = calculate_initial_tx_gas(spec.into(), &calldata, false, 0, 0, 0);

        // For 3 calls: base (21k) + 3*calldata + 3*per-call overhead
        // = 21k + 2*(calldata cost) + 3*COLD_ACCOUNT_ACCESS_COST
        let expected = base_tx_gas.initial_gas
            + 2 * (calldata.len() as u64 * 16)
            + 3 * COLD_ACCOUNT_ACCESS_COST;
        assert_eq!(
            gas.initial_gas, expected,
            "Should charge per-call overhead for each call"
        );
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

        let tempo_spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_spec,
        )
        .unwrap();

        // Calculate base gas for normal tx
        let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

        // Expected: normal tx + P256_VERIFY_GAS + per-call overhead
        let expected = base_gas.initial_gas + P256_VERIFY_GAS + COLD_ACCOUNT_ACCESS_COST;
        assert_eq!(
            gas.initial_gas, expected,
            "Should include P256 verification gas"
        );
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

        let tempo_spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_spec,
        )
        .unwrap();

        // Calculate expected using revm's function for CREATE tx
        let base_gas = calculate_initial_tx_gas(
            spec, &initcode, true, // is_create = true
            0, 0, 0,
        );

        // AA CREATE should be: normal CREATE + per-call overhead
        let expected = base_gas.initial_gas + COLD_ACCOUNT_ACCESS_COST;
        assert_eq!(gas.initial_gas, expected, "Should include CREATE costs");
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

        let spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let res = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            None::<std::iter::Empty<&AccessListItem>>,
            spec,
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
        let tempo_spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_spec,
        )
        .unwrap();

        // Calculate expected using revm's function
        let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

        // Expected: normal tx + per-call overhead (no access list in this test)
        let expected = base_gas.initial_gas + COLD_ACCOUNT_ACCESS_COST;
        assert_eq!(
            gas.initial_gas, expected,
            "Should match normal tx + per-call overhead"
        );
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

        let tempo_spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env,
            None::<std::iter::Empty<&AccessListItem>>,
            tempo_spec,
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

        // Use AllegroModerato to test the key authorization gas schedule
        let spec = tempo_chainspec::hardfork::TempoHardfork::AllegroModerato;

        // Calculate gas WITH key authorization
        let gas_with_key_auth = calculate_aa_batch_intrinsic_gas(
            &aa_env_with_key_auth,
            None::<std::iter::Empty<&AccessListItem>>,
            spec,
        )
        .unwrap();

        // Calculate gas WITHOUT key authorization
        let gas_without_key_auth = calculate_aa_batch_intrinsic_gas(
            &aa_env_without_key_auth,
            None::<std::iter::Empty<&AccessListItem>>,
            spec,
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
        let base_tx_gas = calculate_initial_tx_gas(spec.into(), &calldata, false, 0, 0, 0);
        let expected_without = base_tx_gas.initial_gas + COLD_ACCOUNT_ACCESS_COST;
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
    fn test_2d_nonce_gas_schedule() {
        let mut journal = create_test_journal();
        let block = TempoBlockEnv::default();
        let cfg = CfgEnv::<TempoHardfork>::default();
        let caller = Address::random();

        // Protocol nonce (key 0): always 0 gas
        let gas = StorageCtx::enter_evm(&mut journal, &block, &cfg, || {
            let nm = NonceManager::new();
            Ok::<_, EVMError<Infallible, TempoInvalidTransaction>>(
                calculate_2d_nonce_gas(&nm, caller, U256::from(0)).unwrap(),
            )
        })
        .unwrap();
        assert_eq!(gas, 0);

        // New key (nonce == 0): 22,100 gas (cold SLOAD + SSTORE set)
        let gas = StorageCtx::enter_evm(&mut journal, &block, &cfg, || {
            let nm = NonceManager::new();
            Ok::<_, EVMError<Infallible, TempoInvalidTransaction>>(
                calculate_2d_nonce_gas(&nm, caller, U256::from(1)).unwrap(),
            )
        })
        .unwrap();
        assert_eq!(gas, NEW_NONCE_KEY_GAS);

        // Increment the nonce to make it an existing key
        StorageCtx::enter_evm(&mut journal, &block, &cfg, || {
            NonceManager::new()
                .increment_nonce(caller, U256::from(1))
                .unwrap();
            Ok::<_, EVMError<Infallible, TempoInvalidTransaction>>(())
        })
        .unwrap();

        // Existing key (nonce > 0): 5,000 gas (cold SLOAD + warm SSTORE reset)
        let gas = StorageCtx::enter_evm(&mut journal, &block, &cfg, || {
            let nm = NonceManager::new();
            Ok::<_, EVMError<Infallible, TempoInvalidTransaction>>(
                calculate_2d_nonce_gas(&nm, caller, U256::from(1)).unwrap(),
            )
        })
        .unwrap();
        assert_eq!(gas, EXISTING_NONCE_KEY_GAS);
    }
}
