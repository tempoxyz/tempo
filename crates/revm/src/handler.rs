//! Tempo EVM Handler implementation.

use std::fmt::Debug;

use alloy_primitives::{Address, B256, Bytes, TxKind, U256, b256};
use reth_evm::{
    EvmInternals,
    revm::{
        Database,
        context::{
            Block, Cfg, ContextTr, Host, JournalTr, Transaction,
            result::{EVMError, ExecutionResult, HaltReason, InvalidTransaction},
        },
        handler::{EvmTr, FrameResult, FrameTr, Handler, validation},
        inspector::{Inspector, InspectorHandler},
        interpreter::{
            InitialAndFloorGas, instructions::utility::IntoAddress, interpreter::EthInterpreter,
        },
        state::Bytecode,
    },
};
use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        EvmStorageProvider,
        nonce::{self, NonceManager},
        storage::slots::mapping_slot,
        tip_fee_manager::{self, TipFeeManager},
        tip20,
    },
};
use tempo_primitives::AA_TX_TYPE_ID;
use tracing::trace;

use crate::{TempoEvm, TempoInvalidTransaction, evm::TempoContext};

/// Restores the transaction environment to its original state.
///
/// Used in multi-call execution to reset TxEnv after batch processing.
fn restore_tx_env<DB, I>(
    evm: &mut TempoEvm<DB, I>,
    kind: TxKind,
    value: U256,
    data: Bytes,
    gas_limit: u64,
) where
    DB: reth_evm::Database,
{
    let tx = &mut evm.ctx().tx;
    tx.inner.kind = kind;
    tx.inner.value = value;
    tx.inner.data = data;
    tx.inner.gas_limit = gas_limit;
}

/// Additional gas for P256 signature verification
/// P256 precompile cost (6900 from EIP-7951) + 1100 for extra signature size - ecrecover savings (3000)
const P256_VERIFY_GAS: u64 = 5_000;

/// Gas cost for using an existing user nonce key (sequence > 0)
/// Equivalent to cold SSTORE on non-zero slot (2,900 base + 2,100 cold access)
const COLD_SSTORE_GAS: u64 = 5_000;

/// Gas multiplier for each new nonce key
/// Progressive pricing to prevent state bloat
const NEW_NONCE_KEY_MULTIPLIER: u64 = 20_000;

/// Calldata gas cost per zero byte
const CALLDATA_ZERO_BYTE_GAS: u64 = 4;

/// Calldata gas cost per non-zero byte
const CALLDATA_NONZERO_BYTE_GAS: u64 = 16;

/// Hashed account code of default 7702 delegate deployment
const DEFAULT_7702_DELEGATE_CODE_HASH: B256 =
    b256!("e7b3e4597bdbdd0cc4eb42f9b799b580f23068f54e472bb802cb71efb1570482");

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

impl<DB: reth_evm::Database, I> TempoEvmHandler<DB, I> {
    fn load_fee_fields(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
    ) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
        self.fee_token = get_fee_token(evm.ctx_mut())?;
        trace!(fee_token=%self.fee_token, caller=%evm.ctx().caller(), beneficiary=%evm.ctx().beneficiary(), "loaded fee token");
        self.fee_payer = evm.ctx().tx().fee_payer()?;

        Ok(())
    }
}

impl<DB, I> TempoEvmHandler<DB, I>
where
    DB: reth_evm::Database,
{
    /// Executes a standard single-call transaction using the default handler logic.
    ///
    /// This calls the same helper methods used by the default Handler::execution() implementation.
    fn execute_single_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>> {
        // Standard execution flow from Handler::execution() default impl
        let gas_limit = evm.ctx().tx().gas_limit() - init_and_floor_gas.initial_gas;

        // Create first frame action
        let first_frame_input = self.first_frame_input(evm, gas_limit)?;

        // Run execution loop
        let mut frame_result = self.run_exec_loop(evm, first_frame_input)?;

        // Handle last frame result
        self.last_frame_result(evm, &mut frame_result)?;

        Ok(frame_result)
    }

    /// Executes a multi-call AA transaction atomically.
    ///
    /// This method provides atomic batch execution for AA transactions with multiple calls:
    /// 1. Creates a checkpoint before executing any calls
    /// 2. Executes each call sequentially, updating gas tracking
    /// 3. If ANY call fails, reverts ALL state changes atomically
    /// 4. If all calls succeed, commits ALL state changes atomically
    ///
    /// The atomicity is guaranteed by the checkpoint/revert/commit mechanism:
    /// - Each individual call creates its own internal checkpoint
    /// - The outer checkpoint (created here) captures state before any calls execute
    /// - Reverting the outer checkpoint undoes all nested changes
    fn execute_multi_call(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
        calls: Vec<tempo_primitives::transaction::Call>,
    ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>> {
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

        for (idx, call) in calls.iter().enumerate() {
            trace!(
                call_idx = idx,
                to = ?call.to,
                value = ?call.value,
                input_len = call.input.len(),
                remaining_gas,
                "executing call"
            );

            // Update TxEnv to point to this specific call
            {
                let tx = &mut evm.ctx().tx;
                tx.inner.kind = call.to;
                tx.inner.value = call.value;
                tx.inner.data = call.input.clone();
                tx.inner.gas_limit = remaining_gas + init_and_floor_gas.initial_gas;
            }

            // Execute this call using standard single-call execution
            let frame_result = self.execute_single_call(evm, init_and_floor_gas)?;

            // Check if call succeeded
            let instruction_result = frame_result.instruction_result();
            if !instruction_result.is_ok() {
                trace!(
                    call_idx = idx,
                    result = ?instruction_result,
                    gas_used = frame_result.gas().used(),
                    "call failed, reverting all state changes"
                );

                // Revert checkpoint - rolls back ALL state changes from ALL calls
                evm.ctx().journal_mut().checkpoint_revert(checkpoint);

                // Restore original TxEnv
                restore_tx_env(evm, original_kind, original_value, original_data, gas_limit);

                // Return the failure result (gas accounting already correct for failed call)
                return Ok(frame_result);
            }

            // Call succeeded - accumulate gas usage and refunds
            let gas_used = frame_result.gas().used();
            let gas_refunded = frame_result.gas().refunded();

            accumulated_gas_refund = accumulated_gas_refund.saturating_add(gas_refunded);
            remaining_gas = remaining_gas.saturating_sub(gas_used);

            trace!(
                call_idx = idx,
                gas_used, gas_refunded, remaining_gas, accumulated_gas_refund, "call succeeded"
            );

            final_result = Some(frame_result);
        }

        // All calls succeeded - commit checkpoint to finalize ALL state changes
        evm.ctx().journal_mut().checkpoint_commit();

        trace!(
            remaining_gas,
            accumulated_gas_refund, "all calls succeeded, committing state"
        );

        // Restore original TxEnv
        restore_tx_env(evm, original_kind, original_value, original_data, gas_limit);

        // Fix gas accounting for the entire batch
        let mut result =
            final_result.ok_or_else(|| EVMError::Custom("No calls executed".into()))?;

        let total_gas_used = gas_limit - remaining_gas;
        let gas = result.gas_mut();
        gas.set_spent(total_gas_used);
        gas.set_refund(accumulated_gas_refund);

        Ok(result)
    }
}

impl<DB, I> Default for TempoEvmHandler<DB, I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<DB, I> Handler for TempoEvmHandler<DB, I>
where
    DB: reth_evm::Database,
{
    type Evm = TempoEvm<DB, I>;
    type Error = EVMError<DB::Error, TempoInvalidTransaction>;
    type HaltReason = HaltReason;

    #[inline]
    fn run(
        &mut self,
        evm: &mut Self::Evm,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        self.load_fee_fields(evm)?;

        // Standard handler flow - execution() handles single vs multi-call dispatch
        match self.run_without_catch_error(evm) {
            Ok(output) => Ok(output),
            Err(err) => {
                trace!(?err, caller=%evm.ctx().caller(), "failed to transact");
                self.catch_error(evm, err)
            }
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
        // Check transaction type to determine execution path
        let tx_type = evm.ctx().tx().tx_type();

        if tx_type == AA_TX_TYPE_ID {
            // AA transaction - use batch execution with calls field
            let calls = evm
                .ctx()
                .tx()
                .aa_calls
                .clone()
                .ok_or_else(|| EVMError::Custom("AA transaction missing calls field".into()))?;

            trace!(num_calls = calls.len(), "executing AA transaction");
            self.execute_multi_call(evm, init_and_floor_gas, calls)
        } else {
            // Standard transaction - use single-call execution
            self.execute_single_call(evm, init_and_floor_gas)
        }
    }

    #[inline]
    fn validate_against_state_and_deduct_caller(
        &self,
        evm: &mut Self::Evm,
    ) -> Result<(), Self::Error> {
        // modified inlined ethereum state validation logic
        // Extract values before mutable borrow
        let beneficiary = evm.ctx().beneficiary();
        let chain_id = evm.ctx().chain_id().to::<u64>();

        let context = evm.ctx();
        let basefee = context.block().basefee() as u128;
        let blob_price = context.block().blob_gasprice().unwrap_or_default();
        let block_timestamp = context.block().timestamp().to::<u64>(); // Extract timestamp early
        let is_balance_check_disabled = context.cfg().is_balance_check_disabled();
        let is_eip3607_disabled = context.cfg().is_eip3607_disabled();
        let is_nonce_check_disabled = context.cfg().is_nonce_check_disabled();
        let tx_type = context.tx().tx_type();
        let value = context.tx().value();
        let caller_addr = context.tx().caller(); // Extract caller address early

        let (tx, journal) = (&mut context.tx, &mut context.journaled_state);

        // Load the fee payer balance
        let account_balance = get_token_balance(journal, self.fee_token, self.fee_payer)?;

        // Log AA transaction details
        if tx_type == AA_TX_TYPE_ID {
            tracing::info!(
                caller = %caller_addr,
                nonce_key = tx.nonce_key.unwrap_or(0),
                nonce = tx.nonce(),
                fee_payer = %self.fee_payer,
                fee_token = ?self.fee_token,
                "REVM handler processing AA transaction"
            );
        }

        // For AA transactions with user nonces, validate 2D nonce before loading account (avoids borrow conflicts)
        if !is_nonce_check_disabled && tx_type == AA_TX_TYPE_ID {
            let nonce_key = tx.nonce_key.unwrap_or(0);
            if nonce_key != 0 {
                tracing::info!(
                    nonce_key,
                    nonce = tx.nonce(),
                    "Validating 2D nonce from precompile"
                );
                validate_2d_nonce(journal, caller_addr, nonce_key, tx.nonce())?;
            }
        }

        // Load caller's account
        let caller_account = journal.load_account_code(caller_addr)?.data;

        let account_info = &mut caller_account.info;
        if account_info.has_no_code_and_nonce() {
            account_info.set_code_and_hash(
                Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS),
                DEFAULT_7702_DELEGATE_CODE_HASH,
            );
        }

        // Step 1: Validate code (EIP-3607) - same for all transaction types
        if !is_eip3607_disabled {
            let bytecode = match caller_account.info.code.as_ref() {
                Some(code) => code,
                None => &Bytecode::default(),
            };
            // Allow EOAs whose code is a valid delegation designation
            if !bytecode.is_empty() && !bytecode.is_eip7702() {
                return Err(EVMError::Transaction(
                    TempoInvalidTransaction::EthInvalidTransaction(
                        InvalidTransaction::RejectCallerWithCode,
                    ),
                ));
            }
        }

        // Step 2: Validate protocol nonce (for standard txs and AA txs with key=0)
        if !is_nonce_check_disabled {
            let should_validate_protocol_nonce = if tx_type == AA_TX_TYPE_ID {
                // AA transactions: only validate protocol nonce if key=0
                tx.nonce_key.unwrap_or(0) == 0
            } else {
                // Standard transactions: always validate protocol nonce
                true
            };

            if should_validate_protocol_nonce {
                let state_nonce = caller_account.info.nonce;
                let tx_nonce = tx.nonce();
                if tx_nonce != state_nonce {
                    return Err(EVMError::Transaction(
                        TempoInvalidTransaction::EthInvalidTransaction(if tx_nonce > state_nonce {
                            InvalidTransaction::NonceTooHigh {
                                tx: tx_nonce,
                                state: state_nonce,
                            }
                        } else {
                            InvalidTransaction::NonceTooLow {
                                tx: tx_nonce,
                                state: state_nonce,
                            }
                        }),
                    ));
                }
            }
        }

        // Step 3: Time window validation for AA transactions
        if tx_type == AA_TX_TYPE_ID
            && let Some(valid_before) = tx.valid_before
        {
            validate_time_window(tx.valid_after, valid_before, block_timestamp)?;
        }
        // Note: Signature verification happens during recover_signer() before entering the pool

        let max_balance_spending = tx
            .max_balance_spending()
            .map_err(TempoInvalidTransaction::EthInvalidTransaction)?;
        let effective_balance_spending = tx
            .effective_balance_spending(basefee, blob_price)
            .expect("effective balance is always smaller than max balance so it can't overflow");

        caller_account.mark_touch();

        // Bump the nonce for calls. Nonce for CREATE will be bumped in `make_create_frame`.
        if tx.kind().is_call() {
            if tx_type == AA_TX_TYPE_ID {
                let nonce_key = tx.nonce_key.unwrap_or(0);
                if nonce_key == 0 {
                    // Protocol nonce (key 0): increment account nonce
                    caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
                } else {
                    // User nonce (key 1-N): increment 2D nonce in precompile storage
                    // Only increment if nonce checking is enabled to avoid multiple increments
                    if !is_nonce_check_disabled {
                        // Must release caller_account before calling increment function to avoid borrow conflicts
                        let _ = caller_account;

                        // Increment using EvmStorageProvider (same pattern as FeeManager)
                        increment_2d_nonce(
                            journal,
                            &context.block,
                            chain_id,
                            caller_addr,
                            nonce_key,
                        )?;
                    }
                }
            } else {
                // Non-AA transactions always increment protocol nonce
                caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
            }
        }

        // Check if account has enough balance for `gas_limit * max_fee`` and value transfer.
        // Transfer will be done inside `*_inner` functions.
        if is_balance_check_disabled {
            // ignore balance check.
        } else if account_balance < max_balance_spending {
            return Err(EVMError::Transaction(
                TempoInvalidTransaction::EthInvalidTransaction(
                    InvalidTransaction::LackOfFundForMaxFee {
                        fee: Box::new(max_balance_spending),
                        balance: Box::new(account_balance),
                    },
                ),
            ));
        } else if !max_balance_spending.is_zero() {
            // Call collectFeePreTx on TipFeeManager precompile
            let gas_balance_spending = effective_balance_spending - value;

            // Create storage provider wrapper around journal
            let internals = EvmInternals::new(journal, &context.block);
            let mut storage_provider = EvmStorageProvider::new(internals, chain_id);
            let mut fee_manager =
                TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, beneficiary, &mut storage_provider);

            // Call the precompile function to collect the fee
            // We specify the `to_addr` to account for the case where the to address is a tip20
            // token and the fee token is not set for the specified caller.
            // In this case, the collect_fee_pre_tx fn will set the fee token as the `to_addr`
            let to_addr = tx.kind().into_to().unwrap_or_default();
            fee_manager
                .collect_fee_pre_tx(
                    self.fee_payer,
                    self.fee_token,
                    to_addr,
                    gas_balance_spending,
                )
                .map_err(|e| {
                    // Map fee collection errors to transaction validation errors since they
                    // indicate the transaction cannot be included (e.g., insufficient liquidity
                    // in FeeAMM pool for fee swaps)
                    use tempo_precompiles::contracts::IFeeManager;
                    match e {
                        IFeeManager::IFeeManagerErrors::InsufficientLiquidity(_) => {
                            EVMError::Transaction(
                                TempoInvalidTransaction::InsufficientAmmLiquidity {
                                    fee: Box::new(gas_balance_spending),
                                },
                            )
                        }
                        IFeeManager::IFeeManagerErrors::InsufficientFeeTokenBalance(_) => {
                            EVMError::Transaction(
                                TempoInvalidTransaction::InsufficientFeeTokenBalance {
                                    fee: Box::new(gas_balance_spending),
                                    balance: Box::new(account_balance),
                                },
                            )
                        }
                        _ => EVMError::Custom(format!("{e:?}")),
                    }
                })?;
        }

        // journal.caller_accounting_journal_entry(tx.caller(), old_balance, tx.kind().is_call());
        Ok(())
    }

    fn reimburse_caller(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        // Call collectFeePostTx on TipFeeManager precompile
        let context = evm.ctx();
        let tx = context.tx();
        let basefee = context.block().basefee() as u128;
        let effective_gas_price = tx.effective_gas_price(basefee);
        let gas = exec_result.gas();
        let chain_id = context.cfg().chain_id;

        // Calculate actual used and refund amounts
        let gas_used = gas.used();
        let actual_used = U256::from(gas_used).saturating_mul(U256::from(effective_gas_price));
        let refund_amount = U256::from(
            effective_gas_price.saturating_mul((gas.remaining() + gas.refunded() as u64) as u128),
        );

        // Create storage provider and fee manager
        let (journal, block) = (&mut context.journaled_state, &context.block);
        let internals = EvmInternals::new(journal, block);
        let mut storage_provider = EvmStorageProvider::new(internals, chain_id);
        let mut fee_manager = TipFeeManager::new(
            TIP_FEE_MANAGER_ADDRESS,
            block.beneficiary,
            &mut storage_provider,
        );

        if !actual_used.is_zero() || !refund_amount.is_zero() {
            // Call collectFeePostTx (handles both refund and fee queuing)
            fee_manager
                .collect_fee_post_tx(self.fee_payer, actual_used, refund_amount, self.fee_token)
                .map_err(|e| EVMError::Custom(format!("{e:?}")))?;
        }
        Ok(())
    }

    #[inline]
    fn reward_beneficiary(
        &self,
        _evm: &mut Self::Evm,
        _exec_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        // All fee handling (refunds and queuing) is done in reimburse_caller via collectFeePostTx
        // The actual swap and transfer to validator happens in executeBlock at the end of block processing
        Ok(())
    }

    /// Validates environment and transaction gas, with custom handling for AA transactions.
    ///
    /// Overrides the default validate() to enable state access for calculating exact nonce key gas.
    /// AA transactions require reading nonce state to determine if a key is new or existing.
    #[inline]
    fn validate(&self, evm: &mut Self::Evm) -> Result<InitialAndFloorGas, Self::Error> {
        // First, validate environment (block/tx params)
        self.validate_env(evm)?;

        // Then validate and calculate intrinsic gas
        validate_aa_initial_tx_gas(evm)
    }
}

/// Validates and calculates initial transaction gas for AA transactions with state access.
///
/// For AA transactions (type 0x5), calculates intrinsic gas based on:
/// - Signature type (secp256k1: 21k, P256: 26k, WebAuthn: 26k + calldata)
/// - Nonce key usage (protocol: 0, existing: 5k, new: num_active * 20k)
///
/// For non-AA transactions, uses the default Ethereum calculation.
///
/// See aa-spec.md:353-410 for complete gas schedule pseudocode.
fn validate_aa_initial_tx_gas<DB, I>(
    evm: &mut TempoEvm<DB, I>,
) -> Result<InitialAndFloorGas, EVMError<DB::Error, TempoInvalidTransaction>>
where
    DB: reth_evm::Database,
{
    let tx_type = evm.ctx_ref().tx().tx_type();
    let spec = evm.ctx_ref().cfg().spec();

    // For non-AA transactions, use default validation
    if tx_type != AA_TX_TYPE_ID {
        let tx = evm.ctx_ref().tx();
        return validation::validate_initial_tx_gas(tx, spec).map_err(From::from);
    }

    // For AA transactions, extract all needed data first
    let (nonce_key, nonce, signature, caller_addr, gas_limit) = {
        let tx = evm.ctx_ref().tx();
        (
            tx.nonce_key.unwrap_or(0),
            tx.nonce(),
            tx.signature.clone(),
            tx.caller(),
            tx.gas_limit(),
        )
    };

    // Get signature bytes
    let sig_bytes =
        signature
            .as_ref()
            .ok_or_else(|| TempoInvalidTransaction::InvalidWebAuthnSignature {
                reason: "Missing signature for AA transaction".into(),
            })?;

    // Start with the standard intrinsic gas calculation (calldata, access list, etc.)
    let standard_gas = {
        let tx = evm.ctx_ref().tx();
        validation::validate_initial_tx_gas(tx, spec)
            .map_err(|e: InvalidTransaction| TempoInvalidTransaction::EthInvalidTransaction(e))?
    };

    // Calculate AA-specific additional gas (signature + nonce key costs)

    // Calculate additional signature verification gas beyond the base 21k
    // secp256k1 (64 or 65 bytes): 0 additional (already included in base)
    // P256 (129 bytes): 5,000 additional
    // WebAuthn (>129 bytes): 5,000 + calldata gas for variable data
    let additional_signature_gas = match sig_bytes.len() {
        64 | 65 => {
            // secp256k1 signature - no additional gas needed
            0
        }
        129 => {
            // P256 signature - add P256 verification gas
            P256_VERIFY_GAS
        }
        len if len > 129 && len <= 2048 => {
            // WebAuthn signature format: webauthn_data || r (32) || s (32) || pubKeyX (32) || pubKeyY (32)
            // Charge calldata gas for variable webauthn_data (everything except last 128 bytes)
            let webauthn_data = &sig_bytes[..sig_bytes.len() - 128];
            // Calculate calldata gas inline
            let mut webauthn_data_gas = 0u64;
            for &byte in webauthn_data {
                webauthn_data_gas = webauthn_data_gas.saturating_add(if byte == 0 {
                    CALLDATA_ZERO_BYTE_GAS
                } else {
                    CALLDATA_NONZERO_BYTE_GAS
                });
            }
            P256_VERIFY_GAS + webauthn_data_gas
        }
        _ => {
            return Err(TempoInvalidTransaction::InvalidWebAuthnSignature {
                reason: format!("Invalid signature length: {}", sig_bytes.len()),
            }
            .into());
        }
    };

    // Calculate nonce key gas exactly as per spec pseudocode (lines 390-404)
    let nonce_key_gas = if nonce_key == 0 {
        // Protocol nonce (backward compatible)
        0
    } else {
        // User nonce key - read from state to determine if new or existing
        let journal = &mut evm.ctx().journaled_state;

        // Inline implementation from gas::calculate_nonce_key_gas
        // Ensure nonce precompile is loaded
        journal
            .load_account(NONCE_PRECOMPILE_ADDRESS)
            .map_err(EVMError::Database)?;

        // Compute storage slot for nonces[account][nonce_key]
        let storage_key = nonce::slots::nonce_slot(&caller_addr, nonce_key);

        // Read current sequence from storage (matches spec: current_sequence = get_nonce())
        let stored_sequence = journal
            .sload(NONCE_PRECOMPILE_ADDRESS, storage_key)
            .map_err(EVMError::Database)?
            .data;

        if stored_sequence.is_zero() {
            // New nonce key (sequence transitioning from 0 to 1)
            // Progressive pricing based on number of active keys
            // Inline get_active_nonce_key_count
            let count_storage_key = nonce::slots::active_key_count_slot(&caller_addr);
            let num_active_keys = journal
                .sload(NONCE_PRECOMPILE_ADDRESS, count_storage_key)
                .map_err(EVMError::Database)?
                .data
                .to::<u64>();

            num_active_keys * NEW_NONCE_KEY_MULTIPLIER
        } else {
            // Existing nonce key (sequence > 0)
            // Fixed cost for cold SSTORE
            COLD_SSTORE_GAS
        }
    };

    // Total intrinsic gas = standard_gas + additional_signature_gas + nonce_key_gas
    let total_intrinsic_gas = standard_gas
        .initial_gas
        .saturating_add(additional_signature_gas)
        .saturating_add(nonce_key_gas);

    // Validate gas limit is sufficient
    if gas_limit < total_intrinsic_gas {
        return Err(TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
            gas_limit,
            intrinsic_gas: total_intrinsic_gas,
        }
        .into());
    }

    trace!(
        signature_len = sig_bytes.len(),
        nonce_key,
        nonce,
        additional_signature_gas,
        nonce_key_gas,
        standard_gas = standard_gas.initial_gas,
        total_intrinsic_gas,
        "Calculated AA transaction intrinsic gas"
    );

    Ok(InitialAndFloorGas::new(
        total_intrinsic_gas,
        standard_gas.floor_gas,
    ))
}

/// Looks up the user's fee token in the `TIPFeemanager` contract.
///
/// If no fee token is set for the user, or the fee token is the zero address, the returned fee token will be the validator's fee token.
pub fn get_fee_token<DB>(
    ctx: &mut TempoContext<DB>,
) -> Result<Address, EVMError<DB::Error, TempoInvalidTransaction>>
where
    DB: Database,
{
    if let Some(fee_token) = ctx.tx().fee_token {
        return Ok(fee_token);
    }

    let user_slot = mapping_slot(ctx.tx().fee_payer()?, tip_fee_manager::slots::USER_TOKENS);
    // ensure TIP_FEE_MANAGER_ADDRESS is loaded
    ctx.journal_mut().load_account(TIP_FEE_MANAGER_ADDRESS)?;
    let user_fee_token = ctx
        .journal_mut()
        .sload(TIP_FEE_MANAGER_ADDRESS, user_slot)?
        .data
        .into_address();

    if user_fee_token.is_zero() {
        let validator_slot =
            mapping_slot(ctx.beneficiary(), tip_fee_manager::slots::VALIDATOR_TOKENS);
        let validator_fee_token = ctx
            .journal_mut()
            .sload(TIP_FEE_MANAGER_ADDRESS, validator_slot)?
            .data
            .into_address();
        trace!(sender=%ctx.caller(), validator=%ctx.beneficiary(), %validator_fee_token, "loaded validator fee token");

        Ok(validator_fee_token)
    } else {
        Ok(user_fee_token)
    }
}

pub fn get_token_balance<JOURNAL>(
    journal: &mut JOURNAL,
    token: Address,
    sender: Address,
) -> Result<U256, <JOURNAL::Database as Database>::Error>
where
    JOURNAL: JournalTr,
{
    journal.load_account(token)?;
    let balance_slot = mapping_slot(sender, tip20::slots::BALANCES);
    let balance = journal.sload(token, balance_slot)?.data;

    Ok(balance)
}

/// Transfers `amount` from the sender's to the receivers balance inside the token contract.
///
/// Caution: assumes the `token` address is already loaded
pub fn transfer_token<JOURNAL>(
    journal: &mut JOURNAL,
    token: Address,
    sender: Address,
    recipient: Address,
    amount: U256,
) -> Result<(), <JOURNAL::Database as Database>::Error>
where
    JOURNAL: JournalTr,
{
    // Ensure the token account is touched
    journal.touch_account(token);
    // Load sender's current balance
    // NOTE: it is important to note that this expects the token to be a tip20 token with BALANCES
    // slot at slot 10
    let sender_slot = mapping_slot(sender, tip20::slots::BALANCES);
    let sender_balance = journal.sload(token, sender_slot)?.data;

    // Check sender has sufficient balance
    if amount > sender_balance {
        todo!()
    }

    // Update sender balance
    let new_sender_balance = sender_balance
        .checked_sub(amount)
        .expect("TODO: handle err");
    journal.sstore(token, sender_slot, new_sender_balance)?;

    // Update recipient balance or burn
    if recipient != Address::ZERO {
        let recipient_slot = mapping_slot(recipient, tip20::slots::BALANCES);
        let recipient_balance = journal.sload(token, recipient_slot)?.data;
        let new_recipient_balance = recipient_balance
            .checked_add(amount)
            .expect("TODO: handle error");
        journal.sstore(token, recipient_slot, new_recipient_balance)?;
    }

    Ok(())
}

impl<DB, I> InspectorHandler for TempoEvmHandler<DB, I>
where
    DB: reth_evm::Database,
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
}

/// Validates 2D nonce for AA transactions (validation phase only)
///
/// AA transactions use a 2D nonce system with nonce_key and nonce:
/// - nonce_key 0: Protocol nonce (stored in account state, validated separately)
/// - nonce_key 1-N: User nonces (stored in NONCE_PRECOMPILE_ADDRESS)
///
/// This function ONLY validates that the nonce matches the expected value.
/// It does NOT increment the nonce - that happens later in the execution phase.
///
/// This separation is critical because validation can run multiple times
/// (during transaction pool validation, block building, etc.) on fresh state,
/// but the increment should only happen once during actual execution.
pub fn validate_2d_nonce<JOURNAL>(
    journal: &mut JOURNAL,
    caller: Address,
    nonce_key: u64,
    nonce: u64,
) -> Result<(), TempoInvalidTransaction>
where
    JOURNAL: JournalTr,
{
    // Protocol nonce (key 0) is validated through standard nonce check
    if nonce_key == 0 {
        return Ok(());
    }

    // For user nonce keys (1-N), read from nonce precompile storage
    journal
        .load_account(NONCE_PRECOMPILE_ADDRESS)
        .map_err(|e| TempoInvalidTransaction::InvalidWebAuthnSignature {
            reason: format!("Failed to load nonce precompile: {e:?}"),
        })?;

    // Compute storage slot for nonces[caller][nonce_key]
    let storage_key = nonce::slots::nonce_slot(&caller, nonce_key);

    let stored_sequence = journal
        .sload(NONCE_PRECOMPILE_ADDRESS, storage_key)
        .map_err(|e| TempoInvalidTransaction::InvalidWebAuthnSignature {
            reason: format!("Failed to read nonce from storage: {e:?}"),
        })?
        .data;

    tracing::info!(
        caller = %caller,
        nonce_key = nonce_key,
        stored_sequence = %stored_sequence,
        nonce = nonce,
        "2D nonce validation: checking stored vs expected"
    );

    // Validate sequence matches
    let expected_sequence = U256::from(nonce);
    if stored_sequence != expected_sequence {
        return Err(TempoInvalidTransaction::Invalid2DNonce {
            nonce_key,
            expected: stored_sequence.to::<u64>(),
            actual: nonce,
        });
    }

    tracing::info!("2D nonce validation passed");
    Ok(())
}

/// Increments 2D nonce for AA transactions
///
/// Uses the same EvmStorageProvider pattern as FeeManager to ensure consistent
/// storage access. When called during pre-execution (like protocol nonce),
/// the increment happens regardless of transaction success/failure.
///
/// This must be called AFTER the caller account is loaded, in the same journal
/// context as other state operations.
fn increment_2d_nonce<JOURNAL>(
    journal: &mut JOURNAL,
    block: &impl Block,
    chain_id: u64,
    caller: Address,
    nonce_key: u64,
) -> Result<(), TempoInvalidTransaction>
where
    JOURNAL: JournalTr + core::fmt::Debug,
    JOURNAL::Database: reth_evm::Database,
{
    // Protocol nonce (key 0) is incremented through standard account nonce
    if nonce_key == 0 {
        return Ok(());
    }

    // Use EvmStorageProvider pattern (exactly like FeeManager)
    let internals = EvmInternals::new(journal, block);
    let mut storage_provider = EvmStorageProvider::new(internals, chain_id);
    let mut nonce_manager = NonceManager::new(&mut storage_provider);

    let new_nonce = nonce_manager.increment_nonce(&caller, nonce_key);

    tracing::info!(
        caller = %caller,
        nonce_key = nonce_key,
        new_nonce = new_nonce,
        "2D nonce incremented"
    );

    Ok(())
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
    valid_before: u64,
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

    // Validate validBefore constraint (0 means no constraint)
    if valid_before > 0 && block_timestamp >= valid_before {
        return Err(TempoInvalidTransaction::ValidBefore {
            current: block_timestamp,
            valid_before,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use reth_evm::revm::{
        Journal,
        database::{CacheDB, EmptyDB},
        interpreter::instructions::utility::IntoU256,
        primitives::hardfork::SpecId,
        state::Account,
    };

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
        let balance_slot = mapping_slot(account, tip20::slots::BALANCES);
        journal.warm_account(token)?;
        journal
            .sstore(token, balance_slot, expected_balance)
            .unwrap();

        let balance = get_token_balance(&mut journal, token, account).unwrap();
        assert_eq!(balance, expected_balance);

        Ok(())
    }

    #[test]
    fn test_transfer_token() -> eyre::Result<()> {
        let mut journal = create_test_journal();
        let token = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let initial_balance = U256::random();

        let sender_slot = mapping_slot(sender, tip20::slots::BALANCES);
        journal.warm_account(token)?;
        journal.sstore(token, sender_slot, initial_balance).unwrap();
        let sender_balance = get_token_balance(&mut journal, token, sender).unwrap();
        assert_eq!(sender_balance, initial_balance);

        transfer_token(&mut journal, token, sender, recipient, initial_balance).unwrap();

        // Verify balances after transfer
        let sender_balance = get_token_balance(&mut journal, token, sender).unwrap();
        let recipient_balance = get_token_balance(&mut journal, token, recipient).unwrap();

        assert_eq!(sender_balance, 0);
        assert_eq!(recipient_balance, initial_balance);

        Ok(())
    }

    #[test]
    fn test_get_fee_token() -> eyre::Result<()> {
        let journal = create_test_journal();
        let mut ctx = TempoContext::new(CacheDB::new(EmptyDB::default()), SpecId::default())
            .with_new_journal(journal);
        let user = Address::random();
        ctx.tx.inner.caller = user;
        let validator = Address::random();
        ctx.block.beneficiary = validator;
        let user_fee_token = Address::random();
        let validator_fee_token = Address::random();
        let tx_fee_token = Address::random();

        // Set validator token
        let validator_slot = mapping_slot(validator, tip_fee_manager::slots::VALIDATOR_TOKENS);
        ctx.journaled_state.warm_account(TIP_FEE_MANAGER_ADDRESS)?;
        ctx.journaled_state
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                validator_slot,
                validator_fee_token.into_u256(),
            )
            .unwrap();

        let fee_token = get_fee_token(&mut ctx).unwrap();
        assert_eq!(validator_fee_token, fee_token);

        // Set user token
        let user_slot = mapping_slot(user, tip_fee_manager::slots::USER_TOKENS);
        ctx.journaled_state
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                user_slot,
                user_fee_token.into_u256(),
            )
            .unwrap();

        let fee_token = get_fee_token(&mut ctx).unwrap();
        assert_eq!(user_fee_token, fee_token);

        // Set tx fee token
        ctx.tx.fee_token = Some(tx_fee_token);
        let fee_token = get_fee_token(&mut ctx).unwrap();
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
}
