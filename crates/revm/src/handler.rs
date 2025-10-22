//! Tempo EVM Handler implementation.

use std::fmt::Debug;

use alloy_primitives::{Address, B256, U256, b256};
use reth_evm::{
    EvmInternals,
    revm::{
        Database,
        context::{
            Block, Cfg, ContextTr, Host, JournalTr, Transaction,
            result::{EVMError, ExecutionResult, HaltReason, InvalidTransaction},
        },
        handler::{EvmTr, FrameResult, FrameTr, Handler, pre_execution, validation},
        inspector::{Inspector, InspectorHandler},
        interpreter::{
            Gas, InitialAndFloorGas,
            gas::{STANDARD_TOKEN_COST, get_tokens_in_calldata},
            instructions::utility::IntoAddress,
            interpreter::EthInterpreter,
        },
        primitives::hardfork::SpecId as RevmSpecId,
        state::Bytecode,
    },
};
use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    storage::{evm::EvmPrecompileStorageProvider, slots::mapping_slot},
    tip_fee_manager::{self, TipFeeManager, bindings::IFeeManager},
    tip20,
};
use tempo_primitives::transaction::AASignature;

use crate::{TempoEvm, TempoInvalidTransaction, evm::TempoContext};

/// Additional gas for P256 signature verification
/// P256 precompile cost (6900 from EIP-7951) + 1100 for 129 bytes extra signature size - ecrecover savings (3000)
const P256_VERIFY_GAS: u64 = 5_000;

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
        self.fee_payer = evm.ctx().tx().fee_payer()?;

        Ok(())
    }
}

impl<DB, I> TempoEvmHandler<DB, I>
where
    DB: reth_evm::Database,
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

            // Validate and calculate gas for this call
            let subcall_init_gas =
                match Self::validate_and_calculate_call_gas(evm, init_and_floor_gas) {
                    Ok(gas) => gas,
                    Err(e) => {
                        // Revert checkpoint before returning error
                        evm.ctx().journal_mut().checkpoint_revert(checkpoint);
                        return Err(e);
                    }
                };

            // Execute this call using the provided single-call function
            let frame_result = execute_single(self, evm, &subcall_init_gas);

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
            // Subtract both execution gas AND per-call intrinsic costs (calldata, CREATE)
            remaining_gas = remaining_gas
                .saturating_sub(gas_used)
                .saturating_sub(subcall_init_gas.initial_gas);

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

    /// Validates the current call in TxEnv and calculates its intrinsic gas requirements.
    ///
    /// This function assumes TxEnv has already been updated to reflect the call being validated.
    /// Returns an error if validation fails, but does NOT revert checkpoints (caller must handle that).
    fn validate_and_calculate_call_gas(
        evm: &TempoEvm<DB, I>,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> Result<InitialAndFloorGas, EVMError<DB::Error, TempoInvalidTransaction>> {
        let spec = evm.ctx_ref().cfg().spec();
        let cfg = evm.ctx_ref().cfg();
        let tx = evm.ctx_ref().tx();

        // EIP-3860: Limit and meter initcode. Still valid with EIP-7907 and increase of initcode size.
        if spec.is_enabled_in(RevmSpecId::SHANGHAI)
            && tx.kind().is_create()
            && tx.input().len() > cfg.max_initcode_size()
        {
            return Err(EVMError::Transaction(
                TempoInvalidTransaction::EthInvalidTransaction(
                    InvalidTransaction::CreateInitCodeSizeLimit,
                ),
            ));
        }

        // Calculate initial gas for this specific call (includes base 21k + calldata + CREATE costs)
        let call_initial_gas =
            validation::validate_initial_tx_gas(tx, spec, evm.ctx.cfg.is_eip7623_disabled())
                .map_err(TempoInvalidTransaction::EthInvalidTransaction)?;

        // Subtract the batch-level initial gas (base 21k + signature verification) since it was already paid
        // This leaves only the call-specific costs (calldata, CREATE, etc.)
        let additional_gas = call_initial_gas
            .initial_gas
            .saturating_sub(init_and_floor_gas.initial_gas);

        Ok(InitialAndFloorGas::new(
            additional_gas,
            call_initial_gas.floor_gas,
        ))
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
        // Check if this is an AA transaction by checking for aa_tx_env
        if let Some(aa_tx_env) = evm.ctx().tx().aa_tx_env.as_ref() {
            // AA transaction - use batch execution with calls field
            let calls = aa_tx_env.aa_calls.clone();
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
        let is_balance_check_disabled = context.cfg().is_balance_check_disabled();
        let is_eip3607_disabled = context.cfg().is_eip3607_disabled();
        let is_nonce_check_disabled = context.cfg().is_nonce_check_disabled();
        let value = context.tx().value();
        let caller_addr = context.tx().caller();

        let (tx, journal) = (&mut context.tx, &mut context.journaled_state);

        // Load the fee payer balance
        let account_balance = get_token_balance(journal, self.fee_token, self.fee_payer)?;

        // Load caller's account
        let caller_account = journal.load_account_code(caller_addr)?.data;

        let account_info = &mut caller_account.info;
        if account_info.has_no_code_and_nonce() {
            account_info.set_code_and_hash(
                Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS),
                DEFAULT_7702_DELEGATE_CODE_HASH,
            );
        }

        // Validate account nonce and code (EIP-3607) using upstream helper
        pre_execution::validate_account_nonce_and_code(
            &mut caller_account.info,
            tx.nonce(),
            is_eip3607_disabled,
            is_nonce_check_disabled,
        )
        .map_err(TempoInvalidTransaction::EthInvalidTransaction)?;

        // Note: Signature verification happens during recover_signer() before entering the pool
        // Note: Transaction parameter validation (priority fee, time window) happens in validate_env()

        let max_balance_spending = tx
            .max_balance_spending()
            .map_err(TempoInvalidTransaction::EthInvalidTransaction)?;
        let effective_balance_spending = tx
            .effective_balance_spending(basefee, blob_price)
            .expect("effective balance is always smaller than max balance so it can't overflow");

        caller_account.mark_touch();

        // Bump the nonce for calls. Nonce for CREATE will be bumped in `make_create_frame`.
        if tx.kind().is_call() {
            caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
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
            let mut storage_provider = EvmPrecompileStorageProvider::new(internals, chain_id);
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
        let mut storage_provider = EvmPrecompileStorageProvider::new(internals, chain_id);
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

    /// Validates transaction environment with custom handling for AA transactions.
    ///
    /// Performs standard validation plus AA-specific checks:
    /// - Priority fee validation (EIP-1559)
    /// - Time window validation (validAfter/validBefore)
    #[inline]
    fn validate_env(&self, evm: &mut Self::Evm) -> Result<(), Self::Error> {
        // First perform standard validation (header + transaction environment)
        // This validates: prevrandao, excess_blob_gas, chain_id, gas limits, tx type support, etc.
        validation::validate_env::<_, TempoInvalidTransaction>(evm.ctx())?;

        // AA-specific validations
        let cfg = evm.ctx_ref().cfg();
        let tx = evm.ctx_ref().tx();

        if let Some(aa_env) = tx.aa_tx_env.as_ref() {
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
        validate_aa_initial_tx_gas(evm)
    }
}

/// Validates and calculates initial transaction gas for AA transactions.
///
/// For AA transactions (type 0x5), calculates intrinsic gas based on:
/// - Signature type (secp256k1: 21k, P256: 26k, WebAuthn: 26k + calldata)
///
/// For non-AA transactions, uses the default Ethereum calculation.
fn validate_aa_initial_tx_gas<DB, I>(
    evm: &TempoEvm<DB, I>,
) -> Result<InitialAndFloorGas, EVMError<DB::Error, TempoInvalidTransaction>>
where
    DB: reth_evm::Database,
{
    let spec = evm.ctx_ref().cfg().spec();

    let tx = evm.ctx_ref().tx();
    let standard_gas =
        validation::validate_initial_tx_gas(tx, spec, evm.ctx.cfg.is_eip7623_disabled())
            .map_err(TempoInvalidTransaction::EthInvalidTransaction)?;

    let Some(aa_env) = tx.aa_tx_env.as_ref() else {
        // For non-AA transactions, use default validation
        return Ok(standard_gas);
    };

    // For AA transactions, extract signature reference and gas limit
    let aa_signature = &aa_env.signature;
    let gas_limit = tx.gas_limit();

    // Calculate AA-specific additional gas (signature + nonce key costs)

    // Calculate additional signature verification gas beyond the base 21k
    // secp256k1: 0 additional (already included in base)
    // P256: 5,000 additional
    // WebAuthn: 5,000 + calldata gas for variable data
    let additional_signature_gas = match aa_signature {
        AASignature::Secp256k1(_) => {
            // secp256k1 signature - no additional gas needed (already included in base 21k)
            0
        }
        AASignature::P256(_) => {
            // P256 signature - add P256 verification gas
            P256_VERIFY_GAS
        }
        AASignature::WebAuthn(webauthn_sig) => {
            // WebAuthn signature - add P256 verification gas + calldata gas for variable data
            // Calculate calldata gas using the standard revm function
            // get_tokens_in_calldata counts zero bytes (1 token each) and non-zero bytes (4 tokens each for Istanbul)
            // Multiply by STANDARD_TOKEN_COST (4) to get gas: zero byte = 4 gas, non-zero byte = 16 gas
            let webauthn_data_tokens = get_tokens_in_calldata(&webauthn_sig.webauthn_data, true);
            let webauthn_data_gas = webauthn_data_tokens * STANDARD_TOKEN_COST;
            P256_VERIFY_GAS + webauthn_data_gas
        }
    };

    // Total intrinsic gas = standard_gas + additional_signature_gas
    let total_intrinsic_gas = standard_gas
        .initial_gas
        .saturating_add(additional_signature_gas);

    // Validate gas limit is sufficient
    if gas_limit < total_intrinsic_gas {
        return Err(TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
            gas_limit,
            intrinsic_gas: total_intrinsic_gas,
        }
        .into());
    }

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
        // Check if this is an AA transaction by checking for aa_tx_env
        if let Some(aa_tx_env) = evm.ctx().tx().aa_tx_env.as_ref() {
            // AA transaction - use batch execution with calls field
            let calls = aa_tx_env.aa_calls.clone();
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
