//! Tempo EVM Handler implementation.

use std::{cmp::Ordering, fmt::Debug};

use alloy_evm::EvmInternals;
use alloy_primitives::{Address, B256, U256, b256};
use revm::{
    Database,
    context::{
        Block, Cfg, ContextTr, JournalTr, Transaction,
        result::{EVMError, ExecutionResult, HaltReason, InvalidTransaction},
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
            CREATE, STANDARD_TOKEN_COST, calc_tx_floor_cost, get_tokens_in_calldata, initcode_cost,
        },
        interpreter::EthInterpreter,
    },
    primitives::eip7702,
    state::Bytecode,
};
use tempo_contracts::{
    DEFAULT_7702_DELEGATE_ADDRESS,
    precompiles::{
        FeeManagerError, IAccountKeychain::SignatureType as PrecompileSignatureType, TIPFeeAMMError,
    },
};
use tempo_precompiles::{
    account_keychain::{AccountKeychain, TokenLimit, authorizeKeyCall},
    error::TempoPrecompileError,
    nonce::{INonce::getNonceCall, NonceManager},
    storage::{evm::EvmPrecompileStorageProvider, slots::mapping_slot},
    tip_fee_manager::TipFeeManager,
    tip20::{self},
};
use tempo_primitives::transaction::{
    AASignature, PrimitiveSignature, SignatureType, calc_gas_balance_spending,
};

use crate::{TempoEvm, TempoInvalidTransaction, common::TempoStateAccess, evm::TempoContext};

/// Additional gas for P256 signature verification
/// P256 precompile cost (6900 from EIP-7951) + 1100 for 129 bytes extra signature size - ecrecover savings (3000)
const P256_VERIFY_GAS: u64 = 5_000;

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
/// For Keychain signatures, unwraps to the inner primitive signature for gas calculation.
/// Returns the additional gas required beyond the base transaction cost.
#[inline]
fn aa_signature_verification_gas(signature: &AASignature) -> u64 {
    match signature {
        AASignature::Primitive(prim_sig) => primitive_signature_verification_gas(prim_sig),
        AASignature::Keychain(keychain_sig) => {
            // Keychain wraps a primitive signature - calculate gas for the inner signature
            primitive_signature_verification_gas(&keychain_sig.signature)
        }
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
        self.fee_token =
            ctx.journaled_state
                .get_fee_token(&ctx.tx, ctx.block.beneficiary, self.fee_payer)?;

        // Skip fee token validity check for cases when the transaction is free and is not a part of a subblock.
        if (!ctx.tx.max_balance_spending()?.is_zero() || ctx.tx.is_subblock_transaction())
            && !ctx.journaled_state.is_valid_fee_token(self.fee_token)?
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

        let mut mainnet = MainnetHandler::default();
        mainnet.execution_result(evm, result)
    }

    /// Override apply_eip7702_auth_list to support AA transactions with authorization lists.
    ///
    /// The default implementation only processes authorization lists for TransactionType::Eip7702 (0x04).
    /// This override extends support to AA transactions (type 0x76) by checking for the presence
    /// of an aa_authorization_list in the aa_tx_env.
    #[inline]
    fn apply_eip7702_auth_list(&self, evm: &mut Self::Evm) -> Result<u64, Self::Error> {
        let ctx = evm.ctx();

        // Check if this is an AA transaction with an authorization list
        let has_aa_auth_list = ctx
            .tx()
            .aa_tx_env
            .as_ref()
            .map(|aa_env| !aa_env.aa_authorization_list.is_empty())
            .unwrap_or(false);

        // If it's an AA transaction with authorization list, we need to apply it manually
        // since the default implementation only checks for TransactionType::Eip7702
        if has_aa_auth_list {
            // TODO(@rakita) could we have a helper function for this logic in revm?
            // For AA transactions, we need to apply the authorization list ourselves
            // because pre_execution::apply_eip7702_auth_list returns early for non-0x04 tx types

            let chain_id = ctx.cfg().chain_id();
            let (tx, journal) = evm.ctx().tx_journal_mut();

            let aa_tx_env = tx.aa_tx_env.as_ref().unwrap();
            let mut refunded_accounts = 0;

            for authorization in &aa_tx_env.aa_authorization_list {
                // 1. Verify the chain id is either 0 or the chain's current ID.
                let auth_chain_id = authorization.chain_id;
                if !auth_chain_id.is_zero() && auth_chain_id != U256::from(chain_id) {
                    continue;
                }

                // 2. Verify the `nonce` is less than `2**64 - 1`.
                if authorization.nonce == u64::MAX {
                    continue;
                }

                // 3. Recover authority from AA signature
                let authority = match authorization.recover_authority() {
                    Ok(addr) => addr,
                    Err(_) => continue,
                };

                // 4. Add `authority` to `accessed_addresses` (warm the account)
                let mut authority_acc = journal.load_account_with_code_mut(authority)?;

                // 5. Verify the code of `authority` is either empty or already delegated.
                if let Some(bytecode) = &authority_acc.info.code {
                    // if it is not empty and it is not eip7702
                    if !bytecode.is_empty() && !bytecode.is_eip7702() {
                        continue;
                    }
                }

                // 6. Verify the nonce of `authority` is equal to `nonce`.
                if authorization.nonce != authority_acc.info.nonce {
                    continue;
                }

                // 7. Add gas refund if authority already exists
                if !(authority_acc.is_empty()
                    && authority_acc.is_loaded_as_not_existing_not_touched())
                {
                    refunded_accounts += 1;
                }

                // 8. Set the code of `authority` to be `0xef0100 || address`. This is a delegation designation.
                //  * As a special case, if `address` is `0x0000000000000000000000000000000000000000` do not write the designation.
                //    Clear the accounts code and reset the account's code hash to the empty hash `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
                // 9. Increase the nonce of `authority` by one.
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
            .aa_tx_env
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

        if !nonce_key.is_zero() {
            let internals = EvmInternals::new(journal, block);
            let mut storage_provider = EvmPrecompileStorageProvider::new_max_gas(internals, cfg);
            let mut nonce_manager = NonceManager::new(&mut storage_provider);

            if !cfg.is_nonce_check_disabled() {
                let tx_nonce = tx.nonce();
                let state = nonce_manager
                    .get_nonce(getNonceCall {
                        account: tx.caller(),
                        nonceKey: nonce_key,
                    })
                    .map_err(|err| match err {
                        TempoPrecompileError::Fatal(err) => EVMError::Custom(err),
                        err => TempoInvalidTransaction::NonceManagerError(err.to_string()).into(),
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
        } else {
            // Bump the nonce for calls. Nonce for CREATE will be bumped in `make_create_frame`.
            //
            // Always bump nonce for AA transactions.
            if tx.aa_tx_env.is_some() || tx.kind().is_call() {
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
        if let Some(aa_tx_env) = tx.aa_tx_env.as_ref()
            && let Some(key_auth) = &aa_tx_env.key_authorization
        {
            // Check if this TX is using a Keychain signature (access key)
            // Access keys cannot authorize new keys UNLESS it's the same key being authorized (same-tx auth+use)
            if let Some(keychain_sig) = aa_tx_env.signature.as_keychain() {
                // Get the access key address (recovered during Tx->TxEnv conversion and cached)
                let access_key_addr =
                    keychain_sig
                        .key_id(&aa_tx_env.signature_hash)
                        .map_err(|_| {
                            EVMError::Transaction(
                            TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                                reason:
                                    "Failed to recover access key address from Keychain signature"
                                        .to_string(),
                            },
                        )
                        })?;

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

            // Now authorize the key in the precompile
            let internals = EvmInternals::new(journal, block);
            let mut storage_provider = EvmPrecompileStorageProvider::new_max_gas(internals, cfg);

            let mut keychain = AccountKeychain::new(&mut storage_provider);

            let access_key_addr = key_auth.key_id;

            // Convert signature type to precompile SignatureType enum
            // Use the key_type field which specifies the type of key being authorized
            let signature_type = match key_auth.key_type {
                SignatureType::Secp256k1 => PrecompileSignatureType::Secp256k1,
                SignatureType::P256 => PrecompileSignatureType::P256,
                SignatureType::WebAuthn => PrecompileSignatureType::WebAuthn,
            };

            // Convert limits to the format expected by the precompile
            let precompile_limits: Vec<TokenLimit> = key_auth
                .limits
                .iter()
                .map(|limit| TokenLimit {
                    token: limit.token,
                    amount: limit.limit,
                })
                .collect();

            // Create the authorize key call
            let authorize_call = authorizeKeyCall {
                keyId: access_key_addr,
                signatureType: signature_type,
                expiry: key_auth.expiry,
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
                })?;
        }

        // Create storage provider wrapper around journal for fee manager
        let internals = EvmInternals::new(journal, &block);
        let beneficiary = internals.block_env().beneficiary();
        let mut storage_provider = EvmPrecompileStorageProvider::new_max_gas(internals, cfg);

        // For Keychain signatures, validate that the keychain is authorized in the precompile
        // UNLESS this transaction also includes a KeyAuthorization (same-tx auth+use case)
        if let Some(aa_tx_env) = tx.aa_tx_env.as_ref()
            && let Some(keychain_sig) = aa_tx_env.signature.as_keychain()
        {
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
            let access_key_addr = keychain_sig
                .key_id(&aa_tx_env.signature_hash)
                .map_err(|_| {
                    EVMError::Transaction(TempoInvalidTransaction::AccessKeyAuthorizationFailed {
                        reason: "Failed to recover access key address from inner signature"
                            .to_string(),
                    })
                })?;

            // Check if this transaction includes a KeyAuthorization for the same key
            // If so, skip validation here - the key was just validated and authorized
            let is_authorizing_this_key = aa_tx_env
                .key_authorization
                .as_ref()
                .map(|key_auth| key_auth.key_id == access_key_addr)
                .unwrap_or(false);

            // Always need to set the transaction key for Keychain signatures
            let mut keychain = AccountKeychain::new(&mut storage_provider);

            if !is_authorizing_this_key {
                // Not authorizing this key in the same transaction, so validate it exists now
                // Validate that user_address has authorized this access key in the keychain
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
                .map_err(|e| EVMError::Custom(e.to_string()))?;
        }

        let mut fee_manager = TipFeeManager::new(&mut storage_provider);

        if gas_balance_spending.is_zero() {
            return Ok(());
        }

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
                beneficiary,
            )
            .map_err(|e| {
                // Map fee collection errors to transaction validation errors since they
                // indicate the transaction cannot be included (e.g., insufficient liquidity
                // in FeeAMM pool for fee swaps)
                match e {
                    TempoPrecompileError::TIPFeeAMMError(
                        TIPFeeAMMError::InsufficientLiquidity(_),
                    ) => EVMError::Transaction(TempoInvalidTransaction::InsufficientAmmLiquidity {
                        fee: Box::new(gas_balance_spending),
                    }),

                    TempoPrecompileError::FeeManagerError(
                        FeeManagerError::InsufficientFeeTokenBalance(_),
                    ) => EVMError::Transaction(
                        TempoInvalidTransaction::InsufficientFeeTokenBalance {
                            fee: Box::new(gas_balance_spending),
                            balance: Box::new(account_balance),
                        },
                    ),

                    TempoPrecompileError::Fatal(e) => EVMError::Custom(e),

                    _ => EVMError::Transaction(TempoInvalidTransaction::CollectFeePreTxError(
                        e.to_string(),
                    )),
                }
            })?;
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

        // Calculate actual used and refund amounts
        let actual_spending = calc_gas_balance_spending(gas.used(), effective_gas_price);
        let refund_amount = tx.effective_balance_spending(
            context.block.basefee.into(),
            context.block.blob_gasprice().unwrap_or_default(),
        )? - tx.value
            - actual_spending;

        // Create storage provider and fee manager
        let (journal, block) = (&mut context.journaled_state, &context.block);
        let internals = EvmInternals::new(journal, block);
        let beneficiary = internals.block_env().beneficiary();
        let mut storage_provider =
            EvmPrecompileStorageProvider::new_max_gas(internals, &context.cfg);
        let mut fee_manager = TipFeeManager::new(&mut storage_provider);

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

        if let Some(aa_env) = tx.aa_tx_env.as_ref() {
            if aa_env.subblock_transaction && tx.max_fee_per_gas() > 0 {
                return Err(TempoInvalidTransaction::SubblockTransactionMustHaveZeroFee.into());
            }

            // Validate priority fee for AA transactions using revm's validate_priority_fee_tx
            //
            // Skip basefee check for subblock transactions.
            let base_fee = if cfg.is_base_fee_check_disabled() || aa_env.subblock_transaction {
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

            // Validate that keychain operations are only supported after Allegretto
            if (aa_env.key_authorization.is_some() || aa_env.signature.is_keychain())
                && !cfg.spec.is_allegretto()
            {
                return Err(TempoInvalidTransaction::KeychainOpBeforeAllegretto.into());
            }
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
        if tx.aa_tx_env.is_some() {
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
/// - Floor gas calculation (EIP-7623, Prague+)
fn calculate_aa_batch_intrinsic_gas<'a>(
    calls: &[tempo_primitives::transaction::Call],
    signature: &AASignature,
    access_list: Option<impl Iterator<Item = &'a AccessListItem>>,
    aa_authorization_list: &[tempo_primitives::transaction::AASignedAuthorization],
) -> Result<InitialAndFloorGas, TempoInvalidTransaction> {
    let mut gas = InitialAndFloorGas::default();

    // 1. Base stipend (21k, once per transaction)
    gas.initial_gas += 21_000;

    // 2. Signature verification gas
    gas.initial_gas += aa_signature_verification_gas(signature);

    // 3. Per-call overhead: cold account access
    // if the `to` address has not appeared in the call batch before.
    gas.initial_gas += COLD_ACCOUNT_ACCESS_COST * calls.len() as u64;

    // 4. Authorization list costs (EIP-7702)
    gas.initial_gas += aa_authorization_list.len() as u64 * eip7702::PER_EMPTY_ACCOUNT_COST;
    // Add signature verification costs for each authorization
    for aa_auth in aa_authorization_list {
        gas.initial_gas += aa_signature_verification_gas(aa_auth.signature());
    }

    // 4. Per-call costs
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
        .aa_tx_env
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
    let mut batch_gas = calculate_aa_batch_intrinsic_gas(
        calls,
        &aa_env.signature,
        tx.access_list(),
        &aa_env.aa_authorization_list,
    )?;

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
    use crate::{TempoBlockEnv, TempoTxEnv};
    use alloy_primitives::{Address, U256};
    use revm::{
        Context, Journal, MainContext,
        database::{CacheDB, EmptyDB},
        interpreter::instructions::utility::IntoU256,
        primitives::hardfork::SpecId,
        state::Account,
    };
    use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, tip_fee_manager};

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
        journal.load_account(token)?;
        journal
            .sstore(token, balance_slot, expected_balance)
            .unwrap();

        let balance = get_token_balance(&mut journal, token, account).unwrap();
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
        let validator_slot = mapping_slot(validator, tip_fee_manager::slots::VALIDATOR_TOKENS);
        ctx.journaled_state.load_account(TIP_FEE_MANAGER_ADDRESS)?;
        ctx.journaled_state
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                validator_slot,
                validator_fee_token.into_u256(),
            )
            .unwrap();

        let fee_token = ctx
            .journaled_state
            .get_fee_token(&ctx.tx, validator, user)?;
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

        let fee_token = ctx
            .journaled_state
            .get_fee_token(&ctx.tx, validator, user)?;
        assert_eq!(user_fee_token, fee_token);

        // Set tx fee token
        ctx.tx.fee_token = Some(tx_fee_token);
        let fee_token = ctx
            .journaled_state
            .get_fee_token(&ctx.tx, validator, user)?;
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
        use crate::AATxEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{AASignature, Call};

        // Test that AA tx with secp256k1 and single call matches normal tx + per-call overhead
        let calldata = Bytes::from(vec![1, 2, 3, 4, 5]); // 5 non-zero bytes
        let to = Address::random();

        // Single call for AA
        let call = Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        let aa_env = AATxEnv {
            signature: AASignature::Primitive(PrimitiveSignature::Secp256k1(
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
            &aa_env.aa_calls,
            &aa_env.signature,
            None::<std::iter::Empty<&AccessListItem>>, // no access list
            &aa_env.aa_authorization_list,
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
        use crate::AATxEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{AASignature, Call};

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

        let aa_env = AATxEnv {
            signature: AASignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: calls.clone(),
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let spec = tempo_chainspec::hardfork::TempoHardfork::default();
        let gas = calculate_aa_batch_intrinsic_gas(
            &calls,
            &aa_env.signature,
            None::<std::iter::Empty<&AccessListItem>>,
            &aa_env.aa_authorization_list,
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
        use crate::AATxEnv;
        use alloy_primitives::{B256, Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{
            AASignature, Call, aa_signature::P256SignatureWithPreHash,
        };

        let spec = SpecId::CANCUN;
        let calldata = Bytes::from(vec![1, 2]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        let aa_env = AATxEnv {
            signature: AASignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: B256::ZERO,
                s: B256::ZERO,
                pub_key_x: B256::ZERO,
                pub_key_y: B256::ZERO,
                pre_hash: false,
            })),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env.aa_calls,
            &aa_env.signature,
            None::<std::iter::Empty<&AccessListItem>>,
            &aa_env.aa_authorization_list,
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
        use crate::AATxEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{AASignature, Call};

        let spec = SpecId::CANCUN; // Post-Shanghai
        let initcode = Bytes::from(vec![0x60, 0x80]); // 2 bytes

        let call = Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode.clone(),
        };

        let aa_env = AATxEnv {
            signature: AASignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env.aa_calls,
            &aa_env.signature,
            None::<std::iter::Empty<&AccessListItem>>,
            &aa_env.aa_authorization_list,
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
        use crate::AATxEnv;
        use alloy_primitives::{Bytes, TxKind};
        use tempo_primitives::transaction::{AASignature, Call};

        let calldata = Bytes::from(vec![1]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::from(1000), // Non-zero value
            input: calldata,
        };

        let aa_env = AATxEnv {
            signature: AASignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let res = calculate_aa_batch_intrinsic_gas(
            &aa_env.aa_calls,
            &aa_env.signature,
            None::<std::iter::Empty<&AccessListItem>>,
            &aa_env.aa_authorization_list,
        );

        assert_eq!(
            res.unwrap_err(),
            TempoInvalidTransaction::ValueTransferNotAllowedInAATx
        );
    }

    #[test]
    fn test_aa_gas_access_list() {
        use crate::AATxEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{AASignature, Call};

        let spec = SpecId::CANCUN;
        let calldata = Bytes::from(vec![]);

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        let aa_env = AATxEnv {
            signature: AASignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        // Test without access list
        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env.aa_calls,
            &aa_env.signature,
            None::<std::iter::Empty<&AccessListItem>>,
            &aa_env.aa_authorization_list,
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
        let hash1 = KeyAuthorization::authorization_message_hash(key_type, key_id, expiry, &limits);

        // Compute again to verify consistency
        let hash2 = KeyAuthorization::authorization_message_hash(key_type, key_id, expiry, &limits);

        assert_eq!(hash1, hash2, "Hash computation should be deterministic");
    }

    #[test]
    fn test_aa_gas_floor_gas_prague() {
        use crate::AATxEnv;
        use alloy_primitives::{Bytes, TxKind};
        use revm::interpreter::gas::calculate_initial_tx_gas;
        use tempo_primitives::transaction::{AASignature, Call};

        let spec = SpecId::PRAGUE;
        let calldata = Bytes::from(vec![1, 2, 3, 4, 5]); // 5 non-zero bytes

        let call = Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        };

        let aa_env = AATxEnv {
            signature: AASignature::Primitive(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )),
            aa_calls: vec![call],
            key_authorization: None,
            signature_hash: B256::ZERO,
            ..Default::default()
        };

        let gas = calculate_aa_batch_intrinsic_gas(
            &aa_env.aa_calls,
            &aa_env.signature,
            None::<std::iter::Empty<&AccessListItem>>,
            &aa_env.aa_authorization_list,
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
}
