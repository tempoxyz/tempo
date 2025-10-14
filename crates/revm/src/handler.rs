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
        handler::{EvmTr, FrameTr, Handler, pre_execution::validate_account_nonce_and_code},
        inspector::{Inspector, InspectorHandler},
        interpreter::{instructions::utility::IntoAddress, interpreter::EthInterpreter},
        state::Bytecode,
    },
};
use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        EvmStorageProvider,
        storage::slots::mapping_slot,
        tip_fee_manager::{self, TipFeeManager},
        tip20,
    },
};
use tracing::trace;

use crate::{TempoEvm, TempoInvalidTransaction, evm::TempoContext};

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

        // Run inner handler and catch all errors to handle cleanup.
        match self.run_without_catch_error(evm) {
            Ok(output) => Ok(output),
            Err(err) => {
                trace!(?err, caller=%evm.ctx().caller(),  "failed to transact");
                self.catch_error(evm, err)
            }
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

        let (tx, journal) = (&mut context.tx, &mut context.journaled_state);

        // Load the fee payer balance
        let account_balance = get_token_balance(journal, self.fee_token, self.fee_payer)?;

        // Load caller's account.
        let caller_account = journal.load_account_code(tx.caller())?.data;

        let account_info = &mut caller_account.info;
        if account_info.has_no_code_and_nonce() {
            account_info.set_code_and_hash(
                Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS),
                DEFAULT_7702_DELEGATE_CODE_HASH,
            );
        }

        validate_account_nonce_and_code(
            &mut caller_account.info,
            tx.nonce(),
            is_eip3607_disabled,
            is_nonce_check_disabled,
        )
        .map_err(TempoInvalidTransaction::EthInvalidTransaction)?;

        let max_balance_spending = tx
            .max_balance_spending()
            .map_err(TempoInvalidTransaction::EthInvalidTransaction)?;
        let effective_balance_spending = tx
            .effective_balance_spending(basefee, blob_price)
            .expect("effective balance is always smaller than max balance so it can't overflow");

        // Bump the nonce for calls. Nonce for CREATE will be bumped in `make_create_frame`.
        if tx.kind().is_call() {
            caller_account.info.nonce = caller_account.info.nonce.saturating_add(1);
        }
        // Ensure caller account is touched.
        caller_account.mark_touch();

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
