//! Tempo EVM Handler implementation.

use core::fmt;
use std::fmt::Debug;

use alloy_primitives::{Address, U256};
use reth_revm::{
    Database,
    context::{
        Block, Cfg, ContextTr, Host, JournalTr, Transaction,
        result::{HaltReason, InvalidTransaction},
    },
    handler::{
        EthFrame, EvmTr, EvmTrError, FrameResult, FrameTr, Handler,
        pre_execution::validate_account_nonce_and_code,
    },
    inspector::{Inspector, InspectorEvmTr, InspectorHandler},
    interpreter::{
        instructions::utility::IntoAddress, interpreter::EthInterpreter,
        interpreter_action::FrameInit,
    },
    primitives::hardfork::SpecId,
    state::EvmState,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{storage::slots::mapping_slot, tip_fee_manager, tip20},
};
use tracing::trace;

/// Tempo EVM [`Handler`] implementation with Tempo specific modifications:
///
/// Fees are paid in fee tokens instead of account balance.
#[derive(Debug, Clone)]
pub struct TempoEvmHandler<EVM, ERROR, FRAME> {
    fee_token: Address,
    /// Phantom data to avoid type inference issues.
    _phantom: core::marker::PhantomData<(EVM, ERROR, FRAME)>,
}

impl<EVM, ERROR, FRAME> TempoEvmHandler<EVM, ERROR, FRAME> {
    /// Create a new [`TempoEvmHandler`] handler instance
    pub fn new() -> Self {
        Self {
            fee_token: Address::default(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<EVM, ERROR, FRAME> Default for TempoEvmHandler<EVM, ERROR, FRAME> {
    fn default() -> Self {
        Self::new()
    }
}

impl<EVM, ERROR, FRAME> Handler for TempoEvmHandler<EVM, ERROR, FRAME>
where
    EVM: EvmTr<Context: ContextTr<Journal: JournalTr<State = EvmState>>, Frame = FRAME>,
    ERROR: EvmTrError<EVM> + fmt::Debug,
    FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
{
    type Evm = EVM;
    type Error = ERROR;
    type HaltReason = HaltReason;

    #[inline]
    fn run(
        &mut self,
        evm: &mut Self::Evm,
    ) -> Result<reth_revm::context::result::ExecutionResult<Self::HaltReason>, Self::Error> {
        let caller = evm.ctx().caller();
        let beneficiary = evm.ctx().beneficiary();
        let fee_token = get_fee_token(evm.ctx_mut().journal_mut(), caller, beneficiary)?;
        trace!(%fee_token, %caller, %beneficiary, "loaded fee token");
        self.fee_token = fee_token;

        // Run inner handler and catch all errors to handle cleanup.
        match self.run_without_catch_error(evm) {
            Ok(output) => Ok(output),
            Err(err) => {
                trace!(?err, %caller,  "failed to transact");
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
        let context = evm.ctx();
        let basefee = context.block().basefee() as u128;
        let blob_price = context.block().blob_gasprice().unwrap_or_default();
        let is_balance_check_disabled = context.cfg().is_balance_check_disabled();
        let is_eip3607_disabled = context.cfg().is_eip3607_disabled();
        let is_nonce_check_disabled = context.cfg().is_nonce_check_disabled();
        let value = context.tx().value();

        let (tx, journal) = context.tx_journal_mut();

        // Load the fee token balance
        let account_balance = get_token_balance(journal, self.fee_token, tx.caller())?;

        // Load caller's account.
        let caller_account = journal.load_account_code(tx.caller())?.data;

        validate_account_nonce_and_code(
            &mut caller_account.info,
            tx.nonce(),
            is_eip3607_disabled,
            is_nonce_check_disabled,
        )?;

        let max_balance_spending = tx.max_balance_spending()?;
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
            return Err(InvalidTransaction::LackOfFundForMaxFee {
                fee: Box::new(max_balance_spending),
                balance: Box::new(account_balance),
            }
            .into());
        } else {
            // deduct balance from the fee account's balance by transferring it over to the fee manager
            let gas_balance_spending = effective_balance_spending - value;

            // Transfer from caller to fee manager
            transfer_token(
                journal,
                self.fee_token,
                tx.caller(),
                TIP_FEE_MANAGER_ADDRESS,
                gas_balance_spending,
            )?;
        }

        //
        // journal.caller_accounting_journal_entry(tx.caller(), old_balance, tx.kind().is_call());
        Ok(())
    }

    fn reimburse_caller(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        let context = evm.ctx();
        let basefee = context.block().basefee() as u128;
        let caller = context.tx().caller();
        let effective_gas_price = context.tx().effective_gas_price(basefee);
        let gas = exec_result.gas();

        let reimbursement =
            effective_gas_price.saturating_mul((gas.remaining() + gas.refunded() as u64) as u128);

        let journal = evm.ctx().journal_mut();
        transfer_token(
            journal,
            self.fee_token,
            TIP_FEE_MANAGER_ADDRESS,
            caller,
            U256::from(reimbursement),
        )?;

        Ok(())
    }

    #[inline]
    fn reward_beneficiary(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        let context = evm.ctx();
        let tx = context.tx();
        let beneficiary = context.block().beneficiary();
        let basefee = context.block().basefee() as u128;
        let effective_gas_price = tx.effective_gas_price(basefee);
        let gas = exec_result.gas();

        let coinbase_gas_price = if context.cfg().spec().into().is_enabled_in(SpecId::LONDON) {
            effective_gas_price.saturating_sub(basefee)
        } else {
            effective_gas_price
        };

        let reward = coinbase_gas_price.saturating_mul(gas.used() as u128);
        let journal = evm.ctx().journal_mut();
        transfer_token(
            journal,
            self.fee_token,
            TIP_FEE_MANAGER_ADDRESS,
            beneficiary,
            U256::from(reward),
        )?;

        Ok(())
    }
}

/// Looks up the user's fee token in the `TIPFeemanager` contract.
///
/// If no fee token is set for the user, or the fee token is the zero address, the returned fee token will be the validator's fee token.
pub fn get_fee_token<JOURNAL>(
    journal: &mut JOURNAL,
    sender: Address,
    validator: Address,
) -> Result<Address, <JOURNAL::Database as Database>::Error>
where
    JOURNAL: JournalTr,
{
    let user_slot = mapping_slot(sender, tip_fee_manager::slots::USER_TOKENS);
    // ensure TIP_FEE_MANAGER_ADDRESS is loaded
    journal.load_account(TIP_FEE_MANAGER_ADDRESS)?;
    let user_fee_token = journal
        .sload(TIP_FEE_MANAGER_ADDRESS, user_slot)?
        .data
        .into_address();

    if user_fee_token.is_zero() {
        let validator_slot = mapping_slot(validator, tip_fee_manager::slots::VALIDATOR_TOKENS);
        let validator_fee_token = journal
            .sload(TIP_FEE_MANAGER_ADDRESS, validator_slot)?
            .data
            .into_address();
        trace!(%sender, %validator, %validator_fee_token, "loaded validator fee token");

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

impl<EVM, ERROR> InspectorHandler for TempoEvmHandler<EVM, ERROR, EthFrame<EthInterpreter>>
where
    EVM: InspectorEvmTr<
            Context: ContextTr<Journal: JournalTr<State = EvmState>>,
            Frame = EthFrame<EthInterpreter>,
            Inspector: Inspector<<<Self as Handler>::Evm as EvmTr>::Context, EthInterpreter>,
        >,
    ERROR: EvmTrError<EVM> + fmt::Debug,
{
    type IT = EthInterpreter;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use reth_revm::{
        Journal,
        db::{CacheDB, EmptyDB},
        interpreter::instructions::utility::IntoU256,
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
        let mut journal = create_test_journal();
        let user = Address::random();
        let validator = Address::random();
        let user_fee_token = Address::random();
        let validator_fee_token = Address::random();

        // Set validator token
        let validator_slot = mapping_slot(validator, tip_fee_manager::slots::VALIDATOR_TOKENS);
        journal.warm_account(TIP_FEE_MANAGER_ADDRESS)?;
        journal
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                validator_slot,
                validator_fee_token.into_u256(),
            )
            .unwrap();

        let fee_token = get_fee_token(&mut journal, user, validator).unwrap();
        assert_eq!(validator_fee_token, fee_token);

        // Set user token
        let user_slot = mapping_slot(user, tip_fee_manager::slots::USER_TOKENS);
        journal
            .sstore(
                TIP_FEE_MANAGER_ADDRESS,
                user_slot,
                user_fee_token.into_u256(),
            )
            .unwrap();

        let fee_token = get_fee_token(&mut journal, user, validator).unwrap();
        assert_eq!(user_fee_token, fee_token);

        Ok(())
    }
}
