//! Tempo EVM Handler implementation.

use std::fmt::Debug;

use alloy_primitives::{Address, U256};
use reth::revm::{
    context::{Block, Cfg, Transaction, result::InvalidTransaction},
    handler::{MainnetHandler, pre_execution::validate_account_nonce_and_code},
    primitives::hardfork::SpecId,
};
use reth_evm::EvmInternals;
use reth_revm::{
    Database,
    context::{
        ContextTr, JournalTr,
        result::{HaltReason, InvalidHeader},
    },
    handler::{EvmTr, EvmTrError, FrameResult, FrameTr, Handler},
    interpreter::{instructions::utility::IntoAddress, interpreter_action::FrameInit},
    state::EvmState,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        EvmStorageProvider, IFeeManager, TipFeeManager, storage::slots::mapping_slot,
        tip_fee_manager, tip20,
    },
};

/// Tempo EVM [`Handler`] implementation with Tempo specific modifications:
///
/// Fees are paid in fee tokens instead of account balance.
#[derive(Debug, Clone)]
pub struct TempoEvmHandler<EVM, ERROR, FRAME> {
    /// The regular ethereum handler implementation, used to forward equivalent logic.
    mainnet: MainnetHandler<EVM, ERROR, FRAME>,
    /// Phantom data to avoid type inference issues.
    _phantom: core::marker::PhantomData<(EVM, ERROR, FRAME)>,
}

impl<EVM, ERROR, FRAME> TempoEvmHandler<EVM, ERROR, FRAME> {
    /// Create a new [`TempoEvmHandler`] handler instance
    pub fn new() -> Self {
        Self {
            mainnet: MainnetHandler::default(),
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
    EVM: EvmTr<Context: ContextTr<Journal: JournalTr<State = EvmState> + Debug>, Frame = FRAME>,
    ERROR: EvmTrError<EVM>,
    FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
    <<EVM as EvmTr>::Context as ContextTr>::Db: reth_evm::Database + Debug,
    <<<EVM as EvmTr>::Context as ContextTr>::Db as reth_revm::Database>::Error: Send + Sync,
{
    type Evm = EVM;
    type Error = ERROR;
    type HaltReason = HaltReason;

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
        // let caller = context.tx().caller();
        let value = context.tx().value();
        let chain_id = context.tx().chain_id().unwrap_or_default();
        let beneficiary = context.block().beneficiary();

        let (tx, journal) = context.tx_journal_mut();

        // Load the fee token balance
        let fee_token = get_fee_token(journal, tx.caller(), beneficiary)?;
        let account_balance = get_token_balance(journal, tx.caller(), fee_token)?;

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

            // TODO: transfer from caller to fee manager
            // fetch the token balance

            // let fee_manager = TipFeeManager::new(
            //     TIP_FEE_MANAGER_ADDRESS,
            //     &mut EvmStorageProvider::new(EvmInternals::new(journal, block_env), chain_id),
            // );
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

        // TODO: transfer reimbursement from fee manager to caller

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

        // TODO collect fee

        Ok(())
    }
}

pub fn get_fee_token<JOURNAL>(
    journal: &mut JOURNAL,
    sender: Address,
    validator: Address,
) -> Result<Address, <JOURNAL::Database as Database>::Error>
where
    JOURNAL: JournalTr,
{
    let user_slot = mapping_slot(sender, tip_fee_manager::slots::USER_TOKENS);
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

        Ok(validator_fee_token)
    } else {
        Ok(user_fee_token)
    }
}

pub fn get_token_balance<JOURNAL>(
    journal: &mut JOURNAL,
    sender: Address,
    token: Address,
) -> Result<U256, <JOURNAL::Database as Database>::Error>
where
    JOURNAL: JournalTr,
{
    let balance_slot = mapping_slot(sender, tip20::slots::BALANCES);
    let balance = journal.sload(token, balance_slot)?.data;

    Ok(balance)
}
