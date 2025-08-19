//! Tempo EVM Handler implementation.

use alloy_primitives::U256;
use reth::revm::context::{Block, Cfg, Transaction};
use reth::revm::context::result::InvalidTransaction;
use reth::revm::handler::MainnetHandler;
use reth::revm::handler::pre_execution::validate_account_nonce_and_code;
use reth_evm::EvmInternals;
use reth_revm::{
    context::{ContextTr, JournalTr, result::HaltReason},
    handler::{EvmTr, EvmTrError, FrameResult, FrameTr, Handler},
    interpreter::interpreter_action::FrameInit,
    state::EvmState,
};
use tempo_precompiles::contracts::{EvmStorageProvider, TipFeeManager};
use tempo_precompiles::TIP_FEE_MANAGER_ADDRESS;

/// Optimism handler extends the [`Handler`] with Tempo specific logic:
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
    EVM: EvmTr<Context: ContextTr<Journal: JournalTr<State = EvmState>>, Frame = FRAME>,
    ERROR: EvmTrError<EVM>,
    FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
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
        let caller = context.tx().caller();
        let value = context.tx().value();

        let (tx, journal) = context.tx_journal_mut();

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

        // fetch the token balance
        let fee_manager = TipFeeManager::new(
            TIP_FEE_MANAGER_ADDRESS,
            &mut EvmStorageProvider::new(EvmInternals::new(journal, context.block()), chain_id),
        );

        // TODO load fee token balance from fee manager contract storage
        let account_balance = U256::ZERO;

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

            // TODO transfer from caller to fee manager
        }

        //
        // journal.caller_accounting_journal_entry(tx.caller(), old_balance, tx.kind().is_call());
        Ok(())
    }

    fn reimburse_caller(&self, evm: &mut Self::Evm, exec_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult) -> Result<(), Self::Error> {
        let context = evm.ctx();
        let basefee = context.block().basefee() as u128;
        let caller = context.tx().caller();
        let effective_gas_price = context.tx().effective_gas_price(basefee);
        let gas = exec_result.gas();

        let reimbursement =
            effective_gas_price.saturating_mul((gas.remaining() + gas.refunded() as u64) as u128);

        // TODO transfer reimbursement from fee manager to caller

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
