use crate::{TempoStateAccess, TempoTxEnv};
use alloy_primitives::{Address, U256};
use core::fmt::{self, Debug};
use revm::{Database, context::Journal};
use std::cell::RefCell;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    error::Result as TempoResult, storage::StorageActions, tip_fee_manager::TipFeeManager,
};

/// Internal protocol fee hooks, separate from the public FeeManager precompile.
pub trait ProtocolFeeManager<DB: Database>: Debug {
    /// Resolves the fee token that should pay for `tx`.
    fn get_fee_token(
        &self,
        journal: &mut Journal<DB>,
        tx: &TempoTxEnv,
        fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address> {
        journal.get_fee_token(tx, fee_payer, spec, actions)
    }

    /// Collects the maximum possible fee before transaction execution.
    fn collect_fee_pre_tx(
        &self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address>;

    /// Settles the final fee after transaction execution.
    fn collect_fee_post_tx(
        &self,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256>;
}

/// FeeManager for the default TempoEVM configuration.
#[derive(Default)]
pub struct TempoFeeManager {
    fee_manager: RefCell<TipFeeManager>,
}

impl Debug for TempoFeeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoFeeManager").finish_non_exhaustive()
    }
}

impl TempoFeeManager {
    /// Creates the default Tempo protocol fee manager.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<DB: Database> ProtocolFeeManager<DB> for TempoFeeManager {
    fn collect_fee_pre_tx(
        &self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address> {
        self.fee_manager.borrow_mut().collect_fee_pre_tx(
            fee_payer,
            user_token,
            max_amount,
            beneficiary,
            skip_liquidity_check,
        )
    }

    fn collect_fee_post_tx(
        &self,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256> {
        self.fee_manager.borrow_mut().collect_fee_post_tx(
            fee_payer,
            actual_spending,
            refund_amount,
            fee_token,
            beneficiary,
        )
    }
}
