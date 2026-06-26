use crate::{TempoStateAccess, TempoTxEnv};
use alloy_primitives::{Address, U256};
use core::fmt::Debug;
use revm::{Database, context::Journal};
use std::sync::Arc;
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

/// Dispatch handle for protocol fee hooks.
#[derive(Debug)]
pub enum ProtocolFeeManagerHandle<DB: Database> {
    /// Default Tempo fee manager used by production payload execution.
    Default(TempoFeeManager),
    /// Custom fee manager used by tests and specialized EVM callers.
    Custom(Arc<dyn ProtocolFeeManager<DB>>),
}

impl<DB: Database> Default for ProtocolFeeManagerHandle<DB> {
    fn default() -> Self {
        Self::Default(TempoFeeManager::new())
    }
}

impl<DB: Database> ProtocolFeeManagerHandle<DB> {
    /// Creates a custom protocol fee manager handle.
    pub fn custom(fee_manager: Arc<dyn ProtocolFeeManager<DB>>) -> Self {
        Self::Custom(fee_manager)
    }

    /// Resolves the fee token that should pay for `tx`.
    #[inline]
    pub fn get_fee_token(
        &self,
        journal: &mut Journal<DB>,
        tx: &TempoTxEnv,
        fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address> {
        match self {
            Self::Default(fee_manager) => {
                <TempoFeeManager as ProtocolFeeManager<DB>>::get_fee_token(
                    fee_manager,
                    journal,
                    tx,
                    fee_payer,
                    spec,
                    actions,
                )
            }
            Self::Custom(fee_manager) => {
                fee_manager.get_fee_token(journal, tx, fee_payer, spec, actions)
            }
        }
    }

    /// Collects the maximum possible fee before transaction execution.
    #[inline]
    pub fn collect_fee_pre_tx(
        &self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address> {
        match self {
            Self::Default(fee_manager) => {
                <TempoFeeManager as ProtocolFeeManager<DB>>::collect_fee_pre_tx(
                    fee_manager,
                    fee_payer,
                    user_token,
                    max_amount,
                    beneficiary,
                    skip_liquidity_check,
                )
            }
            Self::Custom(fee_manager) => fee_manager.collect_fee_pre_tx(
                fee_payer,
                user_token,
                max_amount,
                beneficiary,
                skip_liquidity_check,
            ),
        }
    }

    /// Settles the final fee after transaction execution.
    #[inline]
    pub fn collect_fee_post_tx(
        &self,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256> {
        match self {
            Self::Default(fee_manager) => {
                <TempoFeeManager as ProtocolFeeManager<DB>>::collect_fee_post_tx(
                    fee_manager,
                    fee_payer,
                    actual_spending,
                    refund_amount,
                    fee_token,
                    beneficiary,
                )
            }
            Self::Custom(fee_manager) => fee_manager.collect_fee_post_tx(
                fee_payer,
                actual_spending,
                refund_amount,
                fee_token,
                beneficiary,
            ),
        }
    }
}

/// FeeManager for the default TempoEVM configuration
#[derive(Debug, Clone, Copy, Default)]
pub struct TempoFeeManager;

impl TempoFeeManager {
    /// Creates the default Tempo protocol fee manager.
    pub const fn new() -> Self {
        Self
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
        TipFeeManager::new().collect_fee_pre_tx(
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
        TipFeeManager::new().collect_fee_post_tx(
            fee_payer,
            actual_spending,
            refund_amount,
            fee_token,
            beneficiary,
        )
    }
}
