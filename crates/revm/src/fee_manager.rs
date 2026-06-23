use crate::{TempoStateAccess, TempoTx};
use alloy_primitives::{Address, U256};
use core::fmt::Debug;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    error::Result as TempoResult, storage::StorageActions, tip_fee_manager::TipFeeManager,
};

/// Internal protocol fee hooks, separate from the public FeeManager precompile.
pub trait ProtocolFeeManager: Debug {
    fn get_fee_token<S, TX, M>(
        &self,
        state: &mut S,
        tx: TX,
        fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address>
    where
        S: TempoStateAccess<M> + Sized,
        TX: TempoTx,
    {
        state.get_fee_token(tx, fee_payer, spec, actions)
    }

    fn can_fee_payer_transfer<S, M>(
        &self,
        state: &mut S,
        fee_token: Address,
        fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<bool>
    where
        S: TempoStateAccess<M> + Sized,
    {
        state.can_fee_payer_transfer(fee_token, fee_payer, spec, actions)
    }

    fn collect_fee_pre_tx(
        &self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address>;

    fn collect_fee_post_tx(
        &self,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256>;
}

/// Default L1 implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct TempoFeeManager;

impl TempoFeeManager {
    pub const fn new() -> Self {
        Self
    }
}

impl ProtocolFeeManager for TempoFeeManager {
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
