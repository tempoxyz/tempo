use crate::{TempoStateAccess, TempoTx};
use alloy_primitives::{Address, U256};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    error::Result as TempoResult, storage::StorageActions, tip_fee_manager::TipFeeManager,
};

/// Protocol fee charging component used by the Tempo EVM's internal fee lifecycle.
///
/// This is separate from the public FeeManager precompile registration. Replacing this component
/// changes the pre-transaction and post-transaction protocol fee hooks without changing which
/// contract is exposed at the FeeManager precompile address.
pub trait TempoFeeManager: core::fmt::Debug {
    /// Resolves the fee token used to pay fees for a transaction.
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

    /// Checks if the fee payer can transfer the given fee token to the fee manager.
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

    /// Collects the maximum fee from the fee payer before transaction execution.
    fn collect_fee_pre_tx(
        &self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> TempoResult<Address>;

    /// Finalizes fee collection after transaction execution.
    fn collect_fee_post_tx(
        &self,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> TempoResult<U256>;
}

/// Default Tempo L1 protocol fee manager.
///
/// Delegates to the existing [`TipFeeManager`] implementation so default L1 behavior is unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct L1FeeManager;

impl TempoFeeManager for L1FeeManager {
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
