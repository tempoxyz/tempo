use alloy_primitives::{Address, U256};
use reth_evm::revm::interpreter::instructions::utility::IntoAddress;
use reth_storage_api::{StateProvider, errors::ProviderResult};

use crate::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{storage::slots::mapping_slot, tip_fee_manager, tip20},
};

pub trait TIPFeeStorageProvider {
    fn get_fee_token_balance(&self, user: Address) -> ProviderResult<U256>;
}

impl<T: StateProvider> TIPFeeStorageProvider for T {
    fn get_fee_token_balance(&self, user: Address) -> ProviderResult<U256> {
        let user_token_slot = mapping_slot(user, tip_fee_manager::slots::USER_TOKENS);
        let fee_token = self
            .storage(TIP_FEE_MANAGER_ADDRESS, user_token_slot.into())?
            .unwrap_or_default()
            .into_address();

        if fee_token.is_zero() {
            // TODO: how to handle getting validator fee token? Should we get the next validator or
            // default to some token?
        }

        let balance_slot = mapping_slot(user, tip20::slots::BALANCES);
        let balance = self
            .storage(fee_token, balance_slot.into())?
            .unwrap_or_default();

        Ok(balance)
    }
}
