use alloy::primitives::{Address, U256};
#[cfg(feature = "reth")]
use reth_storage_api::{StateProvider, errors::ProviderResult};
use revm::{Database, interpreter::instructions::utility::IntoAddress};

use crate::{
    DEFAULT_FEE_TOKEN,
    TIP_FEE_MANAGER_ADDRESS,
    storage::slots::mapping_slot, // tip_fee_manager,
    tip20,
};

/// Trait to provide [`StateProvider`] access to TIPFeeManager storage to fetch fee token data and balances
#[cfg(feature = "reth")]
pub trait TIPFeeStateProviderExt: StateProvider {
    /// Get fee token balance for a user.
    ///
    /// Returns the user's balance in their configured fee token. Falls back to
    /// validator token if user has no token set.
    fn get_fee_token_balance(
        &self,
        fee_payer: Address,
        tx_fee_token: Option<Address>,
        to: Option<&Address>,
    ) -> ProviderResult<U256> {
        Ok(U256::ZERO)
        // use crate::{storage::slots::mapping_slot, tip20};

        // let fee_token = if let Some(fee_token) = tx_fee_token {
        //     fee_token
        // } else {
        //     // Look up user's configured fee token in TIPFeeManager storage
        //     use crate::tip_fee_manager;
        //     let user_token_slot = mapping_slot(fee_payer, tip_fee_manager::slots::USER_TOKENS);
        //     let fee_token = self
        //         .storage(TIP_FEE_MANAGER_ADDRESS, user_token_slot.into())?
        //         .unwrap_or_default()
        //         .into_address();

        //     if fee_token.is_zero() {
        //         if let Some(to) = to
        //             && tip20::is_tip20(*to)
        //         {
        //             *to
        //         } else {
        //             DEFAULT_FEE_TOKEN
        //         }
        //     } else {
        //         fee_token
        //     }
        // };

        // // Query the user's balance in the determined fee token's TIP20 contract
        // let balance_slot = mapping_slot(fee_payer, tip20::slots::BALANCES);
        // let balance = self
        //     .storage(fee_token, balance_slot.into())?
        //     .unwrap_or_default();

        // Ok(balance)
    }
}

#[cfg(feature = "reth")]
impl<T: StateProvider> TIPFeeStateProviderExt for T {}

/// Trait to provide [`Database`] access to TIPFeeManager storage to fetch fee token data and balances
pub trait TIPFeeDatabaseExt: Database {
    /// Get fee token balance for a user.
    ///
    /// Returns the user's balance in their configured fee token. Falls back to
    /// validator token if user has no token set.
    fn get_fee_token_balance(
        &mut self,
        fee_payer: Address,
        validator: Address,
        tx_fee_token: Option<Address>,
    ) -> Result<U256, Self::Error> {
        Ok(U256::ZERO)
        // let fee_token = if let Some(fee_token) = tx_fee_token {
        //     fee_token
        // } else {
        //     // Look up user's configured fee token in TIPFeeManager storage
        //     let user_token_slot = mapping_slot(fee_payer, tip_fee_manager::slots::USER_TOKENS);
        //     // Load fee manager account to ensure that we can load storage for it.
        //     self.basic(TIP_FEE_MANAGER_ADDRESS)?;
        //     let user_fee_token = self
        //         .storage(TIP_FEE_MANAGER_ADDRESS, user_token_slot)?
        //         .into_address();

        //     // If the user feeToken is not set, use the validator fee token
        //     if user_fee_token.is_zero() {
        //         let validator_token_slot =
        //             mapping_slot(validator, tip_fee_manager::slots::VALIDATOR_TOKENS);
        //         let validator_fee_token = self
        //             .storage(TIP_FEE_MANAGER_ADDRESS, validator_token_slot)?
        //             .into_address();

        //         if validator_fee_token.is_zero() {
        //             DEFAULT_FEE_TOKEN
        //         } else {
        //             validator_fee_token
        //         }
        //     } else {
        //         user_fee_token
        //     }
        // };

        // // Query the user's balance in the determined fee token's TIP20 contract
        // let balance_slot = mapping_slot(fee_payer, tip20::slots::BALANCES);
        // // Load fee token account to ensure that we can load storage for it.
        // self.basic(fee_token)?;
        // let balance = self.storage(fee_token, balance_slot)?;

        // Ok(balance)
    }
}

impl<T: Database> TIPFeeDatabaseExt for T {}
