use alloy_primitives::{Address, U256};
use reth_evm::revm::{Database, interpreter::instructions::utility::IntoAddress};
use reth_storage_api::{StateProvider, errors::ProviderResult};

use crate::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        storage::slots::mapping_slot,
        tip_fee_manager::{
            self,
            fee::{FeeToken, TokenBalance},
        },
        tip20,
    },
};

/// Trait to provide [`StateProvider`] access to TIPFeeManager storage to fetch fee token data and balances
pub trait TIPFeeStateProviderExt {
    /// Get fee token balance for a user.
    ///
    /// Returns the user's balance in their configured fee token. Falls back to
    /// validator token if user has no token set.
    fn get_fee_token_balance(&self, user: Address) -> ProviderResult<U256>;
}

/// Implementation of TIPFeeManager storage operations for generic [`StateProvider`]
impl<T: StateProvider> TIPFeeStateProviderExt for T {
    fn get_fee_token_balance(&self, user: Address) -> ProviderResult<U256> {
        // Look up user's configured fee token in TIPFeeManager storage
        let user_token_slot = mapping_slot(user, tip_fee_manager::slots::USER_TOKENS);
        let mut fee_token = self
            .storage(TIP_FEE_MANAGER_ADDRESS, user_token_slot.into())?
            .unwrap_or_default()
            .into_address();

        if fee_token.is_zero() {
            // FIXME: Currently, if the user fee token is not set, we default to the validator fee
            // token. This works during block building since the validator is known, however during
            // gas estimation, we do not currently have a way to know which validator is next. As a
            // temporary fix for testnet, we default to a DEFAULT_FEE_TOKEN which is the first fee token
            // deployed however we should update this to a more robust approach.
            fee_token = DEFAULT_FEE_TOKEN;
        }

        // Query the user's balance in the determined fee token's TIP20 contract
        let balance_slot = mapping_slot(user, tip20::slots::BALANCES);
        let balance = self
            .storage(fee_token, balance_slot.into())?
            .unwrap_or_default();

        Ok(balance)
    }
}

/// Trait to provide [`Database`] access to TIPFeeManager storage to fetch fee token data and balances
pub trait TIPFeeDatabaseExt: Database {
    /// Get fee token balance for a user.
    ///
    /// Returns the user's balance in their configured fee token. Falls back to
    /// validator token if user has no token set.
    fn get_fee_token_balance(
        &mut self,
        user: Address,
        validator: Address,
    ) -> Result<FeeToken, Self::Error>;
}

/// Implementation of TIPFeeManager storage operations for generic [`Database`]
impl<T: Database> TIPFeeDatabaseExt for T {
    fn get_fee_token_balance(
        &mut self,
        user: Address,
        validator: Address,
    ) -> Result<FeeToken, Self::Error> {
        // Look up user's configured fee token in TIPFeeManager storage
        let user_token_slot = mapping_slot(user, tip_fee_manager::slots::USER_TOKENS);
        let user_fee_token = self
            .storage(TIP_FEE_MANAGER_ADDRESS, user_token_slot)?
            .into_address();

        // If the user feeToken is not set, use the validator fee token
        if user_fee_token.is_zero() {
            let validator_token_slot =
                mapping_slot(validator, tip_fee_manager::slots::VALIDATOR_TOKENS);
            let validator_fee_token = self
                .storage(TIP_FEE_MANAGER_ADDRESS, validator_token_slot)?
                .into_address();

            let fee_token = if validator_fee_token.is_zero() {
                DEFAULT_FEE_TOKEN
            } else {
                validator_fee_token
            };

            // Query the user's balance in the validator's fee token
            let balance_slot = mapping_slot(user, tip20::slots::BALANCES);
            let balance = self.storage(fee_token, balance_slot)?;

            Ok(FeeToken::Validator(TokenBalance::new(fee_token, balance)))
        } else {
            // Query the user's balance in their configured fee token
            let balance_slot = mapping_slot(user, tip20::slots::BALANCES);
            let balance = self.storage(user_fee_token, balance_slot)?;

            Ok(FeeToken::User(TokenBalance::new(user_fee_token, balance)))
        }
    }
}
