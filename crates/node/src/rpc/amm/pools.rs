use crate::rpc::dex::{FilterRange, types::FieldName};
use alloy_primitives::{Address, U256};
use jsonrpsee::core::Serialize;
use serde::Deserialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolsFilters {
    /// Effective validator reserve in range
    pub effective_validator_reserve: Option<FilterRange<U256>>,
    /// Pending fee swap input in range
    pub pending_fee_swap_in: Option<FilterRange<U256>>,
    /// Reserve user token in range
    pub reserve_user_token: Option<FilterRange<U256>>,
    /// Reserve validator token in range
    pub reserve_validator_token: Option<FilterRange<U256>>,
    /// Total supply (LP tokens) in range
    pub total_supply: Option<FilterRange<U256>>,
    /// Filter by user token address
    pub user_token: Option<Address>,
    /// Filter by validator token address
    pub validator_token: Option<Address>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pool {
    /// Effective reserve of validator token after pending swaps
    pub effective_reserve_validator_token: U256,
    /// Pool ID (keccak256 of userToken and validatorToken)
    pub pool_id: U256,
    /// User token reserve
    pub reserve_user_token: U256,
    /// Validator token reserve
    pub reserve_validator_token: U256,
    /// Total LP token supply for this pool
    pub total_supply: U256,
    /// User token address
    pub user_token: Address,
    /// Validator token address
    pub validator_token: Address,
}

impl FieldName for Pool {
    fn field_plural_camel_case() -> &'static str {
        "pools"
    }
}
