use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use tempo_alloy::rpc::pagination::FilterRange;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolsResponse {
    /// Cursor for next page, null if no more results
    pub next_cursor: Option<String>,
    /// Array of items matching the input query
    pub pools: Vec<Pool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolsFilters {
    /// Effective validator reserve in range
    pub effective_validator_reserve: Option<FilterRange<U256>>,
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
    pub pool_id: B256,
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
