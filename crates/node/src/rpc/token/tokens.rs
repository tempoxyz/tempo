use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use tempo_alloy::rpc::pagination::FilterRange;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokensResponse {
    /// Cursor for next page, null if no more results
    pub next_cursor: Option<String>,
    /// Array of items matching the input query
    pub tokens: Vec<Token>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokensFilters {
    /// Filter by currency code (e.g., "USD", "EUR", "JPY")
    pub currency: Option<String>,
    /// Filter by creator address
    pub creator: Option<Address>,
    /// Created timestamp (seconds) in range
    pub created_at: Option<FilterRange<u64>>,
    /// Filter by token name (case-insensitive)
    pub name: Option<String>,
    /// Filter by pause state
    pub paused: Option<bool>,
    /// Filter by quote token address
    pub quote_token: Option<Address>,
    /// Supply cap in range
    pub supply_cap: Option<FilterRange<u128>>,
    /// Filter by symbol
    pub symbol: Option<String>,
    /// Total supply in range
    pub total_supply: Option<FilterRange<u128>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Token {
    /// Token contract address (deterministic vanity address based on tokenId)
    pub address: Address,
    /// Timestamp when token was created
    #[serde(with = "alloy_serde::quantity")]
    pub created_at: u64,
    /// Address that created the token
    pub creator: Address,
    /// Currency code (e.g., "USD", "EUR")
    pub currency: String,
    /// Token decimals
    #[serde(with = "alloy_serde::quantity")]
    pub decimals: u32,
    /// Token name
    pub name: String,
    /// Whether token transfers are paused
    pub paused: bool,
    /// Quote token address for trading pairs
    pub quote_token: Address,
    /// Maximum token supply
    #[serde(with = "alloy_serde::quantity")]
    pub supply_cap: u128,
    /// Token symbol
    pub symbol: String,
    /// Unique token ID from factory
    #[serde(with = "alloy_serde::quantity")]
    pub token_id: u64,
    /// Current total supply
    #[serde(with = "alloy_serde::quantity")]
    pub total_supply: u128,
    /// Current transfer policy ID
    #[serde(with = "alloy_serde::quantity")]
    pub transfer_policy_id: u64,
}
