use crate::rpc::pagination::{FieldName, FilterRange};
use alloy_primitives::{Address, B256, U256};
use jsonrpsee::core::Serialize;
use serde::Deserialize;

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
    pub supply_cap: Option<FilterRange<U256>>,
    /// Filter by symbol
    pub symbol: Option<String>,
    /// Total supply in range
    pub total_supply: Option<FilterRange<U256>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Token {
    /// Token contract address (deterministic vanity address based on tokenId)
    pub address: Address,
    /// Timestamp when token was created
    pub created_at: u64,
    /// Address that created the token
    pub creator: Address,
    /// Currency code (e.g., "USD", "EUR")
    pub currency: String,
    /// Token decimals (from TIP-4217 registry based on currency)
    pub decimals: u32,
    /// Token name
    pub name: String,
    /// Whether token transfers are paused
    pub paused: bool,
    /// Quote token address for trading pairs
    pub quote_token: Address,
    /// Maximum token supply
    pub supply_cap: U256,
    /// Token symbol
    pub symbol: String,
    /// Unique token ID from factory
    pub token_id: B256,
    /// Current total supply
    pub total_supply: U256,
    /// Current transfer policy ID
    pub transfer_policy_id: B256,
}

impl FieldName for Token {
    fn field_plural_camel_case() -> &'static str {
        "tokens"
    }
}
