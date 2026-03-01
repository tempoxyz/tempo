use crate::rpc::token::tokens::{Token, TokensFilters};
use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use tempo_alloy::rpc::pagination::PaginationParams;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokensByAddressResponse {
    /// Cursor for next page, null if no more results
    pub next_cursor: Option<String>,
    /// Array of items matching the input query
    pub tokens: Vec<AccountToken>,
    /// When `true`, the indexer cache is behind and the response may be incomplete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_stale: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokensByAddressParams {
    /// Account address to query tokens for.
    pub address: Address,
    /// Determines what items should be yielded in the response.
    #[serde(flatten)]
    pub params: PaginationParams<TokensFilters>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountToken {
    /// Account's balance in this token
    pub balance: U256,
    /// Roles the account has for this token
    pub roles: Vec<B256>,
    /// Token details
    pub token: Token,
}
