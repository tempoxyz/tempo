use crate::rpc::{
    dex::{PaginationParams, types::FieldName},
    token::tokens::{Token, TokensFilters},
};
use alloy_primitives::{Address, B256, U256};
use jsonrpsee::core::Serialize;
use serde::Deserialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokensByAddressParams {
    /// Filter by account address that received/lost role.
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

impl FieldName for AccountToken {
    fn field_plural_camel_case() -> &'static str {
        "tokens"
    }
}
