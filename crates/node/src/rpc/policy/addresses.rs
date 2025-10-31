use crate::rpc::pagination::{FieldName, PaginationParams};
use alloy_primitives::{Address, B256};
use jsonrpsee::core::Serialize;
use serde::Deserialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressesParams {
    /// Policy ID to query addresses for
    pub policy_id: B256,
    /// Determines what items should be yielded in the response.
    #[serde(flatten)]
    pub params: PaginationParams<AddressesFilters>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressesFilters {
    /// Filter by authorization status (true = authorized, false = not authorized)
    pub authorized: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAddress {
    /// Address in the policy
    pub address: Address,
    /// Whether address is authorized (depends on policy type)
    pub authorized: bool,
}

impl FieldName for PolicyAddress {
    fn field_plural_camel_case() -> &'static str {
        "addresses"
    }
}
