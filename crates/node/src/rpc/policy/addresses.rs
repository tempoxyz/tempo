use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use tempo_alloy::rpc::pagination::PaginationParams;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressesResponse {
    /// Cursor for next page, null if no more results
    pub next_cursor: Option<String>,
    /// Array of items matching the input query
    pub addresses: Vec<PolicyAddress>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressesParams {
    /// Policy ID to query addresses for
    pub policy_id: u64,
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
