use crate::rpc::pagination::{PaginationParams, Sort};
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

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
    pub params: PaginationParams<AddressesFilters, Sort>,
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

impl PolicyAddress {
    /// Indicates that `address` is an authorized account according to the transfer policy.
    pub const fn allowed(address: Address) -> Self {
        Self {
            address,
            authorized: true,
        }
    }

    /// Indicates that `address` is an unauthorized account according to the transfer policy.
    pub const fn blocked(address: Address) -> Self {
        Self {
            address,
            authorized: false,
        }
    }
}
