use alloy_primitives::{Address, B256, BlockNumber, TxHash};
use serde::{Deserialize, Serialize};
use tempo_alloy::rpc::pagination::FilterRange;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleHistoryResponse {
    /// Cursor for next page, null if no more results
    pub next_cursor: Option<String>,
    /// Array of items matching the input query
    pub role_changes: Vec<RoleChange>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleHistoryFilters {
    /// Filter by account address that received/lost role
    pub account: Option<Address>,
    /// Block number in range
    pub block_number: Option<FilterRange<BlockNumber>>,
    /// Filter by granted vs revoked (true = grants, false = revocations)
    pub granted: Option<bool>,
    /// Filter by specific role (32-byte hex)
    pub role: Option<B256>,
    /// Filter by address that made the change
    pub sender: Option<Address>,
    /// Timestamp (seconds) in range
    pub timestamp: Option<FilterRange<u64>>,
    /// Filter by token address
    pub token: Option<Address>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleChange {
    /// Account that received/lost the role
    pub account: Address,
    /// Block number where change occurred
    pub block_number: BlockNumber,
    /// Whether role was granted (true) or revoked (false)
    pub granted: bool,
    /// Role identifier (32-byte hex)
    pub role: B256,
    /// Address that made the change
    pub sender: Address,
    /// Timestamp of the change
    pub timestamp: u64,
    /// Token address
    pub token: Address,
    /// Transaction hash
    pub transaction_hash: TxHash,
}
