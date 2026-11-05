//! Chain recovery after the network lost the threshold key of an epoch.

use alloy_primitives::{B256, Bytes};

/// Restarts consensus after the epoch containing [`Self::finalized_height`] lost its signing key.
///
/// Every node fills the rest of that epoch with the same empty blocks, writes [`Self::outcome`]
/// into the boundary block that ends it, and starts the next epoch from that outcome. The
/// boundary carries no finalization certificate; its hash is trusted because it is pinned here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Recovery {
    /// Height of the last block finalized before consensus halted.
    pub finalized_height: u64,
    /// Hash of the block at [`Self::finalized_height`].
    pub finalized_hash: B256,
    /// Hash of the boundary block that ends the halted epoch, as every node must build it.
    pub boundary_hash: B256,
    /// Encoded `OnchainDkgOutcome` written into the boundary block's `extra_data`. It is
    /// the outcome for the epoch after the halted one.
    pub outcome: Bytes,
}
