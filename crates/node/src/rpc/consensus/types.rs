//! RPC types for the consensus namespace.

use alloy_primitives::B256;
use futures::Future;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// A block with a threshold BLS certificate (notarization or finalization).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertifiedBlock {
    pub epoch: u64,
    pub view: u64,
    pub height: u64,
    pub digest: B256,
    pub certificate: String,
}

/// Consensus event emitted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Event {
    /// A block was notarized.
    Notarized {
        #[serde(flatten)]
        block: CertifiedBlock,
        /// Unix timestamp in milliseconds when this event was observed.
        seen: u64,
    },
    /// A block was finalized.
    Finalized {
        #[serde(flatten)]
        block: CertifiedBlock,
        /// Unix timestamp in milliseconds when this event was observed.
        seen: u64,
    },
    /// A view was nullified.
    Nullified {
        epoch: u64,
        view: u64,
        /// Unix timestamp in milliseconds when this event was observed.
        seen: u64,
    },
}

/// Query for consensus data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Query {
    /// Get the latest item.
    Latest,
    /// Get by block height.
    Height(u64),
}

/// Response for get_latest - current consensus state snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusState {
    /// The latest finalized block (if any).
    pub finalized: Option<CertifiedBlock>,
    /// The latest notarized block (if any, and not yet finalized).
    pub notarized: Option<CertifiedBlock>,
}

/// Trait for accessing consensus feed data.
pub trait ConsensusFeed: Send + Sync + 'static {
    /// Get a finalization by query (supports `Latest` or `Height`).
    fn get_finalization(&self, query: Query)
    -> impl Future<Output = Option<CertifiedBlock>> + Send;

    /// Get the current consensus state (latest finalized + latest notarized).
    fn get_latest(&self) -> impl Future<Output = ConsensusState> + Send;

    /// Subscribe to consensus events.
    fn subscribe(&self) -> impl Future<Output = Option<broadcast::Receiver<Event>>> + Send;
}
