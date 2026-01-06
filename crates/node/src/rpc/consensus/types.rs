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
    /// Get by block height (for finalizations).
    Height(u64),
    /// Get by view number (for notarizations).
    View(u64),
}

/// Error for unsupported query types.
#[derive(Debug, Clone, thiserror::Error)]
pub enum QueryError {
    /// Height query not supported, use Latest or View.
    #[error("unsupported query: use `latest` or `view` for notarizations")]
    HeightNotSupported,
    /// View query not supported, use Latest or Height.
    #[error("unsupported query: use `latest` or `height` for finalizations")]
    ViewNotSupported,
}

/// Response for get_latest - current consensus state snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusState {
    /// The latest finalized block (if any).
    pub finalized: Option<CertifiedBlock>,
    /// All cached notarizations.
    pub notarized: Vec<CertifiedBlock>,
}

/// Trait for accessing consensus feed data.
pub trait ConsensusFeed: Send + Sync + 'static {
    /// Get a notarization by query (supports `Latest` or `View`).
    fn get_notarization(
        &self,
        query: Query,
    ) -> impl Future<Output = Result<Option<CertifiedBlock>, QueryError>> + Send;

    /// Get a finalization by query (supports `Latest` or `Height`).
    fn get_finalization(
        &self,
        query: Query,
    ) -> impl Future<Output = Result<Option<CertifiedBlock>, QueryError>> + Send;

    /// Get the current consensus state (latest finalized + all cached notarizations).
    fn get_latest(&self) -> impl Future<Output = ConsensusState> + Send;

    /// Subscribe to consensus events.
    fn subscribe(&self) -> impl Future<Output = Option<broadcast::Receiver<Event>>> + Send;
}
