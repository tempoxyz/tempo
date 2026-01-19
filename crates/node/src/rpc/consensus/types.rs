//! RPC types for the consensus namespace.

use alloy_primitives::B256;
use futures::Future;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// A block with a threshold BLS certificate (notarization or finalization).
///
/// Contains all data needed for clients to verify the certificate independently:
/// - Block header fields for commitment reconstruction
/// - The threshold BLS public key for signature verification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertifiedBlock {
    pub epoch: u64,
    pub view: u64,
    /// Block height, if known. May be `None` if the block hasn't been stored yet.
    pub height: Option<u64>,
    /// Block hash (digest).
    pub digest: B256,
    /// Hex-encoded full notarization or finalization certificate.
    pub certificate: String,

    /// Block header data for verification (populated when block is available).
    #[serde(flatten)]
    pub header: Option<BlockHeaderData>,

    /// Hex-encoded threshold BLS public key (G1 point, 48 bytes compressed)
    /// for verifying the certificate signature. `None` if the scheme for
    /// this epoch is not available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_public_key: Option<String>,
}

/// Block header data needed for certificate verification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeaderData {
    /// Parent block hash.
    pub parent_hash: B256,
    /// State root after executing this block.
    pub state_root: B256,
    /// Receipts root (trie root of transaction receipts).
    pub receipts_root: B256,
    /// Block timestamp.
    pub timestamp: u64,
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
