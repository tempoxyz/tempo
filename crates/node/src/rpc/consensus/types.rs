//! RPC types for the consensus namespace.

use alloy_primitives::B256;
use futures::Future;
use serde::{Deserialize, Serialize};
use tempo_alloy::rpc::TempoHeaderResponse;
use tokio::sync::broadcast;

/// A block with a threshold BLS certificate (notarization or finalization).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertifiedBlock {
    pub epoch: u64,
    pub view: u64,
    /// Block height, if known. May be `None` if the block hasn't been stored yet.
    pub height: Option<u64>,
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

/// Error type for identity transition proof requests.
#[derive(Clone, Debug, thiserror::Error)]
pub enum IdentityProofError {
    /// Node is not ready - consensus state not yet initialized.
    #[error("node not ready")]
    NotReady,
    /// Block data has been pruned.
    #[error("block data pruned at height {0}")]
    PrunedData(u64),
    /// Failed to decode DKG outcome from block.
    #[error("malformed DKG outcome at height {0}")]
    MalformedData(u64),
}

/// Response containing identity transition proofs.
///
/// Each transition represents a full DKG ceremony where the network's
/// BLS public key changed. The proof demonstrates that the old network
/// identity endorsed the new identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityTransitionResponse {
    /// Network identity of the requested epoch.
    pub identity: String,
    /// List of identity transitions, ordered newest to oldest.
    /// Empty if no full DKG ceremonies have occurred.
    pub transitions: Vec<IdentityTransition>,
}

/// A single identity transition (full DKG event).
///
/// This proves that the network transitioned from `old_public_key` to
/// `new_public_key` at the given epoch, with a certificate signed by
/// the old network identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityTransition {
    /// Epoch where the full DKG ceremony occurred.
    pub transition_epoch: u64,
    /// Hex-encoded BLS public key before the transition.
    pub old_public_key: String,
    /// Hex-encoded BLS public key after the transition.
    pub new_public_key: String,
    /// Proof of the transition.
    pub proof: TransitionProofData,
}

/// Cryptographic proof data for an identity transition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransitionProofData {
    /// The block header containing the new DKG outcome in extra_data.
    pub header: TempoHeaderResponse,
    /// Hex-encoded finalization.
    pub finalization: String,
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

    /// Get identity transition proofs (full DKG events where network public key changed).
    ///
    /// - `from_epoch`: Optional epoch to start searching from (defaults to latest finalized)
    /// - `full`: If true, return all transitions back to genesis; if false, return only the most recent
    fn get_identity_transition_proof(
        &self,
        from_epoch: Option<u64>,
        full: bool,
    ) -> impl Future<Output = Result<IdentityTransitionResponse, IdentityProofError>> + Send;
}
