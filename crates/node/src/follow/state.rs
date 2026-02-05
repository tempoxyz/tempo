//! Follow mode feed state for serving consensus RPCs.

use super::storage::{self, FinalizationStoreHandle};
use crate::rpc::consensus::{
    CertifiedBlock, ConsensusFeed, ConsensusState, Event, IdentityProofError,
    IdentityTransitionResponse, Query,
};
use std::{
    path::Path,
    sync::{Arc, RwLock},
};
use tokio::sync::broadcast;

const BROADCAST_CHANNEL_SIZE: usize = 1024;

/// Internal state for the follow feed.
struct FeedState {
    latest_finalized: Option<CertifiedBlock>,
}

/// Feed state for follow mode nodes.
///
/// This implements `ConsensusFeed` to serve consensus RPC queries
/// using data fetched and stored by the `CertifiedBlockProvider`.
#[derive(Clone)]
pub struct FollowFeedState {
    state: Arc<RwLock<FeedState>>,
    events_tx: broadcast::Sender<Event>,
    /// Handle to the finalization storage service.
    storage: Option<FinalizationStoreHandle>,
}

impl FollowFeedState {
    /// Create a new follow feed state with persistent storage.
    ///
    /// This starts a background storage service that persists finalization
    /// certificates for snapshot compatibility with validators.
    ///
    /// # Arguments
    /// * `storage_dir` - Directory for storage data (typically `<datadir>/follow`)
    /// * `shutdown_token` - Cancellation token for graceful shutdown
    pub async fn new(
        storage_dir: impl AsRef<Path>,
        shutdown_token: tokio_util::sync::CancellationToken,
    ) -> eyre::Result<Self> {
        let (events_tx, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);

        let config = storage::FinalizationStoreConfig {
            storage_dir: storage_dir.as_ref().to_path_buf(),
            worker_threads: Some(1),
        };

        let (storage, _storage_thread) =
            storage::start_finalization_store_async(config, shutdown_token).await?;

        Ok(Self {
            state: Arc::new(RwLock::new(FeedState {
                latest_finalized: None,
            })),
            events_tx,
            storage: Some(storage),
        })
    }

    /// Create a new follow feed state without persistent storage.
    ///
    /// This is useful for testing or when persistence is not needed.
    /// Historical finalization queries (`Query::Height`) will return `None`.
    pub fn without_storage() -> Self {
        let (events_tx, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);
        Self {
            state: Arc::new(RwLock::new(FeedState {
                latest_finalized: None,
            })),
            events_tx,
            storage: None,
        }
    }

    /// Get the storage handle if set.
    pub(super) fn storage(&self) -> Option<&FinalizationStoreHandle> {
        self.storage.as_ref()
    }

    /// Update the latest finalized block.
    pub fn set_finalized(&self, block: CertifiedBlock) {
        if let Ok(mut state) = self.state.write() {
            state.latest_finalized = Some(block.clone());
        }
        let _ = self.events_tx.send(Event::Finalized {
            block,
            seen: now_millis(),
        });
    }

    /// Get the events sender for broadcasting.
    pub fn events_tx(&self) -> &broadcast::Sender<Event> {
        &self.events_tx
    }

    /// Initialize from storage on startup.
    ///
    /// This loads the latest finalization from storage to populate the in-memory
    /// state, enabling immediate RPC serving after snapshot restore.
    pub async fn init_from_storage(&self) {
        if let Some(storage) = self.storage() {
            if let Some((height, block)) = storage.latest().await {
                reth_tracing::tracing::info!(
                    height,
                    "restored latest finalization from storage"
                );
                if let Ok(mut state) = self.state.write() {
                    state.latest_finalized = Some(block);
                }
            }
        }
    }
}

impl std::fmt::Debug for FollowFeedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("FollowFeedState");
        if let Ok(state) = self.state.read() {
            debug_struct.field("latest_finalized", &state.latest_finalized);
        }
        debug_struct
            .field("subscriber_count", &self.events_tx.receiver_count())
            .finish()
    }
}

impl ConsensusFeed for FollowFeedState {
    async fn get_finalization(&self, query: Query) -> Option<CertifiedBlock> {
        match query {
            Query::Latest => self
                .state
                .read()
                .ok()
                .and_then(|s| s.latest_finalized.clone()),
            Query::Height(height) => {
                // Query from storage
                self.storage()?.get(height).await
            }
        }
    }

    async fn get_latest(&self) -> ConsensusState {
        let finalized = self
            .state
            .read()
            .ok()
            .and_then(|s| s.latest_finalized.clone());
        ConsensusState {
            finalized,
            // Follow mode doesn't track notarizations
            notarized: None,
        }
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Event>> {
        Some(self.events_tx.subscribe())
    }

    async fn get_identity_transition_proof(
        &self,
        _from_epoch: Option<u64>,
        _full: bool,
    ) -> Result<IdentityTransitionResponse, IdentityProofError> {
        // TODO: Implement once we store epoch identity data
        Err(IdentityProofError::NotReady)
    }
}

/// Get current Unix timestamp in milliseconds.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
