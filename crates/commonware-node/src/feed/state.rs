//! Shared state for the feed module.

use crate::alias::marshal;
use alloy_primitives::{B256, hex};
use async_trait::async_trait;
use commonware_codec::Encode;
use parking_lot::RwLock;
use schnellru::{ByLength, LruMap};
use std::sync::{Arc, OnceLock};
use tempo_node::rpc::consensus::{
    CertifiedBlock, ConsensusFeed, ConsensusState, Event, Query, QueryError,
};
use tokio::sync::broadcast;

const BROADCAST_CHANNEL_SIZE: usize = 1024;
const MAX_NOTARIZATIONS: u32 = 1024;

/// Internal shared state for the feed.
pub(super) struct FeedState {
    /// In-memory notarization cache, keyed by view.
    pub(super) notarizations: LruMap<u64, CertifiedBlock, ByLength>,
    /// Latest notarized view.
    pub(super) latest_notarized_view: Option<u64>,
    /// Latest finalized block.
    pub(super) latest_finalized: Option<CertifiedBlock>,
}

/// Handle to shared feed state.
///
/// This handle can be cloned and used by both:
/// - The feed actor (to update state when processing Activity)
/// - RPC handlers (implements `ConsensusFeed`)
#[derive(Clone)]
pub struct FeedStateHandle {
    state: Arc<RwLock<FeedState>>,
    marshal: Arc<OnceLock<marshal::Mailbox>>,
    events_tx: broadcast::Sender<Event>,
}

impl FeedStateHandle {
    /// Create a new feed state handle.
    ///
    /// The marshal mailbox can be set later using `set_marshal`.
    /// Until set, historical finalization lookups will return `None`.
    pub fn new() -> Self {
        let (events_tx, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);
        Self {
            state: Arc::new(RwLock::new(FeedState {
                notarizations: LruMap::new(ByLength::new(MAX_NOTARIZATIONS)),
                latest_notarized_view: None,
                latest_finalized: None,
            })),
            marshal: Arc::new(OnceLock::new()),
            events_tx,
        }
    }

    /// Set the marshal mailbox for historical finalization lookups. Should only be called once.
    pub(crate) fn set_marshal(&self, marshal: marshal::Mailbox) {
        let _ = self.marshal.set(marshal);
    }

    /// Get the broadcast sender for events.
    pub(super) fn events_tx(&self) -> &broadcast::Sender<Event> {
        &self.events_tx
    }

    /// Get write access to the internal state.
    pub(super) fn write(&self) -> parking_lot::RwLockWriteGuard<'_, FeedState> {
        self.state.write()
    }
}

impl Default for FeedStateHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FeedStateHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.read();
        f.debug_struct("FeedStateHandle")
            .field("latest_notarized_view", &state.latest_notarized_view)
            .field("latest_finalized", &state.latest_finalized)
            .field("notarizations_count", &state.notarizations.len())
            .field("marshal_set", &self.marshal.get().is_some())
            .field("subscriber_count", &self.events_tx.receiver_count())
            .finish()
    }
}

#[async_trait]
impl ConsensusFeed for FeedStateHandle {
    async fn get_notarization(&self, query: Query) -> Result<Option<CertifiedBlock>, QueryError> {
        let state = self.state.read();
        match query {
            Query::Latest => Ok(state
                .latest_notarized_view
                .and_then(|view| state.notarizations.peek(&view).cloned())),
            Query::View(view) => Ok(state.notarizations.peek(&view).cloned()),
            Query::Height(_) => Err(QueryError::HeightNotSupported),
        }
    }

    async fn get_finalization(&self, query: Query) -> Result<Option<CertifiedBlock>, QueryError> {
        match query {
            Query::Latest => Ok(self.state.read().latest_finalized.clone()),
            Query::Height(height) => {
                let Some(mut marshal) = self.marshal.get().cloned() else {
                    return Ok(None);
                };

                let Some(finalization) = marshal.get_finalization(height).await else {
                    return Ok(None);
                };

                let view = finalization.proposal.round.view().get();
                let epoch = finalization.proposal.round.epoch().get();
                let digest = B256::from_slice(finalization.proposal.payload.as_ref());
                let certificate = hex::encode(finalization.certificate.encode());

                Ok(Some(CertifiedBlock {
                    epoch,
                    view,
                    height,
                    digest,
                    certificate,
                }))
            }
            Query::View(_) => Err(QueryError::ViewNotSupported),
        }
    }

    async fn get_latest(&self) -> ConsensusState {
        let state = self.state.read();
        ConsensusState {
            finalized: state.latest_finalized.clone(),
            notarized: state.notarizations.iter().map(|(_, v)| v.clone()).collect(),
        }
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Event>> {
        Some(self.events_tx.subscribe())
    }
}
