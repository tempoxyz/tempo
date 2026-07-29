//! Shared state for the feed module.

use crate::alias::marshal;
use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::types::Height;
use parking_lot::RwLock;
use std::sync::{Arc, OnceLock};
use tempo_node::rpc::consensus::{
    CertifiedBlock, ConsensusFeed, ConsensusState, Event, Query, types::Response,
};
use tokio::sync::broadcast;
use tracing::{Level, instrument};

const BROADCAST_CHANNEL_SIZE: usize = 1024;

/// Internal shared state for the feed.
pub(super) struct FeedState {
    /// Latest finalized block.
    pub(super) latest_finalized: Option<CertifiedBlock>,
}

/// Handle to shared feed state.
///
/// This handle can be cloned and used by both:
/// - The feed actor (to update state when processing finalized blocks)
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

    /// Update the latest finalized block and broadcast it to RPC subscribers.
    pub(crate) fn publish_certified(&self, block: CertifiedBlock, seen: u64) -> usize {
        self.state.write().latest_finalized = Some(block.clone());
        let subscribers = self.events_tx.receiver_count();
        let _ = self.events_tx.send(Event::Finalized { block, seen });
        subscribers
    }

    /// Get the marshal mailbox, logging if not yet set.
    fn marshal(&self) -> Option<marshal::Mailbox> {
        let marshal = self.marshal.get().cloned();
        if marshal.is_none() {
            tracing::debug!("marshal not yet set");
        }
        marshal
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
            .field("latest_finalized", &state.latest_finalized)
            .field("marshal_set", &self.marshal.get().is_some())
            .field("subscriber_count", &self.events_tx.receiver_count())
            .finish()
    }
}

impl ConsensusFeed for FeedStateHandle {
    #[instrument(skip_all, fields(%query), ret(level = Level::DEBUG, Display))]
    async fn get_finalization(&self, query: Query) -> Response<CertifiedBlock> {
        match query {
            Query::Latest => self
                .state
                .read()
                .latest_finalized
                .clone()
                .map_or(Response::Missing("certifications"), Response::Success),
            Query::Height(height) => 'process: {
                let height = Height::new(height);
                let Some(marshal) = self.marshal() else {
                    break 'process Response::NotReady;
                };

                let Some(finalization) = marshal.get_finalization(height).await else {
                    break 'process Response::Missing("certificate");
                };
                let Some(block) = marshal.get_block(height).await else {
                    break 'process Response::Missing("block");
                };

                Response::Success(CertifiedBlock {
                    epoch: finalization.proposal.round.epoch().get(),
                    view: finalization.proposal.round.view().get(),
                    block: block.into_execution_block(),
                    digest: finalization.proposal.payload.0,
                    certificate: hex::encode(finalization.encode()),
                })
            }
        }
    }

    async fn get_latest(&self) -> ConsensusState {
        ConsensusState {
            finalized: self.state.read().latest_finalized.clone(),
            notarized: None,
        }
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Event>> {
        Some(self.events_tx.subscribe())
    }
}
