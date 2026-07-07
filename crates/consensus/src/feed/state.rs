//! Shared state for the feed module.

use crate::alias::marshal;
use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::types::{Epoch, Height, Round, View};
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
    /// Latest notarized block.
    pub(super) latest_notarized: Option<CertifiedBlock>,
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
                latest_notarized: None,
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

    /// Get read access to the internal state.
    pub(super) fn read(&self) -> parking_lot::RwLockReadGuard<'_, FeedState> {
        self.state.read()
    }

    /// Get write access to the internal state.
    pub(super) fn write(&self) -> parking_lot::RwLockWriteGuard<'_, FeedState> {
        self.state.write()
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
            .field("latest_notarized", &state.latest_notarized)
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
        let (finalized, mut notarized) = {
            let state = self.state.read();
            (
                state.latest_finalized.clone(),
                state.latest_notarized.clone(),
            )
        };

        let finalized_round = finalized
            .as_ref()
            .map(|f| Round::new(Epoch::new(f.epoch), View::new(f.view)));

        let notarized_round = notarized
            .as_ref()
            .map(|n| Round::new(Epoch::new(n.epoch), View::new(n.view)));

        // Only include the notarization if it is ahead.
        if finalized_round.is_some_and(|f| notarized_round.is_none_or(|n| n <= f)) {
            notarized = None;
        }

        ConsensusState {
            finalized,
            notarized,
        }
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Event>> {
        Some(self.events_tx.subscribe())
    }
}
