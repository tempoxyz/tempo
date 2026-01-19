//! Shared state for the feed module.

use crate::{alias::marshal, consensus::Digest, epoch::SchemeProvider};
use alloy_consensus::BlockHeader as _;
use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::{Heightable as _, types::Height};
use commonware_cryptography::certificate::Provider;
use parking_lot::RwLock;
use std::sync::{Arc, OnceLock};
use tempo_node::rpc::consensus::{
    BlockHeaderData, CertifiedBlock, ConsensusFeed, ConsensusState, Event, Query,
};
use tokio::sync::broadcast;

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
    scheme_provider: Arc<OnceLock<SchemeProvider>>,
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
            scheme_provider: Arc::new(OnceLock::new()),
            events_tx,
        }
    }

    /// Set the marshal mailbox for historical finalization lookups. Should only be called once.
    pub(crate) fn set_marshal(&self, marshal: marshal::Mailbox) {
        let _ = self.marshal.set(marshal);
    }

    /// Set the scheme provider for threshold public key lookups. Should only be called once.
    pub(crate) fn set_scheme_provider(&self, provider: SchemeProvider) {
        let _ = self.scheme_provider.set(provider);
    }

    /// Get the broadcast sender for events.
    pub(super) fn events_tx(&self) -> &broadcast::Sender<Event> {
        &self.events_tx
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

    /// Get the threshold public key for an epoch.
    fn threshold_public_key(&self, epoch: u64) -> Option<String> {
        use commonware_codec::Encode as _;
        self.scheme_provider.get().and_then(|provider| {
            provider
                .scoped(commonware_consensus::types::Epoch::new(epoch))
                .map(|scheme| hex::encode(scheme.identity().encode()))
        })
    }

    /// Fill in missing block data by querying the marshal.
    async fn maybe_fill_block_data(&self, block: &mut CertifiedBlock) {
        if (block.height.is_none() || block.header.is_none())
            && let Some(mut marshal) = self.marshal()
            && let Some(b) = marshal.get_block(&Digest(block.digest)).await
        {
            block.height = Some(b.height().get());
            block.header = Some(BlockHeaderData {
                parent_hash: b.parent_hash(),
                state_root: b.state_root(),
                receipts_root: b.receipts_root(),
                timestamp: b.timestamp(),
            });
        }
        if block.threshold_public_key.is_none() {
            block.threshold_public_key = self.threshold_public_key(block.epoch);
        }
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
    async fn get_finalization(&self, query: Query) -> Option<CertifiedBlock> {
        match query {
            Query::Latest => {
                let mut block = self.state.read().latest_finalized.clone()?;
                self.maybe_fill_block_data(&mut block).await;
                Some(block)
            }
            Query::Height(height) => {
                let mut marshal = self.marshal()?;
                let finalization = marshal.get_finalization(Height::new(height)).await?;

                let epoch = finalization.proposal.round.epoch().get();
                let mut block = CertifiedBlock {
                    epoch,
                    view: finalization.proposal.round.view().get(),
                    height: Some(height),
                    digest: finalization.proposal.payload.0,
                    certificate: hex::encode(finalization.encode()),
                    header: None,
                    threshold_public_key: None,
                };

                self.maybe_fill_block_data(&mut block).await;
                Some(block)
            }
        }
    }

    async fn get_latest(&self) -> ConsensusState {
        let (mut finalized, mut notarized) = {
            let state = self.state.read();
            (
                state.latest_finalized.clone(),
                state.latest_notarized.clone(),
            )
        };

        if let Some(ref mut block) = finalized {
            self.maybe_fill_block_data(block).await;
        }
        if let Some(ref mut block) = notarized {
            self.maybe_fill_block_data(block).await;
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
