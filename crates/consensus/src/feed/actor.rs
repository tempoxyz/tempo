//! Feed actor implementation.
//!
//! The actor receives finalized-tip updates from marshal, resolves their
//! persisted blocks and certificates, offers certificates to `tempo/1` peers,
//! updates the shared RPC state, and broadcasts finalized blocks to subscribers.

use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use futures::StreamExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tempo_node::rpc::consensus::CertifiedBlock;
use tracing::{debug, error, info_span, instrument, warn};

use super::{ingress::FinalizedTip, state::FeedStateHandle};
use crate::alias::marshal;

/// Receiver for finalized tips.
pub(super) type Receiver = futures::channel::mpsc::UnboundedReceiver<FinalizedTip>;

pub(crate) struct Actor<TContext> {
    /// Runtime context.
    context: ContextCell<TContext>,
    /// Receiver for finalized tips.
    receiver: Receiver,
    /// Shared state handle.
    state: FeedStateHandle,
    /// Marshal mailbox for finalization certificate lookups.
    marshal: marshal::Mailbox,
    /// Offers certificates to `tempo/1` peers, when gossip is enabled.
    gossip: Option<crate::gossip::Mailbox>,
}

impl<TContext: Spawner> Actor<TContext> {
    /// Create a new feed actor.
    pub(super) fn new(
        context: TContext,
        marshal: marshal::Mailbox,
        receiver: Receiver,
        state: FeedStateHandle,
        gossip: Option<crate::gossip::Mailbox>,
    ) -> Self {
        state.set_marshal(marshal.clone());

        Self {
            context: ContextCell::new(context),
            receiver,
            state,
            marshal,
            gossip,
        }
    }

    /// Start the actor, returning a handle to the spawned task.
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(tip) = self.receiver.next().await {
            self.handle_tip(tip).await;
        }

        info_span!("feed_actor").in_scope(|| error!("mailbox closed; shutting down"));
    }

    #[instrument(skip_all, fields(height = %tip.height, digest = %tip.digest))]
    async fn handle_tip(&self, tip: FinalizedTip) {
        let Some(finalization) = self.marshal.get_finalization(tip.height).await else {
            warn!("finalized tip without a persisted certificate");
            return;
        };
        let Some(block) = self.marshal.get_block(tip.height).await else {
            warn!("finalized tip without a persisted block");
            return;
        };

        // Publish only after marshal returns both the certificate and its block.
        // The node can now serve the block instead of advertising unavailable
        // data.
        if let Some(gossip) = &self.gossip {
            gossip.publish(
                finalization.round(),
                tempo_node::gossip::wire::encode(&finalization.encode())
                    .freeze()
                    .into(),
            );
        }

        let certified = CertifiedBlock {
            epoch: tip.round.epoch().get(),
            view: tip.round.view().get(),
            digest: tip.digest.0,
            block: block.into_execution_block(),
            certificate: hex::encode(finalization.encode()),
        };

        let subscribers = self.state.publish_certified(certified, now_millis());
        debug!(subscribers, "published new certified block");
    }
}

/// Get current Unix timestamp in milliseconds.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
