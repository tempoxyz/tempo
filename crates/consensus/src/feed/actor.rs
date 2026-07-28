//! Feed actor implementation.
//!
//! The actor receives finalized-tip updates from marshal, resolves their
//! persisted blocks and certificates, updates the shared RPC state, and
//! broadcasts them to subscribers.

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
}

impl<TContext: Spawner> Actor<TContext> {
    /// Create a new feed actor.
    pub(super) fn new(
        context: TContext,
        marshal: marshal::Mailbox,
        receiver: Receiver,
        state: FeedStateHandle,
    ) -> Self {
        state.set_marshal(marshal.clone());

        Self {
            context: ContextCell::new(context),
            receiver,
            state,
            marshal,
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
