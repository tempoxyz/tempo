//! Feed actor implementation.
//!
//! The actor receives finalized blocks from marshal, publishes those with a
//! direct finalization certificate, updates the shared RPC state, and
//! broadcasts them to subscribers.

use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::Heightable as _;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use futures::StreamExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tracing::{debug, error, info_span, instrument};

use super::state::FeedStateHandle;
use crate::{alias::marshal, consensus::block::Block};

/// Receiver for finalized blocks.
pub(super) type Receiver = futures::channel::mpsc::UnboundedReceiver<Block>;

pub(crate) struct Actor<TContext> {
    /// Runtime context.
    context: ContextCell<TContext>,
    /// Receiver for finalized blocks.
    receiver: Receiver,
    /// Shared state handle.
    state: FeedStateHandle,
    /// Marshal mailbox for finalization certificate lookups.
    marshal: marshal::Mailbox,
}

impl<TContext: Spawner> Actor<TContext> {
    /// Create a new feed actor.
    pub(crate) fn new(
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
        while let Some(block) = self.receiver.next().await {
            self.handle_block(block).await;
        }

        info_span!("feed_actor").in_scope(|| error!("mailbox closed; shutting down"));
    }

    #[instrument(skip_all, fields(height = %block.height(), digest = %block.digest()))]
    async fn handle_block(&self, block: Block) {
        let height = block.height();
        let Some(finalization) = self.marshal.get_finalization(height).await else {
            debug!(
                height = height.get(),
                "skipping finalized block without a direct finalization certificate"
            );
            return;
        };
        let round = finalization.proposal.round;

        let finalized = CertifiedBlock {
            epoch: round.epoch().get(),
            view: round.view().get(),
            block: block.into_execution_block(),
            digest: finalization.proposal.payload.0,
            certificate: hex::encode(finalization.encode()),
        };

        self.state.write().latest_finalized = Some(finalized.clone());

        let subscribers = self.state.events_tx().receiver_count();
        debug!(
            subscribers,
            height = height.get(),
            "sending finalized block event"
        );
        let _ = self.state.events_tx().send(Event::Finalized {
            block: finalized,
            seen: now_millis(),
        });
    }
}

/// Get current Unix timestamp in milliseconds.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
