//! Feed actor implementation.
//!
//! This actor:
//! - Receives consensus activity (notarizations, finalizations)
//! - Updates shared state (accessible by RPC handlers)
//! - Broadcasts events to subscribers
//!
//! Block resolution uses [`marshal::Mailbox::subscribe_by_digest`] to wait for the block
//! to become available, avoiding a race where the block hasn't been stored yet
//! when the activity arrives.
//!
//! The actor always polls the oldest (lowest-round) pending subscription so
//! that events are emitted in order. Notarizations are dropped when a finalization
//!  at a higher-or-equal round is pending, since the finalization supersedes them.

use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Activity},
    types::{Epoch, FixedEpocher, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_macros::select;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::channel::oneshot;
use eyre::eyre;
use futures::{FutureExt, StreamExt};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tempo_node::{
    TempoFullNode,
    rpc::consensus::{CertifiedBlock, Event},
};
use tracing::{error, info_span, instrument, warn, warn_span};

use super::state::FeedStateHandle;
use crate::{
    alias::marshal,
    consensus::{Digest, block::Block},
    utils::OptionFuture,
};

/// Type alias for the activity type used by the feed actor.
pub(super) type FeedActivity = Activity<Scheme<PublicKey, MinSig>, Digest>;

/// Receiver for activity messages.
pub(super) type Receiver = futures::channel::mpsc::UnboundedReceiver<FeedActivity>;

/// A pending block subscription paired with its originating activity.
///
/// Resolves to `(Round, FeedActivity, Block)` when the block becomes available.
struct PendingSubscription {
    round: Round,
    activity: Option<FeedActivity>,
    block_rx: oneshot::Receiver<Block>,
}

impl PendingSubscription {
    fn new(round: Round, activity: FeedActivity, block_rx: oneshot::Receiver<Block>) -> Self {
        Self {
            round,
            activity: Some(activity),
            block_rx,
        }
    }
}

impl Future for PendingSubscription {
    type Output = eyre::Result<(Round, FeedActivity, Block)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.block_rx.poll_unpin(cx) {
            Poll::Ready(Ok(block)) => {
                let activity = self.activity.take().expect("polled after completion");
                Poll::Ready(Ok((self.round, activity, block)))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(eyre::eyre!("block subscription cancelled"))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(crate) struct Actor<TContext> {
    /// Runtime context.
    context: ContextCell<TContext>,
    /// Receiver for activity messages.
    receiver: Receiver,
    /// Shared state handle.
    state: FeedStateHandle,
    /// Marshal mailbox for block lookups.
    marshal: marshal::Mailbox,
    /// Pending block subscriptions keyed by round. Since finalizations
    /// must be delivered, pending subscriptions are bound by the marshal.
    pending: BTreeMap<Round, PendingSubscription>,
}

impl<TContext: Spawner> Actor<TContext> {
    /// Create a new feed actor.
    ///
    /// The actor receives Activity messages via `receiver` and updates the shared `state`.
    pub(crate) fn new(
        context: TContext,
        marshal: marshal::Mailbox,
        epocher: FixedEpocher,
        execution_node: TempoFullNode,
        receiver: Receiver,
        state: FeedStateHandle,
    ) -> Self {
        state.set_marshal(marshal.clone());
        state.set_epocher(epocher);
        state.set_execution_node(execution_node);

        Self {
            context: ContextCell::new(context),
            receiver,
            state,
            marshal,
            pending: BTreeMap::new(),
        }
    }

    /// Start the actor, returning a handle to the spawned task.
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    /// Run the actor's main loop.
    ///
    /// The loop races the oldest pending block subscription
    /// against incoming activity so events are emitted in order.
    async fn run(&mut self) {
        let reason = loop {
            // We need a mutable reference to poll pending subscription. Thus if a new activity arrives,
            // we also need to re-insert this popped subscription.
            let mut oldest = OptionFuture::from(self.pending.pop_first().map(|(_, p)| p));

            select!(
                result = &mut oldest => {
                    match result {
                        Ok((_, activity, block)) => self.handle_activity(activity, block),
                        Err(error) => warn_span!("feed_actor").in_scope(||
                            warn!(%error, "did not get pending block")
                        ),
                    }
                },

                activity = self.receiver.next() => {
                    let Some(activity) = activity else {
                        break eyre!("mailbox closed");
                    };

                    if let Some(p) = oldest.take() {
                        self.pending.insert(p.round, p);
                    }
                    self.subscribe(activity).await;
                },
            );
        };

        info_span!("feed_actor").in_scope(|| error!(%reason, "shutting down"));
    }

    async fn subscribe(&mut self, activity: FeedActivity) {
        let (round, payload) = match &activity {
            Activity::Notarization(n) => (n.proposal.round, n.proposal.payload),
            Activity::Finalization(f) => (f.proposal.round, f.proposal.payload),
            _ => return,
        };

        // Prune & filter incoming activity.
        // - Incoming Finalization. Prune older subscriptions as we only care about latest information
        // - Incoming Notarization. Only accept if ahead of the latest Finalization.
        match &activity {
            Activity::Finalization(_) => self.pending.retain(|&r, p| {
                matches!(&p.activity, Some(Activity::Finalization(_))) || r > round
            }),
            Activity::Notarization(_)
                if self
                    .state
                    .read()
                    .latest_finalized
                    .as_ref()
                    .map(|f| Round::new(Epoch::new(f.epoch), View::new(f.view)))
                    .is_none_or(|f| f < round) => {}

            _ => return,
        }

        let block_rx = self.marshal.subscribe_by_digest(Some(round), payload).await;
        let pending = PendingSubscription::new(round, activity, block_rx);
        self.pending.insert(round, pending);
    }

    #[instrument(skip_all, fields(activity = ?activity))]
    fn handle_activity(&self, activity: FeedActivity, consensus_block: Block) {
        let block = consensus_block.into_inner().into_block();
        let (round, digest, certificate) = match activity.clone() {
            Activity::Notarization(notarization) => (
                notarization.proposal.round,
                notarization.proposal.payload.0,
                notarization.encode(),
            ),
            Activity::Finalization(finalization) => (
                finalization.proposal.round,
                finalization.proposal.payload.0,
                finalization.encode(),
            ),
            _ => return,
        };

        let certified = CertifiedBlock {
            epoch: round.epoch().get(),
            view: round.view().get(),
            block,
            digest,
            certificate: hex::encode(certificate),
        };

        let mut state = self.state.write();
        let latest_finalized_round = state
            .latest_finalized
            .as_ref()
            .map(|b| Round::new(Epoch::new(b.epoch), View::new(b.view)));
        let latest_notarized_round = state
            .latest_notarized
            .as_ref()
            .map(|b| Round::new(Epoch::new(b.epoch), View::new(b.view)));

        // Update state and broadcast events
        match activity {
            Activity::Notarization(_) => {
                let _ = self.state.events_tx().send(Event::Notarized {
                    block: certified.clone(),
                    seen: now_millis(),
                });

                if latest_finalized_round.is_none_or(|r| r < round)
                    && latest_notarized_round.is_none_or(|r| r < round)
                {
                    state.latest_notarized = Some(certified);
                }
            }

            Activity::Finalization(_) => {
                let _ = self.state.events_tx().send(Event::Finalized {
                    block: certified.clone(),
                    seen: now_millis(),
                });

                if latest_finalized_round.is_none_or(|r| r < round) {
                    if latest_notarized_round.is_none_or(|r| r < round) {
                        state.latest_notarized = None;
                    }

                    state.latest_finalized = Some(certified);
                }
            }
            _ => {}
        }
    }
}

/// Get current Unix timestamp in milliseconds.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
