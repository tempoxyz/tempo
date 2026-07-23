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
//! The actor prefers the oldest (lowest-round) pending subscription so events
//! are normally emitted in order. When the delivery heartbeat expires, the
//! unresolved oldest subscription is discarded and the actor may advance to a
//! newer resolved finalization. Advancing also discards all older pending activity.

use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Activity},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_macros::select;
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::channel::oneshot;
use eyre::eyre;
use futures::{FutureExt, StreamExt, future::BoxFuture};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tracing::{debug, error, info, info_span, instrument, warn, warn_span};

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

/// How long to prefer ordered marshal delivery before discarding the unresolved
/// oldest subscription and looking for a newer resolved finalization.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

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
    /// Best-effort block subscriptions keyed by round.
    pending: BTreeMap<Round, PendingSubscription>,
    /// Timer that bounds how long the oldest best-effort subscription remains pending.
    heartbeat: OptionFuture<BoxFuture<'static, ()>>,
}

impl<TContext: Spawner> Actor<TContext> {
    /// Create a new feed actor.
    ///
    /// The actor receives Activity messages via `receiver` and updates the shared `state`.
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
            pending: BTreeMap::new(),
            heartbeat: OptionFuture::none(),
        }
    }
}

impl<TContext: Clock + Spawner> Actor<TContext> {
    /// Start the actor, returning a handle to the spawned task.
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    /// Run the actor's main loop.
    async fn run(mut self) {
        let reason = loop {
            self.update_heartbeat();

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
                    self.heartbeat = OptionFuture::none();
                },

                _ = (&mut self.heartbeat).fuse() => {
                    // Let the unresolved oldest subscription expire.
                    if let Some(pending) = oldest.as_ref() {
                        warn!(%pending.round, "feed block subscription expired");
                    }

                    self.handle_heartbeat().await;
                },

                activity = self.receiver.next() => {
                    let Some(activity) = activity else {
                        break eyre!("mailbox closed");
                    };

                    // Follow-up activity must not displace the ordered head.
                    if let Some(p) = oldest.take() {
                        self.pending.insert(p.round, p);
                    }
                    self.subscribe(activity).await;
                },
            );
        };

        info_span!("feed_actor").in_scope(|| error!(%reason, "shutting down"));
    }

    fn update_heartbeat(&mut self) {
        if self.pending.is_empty() {
            self.heartbeat = OptionFuture::none();
        } else if self.heartbeat.is_none() {
            self.heartbeat
                .replace(self.context.sleep(HEARTBEAT_INTERVAL).boxed());
        }
    }

    /// After the unresolved oldest subscription expires, flush finalizations
    /// whose blocks are now available from marshal's buffer or finalized
    /// storage. Each delivered finalization advances the best-effort feed floor.
    #[instrument(skip_all, fields(pending = self.pending.len()))]
    async fn handle_heartbeat(&mut self) {
        let finalizations = self
            .pending
            .iter()
            .filter_map(|(&r, p)| match p.activity.as_ref() {
                Some(Activity::Finalization(f)) => Some((r, f.proposal.payload)),
                _ => None,
            })
            .collect::<Vec<_>>();

        let pending_finalizations = finalizations.len();
        for (round, digest) in finalizations {
            let Some(block) = self.marshal.get_block(&digest).await else {
                debug!(%round, %digest, "finalized block unavailable");
                continue;
            };

            let height = block.block().inner.number;
            let mut pending = self
                .pending
                .remove(&round)
                .expect("pending finalization exists");

            let activity = pending.activity.take().expect("activity is present");
            self.handle_activity(activity, block);

            debug!(%round, %digest, height, "delivered finalized block");
        }

        let latest_finalized_round = self
            .state
            .read()
            .latest_finalized
            .as_ref()
            .map(|block| Round::new(Epoch::new(block.epoch), View::new(block.view)));

        if let Some(round) = latest_finalized_round {
            self.pending
                .retain(|&pending_round, _| pending_round > round);
        }

        debug!(
            remaining_subscriptions = self.pending.len(),
            "feed heartbeat"
        );
    }

    async fn subscribe(&mut self, activity: FeedActivity) {
        let (round, payload) = match &activity {
            Activity::Notarization(n) => (n.proposal.round, n.proposal.payload),
            Activity::Finalization(f) => (f.proposal.round, f.proposal.payload),
            _ => return,
        };

        // Prune & filter incoming activity.
        // - Incoming Finalization. Prune older notarizations
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
        let block = consensus_block.into_execution_block();
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
        let height = certified.block.inner.number;
        let subscribers = self.state.events_tx().receiver_count();
        match activity {
            Activity::Notarization(_) => {
                if latest_notarized_round.is_none_or(|previous| round > previous) {
                    debug!(subscribers, height, "sending new notarized event");
                    let _ = self.state.events_tx().send(Event::Notarized {
                        block: certified.clone(),
                        seen: now_millis(),
                    });
                }

                if latest_finalized_round.is_none_or(|r| r < round)
                    && latest_notarized_round.is_none_or(|r| r < round)
                {
                    state.latest_notarized = Some(certified);
                }
            }

            Activity::Finalization(_) => {
                if latest_finalized_round.is_none_or(|previous| round > previous) {
                    debug!(subscribers, height, "sending new finalized event");
                    let _ = self.state.events_tx().send(Event::Finalized {
                        block: certified.clone(),
                        seen: now_millis(),
                    });
                }

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
