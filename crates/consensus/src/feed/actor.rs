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
//! All pending subscriptions are polled concurrently so one unresolved block
//! cannot prevent newer finalizations from advancing the feed. When a finalization
//! resolves, pending activity at lower-or-equal rounds is discarded.

use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Activity},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_macros::select;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::futures::{AbortablePool, Aborter};
use eyre::eyre;
use futures::StreamExt;
use std::{
    collections::BTreeMap,
    future::Future,
    time::{SystemTime, UNIX_EPOCH},
};
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tracing::{debug, error, info_span, instrument, warn, warn_span};

use super::state::FeedStateHandle;
use crate::{
    alias::marshal,
    consensus::{Digest, block::Block},
};

/// Type alias for the activity type used by the feed actor.
pub(super) type FeedActivity = Activity<Scheme<PublicKey, MinSig>, Digest>;

/// Receiver for activity messages.
pub(super) type Receiver = futures::channel::mpsc::UnboundedReceiver<FeedActivity>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Notarization,
    Finalization,
}

struct PendingEntry {
    id: u64,
    kind: PendingKind,
    _aborter: Aborter,
}

type Resolution<A, B> = (u64, Round, A, eyre::Result<B>);

/// Concurrent block subscriptions indexed by their consensus round.
///
/// The index owns abort handles so superseded subscriptions can be cancelled
/// while the pool yields whichever block resolution completes first.
struct PendingSubscriptions<A, B> {
    next_id: u64,
    entries: BTreeMap<Round, PendingEntry>,
    resolutions: AbortablePool<Resolution<A, B>>,
}

impl<A, B> Default for PendingSubscriptions<A, B>
where
    A: Send,
    B: Send,
{
    fn default() -> Self {
        Self {
            next_id: 0,
            entries: BTreeMap::new(),
            resolutions: AbortablePool::default(),
        }
    }
}

impl<A, B> PendingSubscriptions<A, B>
where
    A: Send + 'static,
    B: Send + 'static,
{
    fn insert(
        &mut self,
        round: Round,
        kind: PendingKind,
        activity: A,
        resolution: impl Future<Output = eyre::Result<B>> + Send + 'static,
    ) {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("subscription id overflow");

        let aborter = self.resolutions.push(async move {
            let result = resolution.await;
            (id, round, activity, result)
        });

        self.entries.insert(
            round,
            PendingEntry {
                id,
                kind,
                _aborter: aborter,
            },
        );
    }

    /// Wait for the next current subscription to resolve.
    ///
    /// Completions from cancelled or replaced subscriptions are ignored.
    async fn next_completed(&mut self) -> (Round, A, eyre::Result<B>) {
        loop {
            let Ok((id, round, activity, result)) = self.resolutions.next_completed().await else {
                continue;
            };

            if self.entries.get(&round).is_none_or(|entry| entry.id != id) {
                continue;
            }

            self.entries.remove(&round);
            return (round, activity, result);
        }
    }

    fn retain(&mut self, mut predicate: impl FnMut(Round, PendingKind) -> bool) {
        self.entries
            .retain(|&round, entry| predicate(round, entry.kind));
    }

    fn remove_through(&mut self, round: Round) {
        self.entries
            .retain(|&pending_round, _| pending_round > round);
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
    /// Pending block subscriptions polled concurrently.
    pending: PendingSubscriptions<FeedActivity, Block>,
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
            pending: PendingSubscriptions::default(),
        }
    }

    /// Start the actor, returning a handle to the spawned task.
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    /// Run the actor's main loop.
    async fn run(mut self) {
        let reason = loop {
            select!(
                (round, activity, result) = self.pending.next_completed() => {
                    match result {
                        Ok(block) => {
                            let is_finalization = matches!(&activity, Activity::Finalization(_));
                            self.handle_activity(activity, block);

                            if is_finalization {
                                self.pending.remove_through(round);
                            }
                        }
                        Err(error) => warn_span!("feed_actor").in_scope(||
                            warn!(%error, "did not get pending block")
                        ),
                    }
                },

                activity = self.receiver.next() => {
                    let Some(activity) = activity else {
                        break eyre!("mailbox closed");
                    };

                    self.subscribe(activity);
                },
            );
        };

        info_span!("feed_actor").in_scope(|| error!(%reason, "shutting down"));
    }

    fn subscribe(&mut self, activity: FeedActivity) {
        let (round, payload, kind) = match &activity {
            Activity::Notarization(n) => (
                n.proposal.round,
                n.proposal.payload,
                PendingKind::Notarization,
            ),
            Activity::Finalization(f) => (
                f.proposal.round,
                f.proposal.payload,
                PendingKind::Finalization,
            ),
            _ => return,
        };

        // Prune & filter incoming activity.
        // - Incoming Finalization. Prune older notarizations; resolved finalizations prune
        //   all lower-or-equal pending activity.
        // - Incoming Notarization. Only accept if ahead of the latest Finalization.
        match &activity {
            Activity::Finalization(_) => self
                .pending
                .retain(|r, kind| matches!(kind, PendingKind::Finalization) || r > round),
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

        let marshal = self.marshal.clone();
        self.pending.insert(round, kind, activity, async move {
            let block_rx = marshal.subscribe_by_digest(Some(round), payload).await;
            block_rx
                .await
                .map_err(|_| eyre!("block subscription cancelled"))
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{channel::oneshot, executor::block_on};

    #[test]
    fn newer_subscription_completes_while_oldest_is_unresolved() {
        block_on(async {
            let older_round = Round::new(Epoch::new(1), View::new(10));
            let newer_round = Round::new(Epoch::new(1), View::new(11));
            let (older_tx, older_rx) = oneshot::channel::<u64>();
            let (newer_tx, newer_rx) = oneshot::channel::<u64>();
            let mut pending = PendingSubscriptions::default();

            // Keep the older sender alive without delivering a block to reproduce
            // a marshal subscription that never completes.
            pending.insert(
                older_round,
                PendingKind::Finalization,
                "older",
                async move { older_rx.await.map_err(eyre::Report::new) },
            );
            pending.insert(
                newer_round,
                PendingKind::Finalization,
                "newer",
                async move { newer_rx.await.map_err(eyre::Report::new) },
            );

            newer_tx.send(11).unwrap();
            let (round, activity, block) = pending.next_completed().await;

            assert_eq!(round, newer_round);
            assert_eq!(activity, "newer");
            assert_eq!(block.unwrap(), 11);

            pending.remove_through(round);
            assert!(pending.is_empty());

            drop(pending);
            assert!(older_tx.send(10).is_err());
        });
    }
}
