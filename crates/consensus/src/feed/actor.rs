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
//! resolves, pending activity at lower-or-equal rounds is discarded. A resolved
//! notarization discards only lower-or-equal notarizations.

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
    generation: u64,
    kind: PendingKind,
    /// Dropping this handle cancels the corresponding in-flight block resolution.
    _cancel_on_drop: Aborter,
}

struct Resolution<A, B> {
    generation: u64,
    round: Round,
    activity: A,
    block: eyre::Result<B>,
}

/// Concurrent block subscriptions indexed by their consensus round.
///
/// The index owns abort handles so superseded subscriptions can be cancelled
/// while the pool yields whichever block resolution completes first.
struct PendingSubscriptions<A, B> {
    next_generation: u64,
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
            next_generation: 0,
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
    ) -> bool {
        // Do not restart an identical pending subscription. A finalization
        // supersedes a notarization at the same round, but never the reverse.
        if self
            .entries
            .get(&round)
            .is_some_and(|entry| entry.kind == kind || entry.kind == PendingKind::Finalization)
        {
            return false;
        }

        // A pending finalization supersedes notarizations at lower-or-equal
        // rounds even when those notarizations arrive later.
        if kind == PendingKind::Notarization
            && self
                .entries
                .range(round..)
                .any(|(_, entry)| entry.kind == PendingKind::Finalization)
        {
            return false;
        }

        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("subscription generation overflow");

        let aborter = self.resolutions.push(async move {
            let block = resolution.await;
            Resolution {
                generation,
                round,
                activity,
                block,
            }
        });

        self.entries.insert(
            round,
            PendingEntry {
                generation,
                kind,
                _cancel_on_drop: aborter,
            },
        );
        true
    }

    /// Wait for the next current subscription to resolve.
    ///
    /// Completions from cancelled or replaced subscriptions are ignored.
    async fn next_completed(&mut self) -> (Round, A, eyre::Result<B>) {
        loop {
            let Ok(resolution) = self.resolutions.next_completed().await else {
                continue;
            };

            if self
                .entries
                .get(&resolution.round)
                .is_none_or(|entry| entry.generation != resolution.generation)
            {
                continue;
            }

            self.entries.remove(&resolution.round);
            return (resolution.round, resolution.activity, resolution.block);
        }
    }

    fn remove_through(&mut self, round: Round) {
        self.entries
            .retain(|&pending_round, _| pending_round > round);
    }

    fn remove_notarizations_through(&mut self, round: Round) {
        self.entries.retain(|&pending_round, entry| {
            entry.kind == PendingKind::Finalization || pending_round > round
        });
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Returns whether an activity can still advance the published feed state.
fn can_advance_state(
    kind: PendingKind,
    round: Round,
    latest_finalized: Option<Round>,
    latest_notarized: Option<Round>,
) -> bool {
    latest_finalized.is_none_or(|latest| round > latest)
        && (kind == PendingKind::Finalization
            || latest_notarized.is_none_or(|latest| round > latest))
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
                            } else {
                                self.pending.remove_notarizations_through(round);
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

        let (latest_finalized, latest_notarized) = {
            let state = self.state.read();
            let round =
                |block: &CertifiedBlock| Round::new(Epoch::new(block.epoch), View::new(block.view));
            (
                state.latest_finalized.as_ref().map(round),
                state.latest_notarized.as_ref().map(round),
            )
        };

        // A stale activity can never update state or emit an event. Avoid
        // registering a marshal subscription that may remain unresolved.
        if !can_advance_state(kind, round, latest_finalized, latest_notarized) {
            return;
        }

        // Prune & filter incoming activity.
        // - Incoming Finalization. Prune older notarizations; resolved finalizations prune
        //   all lower-or-equal pending activity.
        // - Incoming Notarization. PendingSubscriptions rejects it if a higher-or-equal
        //   finalization is already pending.
        if kind == PendingKind::Finalization {
            self.pending.remove_notarizations_through(round);
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
    use futures::{FutureExt, channel::oneshot, executor::block_on, pin_mut};

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
            assert!(pending.insert(
                older_round,
                PendingKind::Finalization,
                "older",
                async move { older_rx.await.map_err(eyre::Report::new) },
            ));
            assert!(pending.insert(
                newer_round,
                PendingKind::Finalization,
                "newer",
                async move { newer_rx.await.map_err(eyre::Report::new) },
            ));

            // Arm both resolutions while the oldest remains unresolved, then
            // make only the newer block available.
            let completed = {
                let next = pending.next_completed();
                pin_mut!(next);
                assert!(futures::poll!(next.as_mut()).is_pending());

                newer_tx.send(11).unwrap();
                next.await
            };
            let (round, activity, block) = completed;
            assert_eq!(round, newer_round);
            assert_eq!(activity, "newer");
            assert_eq!(block.unwrap(), 11);

            pending.remove_through(round);
            assert!(pending.is_empty());

            // The actor polls the pool before accepting more activity, which
            // drains the aborted resolution and drops its marshal receiver.
            assert!(pending.next_completed().now_or_never().is_none());
            assert!(older_tx.send(10).is_err());
        });
    }

    #[test]
    fn pending_finalization_cannot_be_replaced_by_notarization() {
        block_on(async {
            let earlier_round = Round::new(Epoch::new(1), View::new(9));
            let round = Round::new(Epoch::new(1), View::new(10));
            let later_round = Round::new(Epoch::new(1), View::new(11));
            let (finalization_tx, finalization_rx) = oneshot::channel::<u64>();
            let (same_round_tx, same_round_rx) = oneshot::channel::<u64>();
            let (earlier_tx, earlier_rx) = oneshot::channel::<u64>();
            let (later_tx, later_rx) = oneshot::channel::<u64>();
            let mut pending = PendingSubscriptions::default();

            assert!(pending.insert(
                round,
                PendingKind::Finalization,
                "finalization",
                async move { finalization_rx.await.map_err(eyre::Report::new) },
            ));
            assert!(!pending.insert(
                round,
                PendingKind::Notarization,
                "same-round notarization",
                async move { same_round_rx.await.map_err(eyre::Report::new) },
            ));
            assert!(!pending.insert(
                earlier_round,
                PendingKind::Notarization,
                "earlier notarization",
                async move { earlier_rx.await.map_err(eyre::Report::new) },
            ));
            assert!(pending.insert(
                later_round,
                PendingKind::Notarization,
                "later notarization",
                async move { later_rx.await.map_err(eyre::Report::new) },
            ));

            assert!(same_round_tx.send(10).is_err());
            assert!(earlier_tx.send(9).is_err());

            later_tx.send(11).unwrap();
            let (completed_round, activity, block) = pending.next_completed().await;
            assert_eq!(completed_round, later_round);
            assert_eq!(activity, "later notarization");
            assert_eq!(block.unwrap(), 11);

            finalization_tx.send(10).unwrap();
            let (completed_round, activity, block) = pending.next_completed().await;
            assert_eq!(completed_round, round);
            assert_eq!(activity, "finalization");
            assert_eq!(block.unwrap(), 10);
        });
    }

    #[test]
    fn newer_notarization_cancels_only_superseded_notarizations() {
        block_on(async {
            let finalization_round = Round::new(Epoch::new(1), View::new(9));
            let older_round = Round::new(Epoch::new(1), View::new(10));
            let newer_round = Round::new(Epoch::new(1), View::new(11));
            let (finalization_tx, finalization_rx) = oneshot::channel::<u64>();
            let (older_tx, older_rx) = oneshot::channel::<u64>();
            let (newer_tx, newer_rx) = oneshot::channel::<u64>();
            let mut pending = PendingSubscriptions::default();

            assert!(pending.insert(
                finalization_round,
                PendingKind::Finalization,
                "finalization",
                async move { finalization_rx.await.map_err(eyre::Report::new) },
            ));
            assert!(pending.insert(
                older_round,
                PendingKind::Notarization,
                "older notarization",
                async move { older_rx.await.map_err(eyre::Report::new) },
            ));
            assert!(pending.insert(
                newer_round,
                PendingKind::Notarization,
                "newer notarization",
                async move { newer_rx.await.map_err(eyre::Report::new) },
            ));

            newer_tx.send(11).unwrap();
            let (completed_round, activity, block) = pending.next_completed().await;
            assert_eq!(completed_round, newer_round);
            assert_eq!(activity, "newer notarization");
            assert_eq!(block.unwrap(), 11);

            pending.remove_notarizations_through(completed_round);
            assert!(pending.next_completed().now_or_never().is_none());
            assert!(older_tx.send(10).is_err());

            finalization_tx.send(9).unwrap();
            let (completed_round, activity, block) = pending.next_completed().await;
            assert_eq!(completed_round, finalization_round);
            assert_eq!(activity, "finalization");
            assert_eq!(block.unwrap(), 9);
        });
    }

    #[test]
    fn stale_activity_cannot_advance_state() {
        let round_10 = Round::new(Epoch::new(1), View::new(10));
        let round_11 = Round::new(Epoch::new(1), View::new(11));
        let round_12 = Round::new(Epoch::new(1), View::new(12));

        assert!(!can_advance_state(
            PendingKind::Finalization,
            round_10,
            Some(round_10),
            None,
        ));
        assert!(can_advance_state(
            PendingKind::Finalization,
            round_11,
            Some(round_10),
            Some(round_12),
        ));
        assert!(!can_advance_state(
            PendingKind::Notarization,
            round_11,
            Some(round_10),
            Some(round_11),
        ));
        assert!(!can_advance_state(
            PendingKind::Notarization,
            round_11,
            Some(round_11),
            None,
        ));
        assert!(can_advance_state(
            PendingKind::Notarization,
            round_12,
            Some(round_10),
            Some(round_11),
        ));
    }
}
