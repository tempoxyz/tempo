//! Feed actor implementation.
//!
//! This actor:
//! - Receives consensus activity (notarizations, finalizations)
//! - Updates shared state (accessible by RPC handlers)
//! - Broadcasts events to subscribers
//!
//! Block resolution uses [`marshal::Mailbox::subscribe`] to wait for the block
//! to become available, avoiding a race where the block hasn't been stored yet
//! when the activity arrives. If a newer activity arrives while waiting, the
//! pending subscription is dropped (cancelling it in the marshal) since the
//! feed only tracks the latest state.

use alloy_consensus::BlockHeader;
use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::types::FixedEpocher;
use commonware_consensus::{
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Activity},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_macros::select;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use futures::StreamExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tracing::{info, info_span, instrument};

use super::state::FeedStateHandle;
use crate::{alias::marshal, consensus::Digest, consensus::block::Block};

/// Type alias for the activity type used by the feed actor.
pub(super) type FeedActivity = Activity<Scheme<PublicKey, MinSig>, Digest>;

/// Receiver for activity messages.
pub(super) type Receiver = futures::channel::mpsc::UnboundedReceiver<FeedActivity>;

pub(crate) struct Actor<TContext> {
    /// Runtime context.
    context: ContextCell<TContext>,
    /// Receiver for activity messages.
    receiver: Receiver,
    /// Shared state handle.
    state: FeedStateHandle,
    /// Marshal mailbox for block lookups.
    marshal: marshal::Mailbox,
}

impl<TContext: Spawner> Actor<TContext> {
    /// Create a new feed actor.
    ///
    /// The actor receives Activity messages via `receiver` and updates the shared `state`.
    pub(crate) fn new(
        context: TContext,
        marshal: marshal::Mailbox,
        epocher: FixedEpocher,
        receiver: Receiver,
        state: FeedStateHandle,
    ) -> Self {
        state.set_marshal(marshal.clone());
        state.set_epocher(epocher);

        Self {
            context: ContextCell::new(context),
            receiver,
            state,
            marshal,
        }
    }

    /// Start the actor, returning a handle to the spawned task.
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    /// Run the actor's main loop.
    ///
    /// When a notarization or finalization arrives, a marshal subscription is started
    /// to resolve the block. The inner loop races the subscription against the next
    /// incoming activity. If a newer activity arrives first, the old subscription is
    /// dropped and the new activity is processed immediately.
    async fn run(&mut self) {
        'subscribe: loop {
            let Some(mut activity) = self.receiver.next().await else {
                info_span!("shutdown").in_scope(|| info!("actor shutting down"));
                break;
            };

            'process: loop {
                let (round, payload) = match &activity {
                    Activity::Notarization(n) => (n.proposal.round, n.proposal.payload),
                    Activity::Finalization(f) => (f.proposal.round, f.proposal.payload),
                    _ => continue 'subscribe,
                };

                select!(
                    // We should expect to see the block immediately as the block was processed by the
                    // consensus pipeline. We allow interrupts to avoid a syncing node from blocking this
                    // actor from processing.
                    block = self.marshal.subscribe(Some(round), payload).await => {
                        let Ok(block) = block else {
                            continue 'subscribe;
                        };

                        self.handle_activity(activity, block);
                        continue 'subscribe;
                    },

                    new_activity = self.receiver.next() => {
                        let Some(new_activity) = new_activity else {
                            info_span!("shutdown").in_scope(|| info!("actor shutting down"));
                            break 'subscribe;
                        };

                        activity = new_activity;
                        continue 'process;
                    },
                )
            }
        }
    }

    #[instrument(skip_all, fields(activity = ?activity))]
    fn handle_activity(&self, activity: FeedActivity, consensus_block: Block) {
        let block = consensus_block.into_inner().into_block();
        let height = block.number();

        match activity {
            Activity::Notarization(notarization) => {
                let view = notarization.proposal.round.view().get();
                let round = notarization.proposal.round;
                let certified = CertifiedBlock {
                    epoch: round.epoch().get(),
                    view,
                    block: Some(block),
                    height: Some(height),
                    digest: notarization.proposal.payload.0,
                    certificate: hex::encode(notarization.encode()),
                };

                let _ = self.state.events_tx().send(Event::Notarized {
                    block: certified.clone(),
                    seen: now_millis(),
                });

                let mut state = self.state.write();
                if state
                    .latest_finalized
                    .as_ref()
                    .map(|f| Round::new(Epoch::new(f.epoch), View::new(f.view)))
                    .is_none_or(|r| r < round)
                    && state
                        .latest_notarized
                        .as_ref()
                        .is_none_or(|n| n.view < view)
                {
                    state.latest_notarized = Some(certified);
                }
            }

            Activity::Finalization(finalization) => {
                let view = finalization.proposal.round.view().get();
                let round = finalization.proposal.round;
                let certified = CertifiedBlock {
                    epoch: round.epoch().get(),
                    view,
                    block: Some(block),
                    height: Some(height),
                    digest: finalization.proposal.payload.0,
                    certificate: hex::encode(finalization.encode()),
                };

                let _ = self.state.events_tx().send(Event::Finalized {
                    block: certified.clone(),
                    seen: now_millis(),
                });

                let mut state = self.state.write();
                if state
                    .latest_finalized
                    .as_ref()
                    .map(|f| Round::new(Epoch::new(f.epoch), View::new(f.view)))
                    .is_none_or(|r| r < round)
                {
                    if state
                        .latest_notarized
                        .as_ref()
                        .map(|n| Round::new(Epoch::new(n.epoch), View::new(n.view)))
                        .is_none_or(|r| r < round)
                    {
                        state.latest_notarized = None;
                    }
                    state.latest_finalized = Some(certified);
                }
            }
            _ => unreachable!("only notarizations and finalizations are inflight"),
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
