//! Feed actor implementation.
//!
//! This actor:
//! - Receives consensus activity (notarizations, finalizations, nullifications)
//! - Updates shared state (accessible by RPC handlers)
//! - Broadcasts events to subscribers

use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::{
    Heightable as _,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Activity},
    types::{Epoch, FixedEpocher, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_macros::select;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use futures::StreamExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tracing::{info, info_span, instrument};

use super::state::FeedStateHandle;
use crate::{alias::marshal, consensus::Digest};

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
    async fn run(&mut self) {
        loop {
            select!(
                activity = self.receiver.next() => {
                    let Some(activity) = activity else {
                        info_span!("shutdown").in_scope(|| info!("actor shutting down"));
                        break;
                    };
                    self.handle_activity(activity).await;
                },
            )
        }
    }

    /// Create a [`CertifiedBlock`] from the notarization or finalization.
    async fn create_certified_block(
        &mut self,
        round: Round,
        digest: Digest,
        certificate: &impl Encode,
    ) -> CertifiedBlock {
        let certificate = hex::encode(certificate.encode());
        let height = self
            .marshal
            .get_block(&digest)
            .await
            .map(|b| b.height().get());

        let view = round.view().get();
        let epoch = round.epoch().get();

        CertifiedBlock {
            epoch,
            view,
            height,
            digest: digest.0,
            certificate,
        }
    }

    #[instrument(skip_all, fields(activity = ?activity))]
    async fn handle_activity(&mut self, activity: FeedActivity) {
        match activity {
            Activity::Notarization(notarization) => {
                let seen = now_millis();
                let round = notarization.proposal.round;

                let block = self
                    .create_certified_block(round, notarization.proposal.payload, &notarization)
                    .await;

                let _ = self.state.events_tx().send(Event::Notarized {
                    block: block.clone(),
                    seen,
                });

                {
                    let mut state = self.state.write();

                    // Late-arriving notarization relative finalization is ignored.
                    if state
                        .latest_finalized
                        .as_ref()
                        .is_none_or(|f| f.height < block.height)
                        // Notarization must be strictly newer
                        && state
                            .latest_notarized
                            .as_ref()
                            .map(|n| Round::new(Epoch::new(n.epoch), View::new(n.view)))
                            .is_none_or(|r| r <= round)
                    {
                        state.latest_notarized = Some(block);
                    }
                }
            }
            Activity::Finalization(finalization) => {
                let seen = now_millis();
                let round = finalization.proposal.round;

                let block = self
                    .create_certified_block(round, finalization.proposal.payload, &finalization)
                    .await;

                let _ = self.state.events_tx().send(Event::Finalized {
                    block: block.clone(),
                    seen,
                });

                {
                    let mut state = self.state.write();

                    // Finalization must be strictly newer
                    if state
                        .latest_finalized
                        .as_ref()
                        .is_none_or(|f| f.height < block.height)
                    {
                        state.latest_finalized = Some(block);

                        // Clear any older notarization
                        if state
                            .latest_notarized
                            .as_ref()
                            .map(|n| Round::new(Epoch::new(n.epoch), View::new(n.view)))
                            .is_some_and(|r| r <= round)
                        {
                            state.latest_notarized = None;
                        }
                    }
                }
            }
            Activity::Nullification(nullification) => {
                let _ = self.state.events_tx().send(Event::Nullified {
                    epoch: nullification.round.epoch().get(),
                    view: nullification.round.view().get(),
                    seen: now_millis(),
                });
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
