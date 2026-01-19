//! Feed actor implementation.
//!
//! This actor:
//! - Receives consensus activity (notarizations, finalizations, nullifications)
//! - Updates shared state (accessible by RPC handlers)
//! - Broadcasts events to subscribers

use alloy_consensus::BlockHeader as _;
use alloy_primitives::hex;
use commonware_codec::Encode;
use commonware_consensus::{
    Heightable as _,
    simplex::{scheme::bls12381_threshold::Scheme, types::Activity},
    types::Epoch,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Provider, ed25519::PublicKey,
};
use commonware_macros::select;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use futures::StreamExt;
use std::time::{SystemTime, UNIX_EPOCH};
use tempo_node::rpc::consensus::{BlockHeaderData, CertifiedBlock, Event};
use tracing::{info, info_span, instrument};

use super::state::FeedStateHandle;
use crate::{alias::marshal, consensus::Digest, epoch::SchemeProvider};

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
    /// Scheme provider for looking up threshold public keys.
    scheme_provider: SchemeProvider,
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
        scheme_provider: SchemeProvider,
    ) -> Self {
        state.set_marshal(marshal.clone());
        state.set_scheme_provider(scheme_provider.clone());

        Self {
            context: ContextCell::new(context),
            receiver,
            state,
            marshal,
            scheme_provider,
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
        view: u64,
        epoch: u64,
        digest: Digest,
        certificate: &impl Encode,
    ) -> CertifiedBlock {
        let certificate_bytes = certificate.encode();
        let certificate = hex::encode(&certificate_bytes);

        let block = self.marshal.get_block(&digest).await;
        let height = block.as_ref().map(|b| b.height().get());

        let header = block.as_ref().map(|b| BlockHeaderData {
            parent_hash: b.parent_hash(),
            state_root: b.state_root(),
            receipts_root: b.receipts_root(),
            timestamp: b.timestamp(),
        });

        let threshold_public_key = self
            .scheme_provider
            .scoped(Epoch::new(epoch))
            .map(|scheme| {
                let identity = scheme.identity();
                hex::encode(identity.encode())
            });

        CertifiedBlock {
            epoch,
            view,
            height,
            digest: digest.0,
            certificate,
            header,
            threshold_public_key,
        }
    }

    #[instrument(skip_all, fields(activity = ?activity))]
    async fn handle_activity(&mut self, activity: FeedActivity) {
        match activity {
            Activity::Notarization(notarization) => {
                let seen = now_millis();
                let view = notarization.proposal.round.view().get();

                let block = self
                    .create_certified_block(
                        view,
                        notarization.proposal.round.epoch().get(),
                        notarization.proposal.payload,
                        &notarization,
                    )
                    .await;

                let _ = self.state.events_tx().send(Event::Notarized {
                    block: block.clone(),
                    seen,
                });

                {
                    let mut state = self.state.write();
                    if state
                        .latest_finalized
                        .as_ref()
                        .is_none_or(|f| f.height < block.height)
                        && state
                            .latest_notarized
                            .as_ref()
                            .is_none_or(|n| n.view < view)
                    {
                        state.latest_notarized = Some(block);
                    }
                }
            }
            Activity::Finalization(finalization) => {
                let seen = now_millis();
                let view = finalization.proposal.round.view().get();

                let block = self
                    .create_certified_block(
                        view,
                        finalization.proposal.round.epoch().get(),
                        finalization.proposal.payload,
                        &finalization,
                    )
                    .await;

                let _ = self.state.events_tx().send(Event::Finalized {
                    block: block.clone(),
                    seen,
                });

                {
                    let mut state = self.state.write();
                    if state
                        .latest_finalized
                        .as_ref()
                        .is_none_or(|f| f.height < block.height)
                    {
                        if state
                            .latest_notarized
                            .as_ref()
                            .is_some_and(|n| n.view <= view)
                        {
                            state.latest_notarized = None;
                        }
                        state.latest_finalized = Some(block);
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
