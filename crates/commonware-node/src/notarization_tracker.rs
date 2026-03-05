//! Tracks notarized blocks and forwards them to the execution layer.
//!
//! When commonware consensus skips sending a block to the Automaton's `verify`
//! (because it observed a notarization certificate), the EL never receives a
//! `new_payload` for that block. This actor closes that gap by listening for
//! `Activity::Notarization` events, fetching the block from the marshal, and
//! forwarding it to reth.
//!
//! See <https://github.com/tempoxyz/tempo/issues/1411>.

use std::sync::Arc;

use commonware_consensus::{
    Heightable as _, Reporter,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Activity},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{Handle, Spawner};
use futures::channel::mpsc;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tracing::{debug, error, warn};

use crate::{alias::marshal, consensus::Digest};

/// Type alias for the activity type used by this actor.
type TrackerActivity = Activity<Scheme<PublicKey, MinSig>, Digest>;

/// Mailbox for sending consensus activity to the notarization tracker.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: mpsc::UnboundedSender<TrackerActivity>,
}

impl Reporter for Mailbox {
    type Activity = TrackerActivity;

    async fn report(&mut self, activity: Self::Activity) {
        if self.sender.unbounded_send(activity).is_err() {
            error!("failed sending activity to notarization tracker because it is no longer running");
        }
    }
}

pub(crate) struct Actor<TContext> {
    context: TContext,
    receiver: mpsc::UnboundedReceiver<TrackerActivity>,
    marshal: marshal::Mailbox,
    execution_node: TempoFullNode,
}

pub(crate) fn init<TContext: Spawner>(
    context: TContext,
    marshal: marshal::Mailbox,
    execution_node: TempoFullNode,
) -> (Actor<TContext>, Mailbox) {
    let (tx, rx) = mpsc::unbounded();
    let mailbox = Mailbox { sender: tx };
    let actor = Actor {
        context,
        receiver: rx,
        marshal,
        execution_node,
    };
    (actor, mailbox)
}

impl<TContext: Spawner> Actor<TContext> {
    pub(crate) fn start(self) -> Handle<()> {
        let context = self.context;
        let mut receiver = self.receiver;
        let mut marshal = self.marshal;
        let execution_node = self.execution_node;

        context.spawn(|_| async move {
            use futures::StreamExt as _;

            while let Some(activity) = receiver.next().await {
                let Activity::Notarization(notarization) = activity else {
                    continue;
                };

                let digest = notarization.proposal.payload;
                let round = notarization.proposal.round;
                let rx = marshal.subscribe(Some(round), digest).await;
                let block = match rx.await {
                    Ok(block) => block,
                    Err(err) => {
                        warn!(
                            %digest,
                            %round,
                            %err,
                            "marshal dropped channel before notarized block was delivered",
                        );
                        continue;
                    }
                };

                let height = block.height();
                let block = block.into_inner();

                match execution_node
                    .add_ons_handle
                    .beacon_engine_handle
                    .new_payload(TempoExecutionData {
                        block: Arc::new(block),
                        validator_set: None,
                    })
                    .await
                {
                    Ok(status) => {
                        debug!(
                            %digest,
                            %height,
                            %status,
                            "forwarded notarized block to execution layer",
                        );
                    }
                    Err(err) => {
                        warn!(
                            %digest,
                            %height,
                            %err,
                            "failed forwarding notarized block to execution layer",
                        );
                    }
                }
            }
        })
    }
}
