//! Mailbox for sending consensus activity to the feed actor.

use commonware_consensus::{
    Reporter,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Activity},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use futures::channel::mpsc;
use tracing::error;

use super::actor::FeedActivity;
use crate::consensus::Digest;

/// Sender half of the feed channel.
pub(super) type Sender = mpsc::UnboundedSender<FeedActivity>;

/// Mailbox for sending consensus activity to the feed actor.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    sender: Sender,
}

impl Mailbox {
    pub(super) fn new(sender: Sender) -> Self {
        Self { sender }
    }
}

impl Reporter for Mailbox {
    type Activity = Activity<Scheme<PublicKey, MinSig>, Digest>;

    async fn report(&mut self, activity: Self::Activity) {
        if self.sender.unbounded_send(activity).is_err() {
            error!("failed sending activity to feed because it is no longer running");
        }
    }
}
