use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay,
    simplex::types::Context,
    types::{Epoch, Round, View},
};

use commonware_cryptography::ed25519::PublicKey;
use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};

use crate::consensus::Digest;

#[derive(Clone)]
pub(crate) struct Mailbox {
    inner: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn from_sender(inner: mpsc::Sender<Message>) -> Self {
        Self { inner }
    }
}

/// Messages forwarded from consensus to application.
// TODO: add trace spans into all of these messages.
pub(super) enum Message {
    Broadcast(Broadcast),
    Genesis(Genesis),
    Propose(Propose),
    Verify(Box<Verify>),
}

pub(super) struct Genesis {
    pub(super) epoch: Epoch,
    pub(super) response: oneshot::Sender<Digest>,
}

impl From<Genesis> for Message {
    fn from(value: Genesis) -> Self {
        Self::Genesis(value)
    }
}

pub(super) struct Propose {
    pub(super) parent: (View, Digest),
    pub(super) response: oneshot::Sender<Digest>,
    pub(super) round: Round,
}

impl From<Propose> for Message {
    fn from(value: Propose) -> Self {
        Self::Propose(value)
    }
}

pub(super) struct Broadcast {
    pub(super) payload: Digest,
}

impl From<Broadcast> for Message {
    fn from(value: Broadcast) -> Self {
        Self::Broadcast(value)
    }
}

pub(super) struct Verify {
    pub(super) parent: (View, Digest),
    pub(super) payload: Digest,
    pub(super) proposer: PublicKey,
    pub(super) response: oneshot::Sender<bool>,
    pub(super) round: Round,
}

impl From<Verify> for Message {
    fn from(value: Verify) -> Self {
        Self::Verify(Box::new(value))
    }
}

impl Automaton for Mailbox {
    type Context = Context<Self::Digest, PublicKey>;

    type Digest = Digest;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (tx, rx) = oneshot::channel();
        // XXX: Cannot propagate the error upstream because of the trait def.
        // But if the actor no longer responds the application is dead.
        self.inner
            .send(
                Genesis {
                    epoch,
                    response: tx,
                }
                .into(),
            )
            .await
            .expect("application is present and ready to receive genesis");
        rx.await
            .expect("application returns the digest of the genesis")
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        // XXX: Cannot propagate the error upstream because of the trait def.
        // But if the actor no longer responds the application is dead.
        let (tx, rx) = oneshot::channel();
        self.inner
            .send(
                Propose {
                    parent: context.parent,
                    response: tx,
                    round: context.round,
                }
                .into(),
            )
            .await
            .expect("application is present and ready to receive proposals");
        rx
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // XXX: Cannot propagate the error upstream because of the trait def.
        // But if the actor no longer responds the application is dead.
        let (tx, rx) = oneshot::channel();
        self.inner
            .send(
                Verify {
                    parent: context.parent,
                    payload,
                    proposer: context.leader,
                    round: context.round,
                    response: tx,
                }
                .into(),
            )
            .await
            .expect("application is present and ready to receive verify requests");
        rx
    }
}

// TODO: figure out if this can be useful for tempo. The original PR implementing
// this trait:
// https://github.com/commonwarexyz/monorepo/pull/2565
// Associated issue:
// https://github.com/commonwarexyz/monorepo/issues/1767
impl CertifiableAutomaton for Mailbox {
    // NOTE: uses the default impl for CertifiableAutomaton which always
    // returns true.
}

impl Relay for Mailbox {
    type Digest = Digest;

    async fn broadcast(&mut self, digest: Self::Digest) {
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        self.inner
            .send(Broadcast { payload: digest }.into())
            .await
            .expect("application is present and ready to receive broadcasts");
    }
}
