use commonware_consensus::{
    Automaton, Relay, Reporter,
    marshal::Update,
    simplex::types::Context,
    types::{Epoch, Round, View},
};

use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::acknowledgement::Exact;
use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};

use crate::consensus::{Digest, block::Block};

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
    Finalized(Box<Finalized>),
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

/// A finalization forwarded from the marshal actor to the application's
/// executor actor.
///
/// This enum unwraps `Update<Block>` into this `Finalized` enum so that
/// a `response` channel is attached to a block-finalization.
///
/// The reason is that the marshal actor expects blocks finalizations to be
/// acknowledged by the application.
///
/// Updated tips on the other hand are fire-and-forget.
#[derive(Debug)]
pub(super) struct Finalized {
    pub(super) inner: Update<Block, Exact>,
}

impl From<Finalized> for Message {
    fn from(value: Finalized) -> Self {
        Self::Finalized(value.into())
    }
}

impl Automaton for Mailbox {
    type Context = Context<Self::Digest, PublicKey>;

    type Digest = Digest;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        let (tx, rx) = oneshot::channel();
        // TODO: panicking here really is not good. there's actually no requirement on `Self::Context` nor `Self::Digest` to fulfill
        // any invariants, so we could just turn them into `Result<Context, Error>` and be happy.
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
        // TODO: panicking here really is not good. there's actually no requirement on `Self::Context` nor `Self::Digest` to fulfill
        // any invariants, so we could just turn them into `Result<Context, Error>` and be happy.
        //
        // XXX: comment taken from alto - what does this mean? is this relevant to us?
        // > If we linked payloads to their parent, we would verify
        // > the parent included in the payload matches the provided `Context`.
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
        // TODO: panicking here really is not good. there's actually no requirement on `Self::Context` nor `Self::Digest` to fulfill
        // any invariants, so we could just turn them into `Result<Context, Error>` and be happy.
        //
        // XXX: comment taken from alto - what does this mean? is this relevant to us?
        // > If we linked payloads to their parent, we would verify
        // > the parent included in the payload matches the provided `Context`.
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

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    async fn report(&mut self, update: Self::Activity) {
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        self.inner
            .send(Finalized { inner: update }.into())
            .await
            .expect("application is present and ready to receive broadcasts");
    }
}
