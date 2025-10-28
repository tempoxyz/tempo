use commonware_consensus::{
    Automaton, Epochable, Relay, Reporter,
    simplex::types::Context,
    types::{Epoch, Round, View},
};

use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};

use crate::consensus::{Digest, block::Block};

#[derive(Clone)]
pub(crate) struct ExecutionDriverMailbox {
    to_execution_driver: mpsc::Sender<Message>,
}

impl ExecutionDriverMailbox {
    pub(super) fn from_sender(to_execution_driver: mpsc::Sender<Message>) -> Self {
        Self {
            to_execution_driver,
        }
    }
}

/// Messages forwarded from consensus to execution driver.
// TODO: add trace spans into all of these messages.
pub(super) enum Message {
    Broadcast(Broadcast),
    Finalized(Box<Finalized>),
    Genesis(Genesis),
    Propose(Propose),
    Verify(Verify),
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
    pub(super) response: oneshot::Sender<bool>,
    pub(super) round: Round,
}

impl From<Verify> for Message {
    fn from(value: Verify) -> Self {
        Self::Verify(value)
    }
}

#[derive(Debug)]
pub(super) struct Finalized {
    pub(super) block: Block,
    pub(super) response: oneshot::Sender<()>,
}

impl From<Finalized> for Message {
    fn from(value: Finalized) -> Self {
        Self::Finalized(value.into())
    }
}

impl Automaton for ExecutionDriverMailbox {
    type Context = Context<Self::Digest>;

    type Digest = Digest;

    async fn genesis(&mut self, epoch: <Self::Context as Epochable>::Epoch) -> Self::Digest {
        let (tx, rx) = oneshot::channel();
        // TODO: panicking here really is not good. there's actually no requirement on `Self::Context` nor `Self::Digest` to fulfill
        // any invariants, so we could just turn them into `Result<Context, Error>` and be happy.
        self.to_execution_driver
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
        self.to_execution_driver
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
        self.to_execution_driver
            .send(
                Verify {
                    parent: context.parent,
                    payload,
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

impl Relay for ExecutionDriverMailbox {
    type Digest = Digest;

    async fn broadcast(&mut self, digest: Self::Digest) {
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        self.to_execution_driver
            .send(Broadcast { payload: digest }.into())
            .await
            .expect("application is present and ready to receive broadcasts");
    }
}

impl Reporter for ExecutionDriverMailbox {
    type Activity = Block;

    async fn report(&mut self, block: Self::Activity) {
        let (response, rx) = oneshot::channel();
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        self.to_execution_driver
            .send(Finalized { block, response }.into())
            .await
            .expect("application is present and ready to receive broadcasts");

        // XXX: This is used as an acknowledgement that the application
        // finalized the block:
        // Response on this channel -> future returns -> marshaller gets an ack
        //
        // TODO(janis): report if this channel gets dropped?
        let _ = rx.await;
    }
}
