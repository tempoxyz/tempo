use commonware_consensus::{Reporter, marshal::Update, types::Height};
use eyre::{WrapErr as _, eyre};
use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};
use tracing::Span;

use crate::consensus::{Digest, block::Block};

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    pub(super) inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    /// Requests the agent to update the head of the canonical chain to `digest`.
    pub(crate) fn canonicalize_head(
        &self,
        height: Height,
        digest: Digest,
    ) -> eyre::Result<oneshot::Receiver<()>> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(CanonicalizeHead {
                height,
                digest,
                ack: tx,
            }))
            .wrap_err("failed sending canonicalize request to agent, this means it exited")?;

        Ok(rx)
    }

    pub(crate) async fn subscribe_finalized(&self, height: Height) -> eyre::Result<()> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(SubscribeFinalized {
                height,
                response,
            }))
            .wrap_err(
                "failed sending subscribe finalized request to agent, this means it exited",
            )?;
        rx.await.map_err(|_| eyre!("actor dropped response"))
    }
}

#[derive(Debug)]
pub(super) struct Message {
    pub(super) cause: Span,
    pub(super) command: Command,
}

impl Message {
    fn in_current_span(command: impl Into<Command>) -> Self {
        Self {
            cause: Span::current(),
            command: command.into(),
        }
    }
}

#[derive(Debug)]
pub(super) enum Command {
    /// Requests the agent to set the head of the canonical chain to `digest`.
    CanonicalizeHead(CanonicalizeHead),
    /// Requests the agent to forward a finalization event to the execution layer.
    Finalize(Box<Update<Block>>),
    /// Returns once the executor actor has finalized the block at `height`.
    SubscribeFinalized(SubscribeFinalized),
}

#[derive(Debug)]
pub(super) struct CanonicalizeHead {
    pub(super) height: Height,
    pub(super) digest: Digest,
    pub(super) ack: oneshot::Sender<()>,
}

#[derive(Debug)]
pub(super) struct SubscribeFinalized {
    pub(super) height: Height,
    pub(super) response: oneshot::Sender<()>,
}

impl From<CanonicalizeHead> for Command {
    fn from(value: CanonicalizeHead) -> Self {
        Self::CanonicalizeHead(value)
    }
}

impl From<Update<Block>> for Command {
    fn from(value: Update<Block>) -> Self {
        Self::Finalize(value.into())
    }
}

impl From<SubscribeFinalized> for Command {
    fn from(value: SubscribeFinalized) -> Self {
        Self::SubscribeFinalized(value)
    }
}

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    async fn report(&mut self, update: Self::Activity) {
        self.inner
            .send(Message::in_current_span(update))
            .await
            .expect("actor is present and ready to receive broadcasts");
    }
}
