use commonware_consensus::{Reporter, marshal::Update, types::Height};
use eyre::WrapErr as _;
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
}

#[derive(Debug)]
pub(super) struct CanonicalizeHead {
    pub(super) height: Height,
    pub(super) digest: Digest,
    pub(super) ack: oneshot::Sender<()>,
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

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    async fn report(&mut self, update: Self::Activity) {
        self.inner
            .send(Message::in_current_span(update))
            .await
            .expect("actor is present and ready to receive broadcasts");
    }
}
