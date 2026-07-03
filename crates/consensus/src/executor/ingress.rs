use commonware_consensus::{Reporter, marshal::Update, types::Height};
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tracing::Span;

use crate::consensus::{Digest, block::Block};

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    pub(super) inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    /// Requests the agent to update the head of the canonical chain to `digest`.
    pub(crate) async fn canonicalize_head(
        &self,
        height: Height,
        digest: Digest,
    ) -> eyre::Result<()> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(CanonicalizeHead {
                height,
                digest,
                response,
            }))
            .wrap_err("failed sending canonicalize request to agent, this means it exited")?;
        rx.await.wrap_err(
            "executor dropped the response channel: the forkchoice update \
            failed (the executor logs the cause) or the executor shut down",
        )
    }

    /// Canonicalizes the given head and requests a new payload to be built.
    ///
    /// The built payload is delivered on the returned channel once the
    /// execution layer finishes constructing it. The receiver may be dropped
    /// to signal that the payload is no longer wanted, whereupon the executor
    /// will drop the payload job.
    ///
    /// Conversely, the executor dropping its sender means the build failed;
    /// the executor logs the cause.
    pub(crate) fn canonicalize_and_build(
        &self,
        height: Height,
        digest: Digest,
        attributes: TempoPayloadAttributes,
    ) -> eyre::Result<oneshot::Receiver<TempoBuiltPayload>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(CanonicalizeAndBuild {
                height,
                digest,
                attributes: Box::new(attributes),
                response,
            }))
            .wrap_err(
                "failed sending canonicalize and build request to agent, this means it exited",
            )?;
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
    /// Requests the agent to canonicalize the head and build a new payload.
    CanonicalizeAndBuild(CanonicalizeAndBuild),
    /// Requests the agent to forward a finalization event to the execution layer.
    Finalize(Box<Update<Block>>),
}

#[derive(Debug)]
pub(super) struct CanonicalizeHead {
    pub(super) height: Height,
    pub(super) digest: Digest,
    pub(super) response: oneshot::Sender<()>,
}

#[derive(Debug)]
pub(super) struct CanonicalizeAndBuild {
    pub(super) height: Height,
    pub(super) digest: Digest,
    pub(super) attributes: Box<TempoPayloadAttributes>,
    pub(super) response: oneshot::Sender<TempoBuiltPayload>,
}

impl From<CanonicalizeHead> for Command {
    fn from(value: CanonicalizeHead) -> Self {
        Self::CanonicalizeHead(value)
    }
}

impl From<CanonicalizeAndBuild> for Command {
    fn from(value: CanonicalizeAndBuild) -> Self {
        Self::CanonicalizeAndBuild(value)
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
            .unbounded_send(Message::in_current_span(update))
            .expect("actor is present and ready to receive broadcasts");
    }
}
