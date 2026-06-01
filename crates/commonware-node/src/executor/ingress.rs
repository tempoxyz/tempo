use alloy_rpc_types_engine::PayloadId;
use commonware_consensus::{Reporter, marshal::Update, types::Height};
use eyre::WrapErr as _;
use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};
use reth_payload_builder::PayloadValidityToken;
use tempo_payload_types::TempoPayloadAttributes;
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
        rx.await
            .wrap_err("executor dropped response")
            .and_then(|res| res)
    }

    /// Canonicalizes the given head and requests a new payload to be built.
    pub(crate) fn canonicalize_and_build(
        &self,
        height: Height,
        digest: Digest,
        attributes: TempoPayloadAttributes,
    ) -> eyre::Result<oneshot::Receiver<eyre::Result<PayloadId>>> {
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

    /// Starts a speculative build for the child of `parent` without canonicalizing `parent`.
    pub(crate) fn speculatively_build(
        &self,
        parent: Block,
        attributes: TempoPayloadAttributes,
        validity_token: PayloadValidityToken,
    ) -> eyre::Result<oneshot::Receiver<eyre::Result<PayloadId>>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(SpeculativeBuild {
                parent: Box::new(parent),
                attributes: Box::new(attributes),
                validity_token,
                response,
            }))
            .wrap_err("failed sending speculative build request to agent, this means it exited")?;
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
    /// Requests the agent to build a child payload against a speculative parent state.
    SpeculativeBuild(SpeculativeBuild),
    /// Requests the agent to forward a finalization event to the execution layer.
    Finalize(Box<Update<Block>>),
}

#[derive(Debug)]
pub(super) struct CanonicalizeHead {
    pub(super) height: Height,
    pub(super) digest: Digest,
    pub(super) response: oneshot::Sender<eyre::Result<()>>,
}

#[derive(Debug)]
pub(super) struct CanonicalizeAndBuild {
    pub(super) height: Height,
    pub(super) digest: Digest,
    pub(super) attributes: Box<TempoPayloadAttributes>,
    pub(super) response: oneshot::Sender<eyre::Result<PayloadId>>,
}

#[derive(Debug)]
pub(super) struct SpeculativeBuild {
    pub(super) parent: Box<Block>,
    pub(super) attributes: Box<TempoPayloadAttributes>,
    pub(super) validity_token: PayloadValidityToken,
    pub(super) response: oneshot::Sender<eyre::Result<PayloadId>>,
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

impl From<SpeculativeBuild> for Command {
    fn from(value: SpeculativeBuild) -> Self {
        Self::SpeculativeBuild(value)
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
