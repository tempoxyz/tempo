use alloy_primitives::B256;
use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
    marshal::Update,
    simplex::types::Context,
    types::{Height, Round},
};
use commonware_cryptography::ed25519::PublicKey;
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use std::{sync::Arc, time::Duration};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tracing::Span;

use crate::consensus::{Digest, block::Block};

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    pub(super) inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    /// Informs the agent that the parent in `context` is notarized (the
    /// context itself is not).
    ///
    /// Consensus only hands out propose/verify contexts whose parent is
    /// notarized, so every context doubles as evidence of its parent's
    /// notarization.
    pub(crate) fn parent_notarized(&self, context: Context<Digest, PublicKey>) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message::in_current_span(ParentNotarized { context }))
            .wrap_err("failed sending notarization info to agent, this means it exited")
    }

    /// Requests the agent to validate the block proposed in `round` against
    /// the execution layer.
    ///
    /// The block is validated via a single new-payload request, which requires
    /// the execution layer to already know the block's parent. If it does not,
    /// the request fails (the executor drops the response channel) and the
    /// executor repairs the gap in the background instead.
    ///
    /// The round arbitrates the slot shared with build requests: only a
    /// request from a newer round replaces a queued one.
    pub(crate) async fn validate_block(
        &self,
        round: Round,
        block: Block,
        validator_set: Option<Vec<B256>>,
    ) -> eyre::Result<Option<Duration>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(ValidateBlock {
                round,
                block: Arc::new(block),
                validator_set,
                response,
            }))
            .wrap_err("failed sending validate-block request to agent, this means it exited")?;
        rx.await.wrap_err(
            "executor dropped the validation response channel: the request was \
            superseded or stale, validation failed, or the executor shut down",
        )
    }

    /// Requests the executor to build a proposal on top of `digest` found at
    /// `round` and with `height`.
    ///
    /// The built payload is delivered on the returned channel once the
    /// execution layer finishes constructing it. The receiver may be dropped
    /// to signal that the payload is no longer wanted, whereupon the executor
    /// will drop the payload job.
    ///
    /// Conversely, the executor dropping its sender means the build failed;
    /// the executor logs the cause.
    ///
    /// If the executor's tracked execution layer state is outdated, the build
    /// fails fast.
    ///
    /// The round arbitrates the slot shared with validation requests: only a
    /// request from a newer round replaces a queued one.
    pub(crate) fn build_proposal(
        &self,
        round: Round,
        height: Height,
        digest: Digest,
        attributes: TempoPayloadAttributes,
    ) -> eyre::Result<oneshot::Receiver<TempoBuiltPayload>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(Build {
                round,
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
    /// Requests the agent to canonicalize the head and build a new payload.
    Build(Build),
    /// Requests the agent to validate a block against the execution layer.
    ValidateBlock(Box<ValidateBlock>),
    /// Requests the agent to forward a finalization event to the execution layer.
    Finalize(Box<Update<Block>>),
    /// Informs the agent that the parent of the contained context is notarized.
    ParentNotarized(ParentNotarized),
}

#[derive(Debug)]
pub(super) struct ParentNotarized {
    pub(super) context: Context<Digest, PublicKey>,
}

impl From<ParentNotarized> for Command {
    fn from(value: ParentNotarized) -> Self {
        Self::ParentNotarized(value)
    }
}

#[derive(Debug)]
pub(super) struct Build {
    pub(super) round: Round,
    pub(super) height: Height,
    pub(super) digest: Digest,
    pub(super) attributes: Box<TempoPayloadAttributes>,
    pub(super) response: oneshot::Sender<TempoBuiltPayload>,
}

#[derive(Debug)]
pub(super) struct ValidateBlock {
    pub(super) round: Round,
    pub(super) block: Arc<Block>,
    pub(super) validator_set: Option<Vec<B256>>,
    pub(super) response: oneshot::Sender<Option<Duration>>,
}

impl From<Build> for Command {
    fn from(value: Build) -> Self {
        Self::Build(value)
    }
}

impl From<ValidateBlock> for Command {
    fn from(value: ValidateBlock) -> Self {
        Self::ValidateBlock(Box::new(value))
    }
}

impl From<Update<Block>> for Command {
    fn from(value: Update<Block>) -> Self {
        Self::Finalize(value.into())
    }
}

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        match self.inner.unbounded_send(Message::in_current_span(update)) {
            Ok(()) => Feedback::Ok,
            Err(_) => Feedback::Closed,
        }
    }
}
