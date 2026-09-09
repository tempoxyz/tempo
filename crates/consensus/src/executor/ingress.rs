use alloy_primitives::B256;
use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context, types::Round};
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
    /// Reports that, from simplex's point of view, `context`'s parent is
    /// the pending head of the chain: the block the proposal of this
    /// context builds on or is verified against. The agent converges the
    /// execution layer's head onto it.
    ///
    /// The parent is necessarily notarized — simplex only hands out
    /// propose/verify contexts with notarized parents — so the report
    /// doubles as a notarization proof. Reported parents are not monotonic
    /// (after nullifications, a later view may build on an older notarized
    /// block), so the newest *context* wins, and the head may legitimately
    /// move backwards.
    pub(crate) fn report_pending_head(
        &self,
        context: Context<Digest, PublicKey>,
    ) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message::in_current_span(PendingHeadReport { context }))
            .wrap_err("failed sending pending-head report to agent, this means it exited")
    }

    /// Requests the agent to verify the block proposed in `round` against the
    /// execution layer.
    ///
    /// The block is validated via a single new-payload request, which requires
    /// the execution layer to already know the block's parent. If it does not,
    /// the request fails (the executor drops the response channel) and the
    /// executor repairs the gap in the background instead.
    ///
    /// The round arbitrates the slot shared with build requests: only a
    /// request from a newer round replaces a queued one.
    pub(crate) async fn verify_block(
        &self,
        round: Round,
        block: Block,
        validator_set: Option<Vec<B256>>,
    ) -> eyre::Result<Option<Duration>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(VerifyBlock {
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

    /// Requests the executor to build a proposal on top of `digest` in
    /// `round`.
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
        digest: Digest,
        attributes: TempoPayloadAttributes,
    ) -> eyre::Result<oneshot::Receiver<TempoBuiltPayload>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(Build {
                round,
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
    /// Requests the agent to verify a block against the execution layer.
    VerifyBlock(Box<VerifyBlock>),
    /// Requests the agent to forward a finalization event to the execution layer.
    Finalize(Box<Update<Block>>),
    /// Reports the contained context's parent as the pending head that
    /// consensus builds on.
    PendingHeadReport(PendingHeadReport),
}

#[derive(Debug)]
pub(super) struct PendingHeadReport {
    pub(super) context: Context<Digest, PublicKey>,
}

impl From<PendingHeadReport> for Command {
    fn from(value: PendingHeadReport) -> Self {
        Self::PendingHeadReport(value)
    }
}

#[derive(Debug)]
pub(super) struct Build {
    pub(super) round: Round,
    pub(super) digest: Digest,
    pub(super) attributes: Box<TempoPayloadAttributes>,
    pub(super) response: oneshot::Sender<TempoBuiltPayload>,
}

#[derive(Debug)]
pub(super) struct VerifyBlock {
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

impl From<VerifyBlock> for Command {
    fn from(value: VerifyBlock) -> Self {
        Self::VerifyBlock(Box::new(value))
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
