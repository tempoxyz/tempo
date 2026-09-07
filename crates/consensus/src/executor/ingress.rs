use alloy_primitives::B256;
use commonware_actor::Feedback;
use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context};
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
    /// Verifies `block` against the execution layer, fetching missing ancestors
    /// as needed. The newest context's parent selects the pending head.
    ///
    /// Returns the time spent in engine calls for a valid block, `None` for an
    /// invalid block, or an error if verification could not complete.
    pub(crate) async fn verify_block(
        &self,
        context: Context<Digest, PublicKey>,
        block: Block,
        validator_set: Option<Vec<B256>>,
    ) -> eyre::Result<Option<Duration>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(VerifyBlock {
                context,
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

    /// Requests the executor to build a proposal on top of `context`'s parent.
    ///
    /// The parent in the newest request context selects the pending head,
    /// independently of whether the request completes or is canceled.
    ///
    /// The built payload is delivered on the returned channel once the
    /// execution layer finishes constructing it. The receiver may be dropped
    /// to signal that the payload is no longer wanted, whereupon the executor
    /// will drop the payload job.
    ///
    /// Conversely, the executor dropping its sender means the build failed;
    /// the executor logs the cause.
    ///
    /// Fetches and delivers the parent, then starts the build if it is VALID.
    /// A newer request can replace a queued build. Once started, the build
    /// continues until it finishes, fails, or its receiver is dropped.
    pub(crate) fn build_proposal(
        &self,
        context: Context<Digest, PublicKey>,
        attributes: TempoPayloadAttributes,
    ) -> eyre::Result<oneshot::Receiver<TempoBuiltPayload>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(Build {
                context,
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
    Build(Box<Build>),
    /// Requests the agent to verify a block against the execution layer.
    VerifyBlock(Box<VerifyBlock>),
    /// Requests the agent to forward a finalization event to the execution layer.
    Finalize(Box<Update<Block>>),
}

#[derive(Debug)]
pub(super) struct Build {
    pub(super) context: Context<Digest, PublicKey>,
    pub(super) attributes: Box<TempoPayloadAttributes>,
    pub(super) response: oneshot::Sender<TempoBuiltPayload>,
}

#[derive(Debug)]
pub(super) struct VerifyBlock {
    pub(super) context: Context<Digest, PublicKey>,
    pub(super) block: Arc<Block>,
    pub(super) validator_set: Option<Vec<B256>>,
    pub(super) response: oneshot::Sender<Option<Duration>>,
}

impl From<Build> for Command {
    fn from(value: Build) -> Self {
        Self::Build(Box::new(value))
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
