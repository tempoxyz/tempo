use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
    marshal::Update,
    simplex::types::Context,
    types::{Round, View},
};
use commonware_cryptography::{Digested, ed25519::PublicKey};
use eyre::WrapErr as _;
use futures::{
    channel::{mpsc, oneshot},
    future::BoxFuture,
};
use std::time::Duration;
use tempo_dkg_onchain_artifacts::CeremonyOutput;
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tracing::Span;

use crate::consensus::{Digest, block::Block};

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    pub(super) inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    /// Records consensus's parent before application validation or proposal
    /// preparation can fail, so the executor can still converge onto it.
    pub(crate) fn report_pending_head(
        &self,
        round: Round,
        parent: (View, Digest),
    ) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message::in_current_span(Command::PendingHead {
                round,
                parent,
            }))
            .wrap_err("failed reporting consensus parent to executor, this means it exited")
    }

    /// Verifies `block` against the execution layer, fetching missing ancestors
    /// as needed. The newest context's parent selects the pending head.
    ///
    /// Returns the time spent in engine calls for a valid block, `None` for an
    /// invalid block, or an error if verification could not complete.
    pub(crate) async fn verify_block(
        &self,
        context: Context<Digest, PublicKey>,
        block: Digested<Block>,
    ) -> eyre::Result<Option<Duration>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(VerifyBlock {
                context,
                block,
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
    /// If `deferred_ceremony_output` is set, the executor resolves it after the
    /// VALID answer and puts the result into `attributes`.
    /// A newer request can replace a queued build. Once started, the build
    /// continues until it finishes, fails, or its receiver is dropped.
    pub(crate) fn build_proposal(
        &self,
        context: Context<Digest, PublicKey>,
        attributes: TempoPayloadAttributes,
        deferred_ceremony_output: Option<DeferredCeremonyOutput>,
    ) -> eyre::Result<oneshot::Receiver<TempoBuiltPayload>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(Build {
                context,
                attributes: Box::new(attributes),
                deferred_ceremony_output,
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
    /// Reports consensus's parent independently of a build or verification.
    PendingHead {
        round: Round,
        parent: (View, Digest),
    },
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
    /// Set for a boundary proposal, which carries the DKG ceremony output.
    pub(super) deferred_ceremony_output: Option<DeferredCeremonyOutput>,
    pub(super) response: oneshot::Sender<TempoBuiltPayload>,
}

/// The DKG ceremony output of a boundary proposal, which consensus produces
/// while the executor delivers the parent.
///
/// The executor resolves it once, after the engine returned VALID for the
/// parent, puts it into the payload attributes and waits for it before the
/// forkchoice update that starts the build. The build holds the execution slot
/// while it waits.
///
/// It must be `Sync` because it travels in the executor's mailbox messages.
pub(crate) struct DeferredCeremonyOutput(
    Box<
        dyn FnOnce(Digested<Block>) -> BoxFuture<'static, eyre::Result<CeremonyOutput>>
            + Send
            + Sync,
    >,
);

impl DeferredCeremonyOutput {
    pub(crate) fn new<F>(make: F) -> Self
    where
        F: FnOnce(Digested<Block>) -> BoxFuture<'static, eyre::Result<CeremonyOutput>>
            + Send
            + Sync
            + 'static,
    {
        Self(Box::new(make))
    }

    pub(super) fn resolve(
        self,
        parent: Digested<Block>,
    ) -> BoxFuture<'static, eyre::Result<CeremonyOutput>> {
        (self.0)(parent)
    }
}

impl std::fmt::Debug for DeferredCeremonyOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeferredCeremonyOutput")
    }
}

#[derive(Debug)]
pub(super) struct VerifyBlock {
    pub(super) context: Context<Digest, PublicKey>,
    pub(super) block: Digested<Block>,
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
