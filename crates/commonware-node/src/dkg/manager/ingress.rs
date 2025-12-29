use commonware_consensus::{
    Reporter,
    marshal::Update,
    types::{Epoch, Round, View},
};
use commonware_utils::acknowledgement::Exact;
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tempo_dkg_onchain_artifacts::{IntermediateOutcome, PublicOutcome};
use tracing::{Span, warn};

use crate::consensus::{Digest, block::Block};

/// A mailbox to handle finalized blocks.
///
/// It implements the `Reporter` trait with associated
/// `type Activity = Update<Block, Exact>` and is passed to the marshal actor.
#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn new(inner: mpsc::UnboundedSender<Message>) -> Self {
        Self { inner }
    }

    /// Returns the intermediate dealing of this node's ceremony.
    ///
    /// Returns `None` if this node was not a dealer, or if the request is
    /// for a different epoch than the ceremony that's currently running.
    pub(crate) async fn get_intermediate_dealing(
        &self,
        epoch: Epoch,
    ) -> eyre::Result<Option<IntermediateOutcome>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(GetIntermediateDealing {
                epoch,
                response,
            }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with ceremony deal outcome")
    }

    pub(crate) async fn get_public_ceremony_outcome(
        &self,
        parent: (View, Digest),
        round: Round,
    ) -> eyre::Result<PublicOutcome> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(GetOutcome {
                parent,
                round,
                response,
            }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with ceremony deal outcome")
    }

    /// Verifies the `dealing` based on the current status of the DKG actor.
    ///
    /// This method is intended to be called by the application when verifying
    /// the dealing found in a proposal.
    pub(crate) async fn verify_intermediate_dealings(
        &self,
        dealing: IntermediateOutcome,
    ) -> eyre::Result<bool> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(VerifyDealing {
                dealing: dealing.into(),
                response,
            }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with ceremony info")
    }
}

pub(super) struct Message {
    pub(super) cause: Span,
    pub(super) command: Command,
}

impl Message {
    fn in_current_span(cmd: impl Into<Command>) -> Self {
        Self {
            cause: Span::current(),
            command: cmd.into(),
        }
    }
}

pub(super) enum Command {
    // From marshal
    Finalized(Box<Update<Block, Exact>>),

    // From application
    GetIntermediateDealing(GetIntermediateDealing),
    GetOutcome(GetOutcome),
    VerifyDealing(VerifyDealing),
}

impl From<Box<Update<Block, Exact>>> for Command {
    fn from(value: Box<Update<Block, Exact>>) -> Self {
        Self::Finalized(value)
    }
}

impl From<GetIntermediateDealing> for Command {
    fn from(value: GetIntermediateDealing) -> Self {
        Self::GetIntermediateDealing(value)
    }
}

impl From<VerifyDealing> for Command {
    fn from(value: VerifyDealing) -> Self {
        Self::VerifyDealing(value)
    }
}

impl From<GetOutcome> for Command {
    fn from(value: GetOutcome) -> Self {
        Self::GetOutcome(value)
    }
}

pub(super) struct GetIntermediateDealing {
    pub(super) epoch: Epoch,
    pub(super) response: oneshot::Sender<Option<IntermediateOutcome>>,
}

pub(super) struct GetOutcome {
    pub(super) parent: (View, Digest),
    pub(super) round: Round,
    pub(super) response: oneshot::Sender<PublicOutcome>,
}

pub(super) struct VerifyDealing {
    pub(super) dealing: Box<IntermediateOutcome>,
    pub(super) response: oneshot::Sender<bool>,
}

impl Reporter for Mailbox {
    type Activity = Update<Block, Exact>;

    async fn report(&mut self, update: Self::Activity) {
        if let Err(error) = self
            .inner
            .unbounded_send(Message::in_current_span(Box::new(update)))
            .wrap_err("dkg manager no longer running")
        {
            warn!(%error, "failed to report finalized update to dkg manager")
        }
    }
}
