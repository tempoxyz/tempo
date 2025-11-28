use commonware_consensus::{Reporter, marshal::Update, types::Epoch};
use commonware_utils::acknowledgement::Exact;
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tempo_dkg_onchain_artifacts::{IntermediateOutcome, PublicOutcome};
use tracing::{Span, warn};

use crate::consensus::block::Block;

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    pub(super) inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    /// Returns information about the currently running ceremony.
    pub(crate) async fn get_ceremony_info(&self) -> eyre::Result<CeremonyInfo> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(GetCeremonyInfo { response }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with ceremony info")
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

    pub(crate) async fn get_public_ceremony_outcome(&self) -> eyre::Result<PublicOutcome> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(GetOutcome { response }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with ceremony deal outcome")
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
    Finalize(Finalize),
    GetIntermediateDealing(GetIntermediateDealing),
    GetCeremonyInfo(GetCeremonyInfo),
    GetOutcome(GetOutcome),
}

impl From<Finalize> for Command {
    fn from(value: Finalize) -> Self {
        Self::Finalize(value)
    }
}

impl From<GetCeremonyInfo> for Command {
    fn from(value: GetCeremonyInfo) -> Self {
        Self::GetCeremonyInfo(value)
    }
}

impl From<GetIntermediateDealing> for Command {
    fn from(value: GetIntermediateDealing) -> Self {
        Self::GetIntermediateDealing(value)
    }
}

impl From<GetOutcome> for Command {
    fn from(value: GetOutcome) -> Self {
        Self::GetOutcome(value)
    }
}

/// Contains information about the currently running ceremony.
pub(crate) struct CeremonyInfo {
    /// The epoch of the currently running ceremony. If no ceremony is running
    /// (that's only the case after the pre-to-last block but before the
    /// last block have been finalized), then this contains the epoch of the
    /// last ceremony (derived from the epoch state).
    pub(crate) epoch: Epoch,

    /// If the current ceremony is a post-allegretto ceremony.
    pub(crate) is_post_allegretto: bool,
}

pub(super) struct Finalize {
    pub(super) block: Box<Block>,
    pub(super) acknowledgment: Exact,
}

pub(super) struct GetCeremonyInfo {
    pub(super) response: oneshot::Sender<CeremonyInfo>,
}

pub(super) struct GetIntermediateDealing {
    pub(super) epoch: Epoch,
    pub(super) response: oneshot::Sender<Option<IntermediateOutcome>>,
}

pub(super) struct GetOutcome {
    pub(super) response: oneshot::Sender<PublicOutcome>,
}

impl Reporter for Mailbox {
    type Activity = Update<Block, Exact>;

    async fn report(&mut self, update: Self::Activity) {
        let Update::Block(block, acknowledgment) = update else {
            tracing::trace!("dropping tip update; DKG manager is only interested in blocks");
            return;
        };
        if let Err(error) = self
            .inner
            .unbounded_send(Message::in_current_span(Finalize {
                block: block.into(),
                acknowledgment,
            }))
            .wrap_err("dkg manager no longer running")
        {
            warn!(%error, "failed to report finalized block to dkg manager")
        }
    }
}
