use commonware_consensus::{Reporter, types::Epoch};
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tracing::{Span, warn};

use crate::{
    consensus::block::Block,
    dkg::ceremony::{LocalOutcome, PublicOutcome},
};

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    pub(super) inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(crate) async fn get_ceremony_deal(
        &self,
        epoch: Epoch,
    ) -> eyre::Result<Option<LocalOutcome>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(GetCeremonyDeal {
                epoch,
                response,
            }))
            .wrap_err("failed sending message to actor")?;
        rx.await
            .wrap_err("actor dropped channel before responding with ceremony deal outcome")
    }

    pub(crate) async fn get_public_ceremony_outcome(
        &self,
        epoch: Epoch,
    ) -> eyre::Result<Option<PublicOutcome>> {
        let (response, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::in_current_span(GetPublicCeremonyOutcome {
                epoch,
                response,
            }))
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
    GetCeremonyDeal(GetCeremonyDeal),
    GetCeremonyOutcome(GetPublicCeremonyOutcome),
}

impl From<Finalize> for Command {
    fn from(value: Finalize) -> Self {
        Self::Finalize(value)
    }
}

impl From<GetCeremonyDeal> for Command {
    fn from(value: GetCeremonyDeal) -> Self {
        Self::GetCeremonyDeal(value)
    }
}

impl From<GetPublicCeremonyOutcome> for Command {
    fn from(value: GetPublicCeremonyOutcome) -> Self {
        Self::GetCeremonyOutcome(value)
    }
}

pub(super) struct Finalize {
    pub(super) block: Block,
    pub(super) response: oneshot::Sender<()>,
}

pub(super) struct GetCeremonyDeal {
    pub(super) epoch: Epoch,
    pub(super) response: oneshot::Sender<Option<LocalOutcome>>,
}

pub(super) struct GetPublicCeremonyOutcome {
    pub(super) epoch: Epoch,
    pub(super) response: oneshot::Sender<Option<PublicOutcome>>,
}

impl Reporter for Mailbox {
    type Activity = Block;

    async fn report(&mut self, block: Self::Activity) {
        let (response, rx) = oneshot::channel();
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        if let Err(error) = self
            .inner
            .unbounded_send(Message::in_current_span(Finalize { block, response }))
            .wrap_err("dkg manager no longer running")
        {
            warn!(%error, "failed to report finalized block to dkg manager")
        }
        let _ = rx.await;
    }
}
