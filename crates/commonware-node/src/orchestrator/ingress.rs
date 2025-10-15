use commonware_consensus::types::Epoch;
use eyre::WrapErr as _;
use futures::channel::mpsc;
use tempo_commonware_node_cryptography::Digest;
use tracing::{Span, debug, instrument};

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn new(inner: mpsc::UnboundedSender<Message>) -> Self {
        Self { inner }
    }

    /// Signals that boundary of `epoch` was reached and provides `seed` for the next.
    #[instrument(skip_all, fields(%epoch, %seed), err)]
    pub(crate) fn epoch_boundary_reached(&self, epoch: Epoch, seed: Digest) -> eyre::Result<()> {
        debug!("sending request to orchestrator");
        self.inner
            .unbounded_send(Message::in_current_span(EpochBoundaryReached {
                epoch,
                seed,
            }))
            .wrap_err("failed sending activity: orchestrator already went away")
    }

    /// Signals that `epoch` was entered.
    #[instrument(skip_all, fields(%epoch), err)]
    pub(crate) fn epoch_entered(&self, epoch: Epoch) -> eyre::Result<()> {
        debug!("sending request to orchestrator");
        self.inner
            .unbounded_send(Message::in_current_span(EpochEntered { epoch }))
            .wrap_err("failed sending activity: orchestrator already went away")
    }
}

pub(super) struct Message {
    pub(super) cause: Span,
    pub(super) command: Activity,
}

impl Message {
    fn in_current_span(command: impl Into<Activity>) -> Self {
        Self {
            cause: Span::current(),
            command: command.into(),
        }
    }
}

pub(super) enum Activity {
    EpochBoundaryReached(EpochBoundaryReached),
    EpochEntered(EpochEntered),
}

impl From<EpochEntered> for Activity {
    fn from(value: EpochEntered) -> Self {
        Self::EpochEntered(value)
    }
}

impl From<EpochBoundaryReached> for Activity {
    fn from(value: EpochBoundaryReached) -> Self {
        Self::EpochBoundaryReached(value)
    }
}

pub(super) struct EpochEntered {
    /// The epoch that the application has entered.
    pub(super) epoch: Epoch,
}

pub(super) struct EpochBoundaryReached {
    /// The epoch that is ending.
    pub(super) epoch: Epoch,
    /// The seed for the next epoch.
    pub(super) seed: Digest,
}
