use commonware_consensus::{Reporter, types::Epoch};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, sharing::Sharing, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_utils::ordered;
use eyre::WrapErr as _;
use futures::channel::mpsc;
use tracing::{Span, warn};

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn new(inner: mpsc::UnboundedSender<Message>) -> Self {
        Self { inner }
    }
}

#[derive(Debug)]
pub(super) struct Message {
    pub(super) cause: Span,
    pub(super) activity: Activity,
}

impl Message {
    fn in_current_span(activity: impl Into<Activity>) -> Self {
        Self {
            cause: Span::current(),
            activity: activity.into(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum Activity {
    Enter(EpochTransition),
    Exit(Exit),
}

impl From<EpochTransition> for Activity {
    fn from(value: EpochTransition) -> Self {
        Self::Enter(value)
    }
}

impl From<Exit> for Activity {
    fn from(value: Exit) -> Self {
        Self::Exit(value)
    }
}

#[derive(Debug)]
pub(crate) struct EpochTransition {
    pub(crate) epoch: Epoch,
    pub(crate) public: Sharing<MinSig>,
    pub(crate) share: Option<Share>,
    pub(crate) participants: ordered::Set<PublicKey>,
}

#[derive(Debug)]
pub(crate) struct Exit {
    pub(crate) epoch: Epoch,
}

impl Reporter for Mailbox {
    type Activity = Activity;

    async fn report(&mut self, command: Self::Activity) {
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        if let Err(error) = self
            .inner
            .unbounded_send(Message::in_current_span(command))
            .wrap_err("epoch manager no longer running")
        {
            warn!(%error, "failed to report epoch event to epoch manager")
        }
    }
}
