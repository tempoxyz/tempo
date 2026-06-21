use commonware_consensus::{Reporter, marshal::Update, types::Epoch};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, sharing::Sharing, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_utils::ordered;
use eyre::WrapErr as _;
use futures::channel::mpsc;
use tracing::{Span, error};

use crate::consensus::block::Block;

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub(super) fn new(inner: mpsc::UnboundedSender<Message>) -> Self {
        Self { inner }
    }

    pub(crate) fn enter(
        &mut self,
        epoch: Epoch,
        public: Sharing<MinSig>,
        share: Option<Share>,
        participants: ordered::Set<PublicKey>,
    ) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message::in_current_span(EpochTransition {
                epoch,
                public,
                share,
                participants,
            }))
            .wrap_err("epoch manager no longer running")
    }

    pub(crate) fn exit(&mut self, epoch: Epoch) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message::in_current_span(Exit { epoch }))
            .wrap_err("epoch manager no longer running")
    }
}

#[derive(Debug)]
pub(super) struct Message {
    pub(super) cause: Span,
    pub(super) content: Content,
}

impl Message {
    fn in_current_span(activity: impl Into<Content>) -> Self {
        Self {
            cause: Span::current(),
            content: activity.into(),
        }
    }
}

#[derive(Debug)]
pub(super) enum Content {
    Enter(EpochTransition),
    Exit(Exit),
    Update(Box<Update<Block>>),
}

impl From<EpochTransition> for Content {
    fn from(value: EpochTransition) -> Self {
        Self::Enter(value)
    }
}

impl From<Exit> for Content {
    fn from(value: Exit) -> Self {
        Self::Exit(value)
    }
}

impl From<Update<Block>> for Content {
    fn from(value: Update<Block>) -> Self {
        Self::Update(Box::new(value))
    }
}

#[derive(Debug)]
pub(super) struct EpochTransition {
    pub(super) epoch: Epoch,
    pub(super) public: Sharing<MinSig>,
    pub(super) share: Option<Share>,
    pub(super) participants: ordered::Set<PublicKey>,
}

#[derive(Debug)]
pub(super) struct Exit {
    pub(super) epoch: Epoch,
}

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    async fn report(&mut self, activity: Self::Activity) {
        if self
            .inner
            .unbounded_send(Message::in_current_span(activity))
            .is_err()
        {
            error!(
                "failed sending finalization activity to epoch manager because \
                it is no longer running"
            );
        }
    }
}
