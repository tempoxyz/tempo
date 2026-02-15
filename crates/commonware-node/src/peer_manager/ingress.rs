use commonware_consensus::{Reporter, marshal::Update};
use commonware_p2p::{Address, AddressableManager, Provider};
use commonware_utils::ordered::{Map, Set};
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tracing::{Span, error};

type SubscribeReceiver =
    commonware_utils::channel::mpsc::UnboundedReceiver<(u64, Set<PublicKey>, Set<PublicKey>)>;

use commonware_cryptography::ed25519::PublicKey;

use crate::consensus::block::Block;

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    inner: mpsc::UnboundedSender<MessageWithCause>,
}

impl Mailbox {
    pub(super) fn new(inner: mpsc::UnboundedSender<MessageWithCause>) -> Self {
        Self { inner }
    }
}

pub(super) struct MessageWithCause {
    pub(super) cause: Span,
    pub(super) message: Message,
}

impl MessageWithCause {
    fn in_current_span(cmd: impl Into<Message>) -> Self {
        Self {
            cause: Span::current(),
            message: cmd.into(),
        }
    }
}

pub(super) enum Message {
    Track {
        id: u64,
        peers: Map<PublicKey, Address>,
    },
    Overwrite {
        peers: Map<PublicKey, Address>,
    },
    PeerSet {
        id: u64,
        response: oneshot::Sender<Option<Set<PublicKey>>>,
    },
    Subscribe {
        response: oneshot::Sender<SubscribeReceiver>,
    },
    Finalized(Box<Update<Block>>),
}

impl From<Update<Block>> for Message {
    fn from(value: Update<Block>) -> Self {
        Self::Finalized(Box::new(value))
    }
}

impl Provider for Mailbox {
    type PublicKey = PublicKey;

    async fn peer_set(&mut self, id: u64) -> Option<Set<Self::PublicKey>> {
        let (tx, rx) = oneshot::channel();
        if let Err(error) =
            self.inner
                .unbounded_send(MessageWithCause::in_current_span(Message::PeerSet {
                    id,
                    response: tx,
                }))
        {
            error!(%error, "failed to send message to peer_manager");
            return None;
        }
        rx.await.ok().flatten()
    }

    async fn subscribe(
        &mut self,
    ) -> commonware_utils::channel::mpsc::UnboundedReceiver<(
        u64,
        Set<Self::PublicKey>,
        Set<Self::PublicKey>,
    )> {
        let (tx, rx) = oneshot::channel();

        let (_, fallback_rx) = commonware_utils::channel::mpsc::unbounded_channel();

        if let Err(error) =
            self.inner
                .unbounded_send(MessageWithCause::in_current_span(Message::Subscribe {
                    response: tx,
                }))
        {
            error!(%error, "failed to send message to peer_manager");
            return fallback_rx;
        }

        if let Ok(subscription) = rx.await {
            return subscription;
        }

        error!(
            error = "actor dropped channel before returning subscription",
            "failed to send message to peer_manager",
        );

        fallback_rx
    }
}

impl AddressableManager for Mailbox {
    async fn track(&mut self, id: u64, peers: Map<Self::PublicKey, Address>) {
        if let Err(error) = self
            .inner
            .unbounded_send(MessageWithCause::in_current_span(Message::Track {
                id,
                peers,
            }))
            .wrap_err("actor no longer running")
        {
            error!(%error, "failed to send message to peer_manager");
        }
    }

    async fn overwrite(&mut self, peers: Map<Self::PublicKey, Address>) {
        if let Err(error) = self
            .inner
            .unbounded_send(MessageWithCause::in_current_span(Message::Overwrite {
                peers,
            }))
            .wrap_err("actor no longer running")
        {
            error!(%error, "failed to send message to peer_manager");
        }
    }
}

impl Reporter for Mailbox {
    type Activity = Update<Block>;

    async fn report(&mut self, activity: Self::Activity) {
        if let Err(error) = self
            .inner
            .unbounded_send(MessageWithCause::in_current_span(activity))
        {
            error!(%error, "failed to send message to peer_manager");
        }
    }
}
