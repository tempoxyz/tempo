use commonware_consensus::{Reporter, marshal::Update};
use commonware_p2p::{
    Address, AddressableManager, AddressableTrackedPeers, PeerSetSubscription, Provider,
    TrackedPeers,
};
use commonware_utils::ordered::Map;
use eyre::WrapErr as _;
use futures::channel::{mpsc, oneshot};
use tracing::{Span, error};

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
        peers: AddressableTrackedPeers<PublicKey>,
    },
    Overwrite {
        peers: Map<PublicKey, Address>,
    },
    PeerSet {
        id: u64,
        response: oneshot::Sender<Option<TrackedPeers<PublicKey>>>,
    },
    Subscribe {
        response: oneshot::Sender<PeerSetSubscription<PublicKey>>,
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

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
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

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
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
    async fn track<R>(&mut self, id: u64, peers: R)
    where
        R: Into<AddressableTrackedPeers<Self::PublicKey>> + Send,
    {
        let addressable: AddressableTrackedPeers<Self::PublicKey> = peers.into();
        if let Err(error) = self
            .inner
            .unbounded_send(MessageWithCause::in_current_span(Message::Track {
                id,
                peers: addressable,
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use futures::StreamExt as _;

    use super::*;

    fn key(seed: u64) -> PublicKey {
        PublicKey::from(PrivateKey::from_seed(seed))
    }

    fn addr(port: u16) -> Address {
        SocketAddr::from(([127, 0, 0, 1], port)).into()
    }

    #[tokio::test]
    async fn track_preserves_secondary_peers_in_mailbox_message() {
        let (tx, mut rx) = mpsc::unbounded();
        let mut mailbox = Mailbox::new(tx);
        let primary = key(1);
        let secondary = key(2);

        mailbox
            .track(
                7,
                AddressableTrackedPeers::new(
                    Map::try_from([(primary.clone(), addr(9101))]).unwrap(),
                    Map::try_from([(secondary.clone(), addr(9102))]).unwrap(),
                ),
            )
            .await;

        let message = rx
            .next()
            .await
            .expect("mailbox should emit a track message");
        match message.message {
            Message::Track { id, peers } => {
                assert_eq!(id, 7);
                assert_eq!(
                    peers.primary.keys(),
                    &commonware_utils::ordered::Set::try_from([primary]).unwrap()
                );
                assert_eq!(
                    peers.secondary.keys(),
                    &commonware_utils::ordered::Set::try_from([secondary]).unwrap()
                );
            }
            _ => panic!("expected track message"),
        }
    }
}
