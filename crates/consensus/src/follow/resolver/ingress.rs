use commonware_consensus::marshal::resolver::handler;
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::{
    channel::{fallible::FallibleExt as _, mpsc},
    vec::NonEmptyVec,
};

use crate::consensus::Digest;

#[derive(Clone)]
pub(crate) struct Mailbox {
    // FIXME: This should probably not be an unbounded channel - but how do
    // we exert backpressure?
    pub(super) inner: mpsc::UnboundedSender<Message>,
}

type Predicate<K> = Box<dyn Fn(&K) -> bool + Send>;

/// Messages sent to the resolver.
pub(super) enum Message {
    /// Initiate fetch requests.
    Fetch { keys: Vec<handler::Request<Digest>> },

    /// Cancel a fetch request by key.
    Cancel { key: handler::Request<Digest> },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests that do not satisfy the predicate.
    Retain {
        predicate: Predicate<handler::Request<Digest>>,
    },
}

impl commonware_resolver::Resolver for Mailbox {
    type Key = handler::Request<Digest>;
    type PublicKey = PublicKey;

    async fn fetch(&mut self, key: Self::Key) {
        self.fetch_all(vec![key]).await;
    }

    async fn fetch_all(&mut self, keys: Vec<Self::Key>) {
        self.inner.send_lossy(Message::Fetch { keys });
    }

    async fn fetch_targeted(&mut self, key: Self::Key, _targets: NonEmptyVec<Self::PublicKey>) {
        self.fetch(key).await;
    }

    async fn fetch_all_targeted(
        &mut self,
        requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
    ) {
        self.fetch_all(requests.into_iter().map(|(key, _)| key).collect())
            .await;
    }

    async fn cancel(&mut self, key: Self::Key) {
        self.inner.send_lossy(Message::Cancel { key });
    }

    async fn clear(&mut self) {
        self.inner.send_lossy(Message::Clear);
    }

    async fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
        self.inner.send_lossy(Message::Retain {
            predicate: Box::new(predicate),
        });
    }
}
