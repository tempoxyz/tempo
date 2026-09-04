use super::{Buffer, Variant};
use commonware_cryptography::Digestible;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool, Aborter},
};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    sync::Arc,
};
use tracing::{info_span, Span};

/// A set of local subscribers waiting for one block.
///
/// Dropping the subscription aborts the backing buffer waiter, if one exists.
struct BlockSubscription<V: Variant> {
    subscribers: Vec<Subscriber<V>>,
    _aborter: Option<Aborter>,
}

/// A waiter for a block, carrying the span of its mailbox request.
struct Subscriber<V: Variant> {
    span: Span,
    sender: oneshot::Sender<Arc<V::Block>>,
}

/// Delivers a block to a subscriber inside the dequeue-side child of its
/// carried span, marking fulfillment in the trace.
fn deliver<V: Variant>(subscriber: Subscriber<V>, block: &Arc<V::Block>) {
    let _guard = info_span!(parent: &subscriber.span, "marshal.actor.notify").entered();
    subscriber.sender.send_lossy(Arc::clone(block));
}

/// The key used to track block subscriptions.
///
/// Digest-scoped and commitment-scoped subscriptions are intentionally distinct
/// so a block that aliases on digest cannot satisfy a different commitment wait.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Key<C, D> {
    Digest(D),
    Commitment(C),
}

pub(super) type KeyFor<V> =
    Key<<V as Variant>::Commitment, <<V as Variant>::Block as Digestible>::Digest>;

pub(super) struct Subscriptions<V: Variant> {
    entries: BTreeMap<KeyFor<V>, BlockSubscription<V>>,
}

impl<V: Variant> Subscriptions<V> {
    pub(super) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub(super) fn remove(&mut self, key: &KeyFor<V>) {
        self.entries.remove(key);
    }

    pub(super) fn retain_open(&mut self) {
        self.entries.retain(|_, subscription| {
            subscription
                .subscribers
                .retain(|subscriber| !subscriber.sender.is_closed());
            !subscription.subscribers.is_empty()
        });
    }

    /// Notify subscribers waiting for the provided block.
    pub(super) fn notify(&mut self, block: Arc<V::Block>) {
        let digest_key = Key::Digest(block.digest());
        let commitment_key = Key::Commitment(V::commitment(&block));

        if let Some(mut subscription) = self.entries.remove(&digest_key) {
            for subscriber in subscription.subscribers.drain(..) {
                deliver(subscriber, &block);
            }
        }
        if let Some(mut subscription) = self.entries.remove(&commitment_key) {
            for subscriber in subscription.subscribers.drain(..) {
                deliver(subscriber, &block);
            }
        }
    }

    pub(super) fn insert<Buf: Buffer<V>>(
        &mut self,
        span: Span,
        key: KeyFor<V>,
        response: oneshot::Sender<Arc<V::Block>>,
        waiters: &mut AbortablePool<Result<Arc<V::Block>, KeyFor<V>>>,
        buffer: &Buf,
    ) {
        let subscriber = Subscriber {
            span,
            sender: response,
        };
        match self.entries.entry(key) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(subscriber);
            }
            Entry::Vacant(entry) => {
                let rx = match key {
                    Key::Digest(digest) => buffer.subscribe_by_digest(digest),
                    Key::Commitment(commitment) => buffer.subscribe_by_commitment(commitment),
                };
                let aborter = rx.map(|rx| {
                    let waiter_key = key;
                    waiters.push(async move { rx.await.map_err(|_| waiter_key) })
                });
                entry.insert(BlockSubscription {
                    subscribers: vec![subscriber],
                    _aborter: aborter,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{core::variant::NoBuffer, mocks::block::Block, standard::Standard},
        types::{Height, Round},
    };
    use commonware_cryptography::{
        ed25519::PublicKey,
        sha256::{Digest, Sha256},
        Digestible,
    };
    use commonware_macros::select;
    use commonware_p2p::Recipients;
    use commonware_runtime::{deterministic, Clock, Runner as _};
    use commonware_utils::sync::Mutex;
    use futures::FutureExt;
    use std::sync::Arc;

    type TestBlock = Block<Digest, ()>;
    type TestVariant = Standard<TestBlock>;
    type TestWaiters = AbortablePool<Result<Arc<TestBlock>, KeyFor<TestVariant>>>;
    type Subscriber = oneshot::Sender<Arc<TestBlock>>;
    type Subscribers = Arc<Mutex<Vec<Subscriber>>>;

    #[derive(Clone, Default)]
    struct TestBuffer {
        digest_subscribers: Subscribers,
        commitment_subscribers: Subscribers,
    }

    impl TestBuffer {
        fn digest_subscription_count(&self) -> usize {
            self.digest_subscribers.lock().len()
        }

        fn commitment_subscription_count(&self) -> usize {
            self.commitment_subscribers.lock().len()
        }
    }

    impl Buffer<TestVariant> for TestBuffer {
        type PublicKey = PublicKey;

        async fn find_by_digest(&self, _digest: Digest) -> Option<Arc<TestBlock>> {
            None
        }

        async fn find_by_commitment(&self, _commitment: Digest) -> Option<Arc<TestBlock>> {
            None
        }

        fn subscribe_by_digest(
            &self,
            _digest: Digest,
        ) -> Option<oneshot::Receiver<Arc<TestBlock>>> {
            let (sender, receiver) = oneshot::channel();
            self.digest_subscribers.lock().push(sender);
            Some(receiver)
        }

        fn subscribe_by_commitment(
            &self,
            _commitment: Digest,
        ) -> Option<oneshot::Receiver<Arc<TestBlock>>> {
            let (sender, receiver) = oneshot::channel();
            self.commitment_subscribers.lock().push(sender);
            Some(receiver)
        }

        fn finalized(&self, _commitment: Digest) {}

        fn send(&self, _round: Round, _block: Arc<TestBlock>, _recipients: Recipients<PublicKey>) {}
    }

    fn block(height: u64, timestamp: u64) -> TestBlock {
        Block::new::<Sha256>((), Sha256::fill(0), Height::new(height), timestamp)
    }

    fn assert_receives(receiver: oneshot::Receiver<Arc<TestBlock>>, expected: &TestBlock) {
        let received = receiver
            .now_or_never()
            .expect("receiver should be ready")
            .expect("sender should deliver block");
        assert_eq!(received.digest(), expected.digest());
    }

    #[test]
    fn insert_coalesces_duplicate_keys() {
        let test_buffer = TestBuffer::default();
        let buffer = test_buffer.clone();
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let block = block(1, 10);

        let (first_sender, first_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            Key::Digest(block.digest()),
            first_sender,
            &mut waiters,
            &buffer,
        );
        let (second_sender, second_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            Key::Digest(block.digest()),
            second_sender,
            &mut waiters,
            &buffer,
        );

        assert_eq!(test_buffer.digest_subscription_count(), 1);
        assert_eq!(subscriptions.entries.len(), 1);

        subscriptions.notify(Arc::new(block.clone()));
        assert_receives(first_receiver, &block);
        assert_receives(second_receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    #[test]
    fn notify_wakes_digest_and_commitment_subscribers() {
        let test_buffer = TestBuffer::default();
        let buffer = test_buffer.clone();
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let block = block(2, 20);

        let (digest_sender, digest_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            Key::Digest(block.digest()),
            digest_sender,
            &mut waiters,
            &buffer,
        );
        let (commitment_sender, commitment_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            Key::Commitment(block.digest()),
            commitment_sender,
            &mut waiters,
            &buffer,
        );

        assert_eq!(test_buffer.digest_subscription_count(), 1);
        assert_eq!(test_buffer.commitment_subscription_count(), 1);
        assert_eq!(subscriptions.entries.len(), 2);

        subscriptions.notify(Arc::new(block.clone()));
        assert_receives(digest_receiver, &block);
        assert_receives(commitment_receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    #[test]
    fn retain_open_drops_closed_subscribers_and_keeps_open_ones() {
        let buffer = TestBuffer::default();
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let block = block(3, 30);

        let (closed_sender, closed_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            Key::Digest(block.digest()),
            closed_sender,
            &mut waiters,
            &buffer,
        );
        let (open_sender, open_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            Key::Digest(block.digest()),
            open_sender,
            &mut waiters,
            &buffer,
        );
        drop(closed_receiver);

        subscriptions.retain_open();
        let subscription = subscriptions
            .entries
            .get(&Key::Digest(block.digest()))
            .expect("open subscriber should remain");
        assert_eq!(subscription.subscribers.len(), 1);

        subscriptions.notify(Arc::new(block.clone()));
        assert_receives(open_receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    #[test]
    fn remove_drops_waiter_and_aborts_buffer_waiter() {
        deterministic::Runner::default().start(|context| async move {
            let buffer = TestBuffer::default();
            let mut waiters = TestWaiters::default();
            let mut subscriptions = Subscriptions::<TestVariant>::new();
            let block = block(4, 40);
            let key = Key::Digest(block.digest());

            let (sender, _receiver) = oneshot::channel();
            subscriptions.insert(Span::none(), key, sender, &mut waiters, &buffer);
            subscriptions.remove(&key);

            select! {
                completion = waiters.next_completed() => {
                    assert!(
                        completion.is_err(),
                        "removing the subscription should abort the buffer waiter"
                    );
                },
                _ = context.sleep(std::time::Duration::from_secs(1)) => {
                    panic!("waiter should close after subscription removal");
                },
            }
        });
    }

    #[test]
    fn insert_without_buffer_keeps_local_subscriber() {
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let buffer = NoBuffer::<PublicKey>::new();
        let block = block(5, 50);

        let (sender, receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            Key::Digest(block.digest()),
            sender,
            &mut waiters,
            &buffer,
        );

        assert_eq!(subscriptions.entries.len(), 1);
        subscriptions.notify(Arc::new(block.clone()));
        assert_receives(receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }
}
