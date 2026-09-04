use crate::types::{Height, Round};
use bytes::{Buf, BufMut, Bytes};
use commonware_actor::mailbox::{self, Overflow, Policy, Sender};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::Digest;
use commonware_resolver::{p2p::Producer, Consumer, Delivery, Fetch as ResolverFetch};
use commonware_runtime::Metrics;
use commonware_utils::{channel::oneshot, Span};
use std::{
    collections::VecDeque,
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    sync::mpsc::TryRecvError,
};
use tracing::info_span;

/// The subject of a backfill request.
const BLOCK_REQUEST: u8 = 0;
const FINALIZED_REQUEST: u8 = 1;
const NOTARIZED_REQUEST: u8 = 2;

/// Messages sent from the resolver's [Consumer]/[Producer] implementation
/// to the marshal actor.
pub(crate) enum Message<D: Digest> {
    /// A request to deliver a value for a given key.
    Deliver {
        /// The delivery metadata attached to the resolved value.
        delivery: Delivery<Key<D>, Annotation>,
        /// The value being delivered.
        value: Bytes,
        /// A channel to send the result of the delivery.
        response: oneshot::Sender<bool>,
    },
    /// A request to produce a value for a given key.
    Produce {
        /// The key of the value to produce.
        key: Key<D>,
        /// A channel to send the produced value.
        response: oneshot::Sender<Bytes>,
    },
}

impl<D: Digest> Message<D> {
    /// Returns true if the requester has stopped waiting for this response.
    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

/// Pending resolver handler messages retained after the mailbox fills.
pub(crate) struct Pending<D: Digest>(VecDeque<Message<D>>);

impl<D: Digest> Default for Pending<D> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<D: Digest> Overflow<Message<D>> for Pending<D> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<D>) -> Option<Message<D>>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl<D: Digest> Policy for Message<D> {
    type Overflow = Pending<D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }
        overflow.0.push_back(message);
    }
}

/// A handler that forwards requests from the resolver to the marshal actor.
///
/// This struct implements the [Consumer] and [Producer] traits from the
/// resolver, and acts as a bridge to the main actor loop.
#[derive(Clone)]
pub struct Handler<D: Digest> {
    sender: Sender<Message<D>>,
}

impl<D: Digest> Handler<D> {
    /// Creates a new handler.
    pub(crate) const fn new(sender: Sender<Message<D>>) -> Self {
        Self { sender }
    }
}

/// Creates a resolver receiver and handler pair.
pub fn init<D: Digest>(metrics: impl Metrics, capacity: NonZeroUsize) -> (Receiver<D>, Handler<D>) {
    let (sender, receiver) = mailbox::new(metrics, capacity);
    (Receiver::new(receiver), Handler::new(sender))
}

/// Receiver for resolver handler messages.
pub struct Receiver<D: Digest> {
    inner: mailbox::Receiver<Message<D>>,
}

impl<D: Digest> Receiver<D> {
    pub(crate) const fn new(inner: mailbox::Receiver<Message<D>>) -> Self {
        Self { inner }
    }

    pub(crate) async fn recv(&mut self) -> Option<Message<D>> {
        self.inner.recv().await
    }

    pub(crate) fn try_recv(&mut self) -> Result<Message<D>, TryRecvError> {
        self.inner.try_recv()
    }
}

impl<D: Digest> Consumer for Handler<D> {
    type Key = Key<D>;
    type Value = Bytes;
    type Subscriber = Annotation;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Deliver {
            delivery,
            value,
            response,
        });
        receiver
    }
}

impl<D: Digest> Producer for Handler<D> {
    type Key = Key<D>;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Produce { key, response });
        receiver
    }
}

/// Local processing annotation for a resolved key.
///
/// The resolver key is the peer-visible lookup. An annotation is local
/// metadata attached to that lookup so marshal can decide how to process the
/// response after validating it against the key. It is not part of peer
/// response validity. Multiple local annotations may share one peer key when
/// they depend on the same block.
///
/// [`Notarization`](Annotation::Notarization) carries round-bound local
/// context. [`Certified`](Annotation::Certified) and
/// [`Finalized`](Annotation::Finalized) describe how block-bearing responses
/// should be processed locally.
///
/// This storage role is part of the annotation because a [`Key::Block`]
/// only names the peer-visible commitment. The same block-shaped response may
/// need to update different local stores depending on whether it was fetched
/// for a certified chain or for the finalized chain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Annotation {
    /// A notarization requested by round.
    Notarization { round: Round },
    /// A block requested by commitment for a certified chain.
    ///
    /// The expected height is local pruning metadata and should only be
    /// supplied when the caller has a validated height bound. It must not make
    /// a commitment-matching response invalid, and certified storage uses the
    /// fetched block's decoded height.
    Certified { height: Height },
    /// A block requested by commitment for the finalized chain.
    Finalized(Finalized),
}

/// Metadata for a finalized block requested by commitment.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Finalized {
    /// The finalized height is known before the request.
    ByHeight { height: Height },
    /// Only the finalization round is known before the request.
    ///
    /// This happens when a finalization names the block commitment but not the
    /// block height.
    ByRound { round: Round },
}

/// A raw resolver key for backfilling data.
#[derive(Clone, Copy)]
pub enum Key<D: Digest> {
    /// Fetch a block by consensus commitment.
    Block(D),
    Finalized {
        height: Height,
    },
    Notarized {
        round: Round,
    },
}

impl<D: Digest> Key<D> {
    /// The subject of the request.
    const fn subject(&self) -> u8 {
        match self {
            Self::Block(_) => BLOCK_REQUEST,
            Self::Finalized { .. } => FINALIZED_REQUEST,
            Self::Notarized { .. } => NOTARIZED_REQUEST,
        }
    }
}

/// A valid marshal backfill fetch request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestKind<D: Digest> {
    /// Fetch a notarized proposal for a round.
    Notarized { round: Round },
    /// Fetch a finalization for a height.
    Finalized { height: Height },
    /// Fetch a certified-chain block by commitment.
    CertifiedBlock { commitment: D, height: Height },
    /// Fetch a finalized-chain block by commitment when its height is known.
    FinalizedBlockByHeight { commitment: D, height: Height },
    /// Fetch a finalized-chain block by commitment when only its finalization round is known.
    FinalizedBlockByRound { commitment: D, round: Round },
}

/// A marshal backfill fetch with a request and local processing annotation that match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<D: Digest> {
    kind: RequestKind<D>,
}

impl<D: Digest> Request<D> {
    /// Fetch a notarized proposal for `round`.
    pub const fn notarized(round: Round) -> Self {
        Self {
            kind: RequestKind::Notarized { round },
        }
    }

    /// Fetch a finalization for `height`.
    pub const fn finalized(height: Height) -> Self {
        Self {
            kind: RequestKind::Finalized { height },
        }
    }

    /// Fetch a certified-chain block by commitment.
    pub const fn certified_block(commitment: D, height: Height) -> Self {
        Self {
            kind: RequestKind::CertifiedBlock { commitment, height },
        }
    }

    /// Fetch a finalized-chain block by commitment when its height is known.
    pub const fn finalized_block_by_height(commitment: D, height: Height) -> Self {
        Self {
            kind: RequestKind::FinalizedBlockByHeight { commitment, height },
        }
    }

    /// Fetch a finalized-chain block by commitment when only its finalization round is known.
    pub const fn finalized_block_by_round(commitment: D, round: Round) -> Self {
        Self {
            kind: RequestKind::FinalizedBlockByRound { commitment, round },
        }
    }

    pub(crate) fn above_height_floor(&self, floor: Height) -> bool {
        match self.kind {
            RequestKind::Finalized { height }
            | RequestKind::CertifiedBlock { height, .. }
            | RequestKind::FinalizedBlockByHeight { height, .. } => height > floor,
            RequestKind::Notarized { .. } | RequestKind::FinalizedBlockByRound { .. } => true,
        }
    }

    pub(crate) fn above_round_floor(&self, floor: Round) -> bool {
        match self.kind {
            RequestKind::Notarized { round } | RequestKind::FinalizedBlockByRound { round, .. } => {
                round > floor
            }
            RequestKind::Finalized { .. }
            | RequestKind::CertifiedBlock { .. }
            | RequestKind::FinalizedBlockByHeight { .. } => true,
        }
    }

    pub(crate) fn into_inner(self) -> ResolverFetch<Key<D>, Annotation> {
        let (key, subscriber) = match self.kind {
            RequestKind::Notarized { round } => {
                (Key::Notarized { round }, Annotation::Notarization { round })
            }
            RequestKind::Finalized { height } => (
                Key::Finalized { height },
                Annotation::Finalized(Finalized::ByHeight { height }),
            ),
            RequestKind::CertifiedBlock { commitment, height } => {
                (Key::Block(commitment), Annotation::Certified { height })
            }
            RequestKind::FinalizedBlockByHeight { commitment, height } => (
                Key::Block(commitment),
                Annotation::Finalized(Finalized::ByHeight { height }),
            ),
            RequestKind::FinalizedBlockByRound { commitment, round } => (
                Key::Block(commitment),
                Annotation::Finalized(Finalized::ByRound { round }),
            ),
        };
        let span = info_span!("marshal.resolver.fetch", key = %key);
        ResolverFetch {
            key,
            subscriber,
            span,
        }
    }
}

impl<D: Digest> From<Request<D>> for ResolverFetch<Key<D>, Annotation> {
    fn from(fetch: Request<D>) -> Self {
        fetch.into_inner()
    }
}

/// Returns a predicate that keeps resolver requests above the processed height floor.
///
/// Unrelated requests are retained. Height-bound requests are pruned once the
/// processed height reaches them.
pub(crate) fn above_height_floor<D: Digest>(
    height: Height,
) -> impl Fn(&Key<D>, &Annotation) -> bool + Send + 'static {
    move |request, annotation| match (request, annotation) {
        (Key::Finalized { height: requested }, _) => *requested > height,
        (
            Key::Block(_),
            Annotation::Certified { height: requested }
            | Annotation::Finalized(Finalized::ByHeight { height: requested }),
        ) => *requested > height,
        _ => true,
    }
}

/// Returns a predicate that keeps resolver requests above the processed round floor.
///
/// Unrelated requests are retained. Round-bound requests are pruned once the
/// processed round reaches them.
pub(crate) fn above_round_floor<D: Digest>(
    round: Round,
) -> impl Fn(&Key<D>, &Annotation) -> bool + Send + 'static {
    move |request, annotation| match (request, annotation) {
        (Key::Notarized { round: requested }, _) => *requested > round,
        (Key::Block(_), Annotation::Finalized(Finalized::ByRound { round: requested })) => {
            *requested > round
        }
        _ => true,
    }
}

impl<D: Digest> Write for Key<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.subject().write(buf);
        match self {
            Self::Block(commitment) => commitment.write(buf),
            Self::Finalized { height } => height.write(buf),
            Self::Notarized { round } => round.write(buf),
        }
    }
}

impl<D: Digest> Read for Key<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request = match u8::read(buf)? {
            BLOCK_REQUEST => Self::Block(D::read(buf)?),
            FINALIZED_REQUEST => Self::Finalized {
                height: Height::read(buf)?,
            },
            NOTARIZED_REQUEST => Self::Notarized {
                round: Round::read(buf)?,
            },
            i => return Err(CodecError::InvalidEnum(i)),
        };
        Ok(request)
    }
}

impl<D: Digest> EncodeSize for Key<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Block(commitment) => commitment.encode_size(),
            Self::Finalized { height } => height.encode_size(),
            Self::Notarized { round } => round.encode_size(),
        }
    }
}

impl<D: Digest> Span for Key<D> {}

impl<D: Digest> PartialEq for Key<D> {
    fn eq(&self, other: &Self) -> bool {
        match (&self, &other) {
            (Self::Block(a), Self::Block(b)) => a == b,
            (Self::Finalized { height: a }, Self::Finalized { height: b }) => a == b,
            (Self::Notarized { round: a }, Self::Notarized { round: b }) => a == b,
            _ => false,
        }
    }
}

impl<D: Digest> Eq for Key<D> {}

impl<D: Digest> Ord for Key<D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (&self, &other) {
            (Self::Block(a), Self::Block(b)) => a.cmp(b),
            (Self::Finalized { height: a }, Self::Finalized { height: b }) => a.cmp(b),
            (Self::Notarized { round: a }, Self::Notarized { round: b }) => a.cmp(b),
            (a, b) => a.subject().cmp(&b.subject()),
        }
    }
}

impl<D: Digest> PartialOrd for Key<D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<D: Digest> Hash for Key<D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.subject().hash(state);
        match self {
            Self::Block(commitment) => commitment.hash(state),
            Self::Finalized { height } => height.hash(state),
            Self::Notarized { round } => round.hash(state),
        }
    }
}

impl<D: Digest> Display for Key<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(commitment) => write!(f, "Block({commitment:?})"),
            Self::Finalized { height } => write!(f, "Finalized({height:?})"),
            Self::Notarized { round } => write!(f, "Notarized({round:?})"),
        }
    }
}

impl<D: Digest> Debug for Key<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(commitment) => write!(f, "Block({commitment:?})"),
            Self::Finalized { height } => write!(f, "Finalized({height:?})"),
            Self::Notarized { round } => write!(f, "Notarized({round:?})"),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Key<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(Self::Block(u.arbitrary()?)),
            1 => Ok(Self::Finalized {
                height: u.arbitrary()?,
            }),
            2 => Ok(Self::Notarized {
                round: u.arbitrary()?,
            }),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Epoch, View};
    use commonware_codec::{Encode, ReadExt};
    use commonware_cryptography::{
        sha256::{Digest as Sha256Digest, Sha256},
        Hasher as _,
    };
    use std::collections::BTreeSet;

    type D = Sha256Digest;

    #[test]
    fn handler_drain_skips_closed_responses() {
        let mut overflow = Pending::<D>::default();

        let (closed_response, closed_receiver) = oneshot::channel();
        Message::handle(
            &mut overflow,
            Message::Produce {
                key: Key::Finalized {
                    height: Height::new(1),
                },
                response: closed_response,
            },
        );
        drop(closed_receiver);

        let (open_response, _open_receiver) = oneshot::channel();
        Message::handle(
            &mut overflow,
            Message::Produce {
                key: Key::Finalized {
                    height: Height::new(2),
                },
                response: open_response,
            },
        );

        let mut messages = Vec::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push(message);
            None
        });

        assert_eq!(messages.len(), 1);
        assert!(matches!(
            messages.pop(),
            Some(Message::Produce {
                key: Key::Finalized { height },
                ..
            }) if height == Height::new(2)
        ));
    }

    #[test]
    fn test_cross_variant_hash_differs() {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };

        fn hash_of<T: Hash>(t: &T) -> u64 {
            let mut h = DefaultHasher::new();
            t.hash(&mut h);
            h.finish()
        }

        let finalized = Key::<D>::Finalized {
            height: Height::new(1),
        };
        let notarized = Key::<D>::Notarized {
            round: Round::new(Epoch::new(0), View::new(1)),
        };
        assert_ne!(hash_of(&finalized), hash_of(&notarized));
    }

    #[test]
    fn test_subject_block_encoding() {
        let commitment = Sha256::hash(b"test");
        let request = Key::<D>::Block(commitment);

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded.len(), 33); // 1 byte for enum variant + 32 bytes for commitment
        assert_eq!(encoded[0], 0); // Block variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Key::<D>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Key::Block(commitment));
    }

    #[test]
    fn test_subject_finalized_encoding() {
        let height = Height::new(12345u64);
        let request = Key::<D>::Finalized { height };

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 1); // Finalized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Key::<D>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Key::Finalized { height });
    }

    #[test]
    fn test_subject_notarized_encoding() {
        let round = Round::new(Epoch::new(67890), View::new(12345));
        let request = Key::<D>::Notarized { round };

        // Test encoding
        let encoded = request.encode();
        assert_eq!(encoded[0], 2); // Notarized variant

        // Test decoding
        let mut buf = encoded.as_ref();
        let decoded = Key::<D>::read(&mut buf).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded, Key::Notarized { round });
    }

    #[test]
    fn test_subject_decode_rejects_invalid_enum_tag() {
        let bad = [3u8];
        let mut buf = bad.as_ref();
        assert!(matches!(
            Key::<D>::read(&mut buf),
            Err(CodecError::InvalidEnum(3))
        ));
    }

    #[test]
    fn test_subject_hash() {
        use std::collections::HashSet;

        let r1 = Key::<D>::Finalized {
            height: Height::new(100),
        };
        let r2 = Key::<D>::Finalized {
            height: Height::new(100),
        };
        let r3 = Key::<D>::Finalized {
            height: Height::new(200),
        };

        let mut set = HashSet::new();
        set.insert(r1);
        assert!(!set.insert(r2)); // Should not insert duplicate
        assert!(set.insert(r3)); // Should insert different value
    }

    #[test]
    fn test_height_floor_predicate() {
        let floor = Height::new(100);
        let higher_finalized = Key::<D>::Finalized {
            height: Height::new(200),
        };
        let notarized = Key::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(150)),
        };
        let block = Key::<D>::Block(Sha256::hash(b"block"));
        let stale_finalized = Annotation::Finalized(Finalized::ByHeight {
            height: Height::new(100),
        });
        let fresh_certified = Annotation::Certified {
            height: Height::new(101),
        };
        let stale_certified = Annotation::Certified {
            height: Height::new(100),
        };

        let predicate = above_height_floor(floor);
        assert!(predicate(
            &higher_finalized,
            &Annotation::Finalized(Finalized::ByHeight {
                height: Height::new(200),
            })
        ));
        assert!(predicate(
            &notarized,
            &Annotation::Notarization {
                round: Round::new(Epoch::new(333), View::new(150)),
            }
        ));
        assert!(predicate(&block, &fresh_certified));

        let same_height = Key::<D>::Finalized {
            height: Height::new(100),
        };
        assert!(!predicate(
            &same_height,
            &Annotation::Finalized(Finalized::ByHeight {
                height: Height::new(100),
            })
        ));
        assert!(!predicate(&block, &stale_finalized));
        assert!(!predicate(&block, &stale_certified));
    }

    #[test]
    fn test_round_floor_predicate() {
        let floor = Round::new(Epoch::new(1), View::new(10));
        let block = Key::<D>::Block(Sha256::hash(b"block"));
        let higher_notarized = Key::<D>::Notarized {
            round: Round::new(Epoch::new(1), View::new(11)),
        };
        let same_notarized = Key::<D>::Notarized {
            round: Round::new(Epoch::new(1), View::new(10)),
        };
        let finalized = Key::<D>::Finalized {
            height: Height::new(100),
        };

        let predicate = above_round_floor(floor);
        assert!(predicate(
            &higher_notarized,
            &Annotation::Notarization {
                round: Round::new(Epoch::new(1), View::new(11)),
            }
        ));
        assert!(predicate(
            &finalized,
            &Annotation::Finalized(Finalized::ByHeight {
                height: Height::new(100),
            })
        ));
        assert!(predicate(
            &block,
            &Annotation::Finalized(Finalized::ByRound {
                round: Round::new(Epoch::new(1), View::new(11)),
            })
        ));
        assert!(!predicate(
            &same_notarized,
            &Annotation::Notarization {
                round: Round::new(Epoch::new(1), View::new(10)),
            }
        ));
        assert!(!predicate(
            &block,
            &Annotation::Finalized(Finalized::ByRound {
                round: Round::new(Epoch::new(1), View::new(10)),
            })
        ));
    }

    #[test]
    fn test_encode_size() {
        let commitment = Sha256::hash(&[0u8; 32]);
        let r1 = Key::<D>::Block(commitment);
        let r2 = Key::<D>::Finalized {
            height: Height::new(u64::MAX),
        };
        let r3 = Key::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(0)),
        };

        // Verify encode_size matches actual encoded length
        assert_eq!(r1.encode_size(), r1.encode().len());
        assert_eq!(r2.encode_size(), r2.encode().len());
        assert_eq!(r3.encode_size(), r3.encode().len());
    }

    #[test]
    fn test_request_ord_same_variant() {
        // Test ordering within the same variant
        let commitment1 = Sha256::hash(b"test1");
        let commitment2 = Sha256::hash(b"test2");
        let block1 = Key::<D>::Block(commitment1);
        let block2 = Key::<D>::Block(commitment2);

        // Block ordering depends on commitment ordering
        if commitment1 < commitment2 {
            assert!(block1 < block2);
            assert!(block2 > block1);
        } else {
            assert!(block1 > block2);
            assert!(block2 < block1);
        }

        // Finalized ordering by height
        let fin1 = Key::<D>::Finalized {
            height: Height::new(100),
        };
        let fin2 = Key::<D>::Finalized {
            height: Height::new(200),
        };
        let fin3 = Key::<D>::Finalized {
            height: Height::new(200),
        };

        assert!(fin1 < fin2);
        assert!(fin2 > fin1);
        assert_eq!(fin2.cmp(&fin3), std::cmp::Ordering::Equal);

        // Notarized ordering by view
        let not1 = Key::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(50)),
        };
        let not2 = Key::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(150)),
        };
        let not3 = Key::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(150)),
        };

        assert!(not1 < not2);
        assert!(not2 > not1);
        assert_eq!(not2.cmp(&not3), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_request_ord_cross_variant() {
        let commitment = Sha256::hash(b"test");
        let block = Key::<D>::Block(commitment);
        let finalized = Key::<D>::Finalized {
            height: Height::new(100),
        };
        let notarized = Key::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(200)),
        };

        // Block < Finalized < Notarized
        assert!(block < finalized);
        assert!(block < notarized);
        assert!(finalized < notarized);

        assert!(finalized > block);
        assert!(notarized > block);
        assert!(notarized > finalized);

        // Test all combinations
        assert_eq!(block.cmp(&finalized), std::cmp::Ordering::Less);
        assert_eq!(block.cmp(&notarized), std::cmp::Ordering::Less);
        assert_eq!(finalized.cmp(&notarized), std::cmp::Ordering::Less);
        assert_eq!(finalized.cmp(&block), std::cmp::Ordering::Greater);
        assert_eq!(notarized.cmp(&block), std::cmp::Ordering::Greater);
        assert_eq!(notarized.cmp(&finalized), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_request_partial_ord() {
        let commitment1 = Sha256::hash(b"test1");
        let commitment2 = Sha256::hash(b"test2");
        let block1 = Key::<D>::Block(commitment1);
        let block2 = Key::<D>::Block(commitment2);
        let finalized = Key::<D>::Finalized {
            height: Height::new(100),
        };
        let notarized = Key::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(200)),
        };

        // PartialOrd should always return Some
        assert!(block1.partial_cmp(&block2).is_some());
        assert!(block1.partial_cmp(&finalized).is_some());
        assert!(finalized.partial_cmp(&notarized).is_some());

        // Verify consistency with Ord
        assert_eq!(
            block1.partial_cmp(&finalized),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            finalized.partial_cmp(&notarized),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            notarized.partial_cmp(&block1),
            Some(std::cmp::Ordering::Greater)
        );
    }

    #[test]
    fn test_request_ord_sorting() {
        let commitment1 = Sha256::hash(b"a");
        let commitment2 = Sha256::hash(b"b");
        let commitment3 = Sha256::hash(b"c");

        let requests = vec![
            Key::<D>::Notarized {
                round: Round::new(Epoch::new(333), View::new(300)),
            },
            Key::<D>::Block(commitment2),
            Key::<D>::Finalized {
                height: Height::new(200),
            },
            Key::<D>::Block(commitment1),
            Key::<D>::Notarized {
                round: Round::new(Epoch::new(333), View::new(250)),
            },
            Key::<D>::Finalized {
                height: Height::new(100),
            },
            Key::<D>::Block(commitment3),
        ];

        // Sort using BTreeSet (uses Ord)
        let sorted: Vec<_> = requests
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        // Verify order: all Blocks first (sorted by commitment), then Finalized (by height), then Notarized (by view)
        assert_eq!(sorted.len(), 7);

        // Check that all blocks come first
        assert!(matches!(sorted[0], Key::<D>::Block(_)));
        assert!(matches!(sorted[1], Key::<D>::Block(_)));
        assert!(matches!(sorted[2], Key::<D>::Block(_)));

        // Check that finalized come next
        assert_eq!(
            sorted[3],
            Key::<D>::Finalized {
                height: Height::new(100)
            }
        );
        assert_eq!(
            sorted[4],
            Key::<D>::Finalized {
                height: Height::new(200)
            }
        );

        // Check that notarized come last
        assert_eq!(
            sorted[5],
            Key::<D>::Notarized {
                round: Round::new(Epoch::new(333), View::new(250))
            }
        );
        assert_eq!(
            sorted[6],
            Key::<D>::Notarized {
                round: Round::new(Epoch::new(333), View::new(300))
            }
        );
    }

    #[test]
    fn test_request_ord_edge_cases() {
        // Test with extreme values
        let min_finalized = Key::<D>::Finalized {
            height: Height::new(0),
        };
        let max_finalized = Key::<D>::Finalized {
            height: Height::new(u64::MAX),
        };
        let min_notarized = Key::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(0)),
        };
        let max_notarized = Key::<D>::Notarized {
            round: Round::new(Epoch::new(333), View::new(u64::MAX)),
        };

        assert!(min_finalized < max_finalized);
        assert!(min_notarized < max_notarized);
        assert!(max_finalized < min_notarized);

        // Test self-comparison
        let commitment = Sha256::hash(b"self");
        let block = Key::<D>::Block(commitment);
        assert_eq!(block.cmp(&block), std::cmp::Ordering::Equal);
        assert_eq!(min_finalized.cmp(&min_finalized), std::cmp::Ordering::Equal);
        assert_eq!(max_notarized.cmp(&max_notarized), std::cmp::Ordering::Equal);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Key<D>>
        }
    }
}
