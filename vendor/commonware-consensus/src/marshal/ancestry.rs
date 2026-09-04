//! A stream that yields the ancestors of a block while prefetching parents.

use crate::{types::Height, Block, Heightable};
use commonware_cryptography::{Digest, Digestible};
use commonware_runtime::{telemetry::metrics::histogram::Timed, Clock};
use futures::{
    future::{BoxFuture, OptionFuture},
    FutureExt, Stream,
};
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// A stream of blocks used by application propose and verify calls.
pub trait Ancestry<B: Block>: Stream<Item = Arc<B>> + Send + Unpin + 'static {
    /// Peeks at the latest block in the stream without consuming it. Returns [None]
    /// if the stream does not yet have a block available or has been exhausted.
    fn peek(&self) -> Option<&B>;
}

/// Creates an ancestry stream from a fixed sequence of blocks.
///
/// Blocks are yielded in iterator order and no parent fetching is performed. This is useful when
/// the caller wants to bound the ancestry available to the application.
pub fn from_iter<B>(blocks: impl IntoIterator<Item = Arc<B>>) -> impl Ancestry<B>
where
    B: Block,
{
    BoundedAncestry {
        blocks: blocks.into_iter().collect(),
    }
}

struct BoundedAncestry<B: Block> {
    blocks: VecDeque<Arc<B>>,
}

impl<B: Block> Unpin for BoundedAncestry<B> {}

impl<B: Block> Ancestry<B> for BoundedAncestry<B> {
    fn peek(&self) -> Option<&B> {
        self.blocks.front().map(Arc::as_ref)
    }
}

impl<B: Block> Stream for BoundedAncestry<B> {
    type Item = Arc<B>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.blocks.pop_front())
    }
}

/// An interface for providing parent blocks.
pub trait BlockProvider: Send + 'static {
    /// The block type the provider walks.
    type Block: Block;

    /// Subscribe to the parent of a known block.
    ///
    /// If the parent is found available locally, the parent will be returned immediately.
    ///
    /// If the parent is not available locally, the subscription will be registered and the caller
    /// will be notified when the parent is available. If the parent is not finalized, it's possible
    /// that it may never become available.
    ///
    /// Returns `None` when the subscription is canceled or the provider can no longer deliver
    /// the parent.
    ///
    /// The child block can carry variant-specific context needed to retrieve its parent.
    fn subscribe_parent(
        &self,
        block: &Self::Block,
    ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static;
}

// Expected parent height and digest for a pending fetch.
struct ExpectedParent<D>(Height, D);

// Pending parent fetch paired with the relationship it must satisfy.
type PendingFetch<B> =
    BoxFuture<'static, Option<(ExpectedParent<<B as Digestible>::Digest>, Arc<B>)>>;

impl<D: Digest> ExpectedParent<D> {
    fn from_child<B: Block<Digest = D>>(child: &B) -> Self {
        Self(
            child.height().previous().expect("child must have parent"),
            child.parent(),
        )
    }

    fn assert_matches<B: Block<Digest = D>>(self, parent: &B) {
        let Self(parent_height, parent_digest) = self;
        assert_eq!(
            parent.height(),
            parent_height,
            "fetched parent must be contiguous in height"
        );
        assert_eq!(
            parent.digest(),
            parent_digest,
            "fetched parent must be contiguous in ancestry"
        );
    }
}

// Builds a pending parent fetch that records successful fetch latency and carries the
// expected relationship for validation when the parent is delivered.
fn timed_parent_fetch<C, M>(
    clock: &Arc<C>,
    marshal: &M,
    child: &M::Block,
    fetch_duration: &Timed,
) -> PendingFetch<M::Block>
where
    C: Clock,
    M: BlockProvider,
{
    let expected = ExpectedParent::from_child(child);
    let timer = fetch_duration.timer(clock.as_ref());
    let clock = clock.clone();
    marshal
        .subscribe_parent(child)
        .map(move |parent| {
            parent.map(|parent| {
                timer.observe(clock.as_ref());
                (expected, parent)
            })
        })
        .boxed()
}

/// Yields the ancestors of a block while prefetching parents, including the
/// height-zero genesis block if it is available.
#[pin_project]
pub struct AncestorStream<M: BlockProvider, C: Clock> {
    buffered: Vec<Arc<M::Block>>,
    marshal: M,
    fetch_duration: Timed,
    clock: Arc<C>,
    #[pin]
    pending: OptionFuture<PendingFetch<M::Block>>,
}

impl<M: BlockProvider, C: Clock> AncestorStream<M, C> {
    /// Creates a new [AncestorStream] starting from the given ancestry.
    ///
    /// # Panics
    ///
    /// Panics if the initial blocks are not contiguous.
    pub(crate) fn new(
        clock: Arc<C>,
        marshal: M,
        initial: impl IntoIterator<Item = Arc<M::Block>>,
        fetch_duration: Timed,
    ) -> Self {
        let mut buffered = initial.into_iter().collect::<Vec<_>>();
        buffered.sort_by_key(|block| block.height());

        // Check that the initial blocks are contiguous in height.
        buffered.windows(2).for_each(|window| {
            assert_eq!(
                window[0].height().next(),
                window[1].height(),
                "initial blocks must be contiguous in height"
            );
            assert_eq!(
                window[0].digest(),
                window[1].parent(),
                "initial blocks must be contiguous in ancestry"
            );
        });

        Self {
            marshal,
            buffered,
            fetch_duration,
            clock,
            pending: None.into(),
        }
    }

    /// Peeks at the latest block in the stream without consuming it. Returns [None]
    /// if the stream does not yet have a block available or has been exhausted.
    pub fn peek(&self) -> Option<&M::Block> {
        self.buffered.last().map(Arc::as_ref)
    }
}

impl<M, C> Ancestry<M::Block> for AncestorStream<M, C>
where
    M: BlockProvider,
    C: Clock,
{
    fn peek(&self) -> Option<&M::Block> {
        Self::peek(self)
    }
}

impl<M, C> Stream for AncestorStream<M, C>
where
    M: BlockProvider,
    C: Clock,
{
    type Item = Arc<M::Block>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        const END_BOUND: Height = Height::zero();

        let mut this = self.project();

        // If a result has been buffered, return it and queue the parent fetch if needed.
        if let Some(block) = this.buffered.pop() {
            let height = block.height();
            let should_walk_parent = height > END_BOUND;
            let end_of_buffered = this.buffered.is_empty();
            if should_walk_parent && end_of_buffered {
                let future =
                    timed_parent_fetch(this.clock, this.marshal, &block, this.fetch_duration);
                *this.pending.as_mut() = Some(future).into();

                // Explicitly poll the next future to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                match this.pending.as_mut().poll(cx) {
                    Poll::Ready(Some(Some((expected, parent)))) => {
                        expected.assert_matches(parent.as_ref());
                        this.buffered.push(parent);
                    }
                    Poll::Ready(Some(None)) => {
                        *this.pending.as_mut() = None.into();
                    }
                    Poll::Ready(None) | Poll::Pending => {}
                }
            } else if !should_walk_parent {
                // No more parents to fetch; Finish the stream.
                *this.pending.as_mut() = None.into();
            }

            return Poll::Ready(Some(block));
        }

        match this.pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) | Poll::Ready(Some(None)) => {
                *this.pending.as_mut() = None.into();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Some((expected, block)))) => {
                expected.assert_matches(block.as_ref());
                let height = block.height();
                let should_walk_parent = height > END_BOUND;
                if should_walk_parent {
                    let future =
                        timed_parent_fetch(this.clock, this.marshal, &block, this.fetch_duration);
                    *this.pending.as_mut() = Some(future).into();

                    // Explicitly poll the next future to kick off the fetch. If it's already ready,
                    // buffer it for the next poll.
                    match this.pending.as_mut().poll(cx) {
                        Poll::Ready(Some(Some((expected, parent)))) => {
                            expected.assert_matches(parent.as_ref());
                            this.buffered.push(parent);
                        }
                        Poll::Ready(Some(None)) => {
                            *this.pending.as_mut() = None.into();
                        }
                        Poll::Ready(None) | Poll::Pending => {}
                    }
                } else {
                    // No more parents to fetch; Finish the stream.
                    *this.pending.as_mut() = None.into();
                }

                Poll::Ready(Some(block))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::Block;
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Digest, Sha256};
    use commonware_runtime::{
        deterministic,
        telemetry::metrics::{
            histogram::{Buckets, Timed},
            MetricsExt as _,
        },
        Runner as _, Supervisor as _,
    };
    use futures::StreamExt;

    #[derive(Default, Clone)]
    struct MockProvider(Vec<Block<Sha256Digest, ()>>);
    impl BlockProvider for MockProvider {
        type Block = Block<Sha256Digest, ()>;

        fn subscribe_parent(
            &self,
            block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            let parent = block.parent;
            std::future::ready(
                self.0
                    .iter()
                    .find(|b| b.digest() == parent)
                    .cloned()
                    .map(Arc::new),
            )
        }
    }

    #[derive(Clone)]
    struct WrongParentProvider(Block<Sha256Digest, ()>);
    impl BlockProvider for WrongParentProvider {
        type Block = Block<Sha256Digest, ()>;

        fn subscribe_parent(
            &self,
            _block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            std::future::ready(Some(Arc::new(self.0.clone())))
        }
    }

    fn timed(context: &deterministic::Context) -> Timed {
        Timed::new(context.histogram(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the ancestry stream, in seconds",
            Buckets::LOCAL,
        ))
    }

    fn stream<M>(
        context: &deterministic::Context,
        marshal: M,
        initial: impl IntoIterator<Item = M::Block>,
    ) -> AncestorStream<M, deterministic::Context>
    where
        M: BlockProvider,
    {
        let stream_context = context.child("ancestor_stream");
        let fetch_duration = timed(&stream_context);
        AncestorStream::new(
            Arc::new(stream_context),
            marshal,
            initial.into_iter().map(Arc::new),
            fetch_duration,
        )
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in height"]
    fn test_panics_on_non_contiguous_initial_blocks_height() {
        deterministic::Runner::default().start(|context| async move {
            stream(
                &context,
                MockProvider::default(),
                vec![
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1),
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(3), 3),
                ],
            );
        });
    }

    #[test]
    #[should_panic = "initial blocks must be contiguous in ancestry"]
    fn test_panics_on_non_contiguous_initial_blocks_digest() {
        deterministic::Runner::default().start(|context| async move {
            stream(
                &context,
                MockProvider::default(),
                vec![
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1),
                    Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(2), 2),
                ],
            );
        });
    }

    #[test]
    #[should_panic = "fetched parent must be contiguous in height"]
    fn test_panics_on_non_contiguous_fetched_parent_height() {
        deterministic::Runner::default().start(|context| async move {
            let parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 0);
            let child = Block::new::<Sha256>((), parent.digest(), Height::new(3), 3);
            let stream = stream(&context, MockProvider(vec![parent]), [child]);
            futures::pin_mut!(stream);

            let waker = futures::task::noop_waker_ref();
            let mut cx = std::task::Context::from_waker(waker);
            let _ = futures::Stream::poll_next(stream.as_mut(), &mut cx);
        });
    }

    #[test]
    #[should_panic = "fetched parent must be contiguous in ancestry"]
    fn test_panics_on_non_contiguous_fetched_parent_digest() {
        deterministic::Runner::default().start(|context| async move {
            let expected_parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 0);
            let fetched_parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 1);
            let child = Block::new::<Sha256>((), expected_parent.digest(), Height::new(1), 2);
            let stream = stream(&context, WrongParentProvider(fetched_parent), [child]);
            futures::pin_mut!(stream);

            let waker = futures::task::noop_waker_ref();
            let mut cx = std::task::Context::from_waker(waker);
            let _ = futures::Stream::poll_next(stream.as_mut(), &mut cx);
        });
    }

    #[test]
    fn test_peek_available_through_ancestry_trait() {
        deterministic::Runner::default().start(|context| async move {
            fn peek_height(ancestry: impl Ancestry<Block<Sha256Digest, ()>>) -> Option<Height> {
                ancestry.peek().map(Heightable::height)
            }

            let block = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let stream = stream(&context, MockProvider::default(), [block.clone()]);
            assert_eq!(peek_height(stream), Some(block.height()));
        });
    }

    #[test]
    fn test_from_iter_available_through_ancestry_trait() {
        fn peek_height(ancestry: impl Ancestry<Block<Sha256Digest, ()>>) -> Option<Height> {
            ancestry.peek().map(Heightable::height)
        }

        let block = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
        let ancestry = from_iter([Arc::new(block.clone())]);

        assert_eq!(peek_height(ancestry), Some(block.height()));
    }

    #[test]
    fn test_from_iter_yields_blocks_in_order_and_peeks_next() {
        deterministic::Runner::default().start(|_| async move {
            let parent = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let child = Block::new::<Sha256>((), parent.digest(), Height::new(2), 2);
            let mut ancestry = from_iter([Arc::new(child.clone()), Arc::new(parent.clone())]);

            assert_eq!(ancestry.peek(), Some(&child));
            assert_eq!(ancestry.next().await.as_deref(), Some(&child));
            assert_eq!(ancestry.peek(), Some(&parent));
            assert_eq!(ancestry.next().await.as_deref(), Some(&parent));
            assert_eq!(ancestry.peek(), None);
            assert_eq!(ancestry.next().await, None);
        });
    }

    #[test]
    fn test_yields_genesis_and_stops() {
        deterministic::Runner::default().start(|context| async move {
            let genesis = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::zero(), 0);
            let child = Block::new::<Sha256>((), genesis.digest(), Height::new(1), 1);

            let provider = MockProvider(vec![genesis.clone()]);
            let stream = stream(&context, provider, [child.clone()]);

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![Arc::new(child), Arc::new(genesis)]);
        });
    }

    #[test]
    fn test_empty_yields_none() {
        deterministic::Runner::default().start(|context| async move {
            let mut stream: AncestorStream<MockProvider, deterministic::Context> =
                stream(&context, MockProvider::default(), vec![]);
            assert_eq!(stream.next().await, None);
        });
    }

    #[test]
    fn test_yields_ancestors() {
        deterministic::Runner::default().start(|context| async move {
            let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
            let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

            let provider = MockProvider(vec![block1.clone(), block2.clone()]);
            let stream = stream(&context, provider, [block3.clone()]);

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(
                results,
                vec![Arc::new(block3), Arc::new(block2), Arc::new(block1)]
            );
        });
    }

    #[test]
    fn test_yields_ancestors_all_buffered() {
        deterministic::Runner::default().start(|context| async move {
            let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
            let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

            let provider = MockProvider(vec![]);
            let stream = stream(
                &context,
                provider,
                [block1.clone(), block2.clone(), block3.clone()],
            );

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(
                results,
                vec![Arc::new(block3), Arc::new(block2), Arc::new(block1)]
            );
        });
    }

    #[test]
    fn test_missing_parent_ends_stream() {
        deterministic::Runner::default().start(|context| async move {
            let block1 = Block::new::<Sha256>((), Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = Block::new::<Sha256>((), block1.digest(), Height::new(2), 2);
            let block3 = Block::new::<Sha256>((), block2.digest(), Height::new(3), 3);

            let provider = MockProvider(vec![block1]);
            let stream = stream(&context, provider, [block3.clone()]);

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![Arc::new(block3)]);
        });
    }
}
