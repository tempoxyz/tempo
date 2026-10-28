//! A stream that yields the ancestors of a block while prefetching parents.

use crate::{Block, Heightable, types::Height};
use commonware_cryptography::{Digest, Digestible};
use commonware_runtime::{Clock, telemetry::metrics::histogram::Timed};
use futures::{
    FutureExt, Stream,
    future::{BoxFuture, OptionFuture},
};
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tracing::debug;

/// A stream of blocks used by application propose and verify calls.
///
/// Implementations must yield blocks from newest to oldest, with each block
/// after the first being the direct parent of the block yielded before it.
///
/// A clone starts at the source's logical position at the time of cloning and
/// can be consumed independently. Advancing or dropping one clone must not
/// advance, exhaust, or invalidate another. Each clone's [`peek`](Self::peek)
/// reports its own remaining view; clones need not become ready at the same
/// time.
pub trait Ancestry<B: Block>: Stream<Item = Arc<B>> + Clone + Send + Unpin + 'static {
    /// Peeks at the latest block in the stream without consuming it. Returns [None]
    /// if the stream does not yet have a block available or has been exhausted.
    fn peek(&self) -> Option<&B>;
}

/// Returns true when `child_height` is exactly the successor of `parent_height`.
#[inline]
pub(crate) fn has_contiguous_height(parent_height: Height, child_height: Height) -> bool {
    child_height.previous() == Some(parent_height)
}

// Adjacent heights do not establish ancestry, so the parent digest must also match the digest
// committed to by the child.
fn assert_contiguous_parent<B: Block>(child: &B, parent: &B) {
    assert!(
        has_contiguous_height(parent.height(), child.height()),
        "blocks must be contiguous in height"
    );
    assert_eq!(
        parent.digest(),
        child.parent(),
        "blocks must be contiguous in ancestry"
    );
}

// Checks blocks in the same newest-to-oldest order in which they will be yielded.
fn validate_ancestry<B: Block>(blocks: &VecDeque<Arc<B>>) {
    let mut blocks = blocks.iter();
    let Some(mut child) = blocks.next() else {
        return;
    };

    for parent in blocks {
        assert_contiguous_parent(child.as_ref(), parent.as_ref());
        child = parent;
    }
}

/// Creates an ancestry stream from a fixed sequence of blocks.
///
/// Blocks are yielded in iterator order and no parent fetching is performed. Blocks must be
/// ordered from newest to oldest and are validated before this function returns. This is useful
/// when the caller wants to bound the ancestry available to the application.
///
/// # Panics
///
/// Panics during construction if the blocks do not form a contiguous chain in iterator order.
pub fn from_iter<B: Block>(blocks: impl IntoIterator<Item = Arc<B>>) -> impl Ancestry<B> {
    let blocks: VecDeque<_> = blocks.into_iter().collect();
    validate_ancestry(&blocks);

    BoundedAncestry { blocks }
}

/// Prepends a fixed sequence of blocks to an existing ancestry stream.
///
/// Blocks are yielded in iterator order before the tail is polled. The prefix must be ordered from
/// newest to oldest. The tail remains responsible for satisfying [`Ancestry`]. This function
/// validates the prefix and its connection to the first block yielded by the tail.
///
/// # Panics
///
/// Panics during construction if the prefixed blocks do not form a contiguous chain. The returned
/// stream panics when the first tail block is peeked or polled if it is not the parent of the
/// oldest prefixed block.
pub fn with_prefix<B, S>(blocks: impl IntoIterator<Item = Arc<B>>, tail: S) -> impl Ancestry<B>
where
    B: Block,
    S: Ancestry<B>,
{
    let blocks: VecDeque<_> = blocks.into_iter().collect();
    validate_ancestry(&blocks);
    let boundary_child = blocks.back().cloned();

    PrefixedAncestry {
        blocks,
        tail,
        boundary_child,
    }
}

/// Type-erased ancestry stream that preserves cloneability.
pub struct BoxedAncestry<B: Block>(Box<dyn ErasedAncestry<B>>);

impl<B: Block> BoxedAncestry<B> {
    /// Erases the concrete ancestry stream type.
    pub fn new(ancestry: impl Ancestry<B>) -> Self {
        Self(Box::new(ancestry))
    }
}

impl<B: Block> Clone for BoxedAncestry<B> {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

impl<B: Block> Unpin for BoxedAncestry<B> {}

impl<B: Block> Ancestry<B> for BoxedAncestry<B> {
    fn peek(&self) -> Option<&B> {
        self.0.peek_erased()
    }
}

impl<B: Block> Stream for BoxedAncestry<B> {
    type Item = Arc<B>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut *self.0).poll_next(cx)
    }
}

trait ErasedAncestry<B: Block>: Stream<Item = Arc<B>> + Send + Unpin + 'static {
    fn peek_erased(&self) -> Option<&B>;

    fn clone_box(&self) -> Box<dyn ErasedAncestry<B>>;
}

impl<B, A> ErasedAncestry<B> for A
where
    B: Block,
    A: Ancestry<B>,
{
    fn peek_erased(&self) -> Option<&B> {
        Ancestry::peek(self)
    }

    fn clone_box(&self) -> Box<dyn ErasedAncestry<B>> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
struct PrefixedAncestry<B: Block, S> {
    blocks: VecDeque<Arc<B>>,
    tail: S,
    boundary_child: Option<Arc<B>>,
}

impl<B: Block, S> Unpin for PrefixedAncestry<B, S> {}

impl<B, S> Ancestry<B> for PrefixedAncestry<B, S>
where
    B: Block,
    S: Ancestry<B>,
{
    fn peek(&self) -> Option<&B> {
        // Prefix contiguity is established at construction, so these blocks can be exposed
        // directly.
        if let Some(block) = self.blocks.front() {
            return Some(block);
        }

        // The tail may be unavailable during construction, so validate its first visible block
        // before exposing it.
        let parent = self.tail.peek()?;
        if let Some(child) = &self.boundary_child {
            assert_contiguous_parent(child.as_ref(), parent);
        }
        Some(parent)
    }
}

impl<B, S> Stream for PrefixedAncestry<B, S>
where
    B: Block,
    S: Ancestry<B>,
{
    type Item = Arc<B>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Keep the boundary child until a tail block is yielded and can be validated against it.
        if let Some(block) = self.blocks.pop_front() {
            return Poll::Ready(Some(block));
        }

        // Polling can reach the tail without a preceding peek, so validate the same boundary
        // before yielding it.
        match Pin::new(&mut self.tail).poll_next(cx) {
            Poll::Ready(Some(parent)) => {
                if let Some(child) = self.boundary_child.take() {
                    assert_contiguous_parent(child.as_ref(), parent.as_ref());
                }
                Poll::Ready(Some(parent))
            }
            outcome => outcome,
        }
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
    /// Returns `None` only when the provider can no longer obtain the parent from any source.
    /// Dropping the returned future cancels the subscription.
    ///
    /// The child block can carry variant-specific context needed to retrieve its parent.
    fn subscribe_parent(
        &self,
        block: &Self::Block,
    ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static;
}

// Expected parent height and digest for a pending fetch.
struct ExpectedParent<D>(Height, D);

// Pending parent fetch that returns only a validated parent.
type PendingFetch<B> = BoxFuture<'static, Option<Arc<B>>>;

impl<D: Digest> ExpectedParent<D> {
    fn from_child<B: Block<Digest = D>>(child: &B) -> Self {
        Self(
            child.height().previous().expect("child must have parent"),
            child.parent(),
        )
    }

    fn matches<B: Block<Digest = D>>(self, parent: &B) -> bool {
        let Self(parent_height, parent_digest) = self;
        if parent.height() != parent_height {
            debug!(
                expected = %parent_height,
                actual = %parent.height(),
                "ending ancestry stream: fetched parent has non-contiguous height"
            );
            return false;
        }
        if parent.digest() != parent_digest {
            debug!(
                expected = ?parent_digest,
                actual = ?parent.digest(),
                "ending ancestry stream: fetched parent has non-contiguous ancestry"
            );
            return false;
        }
        true
    }
}

// Builds a parent fetch that records latency when a parent arrives. The fetch
// returns only a parent with the expected height and digest.
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
            let parent = parent?;
            timer.observe(clock.as_ref());
            expected.matches(parent.as_ref()).then_some(parent)
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
    pending_child: Option<Arc<M::Block>>,
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
            pending_child: None,
            pending: None.into(),
        }
    }

    /// Peeks at the latest block in the stream without consuming it. Returns [None]
    /// if the stream does not yet have a block available or has been exhausted.
    pub fn peek(&self) -> Option<&M::Block> {
        self.buffered.last().map(Arc::as_ref)
    }
}

impl<M, C> Clone for AncestorStream<M, C>
where
    M: BlockProvider + Clone,
    C: Clock,
{
    fn clone(&self) -> Self {
        let pending_child = self.pending_child.clone();
        let marshal = self.marshal.clone();
        let fetch_duration = self.fetch_duration.clone();
        let clock = self.clock.clone();
        let pending = pending_child
            .as_ref()
            .map(|child| timed_parent_fetch(&clock, &marshal, child, &fetch_duration))
            .into();

        Self {
            buffered: self.buffered.clone(),
            marshal,
            fetch_duration,
            clock,
            pending_child,
            pending,
        }
    }
}

impl<M, C> Ancestry<M::Block> for AncestorStream<M, C>
where
    M: BlockProvider + Clone,
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
                *this.pending_child = Some(block.clone());
                *this.pending.as_mut() = Some(future).into();

                // Explicitly poll the next future to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                match this.pending.as_mut().poll(cx) {
                    Poll::Ready(Some(Some(parent))) => {
                        this.buffered.push(parent);
                        *this.pending_child = None;
                    }
                    Poll::Ready(Some(None)) => {
                        *this.pending.as_mut() = None.into();
                        *this.pending_child = None;
                    }
                    Poll::Ready(None) => {
                        *this.pending_child = None;
                    }
                    Poll::Pending => {}
                }
            } else if !should_walk_parent {
                // No more parents to fetch; Finish the stream.
                *this.pending.as_mut() = None.into();
                *this.pending_child = None;
            }

            return Poll::Ready(Some(block));
        }

        match this.pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) | Poll::Ready(Some(None)) => {
                *this.pending.as_mut() = None.into();
                *this.pending_child = None;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Some(block))) => {
                let height = block.height();
                let should_walk_parent = height > END_BOUND;
                if should_walk_parent {
                    let future =
                        timed_parent_fetch(this.clock, this.marshal, &block, this.fetch_duration);
                    *this.pending_child = Some(block.clone());
                    *this.pending.as_mut() = Some(future).into();

                    // Explicitly poll the next future to kick off the fetch. If it's already ready,
                    // buffer it for the next poll.
                    match this.pending.as_mut().poll(cx) {
                        Poll::Ready(Some(Some(parent))) => {
                            this.buffered.push(parent);
                            *this.pending_child = None;
                        }
                        Poll::Ready(Some(None)) => {
                            *this.pending.as_mut() = None.into();
                            *this.pending_child = None;
                        }
                        Poll::Ready(None) => {
                            *this.pending_child = None;
                        }
                        Poll::Pending => {}
                    }
                } else {
                    // No more parents to fetch; Finish the stream.
                    *this.pending.as_mut() = None.into();
                    *this.pending_child = None;
                }

                Poll::Ready(Some(block))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::marshal::mocks::block::EmptyBlock;
    use commonware_cryptography::{Digest, Sha256, sha256::Digest as Sha256Digest};
    use commonware_runtime::{
        Runner as _, Supervisor as _, deterministic,
        telemetry::metrics::{
            MetricsExt as _,
            histogram::{Buckets, Timed},
        },
    };
    use commonware_utils::{channel::oneshot, sync::Mutex};
    use futures::StreamExt;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    type TestBlock = EmptyBlock<Sha256>;

    #[derive(Default, Clone)]
    struct MockProvider(Vec<TestBlock>);
    impl BlockProvider for MockProvider {
        type Block = TestBlock;

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

    type ParentSubscription = oneshot::Sender<Arc<TestBlock>>;

    #[derive(Default, Clone)]
    struct PendingProvider {
        subscriptions: Arc<Mutex<Vec<ParentSubscription>>>,
    }

    impl PendingProvider {
        fn subscription_count(&self) -> usize {
            self.subscriptions.lock().len()
        }

        fn complete_all(&self, parent: Arc<TestBlock>) {
            let subscriptions = std::mem::take(&mut *self.subscriptions.lock());
            for subscription in subscriptions {
                assert!(subscription.send(parent.clone()).is_ok());
            }
        }
    }

    impl BlockProvider for PendingProvider {
        type Block = TestBlock;

        fn subscribe_parent(
            &self,
            _block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            let (subscription, parent) = oneshot::channel();
            self.subscriptions.lock().push(subscription);
            parent.map(Result::ok)
        }
    }

    #[derive(Clone)]
    struct PendingThenWrongProvider {
        state: Arc<Mutex<(usize, Option<ParentSubscription>)>>,
        wrong_parent: TestBlock,
    }

    impl PendingThenWrongProvider {
        fn new(wrong_parent: TestBlock) -> Self {
            Self {
                state: Arc::new(Mutex::new((0, None))),
                wrong_parent,
            }
        }

        fn complete_first(&self, parent: Arc<TestBlock>) {
            let subscription = self
                .state
                .lock()
                .1
                .take()
                .expect("first parent subscription missing");
            assert!(subscription.send(parent).is_ok());
        }
    }

    impl BlockProvider for PendingThenWrongProvider {
        type Block = TestBlock;

        fn subscribe_parent(
            &self,
            _block: &Self::Block,
        ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
            let mut state = self.state.lock();
            let call = state.0;
            state.0 += 1;
            if call == 0 {
                let (subscription, parent) = oneshot::channel();
                state.1 = Some(subscription);
                parent.map(Result::ok).boxed()
            } else {
                std::future::ready(Some(Arc::new(self.wrong_parent.clone()))).boxed()
            }
        }
    }

    #[derive(Clone)]
    struct WrongParentProvider(TestBlock);
    impl BlockProvider for WrongParentProvider {
        type Block = TestBlock;

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
                    TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1),
                    TestBlock::new(Sha256Digest::EMPTY, Height::new(3), 3),
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
                    TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1),
                    TestBlock::new(Sha256Digest::EMPTY, Height::new(2), 2),
                ],
            );
        });
    }

    #[test]
    fn test_ends_on_non_contiguous_fetched_parent_height() {
        deterministic::Runner::default().start(|context| async move {
            let parent = TestBlock::new(Sha256Digest::EMPTY, Height::zero(), 0);
            let child = TestBlock::new(parent.digest(), Height::new(3), 3);
            let mut stream = stream(&context, MockProvider(vec![parent]), [child.clone()]);

            assert_eq!(stream.next().await.as_deref(), Some(&child));
            assert_eq!(stream.next().await, None);
        });
    }

    #[test]
    fn test_ends_on_non_contiguous_fetched_parent_digest() {
        deterministic::Runner::default().start(|context| async move {
            let expected_parent = TestBlock::new(Sha256Digest::EMPTY, Height::zero(), 0);
            let fetched_parent = TestBlock::new(Sha256Digest::EMPTY, Height::zero(), 1);
            let child = TestBlock::new(expected_parent.digest(), Height::new(1), 2);
            let mut stream = stream(
                &context,
                WrongParentProvider(fetched_parent),
                [child.clone()],
            );

            assert_eq!(stream.next().await.as_deref(), Some(&child));
            assert_eq!(stream.next().await, None);
        });
    }

    #[test]
    fn test_ends_on_delayed_non_contiguous_fetched_parent() {
        deterministic::Runner::default().start(|context| async move {
            let expected_parent = TestBlock::new(Sha256Digest::EMPTY, Height::zero(), 0);
            let fetched_parent = TestBlock::new(Sha256Digest::EMPTY, Height::zero(), 1);
            let child = TestBlock::new(expected_parent.digest(), Height::new(1), 2);
            let provider = PendingProvider::default();
            let mut stream = stream(&context, provider.clone(), [child.clone()]);

            assert_eq!(stream.next().await.as_deref(), Some(&child));
            assert_eq!(provider.subscription_count(), 1);
            provider.complete_all(Arc::new(fetched_parent));
            assert_eq!(stream.next().await, None);
        });
    }

    #[test]
    fn test_ends_on_immediate_bad_grandparent_after_delayed_parent() {
        deterministic::Runner::default().start(|context| async move {
            let expected_grandparent = TestBlock::new(Sha256Digest::EMPTY, Height::zero(), 0);
            let wrong_grandparent = TestBlock::new(Sha256Digest::EMPTY, Height::zero(), 1);
            let parent = TestBlock::new(expected_grandparent.digest(), Height::new(1), 2);
            let child = TestBlock::new(parent.digest(), Height::new(2), 3);
            let provider = PendingThenWrongProvider::new(wrong_grandparent);
            let mut stream = stream(&context, provider.clone(), [child.clone()]);

            assert_eq!(stream.next().await.as_deref(), Some(&child));
            provider.complete_first(Arc::new(parent.clone()));
            assert_eq!(stream.next().await.as_deref(), Some(&parent));
            assert_eq!(stream.next().await, None);
        });
    }

    #[test]
    fn test_peek_available_through_ancestry_trait() {
        deterministic::Runner::default().start(|context| async move {
            fn peek_height(ancestry: impl Ancestry<TestBlock>) -> Option<Height> {
                ancestry.peek().map(Heightable::height)
            }

            let block = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
            let stream = stream(&context, MockProvider::default(), [block.clone()]);
            assert_eq!(peek_height(stream), Some(block.height()));
        });
    }

    #[test]
    fn test_from_iter_available_through_ancestry_trait() {
        fn peek_height(ancestry: impl Ancestry<TestBlock>) -> Option<Height> {
            ancestry.peek().map(Heightable::height)
        }

        let block = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
        let ancestry = from_iter([Arc::new(block.clone())]);

        assert_eq!(peek_height(ancestry), Some(block.height()));
    }

    #[test]
    fn test_has_contiguous_height() {
        assert!(has_contiguous_height(Height::new(6), Height::new(7)));
        assert!(!has_contiguous_height(Height::new(6), Height::new(8)));
        assert!(!has_contiguous_height(
            Height::new(u64::MAX),
            Height::zero()
        ));
    }

    #[test]
    #[should_panic = "blocks must be contiguous in height"]
    fn test_from_iter_panics_on_non_contiguous_height() {
        let parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
        let child = TestBlock::new(parent.digest(), Height::new(3), 3);

        let _ = from_iter([Arc::new(child), Arc::new(parent)]);
    }

    #[test]
    #[should_panic = "blocks must be contiguous in ancestry"]
    fn test_from_iter_panics_on_non_contiguous_ancestry() {
        let expected_parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
        let wrong_parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 2);
        let child = TestBlock::new(expected_parent.digest(), Height::new(2), 3);

        let _ = from_iter([Arc::new(child), Arc::new(wrong_parent)]);
    }

    #[test]
    #[should_panic = "blocks must be contiguous in height"]
    fn test_from_iter_panics_on_reordered_chain() {
        let parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
        let child = TestBlock::new(parent.digest(), Height::new(2), 2);
        let grandchild = TestBlock::new(child.digest(), Height::new(3), 3);

        let _ = from_iter([Arc::new(grandchild), Arc::new(parent), Arc::new(child)]);
    }

    #[test]
    fn test_from_iter_yields_blocks_in_order_and_peeks_next() {
        deterministic::Runner::default().start(|_| async move {
            let parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
            let child = TestBlock::new(parent.digest(), Height::new(2), 2);
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
    fn test_with_prefix_peeks_tail_when_prefix_empty() {
        deterministic::Runner::default().start(|_| async move {
            let block = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
            let mut ancestry = with_prefix([], from_iter([Arc::new(block.clone())]));

            assert_eq!(ancestry.peek(), Some(&block));
            assert_eq!(ancestry.next().await.as_deref(), Some(&block));
            assert_eq!(ancestry.peek(), None);
        });
    }

    #[test]
    fn test_with_prefix_peeks_tail_after_prefix_consumed() {
        deterministic::Runner::default().start(|_| async move {
            let parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
            let child = TestBlock::new(parent.digest(), Height::new(2), 2);
            let mut ancestry = with_prefix(
                [Arc::new(child.clone())],
                from_iter([Arc::new(parent.clone())]),
            );

            assert_eq!(ancestry.peek(), Some(&child));
            assert_eq!(ancestry.next().await.as_deref(), Some(&child));
            assert_eq!(ancestry.peek(), Some(&parent));
            assert_eq!(ancestry.next().await.as_deref(), Some(&parent));
            assert_eq!(ancestry.peek(), None);
        });
    }

    #[test]
    fn test_with_prefix_clones_validate_boundary_independently() {
        deterministic::Runner::default().start(|_| async move {
            let expected_parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
            let wrong_parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 2);
            let child = TestBlock::new(expected_parent.digest(), Height::new(2), 3);
            let mut ancestry = with_prefix(
                [Arc::new(child.clone())],
                from_iter([Arc::new(wrong_parent)]),
            );
            let mut cloned = ancestry.clone();

            assert_eq!(ancestry.next().await.as_deref(), Some(&child));
            assert_eq!(cloned.next().await.as_deref(), Some(&child));

            // Each clone owns its unresolved seam check.
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let _ = ancestry.peek();
                }))
                .is_err()
            );
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let _ = cloned.peek();
                }))
                .is_err()
            );
        });
    }

    #[test]
    #[should_panic = "blocks must be contiguous in height"]
    fn test_with_prefix_panics_on_non_contiguous_prefix() {
        let parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
        let child = TestBlock::new(parent.digest(), Height::new(3), 3);

        let _ = with_prefix(
            [Arc::new(child), Arc::new(parent)],
            from_iter(Vec::<Arc<TestBlock>>::new()),
        );
    }

    #[test]
    #[should_panic = "blocks must be contiguous in height"]
    fn test_with_prefix_panics_when_pending_tail_breaks_height() {
        deterministic::Runner::default().start(|context| async move {
            let parent = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
            let consumed = TestBlock::new(parent.digest(), Height::new(2), 2);
            let provider = PendingProvider::default();
            let mut tail = stream(&context, provider.clone(), [consumed.clone()]);
            assert_eq!(tail.next().await.as_deref(), Some(&consumed));
            assert_eq!(tail.peek(), None);
            assert_eq!(provider.subscription_count(), 1);

            let child = TestBlock::new(consumed.digest(), Height::new(3), 3);
            let mut ancestry = with_prefix([Arc::new(child.clone())], tail);
            assert_eq!(ancestry.next().await.as_deref(), Some(&child));

            // A pending tail poll must not discard the unresolved seam check.
            assert!(ancestry.next().now_or_never().is_none());

            provider.complete_all(Arc::new(parent));
            let _ = ancestry.next().await;
        });
    }

    #[test]
    fn test_yields_genesis_and_stops() {
        deterministic::Runner::default().start(|context| async move {
            let genesis = TestBlock::new(Sha256Digest::EMPTY, Height::zero(), 0);
            let child = TestBlock::new(genesis.digest(), Height::new(1), 1);

            let provider = MockProvider(vec![genesis.clone()]);
            let stream = stream(&context, provider, [child.clone()]);

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![Arc::new(child), Arc::new(genesis)]);
        });
    }

    #[test]
    fn test_clone_preserves_pending_parent_fetch() {
        deterministic::Runner::default().start(|context| async move {
            let parent = Arc::new(TestBlock::new(Sha256Digest::EMPTY, Height::zero(), 0));
            let child = TestBlock::new(parent.digest(), Height::new(1), 1);
            let provider = PendingProvider::default();
            let mut stream = stream(&context, provider.clone(), [child.clone()]);

            assert_eq!(stream.next().await.as_deref(), Some(&child));
            assert_eq!(provider.subscription_count(), 1);

            let mut cloned = stream.clone();
            assert_eq!(provider.subscription_count(), 2);
            provider.complete_all(parent.clone());

            assert_eq!(stream.next().await, Some(parent.clone()));
            assert_eq!(cloned.next().await, Some(parent.clone()));
            assert_eq!(stream.next().await, None);
            assert_eq!(cloned.next().await, None);
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
            let block1 = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = TestBlock::new(block1.digest(), Height::new(2), 2);
            let block3 = TestBlock::new(block2.digest(), Height::new(3), 3);

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
            let block1 = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = TestBlock::new(block1.digest(), Height::new(2), 2);
            let block3 = TestBlock::new(block2.digest(), Height::new(3), 3);

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
            let block1 = TestBlock::new(Sha256Digest::EMPTY, Height::new(1), 1);
            let block2 = TestBlock::new(block1.digest(), Height::new(2), 2);
            let block3 = TestBlock::new(block2.digest(), Height::new(3), 3);

            let provider = MockProvider(vec![block1]);
            let stream = stream(&context, provider, [block3.clone()]);

            let results = stream.collect::<Vec<_>>().await;
            assert_eq!(results, vec![Arc::new(block3)]);
        });
    }
}
