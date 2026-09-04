use super::Variant;
use crate::types::Height;
use commonware_utils::{futures::OptionFuture, Acknowledgement};
use futures::FutureExt;
use pin_project::pin_project;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// A pending acknowledgement from the application for a block at the contained height/commitment.
#[pin_project]
pub(super) struct PendingAck<V: Variant, A: Acknowledgement> {
    pub(super) height: Height,
    pub(super) commitment: V::Commitment,
    #[pin]
    pub(super) receiver: A::Waiter,
}

impl<V: Variant, A: Acknowledgement> Future for PendingAck<V, A> {
    type Output = <A::Waiter as Future>::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().receiver.poll(cx)
    }
}

/// Tracks in-flight application acknowledgements with FIFO semantics.
pub(super) struct PendingAcks<V: Variant, A: Acknowledgement> {
    current: OptionFuture<PendingAck<V, A>>,
    queue: VecDeque<PendingAck<V, A>>,
    max: usize,
}

impl<V: Variant, A: Acknowledgement> PendingAcks<V, A> {
    /// Creates a new pending-ack tracker with a maximum in-flight capacity.
    pub(super) fn new(max: usize) -> Self {
        Self {
            current: None.into(),
            queue: VecDeque::with_capacity(max),
            max,
        }
    }

    /// Drops the current ack and all queued acks.
    pub(super) fn clear(&mut self) {
        self.current = None.into();
        self.queue.clear();
    }

    /// Returns the currently armed ack future (if any) for `select_loop!`.
    pub(super) const fn current(&mut self) -> &mut OptionFuture<PendingAck<V, A>> {
        &mut self.current
    }

    /// Returns whether we can dispatch another block without exceeding capacity.
    pub(super) fn has_capacity(&self) -> bool {
        let reserved = usize::from(self.current.is_some());
        self.queue.len() < self.max - reserved
    }

    /// Returns the next height to dispatch while preserving sequential order.
    pub(super) fn next_dispatch_height(&self, start_height: Height) -> Height {
        self.queue
            .back()
            .map(|ack| ack.height.next())
            .or_else(|| self.current.as_ref().map(|ack| ack.height.next()))
            .unwrap_or(start_height)
    }

    /// Enqueues a newly dispatched ack, arming it immediately when idle.
    pub(super) fn enqueue(&mut self, ack: PendingAck<V, A>) {
        if self.current.is_none() {
            self.current.replace(ack);
            return;
        }
        self.queue.push_back(ack);
    }

    /// Returns metadata for a completed current ack and arms the next queued ack.
    pub(super) fn complete_current(
        &mut self,
        result: <A::Waiter as Future>::Output,
    ) -> (Height, V::Commitment, <A::Waiter as Future>::Output) {
        let PendingAck {
            height, commitment, ..
        } = self.current.take().expect("ack state must be present");
        if let Some(next) = self.queue.pop_front() {
            self.current.replace(next);
        }
        (height, commitment, result)
    }

    /// If the current ack is already resolved, takes it and arms the next ack.
    pub(super) fn pop_ready(
        &mut self,
    ) -> Option<(Height, V::Commitment, <A::Waiter as Future>::Output)> {
        let pending = self.current.as_mut()?;
        let result = Pin::new(&mut pending.receiver).now_or_never()?;
        Some(self.complete_current(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{mocks::block::Block, standard::Standard},
        types::Height,
    };
    use commonware_cryptography::sha256::{Digest, Sha256};
    use commonware_utils::acknowledgement::Exact;

    type TestBlock = Block<Digest, ()>;
    type TestVariant = Standard<TestBlock>;

    fn digest(byte: u8) -> Digest {
        Sha256::fill(byte)
    }

    fn pending_ack(height: u64, byte: u8) -> (PendingAck<TestVariant, Exact>, Exact) {
        let (ack, receiver) = Exact::handle();
        (
            PendingAck {
                height: Height::new(height),
                commitment: digest(byte),
                receiver,
            },
            ack,
        )
    }

    #[test]
    fn enqueue_tracks_capacity_and_fifo_ready_order() {
        let mut pending = PendingAcks::<TestVariant, Exact>::new(2);
        assert!(pending.has_capacity());
        assert_eq!(pending.next_dispatch_height(Height::new(8)), Height::new(8));

        let (first, first_ack) = pending_ack(8, 1);
        pending.enqueue(first);
        assert!(pending.has_capacity());
        assert_eq!(pending.next_dispatch_height(Height::new(8)), Height::new(9));

        let (second, second_ack) = pending_ack(9, 2);
        pending.enqueue(second);
        assert!(!pending.has_capacity());
        assert_eq!(
            pending.next_dispatch_height(Height::new(8)),
            Height::new(10)
        );

        second_ack.acknowledge();
        assert!(pending.pop_ready().is_none());

        first_ack.acknowledge();
        let (height, commitment, result) = pending.pop_ready().expect("first ack should be ready");
        assert_eq!(height, Height::new(8));
        assert_eq!(commitment, digest(1));
        assert!(result.is_ok());

        let (height, commitment, result) = pending
            .pop_ready()
            .expect("queued ready ack should be armed next");
        assert_eq!(height, Height::new(9));
        assert_eq!(commitment, digest(2));
        assert!(result.is_ok());
        assert!(pending.has_capacity());
    }

    #[test]
    fn clear_drops_all_pending_acks() {
        let mut pending = PendingAcks::<TestVariant, Exact>::new(2);
        let (first, first_ack) = pending_ack(3, 1);
        let (second, second_ack) = pending_ack(4, 2);
        pending.enqueue(first);
        pending.enqueue(second);
        assert!(!pending.has_capacity());

        pending.clear();
        first_ack.acknowledge();
        second_ack.acknowledge();

        assert!(pending.pop_ready().is_none());
        assert!(pending.has_capacity());
        assert_eq!(
            pending.next_dispatch_height(Height::new(10)),
            Height::new(10)
        );
    }
}
