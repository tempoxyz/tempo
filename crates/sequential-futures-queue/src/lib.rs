//! An unbounded, strictly sequentially executed set of futures.
//!
//! This acts a bit like a futures-rs `FuturesOrdered` in that results are
//! yielded in the order that futures are pushed into the queue. But with the
//! extra caveat that a later future is only polled once an earlier future
//! completes.
//!
//! This is useful where futures share some form of shared state, and where
//! concurrent operation is not only not desired but should be strictly
//! avoided. This is also the reason why pushing is only allowed at the back of
//! the queue.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use std::{
    collections::VecDeque,
    task::{Poll, ready},
};

use futures_util::Stream;

pin_project_lite::pin_project! {
    pub struct SequentialFuturesQueue<TFut> {
        queued: VecDeque<TFut>,
        #[pin]
        future: Option<TFut>,
    }
}

impl<TFut> SequentialFuturesQueue<TFut> {
    pub fn new() -> Self {
        Self {
            queued: VecDeque::new(),
            future: None,
        }
    }

    pub fn push(&mut self, fut: TFut) {
        self.queued.push_back(fut);
    }
}

impl<TFut> Default for SequentialFuturesQueue<TFut> {
    fn default() -> Self {
        Self::new()
    }
}

impl<TFut> FromIterator<TFut> for SequentialFuturesQueue<TFut> {
    fn from_iter<T: IntoIterator<Item = TFut>>(iter: T) -> Self {
        let mut this = Self::new();
        for fut in iter.into_iter() {
            this.push(fut);
        }
        this
    }
}

impl<TFut: Future> Stream for SequentialFuturesQueue<TFut> {
    type Item = <TFut as Future>::Output;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        Poll::Ready(loop {
            if let Some(fut) = this.future.as_mut().as_pin_mut() {
                let item = ready!(fut.poll(cx));
                this.future.set(None);
                break Some(item);
            } else if let Some(future) = this.queued.pop_front() {
                this.future.set(Some(future));
            } else {
                break None;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use futures_channel::oneshot;
    use futures_executor::block_on_stream;
    use futures_test::task::noop_context;
    use futures_util::FutureExt as _;

    use crate::SequentialFuturesQueue;

    #[test]
    fn works_1() {
        let (a_tx, mut a_rx) = oneshot::channel::<i32>();
        let (b_tx, mut b_rx) = oneshot::channel::<i32>();
        let (c_tx, mut c_rx) = oneshot::channel::<i32>();

        let stream = vec![
            async { a_tx.send(1) }.boxed_local(),
            async { b_tx.send(2) }.boxed_local(),
            async { c_tx.send(3) }.boxed_local(),
        ]
        .into_iter()
        .collect::<SequentialFuturesQueue<_>>();

        let mut iter = block_on_stream(stream);

        // all are pending before the stream is polled the first time.
        assert!(a_rx.poll_unpin(&mut noop_context()).is_pending());
        assert!(b_rx.poll_unpin(&mut noop_context()).is_pending());
        assert!(c_rx.poll_unpin(&mut noop_context()).is_pending());

        let _ = iter.next();

        // after the stream is polled once, the first value is returned but
        // the others are still pending. This is what makes this different
        // from a FuturesOrdered or FuturesUnordered: there, all futures would
        // be polled at once (if ready), while here each future is only polled
        // one after the other (and so each tx sends only after the previous
        // one has sent).
        assert_eq!(Poll::Ready(Ok(1i32)), a_rx.poll_unpin(&mut noop_context()),);
        assert!(b_rx.poll_unpin(&mut noop_context()).is_pending());
        assert!(c_rx.poll_unpin(&mut noop_context()).is_pending());

        let _ = iter.next();
        assert_eq!(Poll::Ready(Ok(2i32)), b_rx.poll_unpin(&mut noop_context()),);
        assert!(c_rx.poll_unpin(&mut noop_context()).is_pending());

        let _ = iter.next();
        assert_eq!(Poll::Ready(Ok(3i32)), c_rx.poll_unpin(&mut noop_context()),);

        assert!(iter.next().is_none());
    }
}
