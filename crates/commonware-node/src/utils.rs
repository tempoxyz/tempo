use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::Poll,
};

use futures::future::FusedFuture;
use pin_project::pin_project;

/// A vendored version of [`commonware_utils::futures::OptionFuture`] to implement
/// [`futures::future::FusedFuture`].
///
/// An optional future that yields [Poll::Pending] when [None]. Useful within `select!` macros,
/// where a future may be conditionally present.
///
/// Not to be confused with [futures::future::OptionFuture], which resolves to [None] immediately
/// when the inner future is `None`.
#[pin_project]
pub(crate) struct OptionFuture<F>(#[pin] Option<F>);

impl<F: Future> Default for OptionFuture<F> {
    fn default() -> Self {
        Self(None)
    }
}

impl<F: Future> From<Option<F>> for OptionFuture<F> {
    fn from(opt: Option<F>) -> Self {
        Self(opt)
    }
}

impl<F: Future> Deref for OptionFuture<F> {
    type Target = Option<F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: Future> DerefMut for OptionFuture<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: Future> Future for OptionFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.0.as_pin_mut() {
            Some(fut) => fut.poll(cx),
            None => Poll::Pending,
        }
    }
}

impl<F: Future> FusedFuture for OptionFuture<F> {
    fn is_terminated(&self) -> bool {
        self.0.is_none()
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use futures::{channel::oneshot, executor::block_on, pin_mut};

    use crate::utils::OptionFuture;

    #[test]
    fn option_future() {
        block_on(async {
            let option_future = OptionFuture::<oneshot::Receiver<()>>::from(None);
            pin_mut!(option_future);

            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(option_future.poll(&mut cx).is_pending());

            let (tx, rx) = oneshot::channel();
            let option_future: OptionFuture<_> = Some(rx).into();
            pin_mut!(option_future);

            tx.send(1usize).unwrap();
            assert_eq!(option_future.poll(&mut cx), Poll::Ready(Ok(1)));
        });
    }
}
