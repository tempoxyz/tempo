use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::Poll,
};

use alloy_primitives::B256;
use commonware_cryptography::ed25519::PublicKey;
use futures::future::FusedFuture;
use pin_project::pin_project;

pub(crate) fn public_key_to_b256(key: &PublicKey) -> B256 {
    key.as_ref()
        .try_into()
        .expect("ed25519 pub keys always map to B256")
}

pub(crate) fn public_key_to_tempo_primitive(
    key: &PublicKey,
) -> tempo_primitives::ed25519::PublicKey {
    tempo_primitives::ed25519::PublicKey::try_from(B256::from_slice(key.as_ref()))
        .expect("shared implementation of ed25519 pub keys")
}

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

    use commonware_cryptography::ed25519::PublicKey as CommonwarePublicKey;
    use futures::{channel::oneshot, executor::block_on, pin_mut};
    use tempo_primitives::ed25519::PublicKey as TempoPublicKey;

    use crate::utils::{OptionFuture, public_key_to_tempo_primitive};

    #[test]
    fn commonware_public_key_to_tempo_primitive_conversion() {
        let tempo_key = TempoPublicKey::from_seed([42u8; 32]);
        let cw_key = CommonwarePublicKey::from(tempo_key.get());
        assert_eq!(public_key_to_tempo_primitive(&cw_key), tempo_key);
        assert_eq!(tempo_key.get().to_bytes(), cw_key.as_ref());
    }

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
