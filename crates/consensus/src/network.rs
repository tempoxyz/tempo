//! A channel wrapper that drops messages that exceed a pre-defined size.
//!
//! This layer defends against the `assert!` in commonware's internal channels
//! (`commonware_p2p::authenticated::lookup::channels::UnlimitedSender::send` at
//! the time of writing) that would lead to the node panicking if we ever
//! exceeds the pre-configured message size.
//!
//! Note the interaction between size-limits and rate-limits: commonware
//! performs rate-limits via the [`LimitedSender::check`] API prior to sending a
//! a message. This means that if a rate-limiter is in place (which is always
//! the case), then a rate-limiting token will be consumed before the message is
//! sent and potentially dropped because it exceeds limits.
//!
//! To avoid this waste, commonware either needs to change the assert! into a
//! graceful rejection (so that the token can be reclaimed), or allow performing
//! the size check before.
use std::time::SystemTime;

use commonware_actor::{Feedback, Unreliable};
use commonware_p2p::{Channel, CheckedSender, LimitedSender, Recipients};
use commonware_runtime::{
    IoBufs, Metrics,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use tracing::warn;

/// A p2p sender that rejects messages larger than the configured network limit.
#[derive(Clone)]
pub(crate) struct SizeLimited<S> {
    inner: S,
    channel: Channel,
    max_size: usize,
    dropped: Counter,
}

impl<S> SizeLimited<S> {
    fn new(inner: S, channel: Channel, max_size: u32, dropped: Counter) -> Self {
        Self {
            inner,
            channel,
            max_size: max_size as usize,
            dropped,
        }
    }
}

/// Apply the outbound size limit to a registered p2p channel.
pub(crate) fn limit_channel<S, R>(
    context: &impl Metrics,
    (sender, receiver): (S, R),
    channel: Channel,
    max_size: u32,
) -> (SizeLimited<S>, R) {
    let dropped = context
        .child("network")
        .with_attribute("channel", channel)
        .counter(
            "dropped_oversized_messages",
            "outbound p2p messages dropped for exceeding the maximum message size",
        );
    (
        SizeLimited::new(sender, channel, max_size, dropped),
        receiver,
    )
}

fn within_limit(
    message: impl Into<IoBufs>,
    channel: Channel,
    max_size: usize,
    dropped: &Counter,
) -> Option<IoBufs> {
    let message = message.into();
    if message.len() > max_size {
        dropped.inc();
        warn!(
            channel,
            message_size = message.len(),
            max_size,
            "dropping oversized outbound p2p message"
        );
        return None;
    }

    Some(message)
}

pub(crate) struct SizeLimitedChecked<S> {
    inner: S,
    channel: Channel,
    max_size: usize,
    dropped: Counter,
}

impl<S: CheckedSender> CheckedSender for SizeLimitedChecked<S> {
    type PublicKey = S::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.inner.recipients()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        let Some(message) = within_limit(message, self.channel, self.max_size, &self.dropped)
        else {
            return Unreliable::rejected();
        };

        self.inner.send(message, priority)
    }
}

impl<S: LimitedSender> LimitedSender for SizeLimited<S> {
    type PublicKey = S::PublicKey;
    type Checked<'a>
        = SizeLimitedChecked<S::Checked<'a>>
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        self.inner
            .check(recipients)
            .map(|inner| SizeLimitedChecked {
                inner,
                channel: self.channel,
                max_size: self.max_size,
                dropped: self.dropped.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use commonware_actor::{Feedback, Unreliable};
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_math::algebra::Random as _;
    use commonware_p2p::{CheckedSender, LimitedSender, Recipients, Sender as _};
    use commonware_runtime::{
        IoBufs,
        telemetry::metrics::{Counter, Registered, Registration, raw},
    };
    use commonware_utils::test_rng;

    use super::SizeLimited;

    /// A counter that is not exposed by any metrics registry.
    fn inert_counter() -> Counter {
        Registered::with_registration(raw::Counter::default(), Registration::from(()))
    }

    #[derive(Clone)]
    struct InertSender<P>(P);

    struct InertCheckedSender<P>(P);

    impl<P: commonware_cryptography::PublicKey> LimitedSender for InertSender<P> {
        type PublicKey = P;
        type Checked<'a>
            = InertCheckedSender<P>
        where
            Self: 'a;

        fn check(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'_>, SystemTime> {
            let recipient = match recipients {
                Recipients::One(recipient) => recipient,
                _ => self.0.clone(),
            };
            Ok(InertCheckedSender(recipient))
        }
    }

    impl<P: commonware_cryptography::PublicKey> CheckedSender for InertCheckedSender<P> {
        type PublicKey = P;

        fn recipients(&self) -> Vec<Self::PublicKey> {
            vec![self.0.clone()]
        }

        fn send(self, _message: impl Into<IoBufs> + Send, _priority: bool) -> Unreliable<Feedback> {
            Unreliable::new(Feedback::Ok)
        }
    }

    #[test]
    fn rejects_oversized_messages() {
        let peer = PrivateKey::random(test_rng()).public_key();
        let dropped = inert_counter();
        let mut sender = SizeLimited::new(InertSender(peer.clone()), 0, 4, dropped.clone());

        let sent = sender.send(Recipients::One(peer), b"large".to_vec(), false);

        assert!(sent.is_empty());
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    fn forwards_messages_within_limit() {
        let peer = PrivateKey::random(test_rng()).public_key();
        let dropped = inert_counter();
        let mut sender = SizeLimited::new(InertSender(peer.clone()), 0, 4, dropped.clone());

        let sent = sender.send(Recipients::One(peer.clone()), b"four".to_vec(), false);

        assert_eq!(sent, vec![peer]);
        assert_eq!(dropped.get(), 0);
    }
}
