use std::time::SystemTime;

use commonware_actor::{Feedback, Unreliable};
use commonware_p2p::{CheckedSender, LimitedSender, Recipients, UnlimitedSender};
use commonware_runtime::IoBufs;
use tracing::warn;

/// A p2p sender that rejects messages larger than the configured network limit.
#[derive(Clone)]
pub(crate) struct SizeLimited<S> {
    inner: S,
    channel: &'static str,
    max_size: usize,
}

impl<S> SizeLimited<S> {
    const fn new(inner: S, channel: &'static str, max_size: u32) -> Self {
        Self {
            inner,
            channel,
            max_size: max_size as usize,
        }
    }
}

/// Apply the outbound size limit to a registered p2p channel.
pub(crate) fn limit_channel<S, R>(
    (sender, receiver): (S, R),
    channel: &'static str,
    max_size: u32,
) -> (SizeLimited<S>, R) {
    (SizeLimited::new(sender, channel, max_size), receiver)
}

fn within_limit(
    message: impl Into<IoBufs>,
    channel: &'static str,
    max_size: usize,
) -> Option<IoBufs> {
    let message = message.into();
    if message.len() > max_size {
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

impl<S: UnlimitedSender> UnlimitedSender for SizeLimited<S> {
    type PublicKey = S::PublicKey;

    fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Unreliable<Feedback> {
        let Some(message) = within_limit(message, self.channel, self.max_size) else {
            return Unreliable::rejected();
        };

        self.inner.send(recipients, message, priority)
    }
}

pub(crate) struct SizeLimitedChecked<S> {
    inner: S,
    channel: &'static str,
    max_size: usize,
}

impl<S: CheckedSender> CheckedSender for SizeLimitedChecked<S> {
    type PublicKey = S::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.inner.recipients()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        let Some(message) = within_limit(message, self.channel, self.max_size) else {
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
    use commonware_runtime::IoBufs;
    use commonware_utils::test_rng;

    use super::SizeLimited;

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
        let mut sender = SizeLimited::new(InertSender(peer.clone()), "test", 4);

        let sent = sender.send(Recipients::One(peer), b"large".to_vec(), false);

        assert!(sent.is_empty());
    }

    #[test]
    fn forwards_messages_within_limit() {
        let peer = PrivateKey::random(test_rng()).public_key();
        let mut sender = SizeLimited::new(InertSender(peer.clone()), "test", 4);

        let sent = sender.send(Recipients::One(peer.clone()), b"four".to_vec(), false);

        assert_eq!(sent, vec![peer]);
    }
}
