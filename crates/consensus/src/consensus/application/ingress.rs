use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay,
    simplex::{Plan, types::Context},
    types::{Round, View},
};

use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, time::Instant};

use crate::consensus::Digest;

#[derive(Clone)]
pub(crate) struct Mailbox {
    inner: mailbox::Sender<Message>,
}

impl Mailbox {
    pub(super) fn from_sender(inner: mailbox::Sender<Message>) -> Self {
        Self { inner }
    }
}

/// Messages forwarded from consensus to application.
// TODO: add trace spans into all of these messages.
pub(super) enum Message {
    Broadcast(Box<Broadcast>),
    Propose(Box<Propose>),
    Verify(Box<Verify>),
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        match message {
            Self::Broadcast(_) => {}
            message => overflow.push_back(message),
        }
    }
}

pub(super) struct Propose {
    pub(super) parent: (View, Digest),
    pub(super) response: oneshot::Sender<Digest>,
    pub(super) round: Round,
    pub(super) leader: PublicKey,
    pub(super) started_at: Instant,
}

impl From<Propose> for Message {
    fn from(value: Propose) -> Self {
        Self::Propose(Box::new(value))
    }
}

pub(super) struct Broadcast {
    pub(super) digest: Digest,
    pub(super) plan: Plan<PublicKey>,
}

impl From<Broadcast> for Message {
    fn from(value: Broadcast) -> Self {
        Self::Broadcast(Box::new(value))
    }
}

pub(super) struct Verify {
    pub(super) parent: (View, Digest),
    pub(super) payload: Digest,
    pub(super) proposer: PublicKey,
    pub(super) response: oneshot::Sender<bool>,
    pub(super) round: Round,
}

impl From<Verify> for Message {
    fn from(value: Verify) -> Self {
        Self::Verify(Box::new(value))
    }
}

impl Automaton for Mailbox {
    type Context = Context<Self::Digest, PublicKey>;

    type Digest = Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        // XXX: Cannot propagate the error upstream because of the trait def.
        // But if the actor no longer responds the application is dead.
        let (tx, rx) = oneshot::channel();
        let propose = Propose {
            parent: context.parent,
            response: tx,
            round: context.round,
            leader: context.leader,
            started_at: Instant::now(),
        };

        assert!(
            self.inner.enqueue(propose.into(),).accepted(),
            "application is present and ready to receive proposals"
        );

        rx
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // XXX: Cannot propagate the error upstream because of the trait def.
        // But if the actor no longer responds the application is dead.
        let (tx, rx) = oneshot::channel();
        let verify = Verify {
            parent: context.parent,
            payload,
            proposer: context.leader,
            round: context.round,
            response: tx,
        };

        assert!(
            self.inner.enqueue(verify.into(),).accepted(),
            "application is present and ready to receive verify requests"
        );

        rx
    }
}

// TODO: figure out if this can be useful for tempo. The original PR implementing
// this trait:
// https://github.com/commonwarexyz/monorepo/pull/2565
// Associated issue:
// https://github.com/commonwarexyz/monorepo/issues/1767
impl CertifiableAutomaton for Mailbox {
    // NOTE: uses the default impl for CertifiableAutomaton which always
    // returns true.
}

impl Relay for Mailbox {
    type Digest = Digest;
    type PublicKey = PublicKey;
    type Plan = commonware_consensus::simplex::Plan<PublicKey>;

    fn broadcast(&mut self, digest: Self::Digest, plan: Self::Plan) -> Feedback {
        self.inner.enqueue(Broadcast { digest, plan }.into())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use commonware_actor::{Feedback, mailbox};
    use commonware_consensus::{
        Relay as _,
        simplex::Plan,
        types::{Epoch, Round, View},
    };
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;

    use super::{Mailbox, Message};
    use crate::consensus::Digest;

    #[test]
    fn broadcast_overflow_is_dropped() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mut mailbox = Mailbox::from_sender(sender);
            let round = Round::new(Epoch::zero(), View::zero());
            let first = Digest(B256::with_last_byte(1));
            let second = Digest(B256::with_last_byte(2));

            assert_eq!(
                mailbox.broadcast(first, Plan::Propose { round }),
                Feedback::Ok
            );
            assert_eq!(
                mailbox.broadcast(second, Plan::Propose { round }),
                Feedback::Backoff
            );

            let Message::Broadcast(first_message) =
                receiver.recv().await.expect("first broadcast missing")
            else {
                panic!("expected broadcast");
            };
            assert_eq!(first_message.digest, first);

            assert!(receiver.try_recv().is_err());
        });
    }
}
