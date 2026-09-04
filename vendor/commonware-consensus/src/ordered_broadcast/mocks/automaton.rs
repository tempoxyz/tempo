use crate::{ordered_broadcast::types::Context, types::Height, Automaton as A, Relay as R};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_cryptography::{sha256, Hasher, PublicKey, Sha256};
use commonware_utils::channel::oneshot;
use tracing::trace;

#[derive(Clone)]
pub struct Automaton<P: PublicKey> {
    invalid_when: fn(Height) -> bool,
    _phantom: std::marker::PhantomData<P>,
}

impl<P: PublicKey> Automaton<P> {
    pub fn new(invalid_when: fn(Height) -> bool) -> Self {
        Self {
            invalid_when,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: PublicKey> A for Automaton<P> {
    type Context = Context<P>;
    type Digest = sha256::Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();

        let Self::Context { sequencer, height } = context;
        let payload = Bytes::from(format!("hello world, {sequencer} {height}"));
        let mut hasher = Sha256::default();
        hasher.update(&payload);

        // Inject an invalid digest by updating with the payload again.
        if (self.invalid_when)(height) {
            hasher.update(&payload);
        }

        let digest = hasher.finalize();
        sender.send(digest).unwrap();

        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        trace!(?context, ?payload, "verify");
        let (sender, receiver) = oneshot::channel();
        // Always say the payload is valid.
        sender.send(true).unwrap();
        receiver
    }
}

impl<P: PublicKey> R for Automaton<P> {
    type Digest = sha256::Digest;
    type Plan = ();
    type PublicKey = P;

    fn broadcast(&mut self, payload: Self::Digest, _plan: ()) -> Feedback {
        trace!(?payload, "broadcast");
        Feedback::Ok
    }
}
