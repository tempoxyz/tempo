//! Broadcast local bodies before sync, without releasing an undurable digest.

use commonware_consensus::{simplex::Plan, types::Round};
use commonware_runtime::{Error, Handle};
use commonware_utils::channel::oneshot;

use crate::consensus::Digest;

/// A bounded, one-shot hint to skip the initial relay of an already sent body.
/// Losing or replacing the hint only causes an extra broadcast. It is never
/// consulted for forwarding, and restart naturally uses the archive path.
#[derive(Default)]
pub(super) struct EarlyBroadcast(Option<(Round, Digest)>);

impl EarlyBroadcast {
    pub(super) fn record(&mut self, round: Round, digest: Digest) {
        self.0 = Some((round, digest));
    }

    pub(super) fn consume<P: commonware_cryptography::PublicKey>(
        &mut self,
        digest: Digest,
        plan: &Plan<P>,
    ) -> bool {
        if let Plan::Propose { round } = plan
            && self.0 == Some((*round, digest))
        {
            self.0 = None;
            return true;
        }
        false
    }
}

/// Match marshal's `verified` durability policy: shutdown abandons the proposal,
/// but a storage failure must remain fatal rather than become a rejected vote.
pub(super) async fn await_durability(
    receiver: oneshot::Receiver<Handle<()>>,
    round: Round,
) -> bool {
    let Ok(handle) = receiver.await else {
        return false;
    };
    match handle.await {
        Ok(()) => true,
        Err(Error::Closed | Error::Aborted) => false,
        Err(error) => panic!("failed to sync proposed block at {round}: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use commonware_consensus::types::{Epoch, View};
    use commonware_cryptography::ed25519::PublicKey;
    use commonware_p2p::Recipients;

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    #[test]
    fn only_matching_initial_relay_is_suppressed_once() {
        let mut sent = EarlyBroadcast::default();
        let digest = Digest(B256::with_last_byte(1));
        let propose = Plan::<PublicKey>::Propose { round: round(1) };
        sent.record(round(1), digest);
        assert!(!sent.consume(
            digest,
            &Plan::Forward {
                round: round(1),
                recipients: Recipients::<PublicKey>::All,
            }
        ));
        assert!(!sent.consume(digest, &Plan::<PublicKey>::Propose { round: round(2) }));
        assert!(!sent.consume(Digest(B256::ZERO), &propose));
        assert!(sent.consume(digest, &propose));
        assert!(!sent.consume(digest, &propose));
    }

    #[test]
    fn replaced_or_missing_hint_keeps_archive_forwarding() {
        let mut sent = EarlyBroadcast::default();
        let digest = Digest(B256::ZERO);
        let old = Plan::<PublicKey>::Propose { round: round(1) };
        assert!(!sent.consume(digest, &old));
        sent.record(round(1), digest);
        sent.record(round(2), digest);
        assert!(!sent.consume(digest, &old));
        assert!(sent.consume(digest, &Plan::<PublicKey>::Propose { round: round(2) }));
    }

    #[tokio::test]
    async fn durability_waits_for_handle_and_sync_completion() {
        let (ack, receiver) = oneshot::channel();
        let mut durability = Box::pin(await_durability(receiver, round(1)));
        assert!(futures::poll!(&mut durability).is_pending());
        let (sync, completion) = oneshot::channel();
        ack.send(Handle::from_receiver(completion)).ok().unwrap();
        assert!(futures::poll!(&mut durability).is_pending());
        sync.send(Ok(())).unwrap();
        assert!(durability.await);
    }

    #[tokio::test]
    async fn lost_ack_and_shutdown_do_not_release_proposal() {
        let (ack, receiver) = oneshot::channel();
        drop(ack);
        assert!(!await_durability(receiver, round(1)).await);
        for error in [Error::Closed, Error::Aborted] {
            let (ack, receiver) = oneshot::channel();
            ack.send(Handle::from_future(async move { Err(error) }))
                .ok()
                .unwrap();
            assert!(!await_durability(receiver, round(1)).await);
        }
    }

    #[tokio::test]
    #[should_panic(expected = "failed to sync proposed block")]
    async fn failed_sync_is_fatal() {
        let (ack, receiver) = oneshot::channel();
        ack.send(Handle::from_future(async { Err(Error::WriteFailed) }))
            .ok()
            .unwrap();
        await_durability(receiver, round(1)).await;
    }
}
