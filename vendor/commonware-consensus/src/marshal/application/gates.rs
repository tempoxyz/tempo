use crate::{
    marshal::core::{durability::Durable as _, Mailbox, Variant},
    types::Round,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_macros::select;
use commonware_runtime::Handle;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use std::{collections::HashMap, future::Future, sync::Arc};
use tracing::debug;

/// A proposal staged for its relay broadcast: the block and the ack that
/// delivers its durable-sync handle once marshal persists it.
type Staged<B> = (Arc<B>, oneshot::Sender<Handle<()>>);

/// The registries behind [`Gates`], sharing one lock.
struct Inner<D: Digest, B> {
    /// In-flight certification gate tasks, consumed by certification.
    certifications: HashMap<(Round, D), oneshot::Receiver<bool>>,
    /// Proposals staged for their relay broadcast, consumed by the relay (or
    /// by certification when no broadcast was requested).
    proposals: HashMap<(Round, D), Staged<B>>,
}

/// A shared, thread-safe registry of in-flight certification gate tasks and
/// staged proposals.
///
/// Each entry is keyed by `(Round, D)` where `D` is a commitment or digest
/// identifying the block. The gate task's [`oneshot::Receiver<bool>`] is
/// consumed by certification and resolves to `true` only when that path may cast
/// a finalize vote: local proposal durability has completed, or verification
/// accepted the block and completed the required durable store. A resolved
/// `false` records a live local rejection. A dropped sender means the task did
/// not complete, so certification may fall back to its recovery fetch path.
/// Storage sync failures are fatal to the local marshal state and must panic
/// before resolving the task.
///
/// Tasks are inserted when a block enters proposal or verification handling and
/// taken (consumed) when certification is ready to act on the result. A staged
/// proposal holds the block itself until consensus requests its broadcast via
/// [`crate::Relay::broadcast`] (or certification demands durability first),
/// keeping marshal's mailbox free of any propose-time handshake. Stale entries
/// are pruned after finalization via [`retain_after`](Self::retain_after).
#[derive(Clone)]
pub struct Gates<D: Digest, B> {
    inner: Arc<Mutex<Inner<D, B>>>,
}

impl<D: Digest, B> Default for Gates<D, B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Digest, B> Gates<D, B> {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                certifications: HashMap::new(),
                proposals: HashMap::new(),
            })),
        }
    }

    /// Registers a certification gate task for the block identified by `(round, digest)`.
    pub fn insert(&self, round: Round, digest: D, task: oneshot::Receiver<bool>) {
        self.inner
            .lock()
            .certifications
            .insert((round, digest), task);
    }

    /// Removes and returns the certification gate task for `(round, digest)`, if present.
    pub fn take(&self, round: Round, digest: D) -> Option<oneshot::Receiver<bool>> {
        self.inner.lock().certifications.remove(&(round, digest))
    }

    /// Removes and returns the staged proposal for `(round, digest)`, if present.
    ///
    /// The taken block and ack are handed to marshal exactly once: by the relay
    /// broadcast, or by certification when no broadcast was ever requested.
    pub fn take_staged(&self, round: Round, digest: D) -> Option<Staged<B>> {
        self.inner.lock().proposals.remove(&(round, digest))
    }

    /// Persists the staged proposal for `(round, id)` without broadcasting it,
    /// completing the propose durability handshake.
    ///
    /// A staged proposal whose broadcast was never requested cannot resolve
    /// its certification gate. Certification demands durability, so the staged
    /// block is flushed to `marshal` for persistence, which delivers the
    /// durable-sync handle through the staged ack. Does nothing when no
    /// proposal is staged (the relay broadcast already took it).
    pub fn flush_unrelayed<S, V>(&self, marshal: &Mailbox<S, V>, round: Round, id: D)
    where
        S: Scheme,
        V: Variant<Block = B>,
    {
        if let Some((block, ack)) = self.take_staged(round, id) {
            marshal.verified_deferred(round, block, ack);
        }
    }

    /// Discards all entries whose round is at or before `finalized_round`.
    ///
    /// A discarded staged proposal drops its ack, which abandons the propose
    /// durability handshake for that (already decided) round.
    pub fn retain_after(&self, finalized_round: &Round) {
        let mut inner = self.inner.lock();
        inner
            .certifications
            .retain(|(round, _), _| round > finalized_round);
        inner
            .proposals
            .retain(|(round, _), _| round > finalized_round);
    }

    /// Stages `block` for its relay broadcast and completes the propose
    /// durability handshake for `(round, id)`.
    ///
    /// Registers a certification gate and the staged block, publishes `id` to
    /// consensus on `tx`, then awaits the durable-sync handle so
    /// [`certify`](crate::CertifiableAutomaton::certify) can require durability
    /// before the finalize vote. Both registrations happen before `id` is
    /// published so the relay broadcast and `certify` always find them.
    ///
    /// The handle arrives once marshal persists the staged block, which happens
    /// when consensus requests its broadcast (or at certification when no
    /// broadcast was requested), so this await can outlive the round. A real
    /// sync failure panics here (the fatal policy, annotated with `name`). A
    /// dropped ack means the marshal actor is gone or the staged entry was
    /// pruned without ever being taken, so the gate is left unresolved and
    /// `certify` falls back to its recovery fetch.
    pub async fn stage(
        &self,
        round: Round,
        id: D,
        block: Arc<B>,
        tx: oneshot::Sender<D>,
        name: &'static str,
    ) {
        let (durable_tx, durable_rx) = oneshot::channel();
        let (ack, persist) = oneshot::channel();
        {
            let mut inner = self.inner.lock();
            inner.certifications.insert((round, id), durable_rx);
            inner.proposals.insert((round, id), (block, ack));
        }
        tx.send_lossy(id);
        let Ok(handle) = persist.await else {
            return;
        };
        if !handle.durable(round, name).await {
            return;
        }
        durable_tx.send_lossy(true);
        debug!(?round, ?id, name, "block durable");
    }
}

/// Resolves a deferred verification's certification gate from the joined `(verdict, durable)`
/// result of running application verification concurrently with the candidate store.
///
/// `verdict` is the application validity (`None` when verification stopped early). A false verdict
/// is a live rejection that needs no durability. A true verdict requires the store to be durable;
/// `durable` is false only when the marshal actor is gone at shutdown (a real sync failure panics
/// at its source), so a true-but-not-durable result abandons the gate. Returns the verdict to
/// publish, or `None` to leave the gate unresolved.
pub const fn resolve(verdict: Option<bool>, durable: bool) -> Option<bool> {
    match verdict {
        Some(true) if !durable => None,
        other => other,
    }
}

/// Drives a certification gate `task` to a certify verdict, recovering through `fallback` after an
/// unclean restart.
///
/// A resolved verdict is published on `tx`. A dropped sender (the in-memory task is gone after
/// restart) triggers `fallback`, whose receiver is awaited and published instead. A
/// consensus-dropped receiver (`tx.closed()`) abandons the work.
pub(crate) async fn drive<D, F, Fut>(
    mut tx: oneshot::Sender<bool>,
    task: oneshot::Receiver<bool>,
    round: Round,
    id: D,
    fallback: F,
) where
    D: Digest,
    F: FnOnce() -> Fut,
    Fut: Future<Output = oneshot::Receiver<bool>>,
{
    let result = select! {
        _ = tx.closed() => {
            debug!(reason = "consensus dropped receiver", "skipping certification");
            return;
        },
        result = task => result,
    };
    match result {
        Ok(result) => {
            tx.send_lossy(result);
        }
        Err(_) => {
            debug!(
                ?round,
                ?id,
                "certification gate task closed before certification, falling back to embedded context"
            );
            let fallback = fallback().await;
            let result = select! {
                _ = tx.closed() => {
                    debug!(reason = "consensus dropped receiver", "skipping certification");
                    return;
                },
                result = fallback => result,
            };
            if let Ok(result) = result {
                tx.send_lossy(result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Epoch, View};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher, Sha256};
    use commonware_runtime::{deterministic, Runner, Spawner};

    type D = Sha256Digest;
    type TestGates = Gates<D, u64>;

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn pending_task() -> oneshot::Receiver<bool> {
        let (_tx, rx) = oneshot::channel();
        rx
    }

    #[test]
    fn test_insert_and_take_returns_task() {
        let tasks = TestGates::new();
        let digest = Sha256::hash(b"block");
        tasks.insert(round(1), digest, pending_task());

        assert!(tasks.take(round(1), digest).is_some());
        assert!(
            tasks.take(round(1), digest).is_none(),
            "taking twice should yield None"
        );
    }

    #[test]
    fn test_take_absent_key_is_none() {
        let tasks = TestGates::new();
        assert!(tasks.take(round(1), Sha256::hash(b"missing")).is_none());
    }

    #[test]
    fn test_take_distinguishes_rounds_and_digests() {
        let tasks = TestGates::new();
        let digest_a = Sha256::hash(b"a");
        let digest_b = Sha256::hash(b"b");
        tasks.insert(round(1), digest_a, pending_task());
        tasks.insert(round(2), digest_a, pending_task());
        tasks.insert(round(1), digest_b, pending_task());

        assert!(tasks.take(round(1), digest_a).is_some());
        assert!(tasks.take(round(2), digest_a).is_some());
        assert!(tasks.take(round(1), digest_b).is_some());
    }

    #[test]
    fn test_retain_after_drops_at_and_below_boundary() {
        let tasks = TestGates::new();
        let digest = Sha256::hash(b"block");
        tasks.insert(round(1), digest, pending_task());
        tasks.insert(round(2), digest, pending_task());
        tasks.insert(round(3), digest, pending_task());

        tasks.retain_after(&round(2));

        assert!(
            tasks.take(round(1), digest).is_none(),
            "tasks strictly below boundary should be dropped"
        );
        assert!(
            tasks.take(round(2), digest).is_none(),
            "tasks at boundary should be dropped"
        );
        assert!(
            tasks.take(round(3), digest).is_some(),
            "tasks strictly above boundary should be retained"
        );
    }

    #[test]
    fn test_retain_after_spans_epochs() {
        let tasks = TestGates::new();
        let digest = Sha256::hash(b"block");
        let early = Round::new(Epoch::zero(), View::new(100));
        let late = Round::new(Epoch::new(1), View::zero());
        tasks.insert(early, digest, pending_task());
        tasks.insert(late, digest, pending_task());

        tasks.retain_after(&early);

        assert!(
            tasks.take(early, digest).is_none(),
            "task at boundary must be dropped"
        );
        assert!(
            tasks.take(late, digest).is_some(),
            "task in later epoch must outlive an earlier boundary"
        );
    }

    #[test]
    fn test_retain_after_empty_map_is_noop() {
        let tasks = TestGates::new();
        tasks.retain_after(&round(5));
        assert!(tasks.take(round(5), Sha256::hash(b"x")).is_none());
    }

    #[test]
    fn test_default_matches_new() {
        let default = <TestGates as Default>::default();
        let digest = Sha256::hash(b"block");
        default.insert(round(1), digest, pending_task());
        assert!(default.take(round(1), digest).is_some());
    }

    #[test]
    fn test_resolve() {
        // Verification stopped early: nothing to publish regardless of durability.
        assert_eq!(resolve(None, true), None);
        assert_eq!(resolve(None, false), None);
        // A false app verdict is a live rejection that needs no durability.
        assert_eq!(resolve(Some(false), false), Some(false));
        assert_eq!(resolve(Some(false), true), Some(false));
        // A true verdict publishes only once the store is durable.
        assert_eq!(resolve(Some(true), true), Some(true));
        assert_eq!(resolve(Some(true), false), None);
    }

    #[test]
    fn test_stage_handshake() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let gates = TestGates::new();
            let digest = Sha256::hash(b"block");
            let (tx, rx) = oneshot::channel();

            context.spawn({
                let gates = gates.clone();
                move |_| async move {
                    gates.stage(round(1), digest, Arc::new(7), tx, "test").await;
                }
            });

            // The id is published only after the gate and staged block are registered.
            assert_eq!(rx.await.expect("id published"), digest);
            let gate = gates.take(round(1), digest).expect("gate registered");
            let (block, ack) = gates.take_staged(round(1), digest).expect("block staged");
            assert_eq!(*block, 7);
            assert!(
                gates.take_staged(round(1), digest).is_none(),
                "taking twice should yield None"
            );

            // Delivering a durable handle resolves the gate.
            ack.send_lossy(Handle::ready(Ok(())));
            assert!(gate.await.expect("gate resolved"));
        });
    }

    #[test]
    fn test_retain_after_drops_staged_and_abandons_handshake() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let gates = TestGates::new();
            let digest = Sha256::hash(b"block");
            let (tx, rx) = oneshot::channel();

            context.spawn({
                let gates = gates.clone();
                move |_| async move {
                    gates.stage(round(1), digest, Arc::new(7), tx, "test").await;
                }
            });
            assert_eq!(rx.await.expect("id published"), digest);

            // Pruning drops the staged ack, leaving the gate unresolved.
            let gate = gates.take(round(1), digest).expect("gate registered");
            gates.retain_after(&round(1));
            assert!(gates.take_staged(round(1), digest).is_none());
            assert!(gate.await.is_err(), "gate must be abandoned, not resolved");
        });
    }
}
