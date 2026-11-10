//! Seeds of certified simplex rounds, which TIP-1153 exposes as `PREVRANDAO`.
//!
//! Simplex reports every certificate it verifies (including those replayed from
//! its journal after a restart) to its reporter. [`SeedCache`] keeps the seed of
//! each round with a notarization, nullification or finalization, so the
//! application can read the seed of a parent's round when it proposes or
//! verifies the child.

use std::{collections::BTreeMap, sync::Arc};

use alloy_primitives::{B256, keccak256};
use commonware_actor::Feedback;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Reporter,
    simplex::{
        scheme::bls12381_threshold::vrf::{Scheme, Seed, Seedable as _},
        types::Activity,
    },
    types::Round,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use futures::channel::oneshot;
use parking_lot::Mutex;

use crate::consensus::Digest;

/// The most seeds kept from each [`Source`]. Rounds below the latest
/// finalization are pruned, so this only binds while finalization stalls; the
/// oldest seeds go first, and the newest certified round is the one a proposal
/// builds on. Capping the sources apart keeps a long run of nullified views
/// from evicting the seed of the certified parent they all build on.
const MAX_SEEDS: usize = 1024;

/// `keccak256` of the seed of each certified round at or above the latest
/// finalization, shared by every epoch's simplex reporter and the application.
#[derive(Clone, Default)]
pub(crate) struct SeedCache {
    state: Arc<Mutex<State>>,
}

impl SeedCache {
    /// Returns `keccak256` of the seed of `round` if a verified certificate for
    /// it was reported.
    pub(crate) fn get(&self, round: Round) -> Option<B256> {
        self.state.lock().get(round)
    }

    /// Waits until a verified certificate for `round` is reported and returns
    /// `keccak256` of its seed.
    ///
    /// Stays pending if `round` falls below a finalization first: a proposal
    /// on such a parent can no longer be certified. Callers run inside
    /// proposals or verifications that consensus cancels when the view ends.
    pub(crate) async fn wait(&self, round: Round) -> B256 {
        let receiver = {
            let mut state = self.state.lock();
            if let Some(seed) = state.get(round) {
                return seed;
            }
            // Proposals and verifications that consensus cancelled leave closed
            // senders behind; drop them so the map stays bounded while
            // finalization stalls.
            state.waiters.retain(|_, senders| {
                senders.retain(|sender| !sender.is_canceled());
                !senders.is_empty()
            });
            let (sender, receiver) = oneshot::channel();
            state.waiters.entry(round).or_default().push(sender);
            while state.waiters.len() > MAX_SEEDS {
                state.waiters.pop_first();
            }
            receiver
        };
        match receiver.await {
            Ok(seed) => seed,
            Err(oneshot::Canceled) => std::future::pending().await,
        }
    }

    fn insert(&self, seed: Seed<MinSig>, source: Source) {
        let mut state = self.state.lock();
        if seed.round < state.floor {
            return;
        }
        let hash = hash_seed(&seed);
        if let Some(waiters) = state.waiters.remove(&seed.round) {
            for waiter in waiters {
                // A waiter whose proposal or verification was cancelled is gone.
                let _ = waiter.send(hash);
            }
        }
        let seeds = match source {
            Source::Notarized => &mut state.notarized,
            Source::Nullified => &mut state.nullified,
        };
        seeds.insert(seed.round, hash);
        while seeds.len() > MAX_SEEDS {
            seeds.pop_first();
        }
    }

    /// Drops seeds and waiters of rounds below `floor`, which no longer
    /// certify a block.
    fn prune_below(&self, floor: Round) {
        let mut state = self.state.lock();
        if floor <= state.floor {
            return;
        }
        state.floor = floor;
        state.notarized = state.notarized.split_off(&floor);
        state.nullified = state.nullified.split_off(&floor);
        state.waiters = state.waiters.split_off(&floor);
    }
}

impl Reporter for SeedCache {
    type Activity = Activity<Scheme<PublicKey, MinSig>, Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // Simplex reports only certificates it has verified.
        match activity {
            Activity::Notarization(notarization) | Activity::Certification(notarization) => {
                self.insert(notarization.seed(), Source::Notarized);
            }
            // The seed signs the round alone, so a nullification of the parent's
            // round carries the same seed. Simplex can certify the first view
            // of a term on a parent whose notarization this node never saw.
            Activity::Nullification(nullification) => {
                if let Some(certificate) = nullification.certificate.get() {
                    self.insert(
                        Seed::new(nullification.round, certificate.seed_signature),
                        Source::Nullified,
                    );
                }
            }
            Activity::Finalization(finalization) => {
                let seed = finalization.seed();
                let round = seed.round;
                self.insert(seed, Source::Notarized);
                self.prune_below(round);
            }
            _ => {}
        }
        Feedback::Ok
    }
}

/// The kind of certificate a seed came from.
enum Source {
    /// A notarization, certification or finalization.
    Notarized,
    Nullified,
}

#[derive(Default)]
struct State {
    /// Rounds below the latest finalization are not kept.
    floor: Round,
    notarized: BTreeMap<Round, B256>,
    nullified: BTreeMap<Round, B256>,
    waiters: BTreeMap<Round, Vec<oneshot::Sender<B256>>>,
}

impl State {
    fn get(&self, round: Round) -> Option<B256> {
        self.notarized
            .get(&round)
            .or_else(|| self.nullified.get(&round))
            .copied()
    }
}

/// `keccak256` over the 48-byte compressed G1 encoding of the seed signature.
pub(crate) fn hash_seed(seed: &Seed<MinSig>) -> B256 {
    keccak256(seed.signature.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        simplex::{
            scheme::bls12381_threshold::vrf::{Certificate, Signature},
            types::Nullification,
        },
        types::{Epoch, View},
    };
    use commonware_cryptography::bls12381::primitives::ops;
    use futures::FutureExt as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    fn seed(round: Round) -> Seed<MinSig> {
        let (private, _) = ops::keypair::<_, MinSig>(&mut StdRng::seed_from_u64(0));
        Seed::new(
            round,
            ops::sign_message::<MinSig>(&private, b"TEMPO_SEED", &round.encode()),
        )
    }

    fn round(view: u64) -> Round {
        Round::new(Epoch::new(1), View::new(view))
    }

    #[test]
    fn waiter_receives_seed_once_reported() {
        let cache = SeedCache::default();
        let mut wait = std::pin::pin!(cache.wait(round(3)));
        assert!(wait.as_mut().now_or_never().is_none());
        assert_eq!(cache.get(round(3)), None);

        let seed = seed(round(3));
        cache.insert(seed.clone(), Source::Notarized);

        let expected = keccak256(seed.signature.encode());
        assert_eq!(wait.now_or_never(), Some(expected));
        assert_eq!(cache.get(round(3)), Some(expected));
        assert_eq!(cache.wait(round(3)).now_or_never(), Some(expected));
    }

    #[test]
    fn finalization_drops_lower_rounds() {
        let cache = SeedCache::default();
        cache.insert(seed(round(2)), Source::Notarized);
        let mut stale_wait = std::pin::pin!(cache.wait(round(4)));
        assert!(stale_wait.as_mut().now_or_never().is_none());

        cache.prune_below(round(5));

        assert_eq!(cache.get(round(2)), None);
        // A late certificate below the floor is not kept, and its waiters
        // stay pending instead of resolving.
        cache.insert(seed(round(4)), Source::Notarized);
        assert_eq!(cache.get(round(4)), None);
        assert!(stale_wait.now_or_never().is_none());

        cache.insert(seed(round(5)), Source::Notarized);
        assert!(cache.get(round(5)).is_some());
    }

    #[test]
    fn nullification_provides_seed() {
        let cache = SeedCache::default();
        let seed = seed(round(3));
        let mut wait = std::pin::pin!(cache.wait(round(3)));
        assert!(wait.as_mut().now_or_never().is_none());

        let nullification = Nullification {
            round: round(3),
            certificate: Certificate::from(Signature::<MinSig> {
                vote_signature: seed.signature,
                seed_signature: seed.signature,
            }),
        };
        assert_eq!(
            cache.clone().report(Activity::Nullification(nullification)),
            Feedback::Ok
        );

        let expected = keccak256(seed.signature.encode());
        assert_eq!(wait.now_or_never(), Some(expected));
        assert_eq!(cache.get(round(3)), Some(expected));
    }

    #[test]
    fn cancelled_waiters_are_dropped() {
        let cache = SeedCache::default();
        assert!(cache.wait(round(1)).now_or_never().is_none());
        let mut live = std::pin::pin!(cache.wait(round(2)));
        assert!(live.as_mut().now_or_never().is_none());

        let waiting_rounds: Vec<_> = cache.state.lock().waiters.keys().copied().collect();
        assert_eq!(waiting_rounds, vec![round(2)]);
    }

    #[test]
    fn nullifications_do_not_evict_notarized_seeds() {
        let cache = SeedCache::default();
        cache.insert(seed(round(1)), Source::Notarized);
        for view in 2..=MAX_SEEDS as u64 + 2 {
            cache.insert(seed(round(view)), Source::Nullified);
        }
        assert!(cache.get(round(1)).is_some());
        assert_eq!(cache.get(round(2)), None);
        assert!(cache.get(round(MAX_SEEDS as u64 + 2)).is_some());
    }

    #[test]
    fn keeps_at_most_max_seeds() {
        let cache = SeedCache::default();
        for view in 0..=MAX_SEEDS as u64 {
            cache.insert(seed(round(view)), Source::Notarized);
        }
        assert_eq!(cache.get(round(0)), None);
        assert!(cache.get(round(MAX_SEEDS as u64)).is_some());
    }
}
