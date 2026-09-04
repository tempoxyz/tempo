//! Leader election strategies for simplex consensus.
//!
//! This module provides the [`Config`] and [`Elector`] traits for customizing
//! how leaders are selected for each consensus round, along with built-in implementations.
//!
//! # Built-in Electors
//!
//! - [`RoundRobin`]/[`RoundRobinElector`]: Deterministic rotation through participants
//!   based on view number. Optionally shuffled using a seed. Works with any signing scheme.
//!
//! - [`Random`]/[`RandomElector`]: Uses randomness derived from BLS threshold VRF signatures
//!   for unpredictable leader selection. Falls back to round-robin for the first view
//!   (no certificate available). Requires [`super::scheme::bls12381_threshold::vrf`]
//!   (implements [`super::scheme::bls12381_threshold::vrf::Seedable`]).
//!
//! # Custom Electors
//!
//! Applications can implement [`Config`] and [`Elector`] for custom leader
//! selection logic such as stake-weighted selection or other application-specific strategies.
//!
//! # Usage
//!
//! This module uses a type-state pattern to ensure correct usage:
//! 1. Users create an elector [`Config`] (e.g., [`RoundRobin`])
//! 2. The config is passed to the consensus configuration
//! 3. Consensus calls [`Config::build`] internally with the correct participants
//! 4. The resulting [`Elector`] can only be created by consensus, preventing misuse

use crate::{
    simplex::scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
    types::{Participant, Round, View},
};
use commonware_codec::Encode;
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, certificate::Scheme, Hasher, PublicKey, Sha256,
};
use commonware_utils::{modulo, ordered::Set};
use std::marker::PhantomData;

/// Configuration for creating an [`Elector`].
///
/// Users create and configure this type, then pass it to the consensus configuration.
/// Consensus will call [`build`](Config::build) internally with the correct
/// participant set to create the initialized [`Elector`].
///
/// # Determinism Requirement
///
/// Implementations **must** be deterministic: given the same construction parameters
/// and the same inputs to [`Elector::elect`], the method must always return
/// the same leader index. This is critical for consensus correctness - all honest
/// participants must agree on the leader for each round.
pub trait Config<S: Scheme>: Clone + Default + Send + 'static {
    /// The initialized elector type.
    type Elector: Elector<S>;

    /// Builds the elector with the given participants.
    ///
    /// Called internally by consensus with the correct participant set.
    ///
    /// # Panics
    ///
    /// Implementations should panic if `participants` is empty.
    fn build(self, participants: &Set<S::PublicKey>) -> Self::Elector;
}

/// An initialized elector that can select leaders for consensus rounds.
///
/// This type can only be created via [`Config::build`], which is called
/// internally by consensus. This ensures the elector is always initialized with
/// the correct participant set.
///
/// # Certificate Handling
///
/// The `certificate` parameter to [`elect`](Elector::elect) is `None` only for
/// view 1 (the first view after genesis). For all subsequent views, a certificate
/// from the previous view is provided. Implementations can use the certificate to
/// derive randomness (like [`RandomElector`]) or ignore it entirely (like [`RoundRobinElector`]).
pub trait Elector<S: Scheme>: Clone + Send + 'static {
    /// Selects the leader for the given round.
    ///
    /// This method **must** be a pure function given the elector's initialization state.
    ///
    /// The `certificate` is expected to be `None` only for view 1.
    ///
    /// Returns the index of the selected leader in the participants list.
    fn elect(&self, round: Round, certificate: Option<&S::Certificate>) -> Participant;
}

/// Configuration for round-robin leader election.
///
/// Rotates through participants based on `(epoch + view) % num_participants`.
/// The rotation order can be shuffled at construction using a seed.
///
/// Works with any signing scheme.
#[derive(Clone, Debug, Default)]
pub struct RoundRobin<H: Hasher = Sha256> {
    seed: Option<Vec<u8>>,
    _phantom: PhantomData<H>,
}

impl<H: Hasher> RoundRobin<H> {
    /// Creates a round-robin config that will shuffle the rotation order based on seed.
    ///
    /// The seed is used during [`Config::build`] to deterministically
    /// shuffle the permutation.
    pub fn shuffled(seed: &[u8]) -> Self {
        Self {
            seed: Some(seed.to_vec()),
            _phantom: PhantomData,
        }
    }
}

impl<S: Scheme, H: Hasher> Config<S> for RoundRobin<H> {
    type Elector = RoundRobinElector<S>;

    fn build(self, participants: &Set<S::PublicKey>) -> RoundRobinElector<S> {
        assert!(!participants.is_empty(), "no participants");

        let mut permutation: Vec<Participant> = (0..participants.len())
            .map(Participant::from_usize)
            .collect();

        if let Some(seed) = &self.seed {
            let mut hasher = H::new();
            permutation.sort_by_key(|&index| {
                hasher.update(seed);
                hasher.update(&index.get().encode());
                hasher.finalize()
            });
        }

        RoundRobinElector {
            permutation,
            _phantom: PhantomData,
        }
    }
}

/// Initialized round-robin leader elector.
///
/// Created via [`RoundRobin::build`].
#[derive(Clone, Debug)]
pub struct RoundRobinElector<S: Scheme> {
    permutation: Vec<Participant>,
    _phantom: PhantomData<S>,
}

impl<S: Scheme> Elector<S> for RoundRobinElector<S> {
    fn elect(&self, round: Round, _certificate: Option<&S::Certificate>) -> Participant {
        let n = self.permutation.len();
        let idx = (round.epoch().get().wrapping_add(round.view().get())) as usize % n;
        self.permutation[idx]
    }
}

/// Configuration for leader election using threshold signature randomness.
///
/// Uses the seed signature from BLS threshold certificates to derive unpredictable
/// leader selection. Falls back to standard round-robin for view 1 when no
/// certificate is available.
///
/// Only works with [`super::scheme::bls12381_threshold::vrf`]
/// (implements [`super::scheme::bls12381_threshold::vrf::Seedable`]).
#[derive(Clone, Debug, Default)]
pub struct Random;

impl Random {
    /// Returns the selected leader index for the given round and seed signature.
    pub fn select_leader<V: Variant>(
        round: Round,
        n: u32,
        seed_signature: Option<V::Signature>,
    ) -> Participant {
        assert!(seed_signature.is_some() || round.view() == View::new(1));

        let Some(seed_signature) = seed_signature else {
            // Standard round-robin for view 1
            return Participant::new(
                (round.epoch().get().wrapping_add(round.view().get())) as u32 % n,
            );
        };

        // Use the seed signature as a source of randomness
        Participant::new(modulo(seed_signature.encode().as_ref(), n as u64) as u32)
    }
}

impl<P, V> Config<bls12381_threshold_vrf::Scheme<P, V>> for Random
where
    P: PublicKey,
    V: Variant,
{
    type Elector = RandomElector<bls12381_threshold_vrf::Scheme<P, V>>;

    fn build(self, participants: &Set<P>) -> RandomElector<bls12381_threshold_vrf::Scheme<P, V>> {
        assert!(!participants.is_empty(), "no participants");
        RandomElector {
            n: participants.len() as u32,
            _phantom: PhantomData,
        }
    }
}

/// Initialized random leader elector using threshold signature randomness.
///
/// Created via [`Random::build`].
#[derive(Clone, Debug)]
pub struct RandomElector<S: Scheme> {
    n: u32,
    _phantom: PhantomData<S>,
}

impl<P, V> Elector<bls12381_threshold_vrf::Scheme<P, V>>
    for RandomElector<bls12381_threshold_vrf::Scheme<P, V>>
where
    P: PublicKey,
    V: Variant,
{
    fn elect(
        &self,
        round: Round,
        certificate: Option<&bls12381_threshold_vrf::Certificate<V>>,
    ) -> Participant {
        Random::select_leader::<V>(
            round,
            self.n,
            certificate.map(|c| {
                c.get()
                    .expect("verified certificate must decode")
                    .seed_signature
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::{bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519},
            types::Subject,
        },
        types::{Epoch, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, certificate::mocks::Fixture,
        sha256::Digest as Sha256Digest, Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, N3f1, TryFromIterator};

    const NAMESPACE: &[u8] = b"test";

    type ThresholdScheme =
        bls12381_threshold_vrf::Scheme<commonware_cryptography::ed25519::PublicKey, MinPk>;

    #[test]
    fn round_robin_rotates_through_participants() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 4);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len() as u32;
        let elector: RoundRobinElector<ed25519::Scheme> =
            RoundRobin::<Sha256>::default().build(&participants);
        let epoch = Epoch::new(0);

        // Run through 3 * n views, record the sequence of leaders
        let mut leaders = Vec::new();
        for view in 1..=(3 * n as u64) {
            let round = Round::new(epoch, View::new(view));
            leaders.push(elector.elect(round, None));
        }

        // Verify leaders cycle: consecutive leaders differ by 1 (mod n)
        for i in 0..leaders.len() - 1 {
            assert_eq!(Participant::new((leaders[i].get() + 1) % n), leaders[i + 1]);
        }
    }

    #[test]
    fn round_robin_cycles_through_epochs() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let elector: RoundRobinElector<ed25519::Scheme> =
            RoundRobin::<Sha256>::default().build(&participants);

        // Record leader for view 1 of epochs 0..n
        let leaders: Vec<_> = (0..n as u64)
            .map(|e| {
                let round = Round::new(Epoch::new(e), View::new(1));
                elector.elect(round, None)
            })
            .collect();

        // Each participant should be selected exactly once
        let mut seen = vec![false; n];
        for leader in &leaders {
            assert!(!seen[usize::from(*leader)]);
            seen[usize::from(*leader)] = true;
        }
        assert!(seen.iter().all(|x| *x));
    }

    #[test]
    fn round_robin_shuffled_changes_order() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();

        let elector_no_seed: RoundRobinElector<ed25519::Scheme> =
            RoundRobin::<Sha256>::default().build(&participants);
        let elector_seed_1: RoundRobinElector<ed25519::Scheme> =
            RoundRobin::<Sha256>::shuffled(b"seed1").build(&participants);
        let elector_seed_2: RoundRobinElector<ed25519::Scheme> =
            RoundRobin::<Sha256>::shuffled(b"seed2").build(&participants);

        // Collect first 5 leaders from each
        let epoch = Epoch::new(0);
        let leaders_no_seed: Vec<_> = (1..=5)
            .map(|v| elector_no_seed.elect(Round::new(epoch, View::new(v)), None))
            .collect();
        let leaders_seed_1: Vec<_> = (1..=5)
            .map(|v| elector_seed_1.elect(Round::new(epoch, View::new(v)), None))
            .collect();
        let leaders_seed_2: Vec<_> = (1..=5)
            .map(|v| elector_seed_2.elect(Round::new(epoch, View::new(v)), None))
            .collect();

        // No seed should be identity permutation
        assert_eq!(
            leaders_no_seed,
            vec![
                Participant::new(1),
                Participant::new(2),
                Participant::new(3),
                Participant::new(4),
                Participant::new(0)
            ]
        );

        // Different seeds should produce different permutations
        assert_ne!(leaders_seed_1, leaders_no_seed);
        assert_ne!(leaders_seed_2, leaders_no_seed);
        assert_ne!(leaders_seed_1, leaders_seed_2);

        // Each permutation should still cover all participants
        for leaders in [&leaders_seed_1, &leaders_seed_2] {
            let mut sorted = leaders.clone();
            sorted.sort();
            assert_eq!(
                sorted,
                vec![
                    Participant::new(0),
                    Participant::new(1),
                    Participant::new(2),
                    Participant::new(3),
                    Participant::new(4)
                ]
            );
        }
    }

    #[test]
    fn round_robin_same_seed_is_deterministic() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();

        let elector1: RoundRobinElector<ed25519::Scheme> =
            RoundRobin::<Sha256>::shuffled(b"same_seed").build(&participants);
        let elector2: RoundRobinElector<ed25519::Scheme> =
            RoundRobin::<Sha256>::shuffled(b"same_seed").build(&participants);

        let epoch = Epoch::new(0);
        for view in 1..=10 {
            let round = Round::new(epoch, View::new(view));
            assert_eq!(elector1.elect(round, None), elector2.elect(round, None));
        }
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn round_robin_build_panics_on_empty_participants() {
        let participants: Set<commonware_cryptography::ed25519::PublicKey> = Set::default();
        let _: RoundRobinElector<ed25519::Scheme> =
            RoundRobin::<Sha256>::default().build(&participants);
    }

    #[test]
    fn random_falls_back_to_round_robin_for_view_1() {
        let mut rng = test_rng();
        let Fixture { participants, .. } =
            bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let n = participants.len();
        let elector: RandomElector<ThresholdScheme> = Random.build(&participants);

        // For view 1 (no certificate), Random should behave like RoundRobin
        let leaders: Vec<_> = (0..n as u64)
            .map(|e| {
                let round = Round::new(Epoch::new(e), View::new(1));
                elector.elect(round, None)
            })
            .collect();

        // Each participant should be selected exactly once (same as RoundRobin)
        let mut seen = vec![false; n];
        for leader in &leaders {
            assert!(!seen[usize::from(*leader)]);
            seen[usize::from(*leader)] = true;
        }
        assert!(seen.iter().all(|x| *x));
    }

    #[test]
    fn random_uses_certificate_randomness() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RandomElector<ThresholdScheme> = Random.build(&participants);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        // Create certificate for round (1, 2)
        let round1 = Round::new(Epoch::new(1), View::new(2));
        let attestations1: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(Subject::Nullify { round: round1 })
                    .unwrap()
            })
            .collect();
        let cert1 = schemes[0]
            .assemble::<_, N3f1>(attestations1, &Sequential)
            .unwrap();

        // Create certificate for round (1, 3) (different round -> different seed signature)
        let round2 = Round::new(Epoch::new(1), View::new(3));
        let attestations2: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| {
                s.sign::<Sha256Digest>(Subject::Nullify { round: round2 })
                    .unwrap()
            })
            .collect();
        let cert2 = schemes[0]
            .assemble::<_, N3f1>(attestations2, &Sequential)
            .unwrap();

        // Same certificate always gives same leader
        let leader1a = elector.elect(round1, Some(&cert1));
        let leader1b = elector.elect(round1, Some(&cert1));
        assert_eq!(leader1a, leader1b);

        // Different certificates produce different leaders
        //
        // NOTE: In general, different certificates could produce the same leader by chance.
        // However, for our specific test inputs (rng seed 42, 5 participants), we've
        // verified these produce different results.
        let leader2 = elector.elect(round1, Some(&cert2));
        assert_ne!(leader1a, leader2);
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn random_build_panics_on_empty_participants() {
        let participants: Set<commonware_cryptography::ed25519::PublicKey> = Set::default();
        let _: RandomElector<ThresholdScheme> = Random.build(&participants);
    }

    #[test]
    #[should_panic]
    fn random_panics_on_none_certificate_after_view_1() {
        let mut rng = test_rng();
        let Fixture { participants, .. } =
            bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RandomElector<ThresholdScheme> = Random.build(&participants);

        // View 2 requires a certificate
        let round = Round::new(Epoch::new(1), View::new(2));
        elector.elect(round, None);
    }

    mod conformance {
        use super::*;
        use commonware_codec::{Encode, Write};
        use commonware_conformance::Conformance;
        use commonware_cryptography::Sha256;
        use rand::{RngExt as _, SeedableRng};
        use rand_chacha::ChaCha8Rng;

        /// Conformance test for shuffled RoundRobin leader election.
        ///
        /// Verifies that the permutation generated by `RoundRobin::shuffled`
        /// remains deterministic across versions. This is critical because
        /// changing the shuffle algorithm would cause consensus failures.
        struct RoundRobinShuffleConformance;

        impl Conformance for RoundRobinShuffleConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let mut rng = ChaCha8Rng::seed_from_u64(seed);

                // Generate deterministic participants (using ed25519 fixture)
                let n = rng.random_range(1..=100);
                let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, n);
                let participants = Set::try_from_iter(participants).unwrap();

                // Generate a random seed for shuffling
                let shuffle_seed: [u8; 32] = rng.random();

                // Build the shuffled elector
                let elector: RoundRobinElector<ed25519::Scheme> =
                    RoundRobin::<Sha256>::shuffled(&shuffle_seed).build(&participants);

                // Encode the permutation as the commitment
                elector.permutation.encode().to_vec()
            }
        }

        /// Conformance test for Random leader election.
        ///
        /// Verifies that `Random::select_leader` produces deterministic results
        /// given the same inputs. This tests the `modulo` function usage and
        /// threshold signature encoding for leader selection.
        struct RandomSelectLeaderConformance;

        impl Conformance for RandomSelectLeaderConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let mut rng = ChaCha8Rng::seed_from_u64(seed);

                // Generate deterministic BLS threshold fixture (4-10 participants)
                let n = rng.random_range(4..=10);
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, n);
                let participants = Set::try_from_iter(participants).unwrap();
                let elector: RandomElector<ThresholdScheme> = Random.build(&participants);
                let quorum = N3f1::quorum(schemes.len()) as usize;

                // Generate deterministic round parameters
                let epoch = rng.random_range(0..1000);
                let view = rng.random_range(2..=101);

                let round = Round::new(Epoch::new(epoch), View::new(view));

                // Create a valid threshold certificate
                let attestations: Vec<_> = schemes
                    .iter()
                    .take(quorum)
                    .map(|s| s.sign::<Sha256Digest>(Subject::Nullify { round }).unwrap())
                    .collect();
                let cert = schemes[0]
                    .assemble::<_, N3f1>(attestations, &Sequential)
                    .unwrap();

                // Elect leader using the certificate
                let leader = elector.elect(round, Some(&cert));

                // Also test view 1 fallback (no certificate, round-robin)
                let round_v1 = Round::new(Epoch::new(epoch), View::new(1));
                let leader_v1 = elector.elect(round_v1, None);

                // Commit both results
                let mut result = leader.encode_mut();
                leader_v1.write(&mut result);
                result.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            RoundRobinShuffleConformance => 512,
            RandomSelectLeaderConformance => 512,
        }
    }
}
