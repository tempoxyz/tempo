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
//! Users configure leader election with an elector [`Config`] (for example,
//! [`RoundRobin`]) and pass it to the consensus configuration. Consensus builds
//! the initialized [`Elector`] with the scheme participants before starting.

use crate::{
    simplex::scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
    types::{Participant, Round, TermLength, View, ViewDelta},
};
use commonware_codec::Encode;
use commonware_cryptography::{
    Hasher, PublicKey, Sha256, bls12381::primitives::variant::Variant, certificate::Scheme,
};
use commonware_utils::{modulo, ordered::Set};
use std::{fmt, marker::PhantomData, time::Duration};

/// Configuration for creating an [`Elector`].
///
/// Users create and configure this type, then pass it to the consensus configuration.
/// Consensus will call [`build`](Config::build) internally with the correct
/// participant set to create the initialized [`Elector`].
///
/// # Determinism Requirement
///
/// Implementations **must** be deterministic. Honest participants with the same
/// configuration and participant set must select the same leader for each round.
/// This is stronger than returning the same output for identical inputs because
/// honest participants may call [`Elector::elect`] with different certificates for
/// the same round. See [`Elector`] for the certificate handling requirements.
pub trait Config<S: Scheme>: Clone + Send + 'static {
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

/// Leadership term structure reported by an [`Elector`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    /// Number of consecutive views per term (one if and only if rotating).
    length: TermLength,
    /// Term-abandonment timeout (set if and only if `length` exceeds one).
    stall_timeout: Option<Duration>,
    /// Optimistic intra-term lookahead (zero unless `length` exceeds one).
    optimistic_views: ViewDelta,
}

impl Terms {
    /// Every view is its own term: a new leader is elected each view, and
    /// leader rotation itself bounds how long finality can stall.
    pub const fn rotating() -> Self {
        Self {
            length: TermLength::ONE,
            stall_timeout: None,
            optimistic_views: ViewDelta::zero(),
        }
    }

    /// Views are grouped into terms of `length` consecutive views served by
    /// one leader.
    ///
    /// The length is consensus-critical: every participant must configure
    /// the same value (see [`TermLength`]).
    ///
    /// `stall_timeout` is local policy: the maximum time an entered view may
    /// remain unfinalized before this participant abandons the term. On
    /// expiry it treats its current view as timed out and votes nullify,
    /// which (with a quorum) forms a nullification covering the rest of the
    /// term and evicts the leader.
    ///
    /// A Byzantine stable leader can keep every per-view timer satisfied
    /// while preventing finality: each view notarizes and certifies, but
    /// no finalization certificate forms. With single-view terms, leader
    /// rotation bounds such a stall to one view. With longer terms, this
    /// timeout bounds it instead.
    ///
    /// `optimistic_views` is how far a participant may optimistically run
    /// ahead of certified ancestry within a term; zero disables optimistic
    /// validation entirely, and values wider than `length` are accepted but
    /// capped by the windows themselves. The voter tracks a round for every
    /// optimistic view, so memory scales with the smaller of
    /// `optimistic_views` and `length`. See [Optimistic Validation] for the
    /// exact window, which anchors at the last directly notarized view. Like
    /// the stall timeout, this is local policy: mismatched values across
    /// participants only degrade the optimization, never safety.
    ///
    /// [Optimistic Validation]: crate::simplex#optimistic-validation
    ///
    /// # Panics
    ///
    /// Panics if `length` is 1 or if `stall_timeout` is zero. Single-view
    /// terms are [`Terms::rotating`] (the default), where per-view timeouts
    /// already bound a stall and no optimistic window exists.
    pub const fn stable(
        length: TermLength,
        stall_timeout: Duration,
        optimistic_views: ViewDelta,
    ) -> Self {
        assert!(
            length.get() > 1,
            "stable leaders require a term length greater than 1"
        );
        assert!(
            !stall_timeout.is_zero(),
            "stable leaders require a stall timeout greater than zero"
        );
        Self {
            length,
            stall_timeout: Some(stall_timeout),
            optimistic_views,
        }
    }

    /// Returns the number of consecutive views per term.
    ///
    /// Returns [`TermLength::ONE`] if and only if this is [`Terms::rotating`].
    /// A length of one is the definition of rotation, not an approximation of
    /// it: all term arithmetic ([`View::covers`], [`View::admits`],
    /// [`View::term_index`], [`View::next_term_start`]) reduces exactly to
    /// per-view behavior at length one. The only regime fact the length does
    /// not carry is the stall deadline, which callers read from
    /// [`Terms::stall_timeout`].
    pub const fn length(&self) -> TermLength {
        self.length
    }

    /// Returns the term-abandonment timeout, if stable leaders are configured.
    ///
    /// Returns `Some` if and only if [`Self::length`] is greater than one.
    pub const fn stall_timeout(&self) -> Option<Duration> {
        self.stall_timeout
    }

    /// Returns the optimistic intra-term lookahead (see [`Terms::stable`]).
    ///
    /// Always zero when [`Self::length`] is one.
    pub const fn optimistic_views(&self) -> ViewDelta {
        self.optimistic_views
    }
}

impl Default for Terms {
    fn default() -> Self {
        Self::rotating()
    }
}

/// An initialized elector that can select leaders for consensus rounds.
///
/// Consensus obtains initialized electors from [`Config::build`] so leader
/// election and term arithmetic use the same participant set.
///
/// # Certificate Handling
///
/// The `certificate` parameter to [`elect`](Elector::elect) is `None` only for
/// view 1 (the first view after genesis). For all subsequent views, the caller
/// provides the certificate that unlocked the target view. With stable leaders,
/// a nullification certificate can skip to the next term start, so this is not
/// necessarily a certificate from the immediately previous view.
///
/// Whether certificate data is safe to use for leader selection depends on the
/// certificate scheme. Certificates are not necessarily canonical: schemes that
/// retain signer contributions can produce different valid certificates for the
/// same subject from different quorum subsets. Message reordering or a Byzantine
/// participant can therefore cause honest participants to call `elect` for the
/// same round with different certificate values. Implementations must not derive
/// the leader from a certificate's raw encoding or signer set unless the scheme
/// guarantees that the result is invariant across every valid representation.
///
/// Honest participants may also enter the same round with certificates for
/// different subjects (for example, one via a notarization of the previous view
/// and another via a nullification). With `term_length > 1`, those certificates
/// may even be from different views. Implementations must return the same leader
/// for every certificate that can unlock the round. [`RoundRobinElector`] meets
/// this requirement by ignoring the certificate. [`RandomElector`] uses the
/// recovered threshold seed signature, which is independent of vote type and
/// quorum subset for a given round. [`Random`] does not support `term_length > 1`
/// because certificates from different views carry different seed signatures.
pub trait Elector<S: Scheme>: Clone + Send + 'static {
    /// Returns the leadership term structure this elector was built with.
    ///
    /// Callers that need term arithmetic should use this value so leader
    /// election and protocol term handling stay aligned.
    fn terms(&self) -> Terms;

    /// Selects the leader for the given round.
    ///
    /// This method **must** be a pure function given the elector's initialization state.
    ///
    /// Implementations **must** return the same leader for every view within a
    /// stable-leader term (as defined by [`Self::terms`]): nullification
    /// coverage, finalize gating, and leader-inactivity tracking all assume the
    /// leader is constant for the remainder of a term. This contract is not
    /// enforced at runtime: once a round's leader is set, the elector is not
    /// consulted again for that round. A non-conforming implementation leaves
    /// participants with inconsistent leaders and stalls progress.
    ///
    /// The `certificate` is expected to be `None` only for view 1.
    ///
    /// Returns the index of the selected leader in the participants list.
    fn elect(&self, round: Round, certificate: Option<&S::Certificate>) -> Participant;
}

/// Configuration for round-robin leader election.
///
/// Rotates through participants based on `(epoch + term) % num_participants`, where `term` is the
/// stable-leader term containing the view.
/// The rotation order can be shuffled at construction using a seed.
///
/// Works with any signing scheme.
#[derive(Debug, Default)]
pub struct RoundRobin<H: Hasher = Sha256> {
    seed: Option<Vec<u8>>,
    terms: Terms,
    _phantom: PhantomData<H>,
}

impl<H: Hasher> Clone for RoundRobin<H> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed.clone(),
            terms: self.terms,
            _phantom: PhantomData,
        }
    }
}

impl<H: Hasher> RoundRobin<H> {
    /// Creates a round-robin config that will shuffle the rotation order based on seed.
    ///
    /// The seed is used during [`Config::build`] to deterministically
    /// shuffle the permutation.
    pub fn shuffled(seed: &[u8]) -> Self {
        Self {
            seed: Some(seed.to_vec()),
            terms: Terms::rotating(),
            _phantom: PhantomData,
        }
    }

    /// Enables stable leaders: `term_length` consecutive views share a leader,
    /// a term abandoned after `stall_timeout` evicts them, and participants
    /// may run up to `optimistic_views` ahead within a term (see
    /// [`Terms::stable`]).
    ///
    /// The term length is consensus-critical: every participant must configure
    /// the same value (see [`TermLength`]). The timeout and lookahead are
    /// local policy.
    ///
    /// # Panics
    ///
    /// Panics if `term_length` is 1 or `stall_timeout` is zero (see
    /// [`Terms::stable`]).
    pub const fn with_term(
        mut self,
        term_length: TermLength,
        stall_timeout: Duration,
        optimistic_views: ViewDelta,
    ) -> Self {
        self.terms = Terms::stable(term_length, stall_timeout, optimistic_views);
        self
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
            permutation.sort_by_key(|&index| H::hash(&[seed, &index.get().encode()]));
        }

        RoundRobinElector {
            permutation,
            terms: self.terms,
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
    terms: Terms,
    _phantom: PhantomData<S>,
}

impl<S: Scheme> Elector<S> for RoundRobinElector<S> {
    fn terms(&self) -> Terms {
        self.terms
    }

    fn elect(&self, round: Round, _certificate: Option<&S::Certificate>) -> Participant {
        // In order to get a stable leader, use the 1-based index of the term
        let term_idx = round.view().term_index(self.terms.length());

        // Incorporate the epoch number
        let n = self.permutation.len();
        let idx = round.epoch().get().wrapping_add(term_idx)
            % u64::try_from(n).expect("permutation length fits in u64");
        let idx = usize::try_from(idx).expect("leader index fits in usize");
        self.permutation[idx]
    }
}

/// Signature-to-leader mapping used by [`Random`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomVersion {
    /// Maps the encoded threshold signature directly to a participant.
    #[deprecated(
        note = "mapping encoded threshold signature directly to participants can bias selection"
    )]
    V0,
    /// Hashes the encoded threshold signature before mapping it to a participant.
    ///
    /// The hasher is selected by [`Random`]'s `H` type parameter and defaults to [`Sha256`].
    V1,
}

/// Configuration for leader election using threshold signature randomness.
///
/// Uses the seed signature from BLS threshold certificates to derive unpredictable
/// leader selection. Falls back to standard round-robin for view 1 when no
/// certificate is available.
///
/// This elector does not support stable leaders: it has no term-length
/// configuration and [`Elector::terms`] always returns [`Terms::rotating`].
///
/// Only works with [`super::scheme::bls12381_threshold::vrf`]
/// (implements [`super::scheme::bls12381_threshold::vrf::Seedable`]).
pub struct Random<H: Hasher = Sha256> {
    version: RandomVersion,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> Random<H> {
    /// Creates a configuration with the specified signature-to-leader mapping.
    pub const fn new(version: RandomVersion) -> Self {
        Self {
            version,
            _hasher: PhantomData,
        }
    }

    /// Returns the selected leader index for the given round and seed signature.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero, or if a seed signature is missing after view 1.
    #[allow(deprecated)]
    pub fn select_leader<V: Variant>(
        &self,
        round: Round,
        n: u32,
        seed_signature: Option<V::Signature>,
    ) -> Participant {
        assert_ne!(n, 0, "no participants");
        assert!(seed_signature.is_some() || round.view() == View::new(1));

        let Some(seed_signature) = seed_signature else {
            // Standard round-robin for view 1
            let idx = round.epoch().get().wrapping_add(round.view().get()) % u64::from(n);
            return Participant::new(u32::try_from(idx).expect("leader index fits in u32"));
        };

        // Use the seed signature as a source of randomness
        let encoded = seed_signature.encode();
        let index = match self.version {
            RandomVersion::V0 => modulo(encoded.as_ref(), u64::from(n)),
            RandomVersion::V1 => modulo(H::hash(&[encoded.as_ref()]).as_ref(), u64::from(n)),
        };
        Participant::new(u32::try_from(index).expect("leader index must fit in u32"))
    }
}

impl<H: Hasher> Clone for Random<H> {
    fn clone(&self) -> Self {
        Self::new(self.version)
    }
}

impl<H: Hasher> fmt::Debug for Random<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.version.fmt(f)
    }
}

impl<P, V, H> Config<bls12381_threshold_vrf::Scheme<P, V>> for Random<H>
where
    P: PublicKey,
    V: Variant,
    H: Hasher,
{
    type Elector = RandomElector<bls12381_threshold_vrf::Scheme<P, V>, H>;

    fn build(
        self,
        participants: &Set<P>,
    ) -> RandomElector<bls12381_threshold_vrf::Scheme<P, V>, H> {
        assert!(!participants.is_empty(), "no participants");
        RandomElector {
            n: participants.len() as u32,
            version: self,
            _phantom: PhantomData,
        }
    }
}

/// Initialized random leader elector using threshold signature randomness.
///
/// Created via [`Random::build`].
pub struct RandomElector<S: Scheme, H: Hasher = Sha256> {
    n: u32,
    version: Random<H>,
    _phantom: PhantomData<S>,
}

impl<S: Scheme, H: Hasher> Clone for RandomElector<S, H> {
    fn clone(&self) -> Self {
        Self {
            n: self.n,
            version: self.version.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S: Scheme, H: Hasher> fmt::Debug for RandomElector<S, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RandomElector")
            .field("n", &self.n)
            .field("version", &self.version)
            .finish()
    }
}

impl<P, V, H> Elector<bls12381_threshold_vrf::Scheme<P, V>>
    for RandomElector<bls12381_threshold_vrf::Scheme<P, V>, H>
where
    P: PublicKey,
    V: Variant,
    H: Hasher,
{
    fn terms(&self) -> Terms {
        Terms::rotating()
    }

    fn elect(
        &self,
        round: Round,
        certificate: Option<&bls12381_threshold_vrf::Certificate<V>>,
    ) -> Participant {
        self.version.select_leader::<V>(
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
        Sha256, bls12381::primitives::variant::MinPk, certificate::mocks::Fixture,
        sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{Faults, N3f1, NZU32, TryFromIterator, non_empty, test_rng};

    const NAMESPACE: &[u8] = b"test";

    type ThresholdScheme =
        bls12381_threshold_vrf::Scheme<commonware_cryptography::ed25519::PublicKey, MinPk>;

    #[test]
    fn stable_terms_preserve_optimistic_views() {
        let stall = Duration::from_secs(1);
        let length = TermLength::new(NZU32!(5));

        // The configured lookahead is stored verbatim, including values wider
        // than the term (bounded by the issuance window, not by config) and
        // zero (optimistic validation disabled).
        for requested in [0, 3, 4, 5, 6, u64::MAX] {
            let terms = Terms::stable(length, stall, ViewDelta::new(requested));
            assert_eq!(terms.optimistic_views(), ViewDelta::new(requested));
        }
    }

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
    fn round_robin_handles_wrapping_epoch_plus_term_index() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RoundRobinElector<ed25519::Scheme> = RoundRobin::<Sha256>::default()
            .with_term(
                TermLength::new(NZU32!(5)),
                Duration::from_secs(10),
                ViewDelta::new(0),
            )
            .build(&participants);

        let round = Round::new(Epoch::new(u64::MAX - 1), View::new(6));
        let term_idx = round.view().term_index(TermLength::new(NZU32!(5)));
        let expected = round.epoch().get().wrapping_add(term_idx) % 5;

        assert_eq!(
            elector.elect(round, None),
            Participant::new(expected as u32)
        );
    }

    #[test]
    fn round_robin_uses_stable_leaders_within_terms() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 4);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RoundRobinElector<ed25519::Scheme> = RoundRobin::<Sha256>::default()
            .with_term(
                TermLength::new(NZU32!(3)),
                Duration::from_secs(10),
                ViewDelta::new(0),
            )
            .build(&participants);
        let epoch = Epoch::new(0);

        let leader_v1 = elector.elect(Round::new(epoch, View::new(1)), None);
        let leader_v2 = elector.elect(Round::new(epoch, View::new(2)), None);
        let leader_v3 = elector.elect(Round::new(epoch, View::new(3)), None);
        let leader_v4 = elector.elect(Round::new(epoch, View::new(4)), None);
        let leader_v5 = elector.elect(Round::new(epoch, View::new(5)), None);
        let leader_v6 = elector.elect(Round::new(epoch, View::new(6)), None);

        assert_eq!(leader_v1, leader_v2);
        assert_eq!(leader_v1, leader_v3);
        assert_eq!(leader_v4, leader_v5);
        assert_eq!(leader_v4, leader_v6);
        assert_ne!(leader_v1, leader_v4);
    }

    #[test]
    fn round_robin_epoch_transition_shifts_stable_term_leader() {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, NAMESPACE, 4);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RoundRobinElector<ed25519::Scheme> = RoundRobin::<Sha256>::default()
            .with_term(
                TermLength::new(NZU32!(3)),
                Duration::from_secs(10),
                ViewDelta::new(0),
            )
            .build(&participants);

        let leader_epoch_0 = elector.elect(Round::new(Epoch::new(0), View::new(1)), None);
        let leader_epoch_0_v2 = elector.elect(Round::new(Epoch::new(0), View::new(2)), None);
        let leader_epoch_1 = elector.elect(Round::new(Epoch::new(1), View::new(1)), None);
        let leader_epoch_1_v3 = elector.elect(Round::new(Epoch::new(1), View::new(3)), None);
        let leader_epoch_2 = elector.elect(Round::new(Epoch::new(2), View::new(1)), None);
        let leader_epoch_2_v2 = elector.elect(Round::new(Epoch::new(2), View::new(2)), None);

        assert_eq!(leader_epoch_0, Participant::new(1));
        assert_eq!(leader_epoch_0_v2, leader_epoch_0);
        assert_eq!(leader_epoch_1, Participant::new(2));
        assert_eq!(leader_epoch_1_v3, leader_epoch_1);
        assert_eq!(leader_epoch_2, Participant::new(3));
        assert_eq!(leader_epoch_2_v2, leader_epoch_2);
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
        let elector: RandomElector<ThresholdScheme> =
            Random::new(RandomVersion::V1).build(&participants);

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
    fn random_fallback_does_not_truncate_before_modulo() {
        // Five participants make truncation observable:
        // 2^32 % 5 is 1, while (2^32 as u32) % 5 is 0
        let mut rng = test_rng();
        let Fixture { participants, .. } =
            bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let random: RandomElector<ThresholdScheme> =
            Random::new(RandomVersion::V1).build(&participants);
        let round_robin: RoundRobinElector<ThresholdScheme> =
            RoundRobin::<Sha256>::default().build(&participants);

        // View 1 exercises Random's round-robin fallback
        let round = Round::new(Epoch::new(u64::from(u32::MAX)), View::new(1));

        // Both electors must preserve the full u64 sum through the modulo
        assert_eq!(round_robin.elect(round, None), Participant::new(1));
        assert_eq!(random.elect(round, None), Participant::new(1));
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
        let elector: RandomElector<ThresholdScheme> =
            Random::new(RandomVersion::V1).build(&participants);
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
            .assemble(non_empty![@attestations1], &Sequential)
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
            .assemble(non_empty![@attestations2], &Sequential)
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
        let _: RandomElector<ThresholdScheme> = Random::new(RandomVersion::V1).build(&participants);
    }

    #[test]
    #[should_panic]
    fn random_panics_on_none_certificate_after_view_1() {
        let mut rng = test_rng();
        let Fixture { participants, .. } =
            bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, 5);
        let participants = Set::try_from_iter(participants).unwrap();
        let elector: RandomElector<ThresholdScheme> =
            Random::new(RandomVersion::V1).build(&participants);

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

        /// Conformance test for Random V0 leader election.
        ///
        /// Pins mapping the encoded threshold signature directly to a participant
        /// with modulo reduction.
        struct RandomV0SelectLeaderConformance;

        /// Conformance test for Random V1 leader election.
        ///
        /// Pins hashing the encoded threshold signature before mapping it to a
        /// participant with modulo reduction.
        struct RandomV1SelectLeaderConformance;

        fn random_select_leader_commit(seed: u64, version: Random) -> Vec<u8> {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);

            // Generate deterministic BLS threshold fixture (4-10 participants)
            let n = rng.random_range(4..=10);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, n);
            let participants = Set::try_from_iter(participants).unwrap();
            let elector: RandomElector<ThresholdScheme> = version.build(&participants);
            let quorum =
                usize::try_from(N3f1::quorum(schemes.len())).expect("quorum exceeds usize::MAX");

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
                .assemble(non_empty![@attestations], &Sequential)
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

        #[allow(deprecated)]
        impl Conformance for RandomV0SelectLeaderConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                random_select_leader_commit(seed, Random::new(RandomVersion::V0))
            }
        }

        impl Conformance for RandomV1SelectLeaderConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                random_select_leader_commit(seed, Random::new(RandomVersion::V1))
            }
        }

        commonware_conformance::conformance_tests! {
            RoundRobinShuffleConformance => 512,
            RandomV0SelectLeaderConformance => 512,
            RandomV1SelectLeaderConformance => 512,
        }
    }
}
