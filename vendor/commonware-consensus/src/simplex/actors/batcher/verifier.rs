use crate::{
    simplex::{
        scheme::Scheme,
        types::{Attributable, Finalize, Notarize, Nullify, Proposal, Subject, Vote},
    },
    types::Participant,
};
use commonware_cryptography::{certificate::Verification, Digest};
use commonware_parallel::Strategy;
use commonware_utils::ordered::Set;
use rand::rngs::StdRng;
use rand_core::{CryptoRng, SeedableRng};
use std::{mem, sync::Arc};
use tracing::{Instrument as _, Span};

/// Runs a CPU-bound job through [Strategy::spawn], entering `span` on the worker thread and
/// instrumenting the awaited future so the offloaded work stays attributed to the caller's trace.
pub(super) async fn offload<P, F, T>(span: Span, strategy: &P, job: F) -> T
where
    P: Strategy,
    F: FnOnce(P) -> T + Send + 'static,
    T: Send + 'static,
{
    let worker_span = span.clone();
    strategy
        .spawn(move |strategy| worker_span.in_scope(|| job(strategy)))
        .instrument(span)
        .await
}

/// `Verifier` is a utility for tracking and verifying consensus messages.
///
/// For schemes where [`Verifier::is_batchable()`](commonware_cryptography::certificate::Verifier::is_batchable)
/// returns `true` (such as [ed25519], [bls12381_multisig] and [bls12381_threshold]), this struct collects
/// messages and defers verification until enough messages exist to potentially reach a quorum, enabling
/// efficient batch verification. For schemes where `is_batchable()` returns `false` (such as [secp256r1]),
/// signatures are verified eagerly as they arrive since there is no batching benefit.
///
/// To avoid unnecessary verification, it also tracks the number of already verified messages (ensuring
/// we no longer attempt to verify messages after a quorum of valid messages have already been verified).
///
/// Once polled, async verification moves the pending batch and accumulated verified votes into
/// the worker. Do not cancel an in-flight verification unless the verifier will also be discarded.
///
/// [ed25519]: crate::simplex::scheme::ed25519
/// [bls12381_multisig]: crate::simplex::scheme::bls12381_multisig
/// [bls12381_threshold]: crate::simplex::scheme::bls12381_threshold
/// [secp256r1]: crate::simplex::scheme::secp256r1
pub struct Verifier<S: Scheme<D>, D: Digest> {
    /// Signing scheme used to verify votes and assemble certificates.
    scheme: Arc<S>,

    /// Required quorum size.
    quorum: usize,

    /// Current leader index.
    leader: Option<Participant>,
    /// Proposal associated with the current leader.
    leader_proposal: Option<Proposal<D>>,

    /// Pending notarize votes waiting to be verified.
    pending_notarizes: Vec<Notarize<S, D>>,
    /// Verified notarize votes available for certificate recovery.
    verified_notarizes: Vec<Notarize<S, D>>,

    /// Pending nullify votes waiting to be verified.
    pending_nullifies: Vec<Nullify<S>>,
    /// Verified nullify votes available for certificate recovery.
    verified_nullifies: Vec<Nullify<S>>,

    /// Pending finalize votes waiting to be verified.
    pending_finalizes: Vec<Finalize<S, D>>,
    /// Verified finalize votes available for certificate recovery.
    verified_finalizes: Vec<Finalize<S, D>>,
}

impl<S: Scheme<D>, D: Digest> Verifier<S, D> {
    /// Creates a new `Verifier`.
    ///
    /// # Arguments
    ///
    /// * `scheme` - Scheme handle used to verify and aggregate votes.
    /// * `quorum` - Number of votes (2f+1) required to reach a quorum.
    pub fn new(scheme: impl Into<Arc<S>>, quorum: u32) -> Self {
        let quorum = quorum as usize;
        Self {
            scheme: scheme.into(),

            // Store quorum as usize to simplify comparisons against queue lengths.
            quorum,

            leader: None,
            leader_proposal: None,

            pending_notarizes: Vec::with_capacity(quorum),
            verified_notarizes: Vec::with_capacity(quorum),

            pending_nullifies: Vec::with_capacity(quorum),
            verified_nullifies: Vec::with_capacity(quorum),

            pending_finalizes: Vec::with_capacity(quorum),
            verified_finalizes: Vec::with_capacity(quorum),
        }
    }

    /// Returns the ordered participant set.
    pub(super) fn participants(&self) -> &Set<S::PublicKey> {
        self.scheme.participants()
    }

    /// Returns the shared signing scheme.
    pub(super) fn scheme(&self) -> Arc<S> {
        Arc::clone(&self.scheme)
    }

    /// Takes verified notarize votes once they reach quorum.
    pub(super) fn take_verified_notarizes(&mut self) -> Option<Vec<Notarize<S, D>>> {
        (self.verified_notarizes.len() >= self.quorum)
            .then(|| mem::take(&mut self.verified_notarizes))
    }

    /// Takes verified nullify votes once they reach quorum.
    pub(super) fn take_verified_nullifies(&mut self) -> Option<Vec<Nullify<S>>> {
        (self.verified_nullifies.len() >= self.quorum)
            .then(|| mem::take(&mut self.verified_nullifies))
    }

    /// Takes verified finalize votes once they reach quorum.
    pub(super) fn take_verified_finalizes(&mut self) -> Option<Vec<Finalize<S, D>>> {
        (self.verified_finalizes.len() >= self.quorum)
            .then(|| mem::take(&mut self.verified_finalizes))
    }

    /// Sets the leader's proposal and filters out any pending votes for other proposals.
    ///
    /// Once the leader's proposal is known, we only care about votes for that specific
    /// proposal. Any votes for other proposals are dropped since they cannot contribute
    /// to a valid certificate.
    fn set_leader_proposal(&mut self, proposal: Proposal<D>) {
        self.pending_notarizes.retain(|n| n.proposal == proposal);
        self.verified_notarizes.retain(|n| n.proposal == proposal);
        self.pending_finalizes.retain(|f| f.proposal == proposal);
        self.verified_finalizes.retain(|f| f.proposal == proposal);
        self.leader_proposal = Some(proposal);
    }

    /// Returns the leader proposal, if it is set.
    pub fn get_leader_proposal(&self) -> Option<(Participant, Proposal<D>)> {
        self.leader_proposal
            .as_ref()
            .map(|proposal| (self.leader.unwrap(), proposal.clone()))
    }

    /// Adds a [Vote] message to the batch for later verification.
    ///
    /// If the message has already been verified (e.g., we built it), it is stored
    /// directly for certificate recovery. Otherwise, it is added to the appropriate
    /// pending queue. Notarize and finalize votes for a proposal other than the
    /// known leader's are dropped since they cannot contribute to a certificate.
    ///
    /// If a leader is known and the message is a [Vote::Notarize] from that leader,
    /// this method may trigger `set_leader_proposal`.
    ///
    /// # Arguments
    ///
    /// * `msg` - The [Vote] message to add.
    /// * `verified` - A boolean indicating if the message has already been verified.
    pub fn add(&mut self, msg: Vote<S, D>, verified: bool) {
        match msg {
            Vote::Notarize(notarize) => {
                if let Some(ref leader_proposal) = self.leader_proposal {
                    // If leader proposal is set and the message is not for it, drop it
                    if leader_proposal != &notarize.proposal {
                        return;
                    }
                } else if let Some(leader) = self.leader {
                    // If leader is set but leader proposal is not, set it
                    if leader == notarize.signer() {
                        // Set the leader proposal
                        self.set_leader_proposal(notarize.proposal.clone());
                    }
                }

                // If we've made it this far, add the notarize
                if verified {
                    self.verified_notarizes.push(notarize);
                } else {
                    self.pending_notarizes.push(notarize);
                }
            }
            Vote::Nullify(nullify) => {
                if verified {
                    self.verified_nullifies.push(nullify);
                } else {
                    self.pending_nullifies.push(nullify);
                }
            }
            Vote::Finalize(finalize) => {
                // If leader proposal is set and the message is not for it, drop it
                if let Some(ref leader_proposal) = self.leader_proposal {
                    if leader_proposal != &finalize.proposal {
                        return;
                    }
                }

                // If we've made it this far, add the finalize
                if verified {
                    self.verified_finalizes.push(finalize);
                } else {
                    self.pending_finalizes.push(finalize);
                }
            }
        }
    }

    /// Sets the leader for the current consensus view.
    ///
    /// If a notarize vote from the leader has already been received, this will
    /// also set the leader's proposal, filtering out any pending votes for other
    /// proposals.
    pub fn set_leader(&mut self, leader: Participant) {
        assert!(self.leader.is_none());
        self.leader = Some(leader);

        // If we already have the leader's vote, set the leader proposal
        let Some(notarize) = self
            .pending_notarizes
            .iter()
            .chain(&self.verified_notarizes)
            .find(|n| n.signer() == leader)
        else {
            return;
        };
        self.set_leader_proposal(notarize.proposal.clone());
    }

    /// Verifies a batch of pending [Vote::Notarize] messages.
    ///
    /// It uses `S::verify_attestations` for efficient batch verification, run as one CPU-bound job
    /// submitted through [Strategy::spawn] so a parallel strategy hosts it on its own pool
    /// instead of occupying the calling task.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    ///
    /// # Returns
    ///
    /// A tuple containing the number of votes processed and the signer indices for whom
    /// verification failed.
    pub async fn verify_notarizes<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> (usize, Vec<Participant>) {
        let notarizes = mem::take(&mut self.pending_notarizes);

        // Early return if there are no notarizes to verify
        if notarizes.is_empty() {
            return (0, vec![]);
        }
        let batch = notarizes.len();
        let mut verified_notarizes = mem::take(&mut self.verified_notarizes);

        let scheme = Arc::clone(&self.scheme);
        let mut rng = StdRng::from_rng(rng);
        let (verified_notarizes, invalid) = offload(Span::current(), strategy, move |strategy| {
            let (proposals, attestations): (Vec<_>, Vec<_>) = notarizes
                .into_iter()
                .map(|n| (n.proposal, n.attestation))
                .unzip();
            let proposal = &proposals[0];

            let Verification { verified, invalid } = scheme.verify_attestations::<_, D, _>(
                &mut rng,
                Subject::Notarize { proposal },
                attestations,
                &strategy,
            );

            verified_notarizes.extend(verified.into_iter().zip(proposals).map(
                |(attestation, proposal)| Notarize {
                    proposal,
                    attestation,
                },
            ));
            (verified_notarizes, invalid)
        })
        .await;

        self.verified_notarizes = verified_notarizes;

        (batch, invalid)
    }

    /// Checks if there are [Vote::Notarize] messages ready for batch verification.
    ///
    /// Verification is considered "ready" when all of the following are true:
    /// 1. There are pending notarize messages to verify.
    /// 2. The leader and their proposal are known (so we know which proposal to verify for).
    /// 3. We haven't already verified enough messages to reach quorum.
    /// 4. The sum of verified and pending messages could potentially reach quorum,
    ///    or the scheme doesn't benefit from batching (eager verification).
    pub fn ready_notarizes(&self) -> bool {
        // If there are no pending notarizes, there is nothing to do.
        if self.pending_notarizes.is_empty() {
            return false;
        }

        // If we don't yet know the leader, notarizes may contain messages for
        // a number of different proposals.
        if self.leader.is_none() || self.leader_proposal.is_none() {
            return false;
        }

        // If we have already verified enough messages, there is nothing more to do.
        if self.verified_notarizes.len() >= self.quorum {
            return false;
        }

        // For schemes that don't benefit from batching, verify immediately.
        if !S::is_batchable() {
            return true;
        }

        // If we don't have enough to reach the quorum, there is nothing to do yet.
        if self.verified_notarizes.len() + self.pending_notarizes.len() < self.quorum {
            return false;
        }

        true
    }

    /// Verifies a batch of pending [Vote::Nullify] messages.
    ///
    /// It uses `S::verify_attestations` for efficient batch verification, run as one CPU-bound job
    /// submitted through [Strategy::spawn] so a parallel strategy hosts it on its own pool
    /// instead of occupying the calling task.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    ///
    /// # Returns
    ///
    /// A tuple containing the number of votes processed and the signer indices for whom
    /// verification failed.
    pub async fn verify_nullifies<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> (usize, Vec<Participant>) {
        let nullifies = mem::take(&mut self.pending_nullifies);

        // Early return if there are no nullifies to verify
        if nullifies.is_empty() {
            return (0, vec![]);
        }
        let batch = nullifies.len();
        let mut verified_nullifies = mem::take(&mut self.verified_nullifies);

        let round = nullifies[0].round;

        let scheme = Arc::clone(&self.scheme);
        let mut rng = StdRng::from_rng(rng);
        let (verified_nullifies, invalid) = offload(Span::current(), strategy, move |strategy| {
            let Verification { verified, invalid } = scheme.verify_attestations::<_, D, _>(
                &mut rng,
                Subject::Nullify { round },
                nullifies.into_iter().map(|nullify| nullify.attestation),
                &strategy,
            );

            verified_nullifies.extend(
                verified
                    .into_iter()
                    .map(|attestation| Nullify { round, attestation }),
            );
            (verified_nullifies, invalid)
        })
        .await;

        self.verified_nullifies = verified_nullifies;

        (batch, invalid)
    }

    /// Checks if there are [Vote::Nullify] messages ready for batch verification.
    ///
    /// Verification is considered "ready" when all of the following are true:
    /// 1. There are pending nullify messages to verify.
    /// 2. We haven't already verified enough messages to reach quorum.
    /// 3. The sum of verified and pending messages could potentially reach quorum,
    ///    or the scheme doesn't benefit from batching (eager verification).
    pub fn ready_nullifies(&self) -> bool {
        // If there are no pending nullifies, there is nothing to do.
        if self.pending_nullifies.is_empty() {
            return false;
        }

        // If we have already verified enough messages, there is nothing more to do.
        if self.verified_nullifies.len() >= self.quorum {
            return false;
        }

        // For schemes that don't benefit from batching, verify immediately.
        if !S::is_batchable() {
            return true;
        }

        // If we don't have enough to reach the quorum, there is nothing to do yet.
        if self.verified_nullifies.len() + self.pending_nullifies.len() < self.quorum {
            return false;
        }

        true
    }

    /// Verifies a batch of pending [Vote::Finalize] messages.
    ///
    /// It uses `S::verify_attestations` for efficient batch verification, run as one CPU-bound job
    /// submitted through [Strategy::spawn] so a parallel strategy hosts it on its own pool
    /// instead of occupying the calling task.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    ///
    /// # Returns
    ///
    /// A tuple containing the number of votes processed and the signer indices for whom
    /// verification failed.
    pub async fn verify_finalizes<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> (usize, Vec<Participant>) {
        let finalizes = mem::take(&mut self.pending_finalizes);

        // Early return if there are no finalizes to verify
        if finalizes.is_empty() {
            return (0, vec![]);
        }
        let batch = finalizes.len();
        let mut verified_finalizes = mem::take(&mut self.verified_finalizes);

        let scheme = Arc::clone(&self.scheme);
        let mut rng = StdRng::from_rng(rng);
        let (verified_finalizes, invalid) = offload(Span::current(), strategy, move |strategy| {
            let (proposals, attestations): (Vec<_>, Vec<_>) = finalizes
                .into_iter()
                .map(|n| (n.proposal, n.attestation))
                .unzip();
            let proposal = &proposals[0];

            let Verification { verified, invalid } = scheme.verify_attestations::<_, D, _>(
                &mut rng,
                Subject::Finalize { proposal },
                attestations,
                &strategy,
            );

            verified_finalizes.extend(verified.into_iter().zip(proposals).map(
                |(attestation, proposal)| Finalize {
                    proposal,
                    attestation,
                },
            ));
            (verified_finalizes, invalid)
        })
        .await;

        self.verified_finalizes = verified_finalizes;

        (batch, invalid)
    }

    /// Checks if there are [Vote::Finalize] messages ready for batch verification.
    ///
    /// Verification is considered "ready" when all of the following are true:
    /// 1. There are pending finalize messages to verify.
    /// 2. The leader and their proposal are known (so we know which proposal to verify for).
    /// 3. We haven't already verified enough messages to reach quorum.
    /// 4. The sum of verified and pending messages could potentially reach quorum,
    ///    or the scheme doesn't benefit from batching (eager verification).
    pub fn ready_finalizes(&self) -> bool {
        // If there are no pending finalizes, there is nothing to do.
        if self.pending_finalizes.is_empty() {
            return false;
        }

        // If we don't yet know the leader, finalizes may contain messages for
        // a number of different proposals.
        if self.leader.is_none() || self.leader_proposal.is_none() {
            return false;
        }

        // If we have already verified enough messages, there is nothing more to do.
        if self.verified_finalizes.len() >= self.quorum {
            return false;
        }

        // For schemes that don't benefit from batching, verify immediately.
        if !S::is_batchable() {
            return true;
        }

        // If we don't have enough to reach the quorum, there is nothing to do yet.
        if self.verified_finalizes.len() + self.pending_finalizes.len() < self.quorum {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::scheme::{
            bls12381_multisig,
            bls12381_threshold::{
                standard as bls12381_threshold_std, vrf as bls12381_threshold_vrf,
            },
            ed25519, secp256r1,
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        sha256::Digest as Sha256,
    };
    use commonware_macros::test_async;
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, N3f1, TestRng};

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32]) // Simple fixed digest for testing
    }

    // Helper to create a Notarize message for any signing scheme
    fn create_notarize<S: Scheme<Sha256>>(
        scheme: &S,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Notarize<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Notarize::sign(scheme, proposal).unwrap()
    }

    // Helper to create a Nullify message for any signing scheme
    fn create_nullify<S: Scheme<Sha256>>(scheme: &S, round: Round) -> Nullify<S> {
        Nullify::sign::<Sha256>(scheme, round).unwrap()
    }

    // Helper to create a Finalize message for any signing scheme
    fn create_finalize<S: Scheme<Sha256>>(
        scheme: &S,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Finalize<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Finalize::sign(scheme, proposal).unwrap()
    }

    fn add_notarize<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);

        let round = Round::new(Epoch::new(0), View::new(1));
        let notarize1 = create_notarize(&schemes[0], round, View::new(0), 1);
        let notarize2 = create_notarize(&schemes[1], round, View::new(0), 1);
        let notarize_diff = create_notarize(&schemes[2], round, View::new(0), 2);

        verifier.add(Vote::Notarize(notarize1.clone()), false);
        assert_eq!(verifier.pending_notarizes.len(), 1);
        assert_eq!(verifier.verified_notarizes.len(), 0);

        verifier.add(Vote::Notarize(notarize1.clone()), true);
        assert_eq!(verifier.pending_notarizes.len(), 1);
        assert_eq!(verifier.verified_notarizes.len(), 1);

        verifier.set_leader(notarize1.signer());
        assert!(verifier.leader_proposal.is_some());
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &notarize1.proposal
        );
        assert_eq!(verifier.pending_notarizes.len(), 1);

        verifier.add(Vote::Notarize(notarize2), false);
        assert_eq!(verifier.pending_notarizes.len(), 2);

        verifier.add(Vote::Notarize(notarize_diff), false);
        assert_eq!(verifier.pending_notarizes.len(), 2);

        let mut verifier2 = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let notarize_non_leader = create_notarize(&schemes[1], round2, View::new(1), 3);
        let notarize_leader = create_notarize(&schemes[0], round2, View::new(1), 3);

        verifier2.set_leader(notarize_leader.signer());
        verifier2.add(Vote::Notarize(notarize_non_leader), false);
        assert!(verifier2.leader_proposal.is_none());
        assert_eq!(verifier2.pending_notarizes.len(), 1);

        verifier2.add(Vote::Notarize(notarize_leader.clone()), false);
        assert!(verifier2.leader_proposal.is_some());
        assert_eq!(
            verifier2.leader_proposal.as_ref().unwrap(),
            &notarize_leader.proposal
        );
        assert_eq!(verifier2.pending_notarizes.len(), 2);
    }

    #[test]
    fn test_add_notarize() {
        add_notarize(bls12381_threshold_vrf::fixture::<MinSig, _>);
        add_notarize(bls12381_threshold_vrf::fixture::<MinPk, _>);
        add_notarize(bls12381_threshold_std::fixture::<MinSig, _>);
        add_notarize(bls12381_threshold_std::fixture::<MinPk, _>);
        add_notarize(bls12381_multisig::fixture::<MinSig, _>);
        add_notarize(bls12381_multisig::fixture::<MinPk, _>);
        add_notarize(ed25519::fixture);
        add_notarize(secp256r1::fixture);
    }

    fn set_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);

        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        let other_notarize = create_notarize(&schemes[1], round, View::new(0), 1);

        verifier.add(Vote::Notarize(other_notarize), false);
        assert_eq!(verifier.pending_notarizes.len(), 1);

        let leader = leader_notarize.signer();
        verifier.set_leader(leader);
        assert_eq!(verifier.leader, Some(leader));
        assert!(verifier.leader_proposal.is_none());
        assert_eq!(verifier.pending_notarizes.len(), 1);

        verifier.add(Vote::Notarize(leader_notarize.clone()), false);
        assert!(verifier.leader_proposal.is_some());
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &leader_notarize.proposal
        );
        assert_eq!(verifier.pending_notarizes.len(), 2);

        let mut verifier2 = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        verifier2.add(Vote::Notarize(leader_notarize.clone()), true);
        verifier2.set_leader(leader);
        assert_eq!(
            verifier2.leader_proposal.as_ref().unwrap(),
            &leader_notarize.proposal
        );
    }

    #[test]
    fn test_set_leader() {
        set_leader(bls12381_threshold_vrf::fixture::<MinSig, _>);
        set_leader(bls12381_threshold_vrf::fixture::<MinPk, _>);
        set_leader(bls12381_threshold_std::fixture::<MinSig, _>);
        set_leader(bls12381_threshold_std::fixture::<MinPk, _>);
        set_leader(bls12381_multisig::fixture::<MinSig, _>);
        set_leader(bls12381_multisig::fixture::<MinPk, _>);
        set_leader(ed25519::fixture);
        set_leader(secp256r1::fixture);
    }

    async fn ready_and_verify_notarizes<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        assert!(!verifier.ready_notarizes());

        verifier.set_leader(notarizes[0].signer());
        verifier.add(Vote::Notarize(notarizes[0].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.ready_notarizes(), S::is_batchable());
        assert_eq!(verifier.pending_notarizes.len(), 1);

        verifier.add(Vote::Notarize(notarizes[1].clone()), false);
        assert_eq!(!verifier.ready_notarizes(), S::is_batchable());
        verifier.add(Vote::Notarize(notarizes[2].clone()), false);
        assert_eq!(!verifier.ready_notarizes(), S::is_batchable());
        verifier.add(Vote::Notarize(notarizes[3].clone()), false);
        assert!(verifier.ready_notarizes());
        assert_eq!(verifier.pending_notarizes.len(), 4);

        let (batch, failed_bulk) = verifier.verify_notarizes(&mut rng, &Sequential).await;
        assert_eq!(batch, 4);
        assert!(failed_bulk.is_empty());
        assert_eq!(verifier.verified_notarizes.len(), 4);
        assert!(verifier.pending_notarizes.is_empty());
        assert!(!verifier.ready_notarizes());

        let mut verifier2 = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let leader_vote = create_notarize(&schemes[0], round2, View::new(1), 10);
        let mut faulty_vote = create_notarize(&schemes[1], round2, View::new(1), 10);
        verifier2.set_leader(leader_vote.signer());
        verifier2.add(Vote::Notarize(leader_vote.clone()), false);
        faulty_vote.attestation.signer = Participant::from_usize(schemes.len() + 10);
        verifier2.add(Vote::Notarize(faulty_vote.clone()), false);

        for scheme in schemes.iter().skip(2).take(quorum as usize - 2) {
            verifier2.add(
                Vote::Notarize(create_notarize(scheme, round2, View::new(1), 10)),
                false,
            );
        }
        assert!(verifier2.ready_notarizes());

        let (batch, failed_second) = verifier2.verify_notarizes(&mut rng, &Sequential).await;
        assert_eq!(batch, quorum as usize);
        assert!(verifier2
            .verified_notarizes
            .iter()
            .any(|notarize| notarize == &leader_vote));
        assert_eq!(failed_second, vec![faulty_vote.signer()]);
    }

    #[test_async]
    async fn test_ready_and_verify_notarizes() {
        ready_and_verify_notarizes(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_and_verify_notarizes(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_and_verify_notarizes(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_and_verify_notarizes(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_and_verify_notarizes(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_and_verify_notarizes(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_and_verify_notarizes(ed25519::fixture).await;
        ready_and_verify_notarizes(secp256r1::fixture).await;
    }

    fn add_nullify<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullify = create_nullify(&schemes[0], round);

        verifier.add(Vote::Nullify(nullify.clone()), false);
        assert_eq!(verifier.pending_nullifies.len(), 1);
        assert_eq!(verifier.verified_nullifies.len(), 0);

        verifier.add(Vote::Nullify(nullify), true);
        assert_eq!(verifier.pending_nullifies.len(), 1);
        assert_eq!(verifier.verified_nullifies.len(), 1);
    }

    #[test]
    fn test_add_nullify() {
        add_nullify(bls12381_threshold_vrf::fixture::<MinSig, _>);
        add_nullify(bls12381_threshold_vrf::fixture::<MinPk, _>);
        add_nullify(bls12381_threshold_std::fixture::<MinSig, _>);
        add_nullify(bls12381_threshold_std::fixture::<MinPk, _>);
        add_nullify(bls12381_multisig::fixture::<MinSig, _>);
        add_nullify(bls12381_multisig::fixture::<MinPk, _>);
        add_nullify(ed25519::fixture);
        add_nullify(secp256r1::fixture);
    }

    async fn ready_and_verify_nullifies<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| create_nullify(scheme, round))
            .collect();

        verifier.add(Vote::Nullify(nullifies[0].clone()), true);
        assert_eq!(verifier.verified_nullifies.len(), 1);

        verifier.add(Vote::Nullify(nullifies[1].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.ready_nullifies(), S::is_batchable());
        verifier.add(Vote::Nullify(nullifies[2].clone()), false);
        assert_eq!(!verifier.ready_nullifies(), S::is_batchable());
        verifier.add(Vote::Nullify(nullifies[3].clone()), false);
        assert!(verifier.ready_nullifies());
        assert_eq!(verifier.pending_nullifies.len(), 3);

        let (batch, failed) = verifier.verify_nullifies(&mut rng, &Sequential).await;
        assert_eq!(batch, 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.verified_nullifies.len(), 4);
        assert!(verifier.pending_nullifies.is_empty());
        assert!(!verifier.ready_nullifies());
    }

    #[test_async]
    async fn test_ready_and_verify_nullifies() {
        ready_and_verify_nullifies(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_and_verify_nullifies(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_and_verify_nullifies(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_and_verify_nullifies(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_and_verify_nullifies(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_and_verify_nullifies(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_and_verify_nullifies(ed25519::fixture).await;
        ready_and_verify_nullifies(secp256r1::fixture).await;
    }

    fn add_finalize<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalize_a = create_finalize(&schemes[0], round, View::new(0), 1);
        let finalize_b = create_finalize(&schemes[1], round, View::new(0), 2);

        verifier.add(Vote::Finalize(finalize_b.clone()), false);
        assert_eq!(verifier.pending_finalizes.len(), 1);
        assert_eq!(verifier.verified_finalizes.len(), 0);

        verifier.add(Vote::Finalize(finalize_a.clone()), false);
        assert_eq!(verifier.pending_finalizes.len(), 2);

        verifier.set_leader(finalize_a.signer());
        assert!(verifier.leader_proposal.is_none());
        verifier.set_leader_proposal(finalize_a.proposal.clone());
        assert_eq!(verifier.pending_finalizes.len(), 1);
        assert_eq!(verifier.pending_finalizes[0], finalize_a);
        assert_eq!(verifier.verified_finalizes.len(), 0);

        verifier.add(Vote::Finalize(finalize_a), true);
        assert_eq!(verifier.pending_finalizes.len(), 1);
        assert_eq!(verifier.verified_finalizes.len(), 1);

        verifier.add(Vote::Finalize(finalize_b), false);
        assert_eq!(verifier.pending_finalizes.len(), 1);
        assert_eq!(verifier.verified_finalizes.len(), 1);
    }

    #[test]
    fn test_add_finalize() {
        add_finalize(bls12381_threshold_vrf::fixture::<MinSig, _>);
        add_finalize(bls12381_threshold_vrf::fixture::<MinPk, _>);
        add_finalize(bls12381_threshold_std::fixture::<MinSig, _>);
        add_finalize(bls12381_threshold_std::fixture::<MinPk, _>);
        add_finalize(bls12381_multisig::fixture::<MinSig, _>);
        add_finalize(bls12381_multisig::fixture::<MinPk, _>);
        add_finalize(ed25519::fixture);
        add_finalize(secp256r1::fixture);
    }

    async fn ready_and_verify_finalizes<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_finalize(scheme, round, View::new(0), 1))
            .collect();

        assert!(!verifier.ready_finalizes());

        verifier.set_leader(finalizes[0].signer());
        verifier.set_leader_proposal(finalizes[0].proposal.clone());

        verifier.add(Vote::Finalize(finalizes[0].clone()), true);
        assert_eq!(verifier.verified_finalizes.len(), 1);
        assert!(verifier.pending_finalizes.is_empty());

        verifier.add(Vote::Finalize(finalizes[1].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.ready_finalizes(), S::is_batchable());
        verifier.add(Vote::Finalize(finalizes[2].clone()), false);
        assert_eq!(!verifier.ready_finalizes(), S::is_batchable());
        verifier.add(Vote::Finalize(finalizes[3].clone()), false);
        assert!(verifier.ready_finalizes());

        let (batch, failed) = verifier.verify_finalizes(&mut rng, &Sequential).await;
        assert_eq!(batch, 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.verified_finalizes.len(), 4);
        assert!(verifier.pending_finalizes.is_empty());
        assert!(!verifier.ready_finalizes());
    }

    #[test_async]
    async fn test_ready_and_verify_finalizes() {
        ready_and_verify_finalizes(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_and_verify_finalizes(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_and_verify_finalizes(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_and_verify_finalizes(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_and_verify_finalizes(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_and_verify_finalizes(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_and_verify_finalizes(ed25519::fixture).await;
        ready_and_verify_finalizes(secp256r1::fixture).await;
    }

    fn leader_proposal_filters_messages<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let proposal_a = Proposal::new(round, View::new(0), sample_digest(10));
        let proposal_b = Proposal::new(round, View::new(0), sample_digest(20));

        let notarize_a = Notarize::sign(&schemes[0], proposal_a.clone()).unwrap();
        let notarize_b = Notarize::sign(&schemes[1], proposal_b.clone()).unwrap();
        let finalize_a = Finalize::sign(&schemes[0], proposal_a.clone()).unwrap();
        let finalize_b = Finalize::sign(&schemes[1], proposal_b).unwrap();

        verifier.add(Vote::Notarize(notarize_a.clone()), false);
        verifier.add(Vote::Notarize(notarize_b.clone()), false);
        verifier.add(Vote::Notarize(notarize_a.clone()), true);
        verifier.add(Vote::Notarize(notarize_b), true);
        verifier.add(Vote::Finalize(finalize_a.clone()), false);
        verifier.add(Vote::Finalize(finalize_b.clone()), false);
        verifier.add(Vote::Finalize(finalize_a), true);
        verifier.add(Vote::Finalize(finalize_b), true);

        assert_eq!(verifier.pending_notarizes.len(), 2);
        assert_eq!(verifier.verified_notarizes.len(), 2);
        assert_eq!(verifier.pending_finalizes.len(), 2);
        assert_eq!(verifier.verified_finalizes.len(), 2);

        verifier.set_leader(notarize_a.signer());

        assert_eq!(verifier.pending_notarizes.len(), 1);
        assert_eq!(verifier.pending_notarizes[0].proposal, proposal_a);
        assert_eq!(verifier.verified_notarizes.len(), 1);
        assert_eq!(verifier.verified_notarizes[0].proposal, proposal_a);
        assert_eq!(verifier.pending_finalizes.len(), 1);
        assert_eq!(verifier.pending_finalizes[0].proposal, proposal_a);
        assert_eq!(verifier.verified_finalizes.len(), 1);
        assert_eq!(verifier.verified_finalizes[0].proposal, proposal_a);
    }

    #[test]
    fn test_leader_proposal_filters_messages() {
        leader_proposal_filters_messages(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_proposal_filters_messages(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_proposal_filters_messages(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_proposal_filters_messages(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_proposal_filters_messages(bls12381_multisig::fixture::<MinSig, _>);
        leader_proposal_filters_messages(bls12381_multisig::fixture::<MinPk, _>);
        leader_proposal_filters_messages(ed25519::fixture);
        leader_proposal_filters_messages(secp256r1::fixture);
    }

    fn set_leader_twice_panics<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), 3);
        verifier.set_leader(Participant::new(0));
        verifier.set_leader(Participant::new(1));
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_threshold_minsig() {
        set_leader_twice_panics(bls12381_threshold_vrf::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_threshold_minpk() {
        set_leader_twice_panics(bls12381_threshold_vrf::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_threshold_std_minsig() {
        set_leader_twice_panics(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_threshold_std_minpk() {
        set_leader_twice_panics(bls12381_threshold_std::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_multisig_minsig() {
        set_leader_twice_panics(bls12381_multisig::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls_multisig_minpk() {
        set_leader_twice_panics(bls12381_multisig::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_ed() {
        set_leader_twice_panics(ed25519::fixture);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_secp() {
        set_leader_twice_panics(secp256r1::fixture);
    }

    async fn notarizes_wait_for_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);

        verifier.set_leader(leader_vote.signer());
        verifier.add(Vote::Notarize(leader_vote), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(
            !verifier.ready_notarizes(),
            S::is_batchable(),
            "Batchable schemes wait for quorum, non-batchable verify immediately"
        );

        for scheme in schemes.iter().skip(1).take(quorum as usize - 1) {
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                false,
            );
        }
        assert!(verifier.ready_notarizes(), "Should be ready at quorum");

        let (batch, _) = verifier.verify_notarizes(&mut rng, &Sequential).await;
        assert_eq!(batch, quorum as usize);
        assert!(!verifier.ready_notarizes());
    }

    #[test_async]
    async fn test_notarizes_wait_for_quorum() {
        notarizes_wait_for_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        notarizes_wait_for_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        notarizes_wait_for_quorum(bls12381_threshold_std::fixture::<MinSig, _>).await;
        notarizes_wait_for_quorum(bls12381_threshold_std::fixture::<MinPk, _>).await;
        notarizes_wait_for_quorum(bls12381_multisig::fixture::<MinSig, _>).await;
        notarizes_wait_for_quorum(bls12381_multisig::fixture::<MinPk, _>).await;
        notarizes_wait_for_quorum(ed25519::fixture).await;
        notarizes_wait_for_quorum(secp256r1::fixture).await;
    }

    fn ready_notarizes_without_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        for vote in notarizes.iter() {
            verifier.add(Vote::Notarize(vote.clone()), false);
        }

        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready without leader/proposal set"
        );

        verifier.set_leader(notarizes[0].signer());
        assert!(
            verifier.ready_notarizes(),
            "Should be ready once leader is set"
        );
    }

    #[test]
    fn test_ready_notarizes_without_leader_or_proposal() {
        ready_notarizes_without_leader(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_notarizes_without_leader(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_notarizes_without_leader(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_notarizes_without_leader(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_notarizes_without_leader(bls12381_multisig::fixture::<MinSig, _>);
        ready_notarizes_without_leader(bls12381_multisig::fixture::<MinPk, _>);
        ready_notarizes_without_leader(ed25519::fixture);
        ready_notarizes_without_leader(secp256r1::fixture);
    }

    fn ready_finalizes_without_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| create_finalize(scheme, round, View::new(0), 1))
            .collect();

        for finalize in finalizes.iter() {
            verifier.add(Vote::Finalize(finalize.clone()), false);
        }

        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready without leader/proposal set"
        );

        verifier.set_leader(finalizes[0].signer());
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready without leader_proposal set"
        );
    }

    #[test]
    fn test_ready_finalizes_without_leader_or_proposal() {
        ready_finalizes_without_leader(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_finalizes_without_leader(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_finalizes_without_leader(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_finalizes_without_leader(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_finalizes_without_leader(bls12381_multisig::fixture::<MinSig, _>);
        ready_finalizes_without_leader(bls12381_multisig::fixture::<MinPk, _>);
        ready_finalizes_without_leader(ed25519::fixture);
        ready_finalizes_without_leader(secp256r1::fixture);
    }

    fn verify_notarizes_empty<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_proposal = Proposal::new(round, View::new(0), sample_digest(1));
        verifier.set_leader_proposal(leader_proposal);
        assert!(verifier.pending_notarizes.is_empty());
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_verify_notarizes_empty_pending_when_forced() {
        verify_notarizes_empty(bls12381_threshold_vrf::fixture::<MinSig, _>);
        verify_notarizes_empty(bls12381_threshold_vrf::fixture::<MinPk, _>);
        verify_notarizes_empty(bls12381_threshold_std::fixture::<MinSig, _>);
        verify_notarizes_empty(bls12381_threshold_std::fixture::<MinPk, _>);
        verify_notarizes_empty(bls12381_multisig::fixture::<MinSig, _>);
        verify_notarizes_empty(bls12381_multisig::fixture::<MinPk, _>);
        verify_notarizes_empty(ed25519::fixture);
        verify_notarizes_empty(secp256r1::fixture);
    }

    async fn verify_nullifies_empty<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        assert!(verifier.pending_nullifies.is_empty());
        assert!(!verifier.ready_nullifies());
        let (batch, failed) = verifier.verify_nullifies(&mut rng, &Sequential).await;
        assert_eq!(batch, 0);
        assert!(failed.is_empty());
        assert_eq!(verifier.verified_nullifies.len(), 0);
    }

    #[test_async]
    async fn test_verify_nullifies_empty_pending() {
        verify_nullifies_empty(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        verify_nullifies_empty(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        verify_nullifies_empty(bls12381_threshold_std::fixture::<MinSig, _>).await;
        verify_nullifies_empty(bls12381_threshold_std::fixture::<MinPk, _>).await;
        verify_nullifies_empty(bls12381_multisig::fixture::<MinSig, _>).await;
        verify_nullifies_empty(bls12381_multisig::fixture::<MinPk, _>).await;
        verify_nullifies_empty(ed25519::fixture).await;
        verify_nullifies_empty(secp256r1::fixture).await;
    }

    async fn verify_finalizes_empty<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        verifier.set_leader(Participant::new(0));
        assert!(verifier.pending_finalizes.is_empty());
        assert!(!verifier.ready_finalizes());
        let (batch, failed) = verifier.verify_finalizes(&mut rng, &Sequential).await;
        assert_eq!(batch, 0);
        assert!(failed.is_empty());
        assert_eq!(verifier.verified_finalizes.len(), 0);
    }

    #[test_async]
    async fn test_verify_finalizes_empty_pending() {
        verify_finalizes_empty(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        verify_finalizes_empty(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        verify_finalizes_empty(bls12381_threshold_std::fixture::<MinSig, _>).await;
        verify_finalizes_empty(bls12381_threshold_std::fixture::<MinPk, _>).await;
        verify_finalizes_empty(bls12381_multisig::fixture::<MinSig, _>).await;
        verify_finalizes_empty(bls12381_multisig::fixture::<MinPk, _>).await;
        verify_finalizes_empty(ed25519::fixture).await;
        verify_finalizes_empty(secp256r1::fixture).await;
    }

    async fn ready_notarizes_exact_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_vote.signer());
        verifier.add(Vote::Notarize(leader_vote), true);
        assert_eq!(verifier.verified_notarizes.len(), 1);

        for (i, scheme) in schemes.iter().enumerate().skip(1).take(quorum as usize - 1) {
            let is_last = i == quorum as usize - 1;
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                false,
            );
            if is_last {
                assert!(
                    verifier.ready_notarizes(),
                    "Should be ready at exact quorum"
                );
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.ready_notarizes());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.ready_notarizes());
            }
        }

        let (batch, failed) = verifier.verify_notarizes(&mut rng, &Sequential).await;
        assert_eq!(batch, quorum as usize - 1);
        assert!(failed.is_empty());
        assert_eq!(verifier.verified_notarizes.len(), quorum as usize);
        assert!(!verifier.ready_notarizes());
    }

    #[test_async]
    async fn test_ready_notarizes_exact_quorum() {
        ready_notarizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_notarizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_notarizes_exact_quorum(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_notarizes_exact_quorum(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_notarizes_exact_quorum(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_notarizes_exact_quorum(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_notarizes_exact_quorum(ed25519::fixture).await;
        ready_notarizes_exact_quorum(secp256r1::fixture).await;
    }

    fn ready_nullifies_exact_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        verifier.add(Vote::Nullify(create_nullify(&schemes[0], round)), true);
        assert_eq!(verifier.verified_nullifies.len(), 1);

        let pending_schemes: Vec<_> = schemes.iter().take(quorum as usize).skip(1).collect();
        for (i, scheme) in pending_schemes.iter().enumerate() {
            let is_last = i == pending_schemes.len() - 1;
            verifier.add(Vote::Nullify(create_nullify(scheme, round)), false);
            if is_last {
                assert!(verifier.ready_nullifies());
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.ready_nullifies());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.ready_nullifies());
            }
        }
    }

    #[test]
    fn test_ready_nullifies_exact_quorum() {
        ready_nullifies_exact_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_nullifies_exact_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_nullifies_exact_quorum(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_nullifies_exact_quorum(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_nullifies_exact_quorum(bls12381_multisig::fixture::<MinSig, _>);
        ready_nullifies_exact_quorum(bls12381_multisig::fixture::<MinPk, _>);
        ready_nullifies_exact_quorum(ed25519::fixture);
        ready_nullifies_exact_quorum(secp256r1::fixture);
    }

    fn ready_finalizes_exact_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_finalize = create_finalize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_finalize.signer());
        verifier.set_leader_proposal(leader_finalize.proposal.clone());
        verifier.add(Vote::Finalize(leader_finalize), true);
        assert_eq!(verifier.verified_finalizes.len(), 1);

        let pending_schemes: Vec<_> = schemes.iter().take(quorum as usize).skip(1).collect();
        for (i, scheme) in pending_schemes.iter().enumerate() {
            let is_last = i == pending_schemes.len() - 1;
            verifier.add(
                Vote::Finalize(create_finalize(scheme, round, View::new(0), 1)),
                false,
            );
            if is_last {
                assert!(verifier.ready_finalizes());
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.ready_finalizes());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.ready_finalizes());
            }
        }
    }

    #[test]
    fn test_ready_finalizes_exact_quorum() {
        ready_finalizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_finalizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_finalizes_exact_quorum(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_finalizes_exact_quorum(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_finalizes_exact_quorum(bls12381_multisig::fixture::<MinSig, _>);
        ready_finalizes_exact_quorum(bls12381_multisig::fixture::<MinPk, _>);
        ready_finalizes_exact_quorum(ed25519::fixture);
        ready_finalizes_exact_quorum(secp256r1::fixture);
    }

    fn ready_notarizes_quorum_already_met_by_verified<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        // Pre-load the leader vote as if it had already been processed.
        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_vote.signer());
        verifier.add(Vote::Notarize(leader_vote), false);

        // Mark enough verified notarizes to satisfy the quorum outright.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                true,
            );
        }
        assert_eq!(verifier.verified_notarizes.len(), quorum as usize);
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Additional pending votes must not flip readiness in this situation.
        let extra_vote = create_notarize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Notarize(extra_vote), false);
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_notarizes_quorum_already_met_by_verified() {
        ready_notarizes_quorum_already_met_by_verified(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        ready_notarizes_quorum_already_met_by_verified(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_notarizes_quorum_already_met_by_verified(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        ready_notarizes_quorum_already_met_by_verified(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_notarizes_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinSig, _>);
        ready_notarizes_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinPk, _>);
        ready_notarizes_quorum_already_met_by_verified(ed25519::fixture);
        ready_notarizes_quorum_already_met_by_verified(secp256r1::fixture);
    }

    fn ready_nullifies_quorum_already_met_by_verified<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        // First mark a quorum's worth of verified nullifies.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(Vote::Nullify(create_nullify(scheme, round)), true);
        }
        assert_eq!(verifier.verified_nullifies.len(), quorum as usize);
        assert!(
            !verifier.ready_nullifies(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Pending messages alone cannot transition the batch to ready.
        let extra_nullify = create_nullify(&schemes[quorum as usize], round);
        verifier.add(Vote::Nullify(extra_nullify), false);
        assert!(
            !verifier.ready_nullifies(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_nullifies_quorum_already_met_by_verified() {
        ready_nullifies_quorum_already_met_by_verified(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        ready_nullifies_quorum_already_met_by_verified(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_nullifies_quorum_already_met_by_verified(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        ready_nullifies_quorum_already_met_by_verified(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_nullifies_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinSig, _>);
        ready_nullifies_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinPk, _>);
        ready_nullifies_quorum_already_met_by_verified(ed25519::fixture);
        ready_nullifies_quorum_already_met_by_verified(secp256r1::fixture);
    }

    fn ready_finalizes_quorum_already_met_by_verified<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        // Prime the leader state so the quorum is already satisfied by verified finalizes.
        let leader_finalize = create_finalize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_finalize.signer());
        verifier.set_leader_proposal(leader_finalize.proposal);

        // Feed exactly the number of verified finalizes required to hit the quorum.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(
                Vote::Finalize(create_finalize(scheme, round, View::new(0), 1)),
                true,
            );
        }
        assert_eq!(verifier.verified_finalizes.len(), quorum as usize);
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Ensure additional pending finalizes do not incorrectly trigger readiness.
        let extra_finalize = create_finalize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Finalize(extra_finalize), false);
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_finalizes_quorum_already_met_by_verified() {
        ready_finalizes_quorum_already_met_by_verified(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        ready_finalizes_quorum_already_met_by_verified(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_finalizes_quorum_already_met_by_verified(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        ready_finalizes_quorum_already_met_by_verified(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_finalizes_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinSig, _>);
        ready_finalizes_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinPk, _>);
        ready_finalizes_quorum_already_met_by_verified(ed25519::fixture);
        ready_finalizes_quorum_already_met_by_verified(secp256r1::fixture);
    }
}
