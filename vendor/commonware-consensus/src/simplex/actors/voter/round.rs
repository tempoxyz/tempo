use super::slot::{Change as ProposalChange, Slot as ProposalSlot, Status as ProposalStatus};
use crate::{
    simplex::{
        actors::span::ViewSpan,
        metrics::TimeoutReason,
        types::{Artifact, Attributable, Finalization, Notarization, Nullification, Proposal},
    },
    types::{Participant, Round as Rnd},
};
use commonware_cryptography::{certificate::Scheme, Digest, PublicKey};
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{futures::Aborter, ordered::Quorum};
use std::{
    mem::replace,
    time::{Duration, SystemTime},
};
use tracing::{debug, info_span, Span};

/// Tracks the leader of a round.
#[derive(Debug, Clone)]
pub struct Leader<P: PublicKey> {
    pub idx: Participant,
    pub key: P,
}

/// Tracks the certification state for a round.
enum CertifyState {
    /// Ready to attempt certification.
    Ready,
    /// Certification request in progress (dropped to abort).
    Outstanding(#[allow(dead_code)] Aborter),
    /// Certification completed: true if succeeded, false if automaton declined.
    Certified(bool),
    /// Certification was cancelled due to finalization.
    Aborted,
}

/// Per-[Rnd] state machine.
pub struct Round<S: Scheme, D: Digest> {
    start: SystemTime,
    scheme: S,

    round: Rnd,

    // Root span for all work attributed to this view.
    span: ViewSpan,

    // Leader is set as soon as we know the seed for the view (if any).
    leader: Option<Leader<S::PublicKey>>,

    proposal: ProposalSlot<D>,
    leader_deadline: Option<SystemTime>,
    certification_deadline: Option<SystemTime>,
    timeout_retry: Option<SystemTime>,
    timeout_reason: Option<TimeoutReason>,

    // Certificates received from batcher (constructed or from network).
    notarization: Option<Notarization<S, D>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,
    nullification: Option<Nullification<S>>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,
    finalization: Option<Finalization<S, D>>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,
    certify: CertifyState,
}

impl<S: Scheme, D: Digest> Round<S, D> {
    pub const fn new(scheme: S, round: Rnd, start: SystemTime) -> Self {
        Self {
            start,
            scheme,
            round,
            span: ViewSpan::new(),
            leader: None,
            proposal: ProposalSlot::new(),
            leader_deadline: None,
            certification_deadline: None,
            timeout_retry: None,
            timeout_reason: None,
            notarization: None,
            broadcast_notarize: false,
            broadcast_notarization: false,
            nullification: None,
            broadcast_nullify: false,
            broadcast_nullification: false,
            finalization: None,
            broadcast_finalize: false,
            broadcast_finalization: false,
            certify: CertifyState::Ready,
        }
    }

    /// Returns the leader info if we should propose.
    fn propose_ready(&self) -> Option<Leader<S::PublicKey>> {
        let leader = self.leader.as_ref()?;
        if !self.is_signer(leader.idx) || self.broadcast_nullify || !self.proposal.should_build() {
            return None;
        }
        Some(leader.clone())
    }

    /// Returns true if we should propose.
    pub fn should_propose(&self) -> bool {
        self.propose_ready().is_some()
    }

    /// Returns the leader info when we should start building a proposal locally.
    pub fn try_propose(&mut self) -> Option<Leader<S::PublicKey>> {
        let leader = self.propose_ready()?;
        self.proposal.set_building();
        Some(leader)
    }

    /// Returns the leader info if we should verify a proposal.
    fn verify_ready(&self) -> Option<&Leader<S::PublicKey>> {
        let leader = self.leader.as_ref()?;
        if self.is_signer(leader.idx) || self.broadcast_nullify {
            return None;
        }
        Some(leader)
    }

    /// Returns the leader key and proposal when the view is ready for verification.
    #[allow(clippy::type_complexity)]
    pub fn should_verify(&self) -> Option<(Leader<S::PublicKey>, Proposal<D>)> {
        let leader = self.verify_ready()?;
        let proposal = self.proposal.proposal().cloned()?;
        Some((leader.clone(), proposal))
    }

    /// Marks that verification is in-flight; returns `false` to avoid duplicate requests.
    pub fn try_verify(&mut self) -> bool {
        if self.verify_ready().is_none() {
            return false;
        }
        self.proposal.request_verify()
    }

    /// Attempt to certify this round's proposal.
    ///
    /// Returns the proposal once a notarization exists for it.
    pub fn try_certify(&mut self) -> Option<Proposal<D>> {
        let notarization = self.notarization.as_ref()?;
        match self.certify {
            CertifyState::Ready => {}
            CertifyState::Outstanding(_) | CertifyState::Certified(_) | CertifyState::Aborted => {
                return None;
            }
        }

        // The proposal must match the notarization's proposal (which
        // is overwritten, regardless of our own initial vote, during
        // processing).
        let proposal = self
            .proposal
            .proposal()
            .cloned()
            .expect("proposal must be set if notarization is set");
        assert_eq!(
            &proposal, &notarization.proposal,
            "slot proposal must match notarization proposal"
        );
        Some(proposal)
    }

    /// Sets the handle for the certification request.
    pub fn set_certify_handle(&mut self, handle: Aborter) {
        self.certify = CertifyState::Outstanding(handle);
    }

    /// Aborts the in-flight certification request.
    pub fn abort_certify(&mut self) {
        if matches!(self.certify, CertifyState::Certified(_)) {
            return;
        }
        self.certify = CertifyState::Aborted;
    }

    /// Returns the root span for all work attributed to this view.
    ///
    /// Disabled once the view is decided (see [Self::close_span]).
    pub fn span(&self) -> Span {
        self.span.get()
    }

    /// Opens the view's root span when the round becomes the active view.
    pub fn open_span(&mut self) {
        let round = self.round;
        self.span.open(|| {
            info_span!(
                parent: None,
                "simplex.voter.view",
                epoch = round.epoch().traced(),
                view = round.view().traced()
            )
        });
    }

    /// Closes the view's root span once the view is decided.
    ///
    /// The round is retained for backfill and deduplication, but its work no
    /// longer anchors a trace.
    pub fn close_span(&mut self) {
        self.span.close();
    }

    /// Returns the elected leader (if any) for this round.
    pub fn leader(&self) -> Option<Leader<S::PublicKey>> {
        self.leader.clone()
    }

    /// Returns true when the local participant controls `signer`.
    pub fn is_signer(&self, signer: Participant) -> bool {
        self.scheme.me().is_some_and(|me| me == signer)
    }

    /// Removes the leader and certification deadlines so timeouts stop firing.
    pub const fn clear_deadlines(&mut self) {
        self.leader_deadline = None;
        self.certification_deadline = None;
    }

    /// Sets the leader for this round using the pre-computed leader index.
    pub fn set_leader(&mut self, leader: Participant) {
        let key = self
            .scheme
            .participants()
            .key(leader)
            .cloned()
            .expect("leader index comes from elector, must be within bounds");
        debug!(round=?self.round, %leader, ?key, "leader elected");
        self.leader = Some(Leader { idx: leader, key });
    }

    /// Returns the notarization certificate if we already reconstructed one.
    pub const fn notarization(&self) -> Option<&Notarization<S, D>> {
        self.notarization.as_ref()
    }

    /// Returns the nullification certificate if we already reconstructed one.
    pub const fn nullification(&self) -> Option<&Nullification<S>> {
        self.nullification.as_ref()
    }

    /// Returns the finalization certificate if we already reconstructed one.
    pub const fn finalization(&self) -> Option<&Finalization<S, D>> {
        self.finalization.as_ref()
    }

    /// Returns true if we have explicitly certified the proposal.
    pub const fn is_certified(&self) -> bool {
        matches!(self.certify, CertifyState::Certified(true))
    }

    /// Returns true if certification was aborted due to finalization.
    #[cfg(test)]
    pub const fn is_certify_aborted(&self) -> bool {
        matches!(self.certify, CertifyState::Aborted)
    }

    /// Returns how much time elapsed since the round started, if the clock monotonicity holds.
    pub fn elapsed_since_start(&self, now: SystemTime) -> Duration {
        now.duration_since(self.start).unwrap_or_default()
    }

    /// Completes the local proposal flow after the automaton returns a payload.
    pub fn proposed(&mut self, proposal: Proposal<D>) -> bool {
        if self.broadcast_nullify {
            return false;
        }
        self.proposal.built(proposal);
        self.leader_deadline = None;
        true
    }

    /// Completes peer proposal verification after the automaton returns.
    ///
    /// Returns `true` if the slot was updated, `false` if we already broadcast nullify
    /// or the slot was in an invalid state (e.g., we received a certificate for a
    /// conflicting proposal).
    pub fn verified(&mut self) -> bool {
        if self.broadcast_nullify {
            return false;
        }
        if !self.proposal.mark_verified() {
            // If we receive a certificate for some proposal, we ignore our verification.
            return false;
        }
        self.leader_deadline = None;
        true
    }

    /// Sets a proposal received from the batcher (leader's first notarize vote).
    ///
    /// Returns true if the proposal should trigger verification, false otherwise.
    pub fn set_proposal(&mut self, proposal: Proposal<D>) -> bool {
        if self.broadcast_nullify {
            return false;
        }
        match self.proposal.update(&proposal, false) {
            ProposalChange::New => {
                self.leader_deadline = None;
                true
            }
            ProposalChange::Unchanged
            | ProposalChange::Equivocated { .. }
            | ProposalChange::Skipped => false,
        }
    }

    /// Marks proposal certification as complete.
    pub fn certified(&mut self, is_success: bool) {
        match &self.certify {
            CertifyState::Certified(v) => {
                assert_eq!(*v, is_success, "certification should not conflict");
                return;
            }
            CertifyState::Ready | CertifyState::Outstanding(_) | CertifyState::Aborted => {}
        }
        self.certify = CertifyState::Certified(is_success);
    }

    pub const fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.proposal()
    }

    pub const fn set_deadlines(
        &mut self,
        leader_deadline: SystemTime,
        certification_deadline: SystemTime,
    ) {
        self.leader_deadline = Some(leader_deadline);
        self.certification_deadline = Some(certification_deadline);
    }

    /// Overrides the timeout retry deadline, allowing callers to reschedule retries deterministically.
    pub const fn set_timeout_retry(&mut self, when: Option<SystemTime>) {
        self.timeout_retry = when;
    }

    /// Records the first timeout reason observed for this round.
    ///
    /// Returns `(canonical_reason, is_first_timeout)` where `is_first_timeout` is true
    /// only when this call records the first timeout reason for the round.
    pub const fn set_timeout_reason(&mut self, reason: TimeoutReason) -> (TimeoutReason, bool) {
        match self.timeout_reason {
            Some(canonical) => (canonical, false),
            None => {
                self.timeout_reason = Some(reason);
                (reason, true)
            }
        }
    }

    /// Returns a nullify vote if we should timeout/retry.
    ///
    /// Returns `Some(true)` if this is a retry (we've already broadcast nullify before),
    /// `Some(false)` if this is the first timeout for this round, and `None` if we
    /// should not timeout (e.g. because we have already finalized).
    pub const fn construct_nullify(&mut self) -> Option<bool> {
        // Ensure we haven't already broadcast a finalize vote.
        if self.broadcast_finalize {
            return None;
        }
        let retry = replace(&mut self.broadcast_nullify, true);
        self.clear_deadlines();
        self.set_timeout_retry(None);
        Some(retry)
    }

    /// Returns the next timeout deadline for the round.
    pub fn next_timeout_deadline(&mut self, now: SystemTime, retry: Duration) -> SystemTime {
        if let Some(deadline) = self.leader_deadline {
            return deadline;
        }
        if let Some(deadline) = self.certification_deadline {
            return deadline;
        }
        if let Some(deadline) = self.timeout_retry {
            return deadline;
        }
        let next = now + retry;
        self.timeout_retry = Some(next);
        next
    }

    /// Adds a proposal recovered from a certificate (notarization or finalization).
    ///
    /// Returns the leader's public key if equivocation is detected (conflicting proposals).
    pub fn add_recovered_proposal(&mut self, proposal: Proposal<D>) -> Option<S::PublicKey> {
        match self.proposal.update(&proposal, true) {
            ProposalChange::New => {
                debug!(?proposal, "setting proposal from certificate");
                self.leader_deadline = None;
                None
            }
            ProposalChange::Unchanged => None,
            ProposalChange::Equivocated { dropped, retained } => {
                // Receiving a certificate for a conflicting proposal means the
                // leader signed two different payloads for the same (epoch,
                // view).
                let equivocator = self.leader().map(|leader| leader.key);
                debug!(
                    ?equivocator,
                    ?dropped,
                    ?retained,
                    "certificate conflicts with proposal (equivocation detected)"
                );
                equivocator
            }
            ProposalChange::Skipped => None,
        }
    }

    /// Adds a verified notarization certificate to the round.
    ///
    /// Returns `(true, equivocator)` if newly added, `(false, None)` if already existed.
    /// Returns the leader's public key if equivocation is detected.
    pub fn add_notarization(
        &mut self,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        // Conflicting notarization certificates cannot exist unless safety already failed.
        // Once we've accepted one we simply ignore subsequent duplicates.
        if self.notarization.is_some() {
            return (false, None);
        }

        // Unlike nullification and finalization, we do not clear deadlines when adding a notarization (and
        // instead wait for certification to successfully complete).

        let equivocator = self.add_recovered_proposal(notarization.proposal.clone());
        self.notarization = Some(notarization);
        (true, equivocator)
    }

    /// Adds a verified nullification certificate to the round.
    ///
    /// Returns `true` if newly added, `false` if already existed.
    pub fn add_nullification(&mut self, nullification: Nullification<S>) -> bool {
        // A nullification certificate is unique per view unless safety already failed.
        if self.nullification.is_some() {
            return false;
        }
        self.clear_deadlines();
        self.nullification = Some(nullification);
        true
    }

    /// Adds a verified finalization certificate to the round.
    ///
    /// Returns `(true, equivocator)` if newly added, `(false, None)` if already existed.
    /// Returns the leader's public key if equivocation is detected.
    pub fn add_finalization(
        &mut self,
        finalization: Finalization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        // Only one finalization certificate can exist unless safety already failed, so we ignore
        // later duplicates.
        if self.finalization.is_some() {
            return (false, None);
        }
        self.clear_deadlines();

        let equivocator = self.add_recovered_proposal(finalization.proposal.clone());
        self.finalization = Some(finalization);
        (true, equivocator)
    }

    /// Returns a notarization certificate for broadcast if we have one and haven't broadcast it yet.
    pub fn broadcast_notarization(&mut self) -> Option<Notarization<S, D>> {
        if self.broadcast_notarization {
            return None;
        }
        if let Some(notarization) = &self.notarization {
            self.broadcast_notarization = true;
            return Some(notarization.clone());
        }
        None
    }

    /// Returns a nullification certificate for broadcast if we have one and haven't broadcast it yet.
    pub fn broadcast_nullification(&mut self) -> Option<Nullification<S>> {
        if self.broadcast_nullification {
            return None;
        }
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }
        None
    }

    /// Returns a finalization certificate for broadcast if we have one and haven't broadcast it yet.
    pub fn broadcast_finalization(&mut self) -> Option<Finalization<S, D>> {
        if self.broadcast_finalization {
            return None;
        }
        if let Some(finalization) = &self.finalization {
            self.broadcast_finalization = true;
            return Some(finalization.clone());
        }
        None
    }

    /// Returns a proposal candidate for notarization if we're ready to vote.
    ///
    /// Marks that we've broadcast our notarize vote to prevent duplicates.
    pub const fn construct_notarize(&mut self) -> Option<&Proposal<D>> {
        // Ensure we haven't already broadcast a notarize vote or nullify vote.
        if self.broadcast_notarize || self.broadcast_nullify {
            return None;
        }
        // Even if we've already seen a notarization, we are still willing to broadcast
        // our notarize vote in case someone is recording our activity.

        // If we don't have a verified proposal, return None.
        //
        // This check prevents us from voting for a proposal if we have observed equivocation (where
        // the proposal would be set to ProposalStatus::Equivocated) or if verification hasn't
        // completed yet.
        if !matches!(self.proposal.status(), ProposalStatus::Verified) {
            return None;
        }

        self.broadcast_notarize = true;
        self.proposal.proposal()
    }

    /// Returns a proposal candidate for finalization if we're ready to vote.
    ///
    /// Marks that we've broadcast our finalize vote to prevent duplicates.
    pub fn construct_finalize(&mut self) -> Option<&Proposal<D>> {
        // Ensure we haven't already broadcast a finalize vote or nullify vote.
        if self.broadcast_finalize || self.broadcast_nullify {
            return None;
        }
        // Even if we've already seen a finalization, we are still willing to broadcast
        // our finalize vote in case someone is recording our activity.

        // If we have a proposal and we have not yet detected equivocation, we are willing
        // to consider constructing a finalize vote.
        if !self.proposal.has_unequivocated_proposal() {
            return None;
        }

        // If there doesn't exist a notarization certificate, return None.
        self.notarization.as_ref()?;

        // If we haven't certified the proposal, return None.
        //
        // Note, this does not require verification.
        if !self.is_certified() {
            return None;
        }

        self.broadcast_finalize = true;
        self.proposal.proposal()
    }

    pub fn replay(&mut self, artifact: &Artifact<S, D>) {
        match artifact {
            Artifact::Notarize(notarize) => {
                assert!(
                    self.is_signer(notarize.signer()),
                    "replaying notarize from another signer"
                );

                // Replaying our local notarize restores a verified proposal and
                // the fact that we already voted. For leader-owned rounds, the
                // proposal was built locally; follower rounds also journal local
                // notarize votes over other leaders' proposals.
                //
                // This relies on journal replay remaining append-ordered. By the
                // time we replay a local vote for round `v`, the earlier
                // certificate for `v - 1` has already replayed and seeded this
                // round's leader.
                if self
                    .leader
                    .as_ref()
                    .is_some_and(|leader| self.is_signer(leader.idx))
                {
                    self.proposal.built(notarize.proposal.clone());
                } else {
                    self.proposal.notarized(notarize.proposal.clone());
                }
                self.broadcast_notarize = true;
            }
            Artifact::Nullify(nullify) => {
                assert!(
                    self.is_signer(nullify.signer()),
                    "replaying nullify from another signer"
                );
                self.broadcast_nullify = true;
            }
            Artifact::Finalize(finalize) => {
                assert!(
                    self.is_signer(finalize.signer()),
                    "replaying finalize from another signer"
                );
                self.broadcast_finalize = true;
            }
            Artifact::Notarization(_) => {
                self.broadcast_notarization = true;
            }
            Artifact::Nullification(_) => {
                self.broadcast_nullification = true;
            }
            Artifact::Finalization(_) => {
                self.broadcast_finalization = true;
            }
            Artifact::Certification(_, success) => {
                self.certified(*success);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{
                Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal,
            },
        },
        types::{Epoch, Participant, View},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_utils::{futures::AbortablePool, test_rng};

    #[test]
    fn equivocation_detected_on_proposal_notarization_conflict() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes,
            participants,
            verifier,
            ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let proposal_a = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            Sha256Digest::from([1u8; 32]),
        );
        let proposal_b = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            Sha256Digest::from([2u8; 32]),
        );
        let leader_scheme = schemes[0].clone();
        let mut round = Round::new(leader_scheme, proposal_a.round, SystemTime::UNIX_EPOCH);

        // Set proposal from batcher
        round.set_leader(Participant::new(0));
        assert!(round.set_proposal(proposal_a.clone()));
        assert!(round.verified());

        // Attempt to vote
        assert_eq!(round.construct_notarize(), Some(&proposal_a));
        assert!(round.construct_finalize().is_none());

        // Add conflicting notarization certificate
        let notarization_votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .map(|scheme| Notarize::sign(scheme, proposal_b.clone()).unwrap())
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (accepted, equivocator) = round.add_notarization(certificate.clone());
        assert!(accepted);
        assert!(equivocator.is_some());
        assert_eq!(equivocator.unwrap(), participants[0]);
        assert_eq!(round.broadcast_notarization(), Some(certificate));

        // Should not vote again
        assert_eq!(round.construct_notarize(), None);

        // Should not vote to finalize
        assert_eq!(round.construct_finalize(), None);
    }

    #[test]
    fn equivocation_detected_on_proposal_finalization_conflict() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes,
            participants,
            verifier,
            ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let proposal_a = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            Sha256Digest::from([1u8; 32]),
        );
        let proposal_b = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            Sha256Digest::from([2u8; 32]),
        );
        let leader_scheme = schemes[0].clone();
        let mut round = Round::new(leader_scheme, proposal_a.round, SystemTime::UNIX_EPOCH);

        // Set proposal from batcher
        round.set_leader(Participant::new(0));
        assert!(round.set_proposal(proposal_a.clone()));
        assert!(round.verified());

        // Attempt to vote
        assert_eq!(round.construct_notarize(), Some(&proposal_a));
        assert!(round.construct_finalize().is_none());

        // Add conflicting finalization certificate
        let finalization_votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .map(|scheme| Finalize::sign(scheme, proposal_b.clone()).unwrap())
            .collect();
        let certificate =
            Finalization::from_finalizes(&verifier, finalization_votes.iter(), &Sequential)
                .unwrap();
        let (accepted, equivocator) = round.add_finalization(certificate.clone());
        assert!(accepted);
        assert!(equivocator.is_some());
        assert_eq!(equivocator.unwrap(), participants[0]);
        assert_eq!(round.broadcast_finalization(), Some(certificate));

        // Add conflicting notarization certificate
        let notarization_votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .map(|scheme| Notarize::sign(scheme, proposal_b.clone()).unwrap())
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (accepted, equivocator) = round.add_notarization(certificate.clone());
        assert!(accepted);
        assert_eq!(equivocator, None); // already detected
        assert_eq!(round.broadcast_notarization(), Some(certificate));

        // Should not vote again
        assert_eq!(round.construct_notarize(), None);

        // Should not vote to finalize
        assert_eq!(round.construct_finalize(), None);
    }

    #[test]
    fn no_equivocation_on_matching_certificate() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let proposal = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            Sha256Digest::from([1u8; 32]),
        );
        let leader_scheme = schemes[0].clone();
        let mut round = Round::new(leader_scheme, proposal.round, SystemTime::UNIX_EPOCH);

        // Set proposal from batcher
        round.set_leader(Participant::new(0));
        assert!(round.set_proposal(proposal.clone()));

        // Add matching notarization certificate
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (accepted, equivocator) = round.add_notarization(certificate);
        assert!(accepted);
        assert!(equivocator.is_none());
    }

    #[test]
    fn broadcast_notarization_without_local_notarize() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([9u8; 32]));

        let mut round = Round::new(schemes[0].clone(), round_info, SystemTime::UNIX_EPOCH);
        round.set_leader(Participant::new(0));

        // Recover a certificate built entirely from remote votes.
        let notarization_votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (accepted, equivocator) = round.add_notarization(certificate.clone());
        assert!(accepted);
        assert!(equivocator.is_none());

        // Recovered certificates must not imply that we cast a local notarize vote.
        assert!(!round.broadcast_notarize);
        assert_eq!(round.construct_notarize(), None);

        // But we should still broadcast the recovered certificate.
        assert_eq!(round.broadcast_notarization(), Some(certificate));
        assert!(!round.broadcast_notarize);
        assert_eq!(round.broadcast_notarization(), None);
    }

    #[test]
    fn broadcast_finalization_without_local_finalize() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([10u8; 32]));

        let mut round = Round::new(schemes[0].clone(), round_info, SystemTime::UNIX_EPOCH);
        round.set_leader(Participant::new(0));

        // Recover a certificate built entirely from remote votes.
        let finalization_votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let certificate =
            Finalization::from_finalizes(&verifier, finalization_votes.iter(), &Sequential)
                .unwrap();
        let (accepted, equivocator) = round.add_finalization(certificate.clone());
        assert!(accepted);
        assert!(equivocator.is_none());

        // Recovered certificates must not imply that we cast a local finalize vote.
        assert!(!round.broadcast_finalize);
        assert_eq!(round.construct_finalize(), None);

        // But we should still broadcast the recovered certificate.
        assert_eq!(round.broadcast_finalization(), Some(certificate));
        assert!(!round.broadcast_finalize);
        assert_eq!(round.broadcast_finalization(), None);
    }

    #[test]
    fn replay_message_sets_broadcast_flags() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        // Setup round and proposal
        let now = SystemTime::UNIX_EPOCH;
        let view = 2;
        let round = Rnd::new(Epoch::new(5), View::new(view));
        let proposal = Proposal::new(round, View::new(0), Sha256Digest::from([40u8; 32]));

        // Create notarization
        let notarize_local = Notarize::sign(&local_scheme, proposal.clone()).expect("notarize");
        let notarize_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                .expect("notarization");

        // Create nullification
        let nullify_local = Nullify::sign::<Sha256Digest>(&local_scheme, round).expect("nullify");
        let nullify_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).expect("nullify"))
            .collect();
        let nullification = Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
            .expect("nullification");

        // Create finalize
        let finalize_local = Finalize::sign(&local_scheme, proposal.clone()).expect("finalize");
        let finalize_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_finalizes(&verifier, finalize_votes.iter(), &Sequential)
                .expect("finalization");

        // Replay messages and verify broadcast flags
        let mut round = Round::new(local_scheme, round, now);
        round.set_leader(Participant::new(0));
        round.replay(&Artifact::Notarize(notarize_local));
        assert!(round.broadcast_notarize);
        round.replay(&Artifact::Nullify(nullify_local));
        assert!(round.broadcast_nullify);
        round.replay(&Artifact::Finalize(finalize_local));
        assert!(round.broadcast_finalize);
        round.replay(&Artifact::Notarization(notarization.clone()));
        assert!(round.broadcast_notarization);
        round.replay(&Artifact::Nullification(nullification.clone()));
        assert!(round.broadcast_nullification);
        round.replay(&Artifact::Finalization(finalization.clone()));
        assert!(round.broadcast_finalization);

        // Replaying the certificate again should keep the flags set.
        round.replay(&Artifact::Notarization(notarization));
        assert!(round.broadcast_notarization);
        round.replay(&Artifact::Nullification(nullification));
        assert!(round.broadcast_nullification);
        round.replay(&Artifact::Finalization(finalization));
        assert!(round.broadcast_finalization);
    }

    /// Replaying a local notarize vote for a leader-owned proposal should
    /// restore the proposal as already verified without requesting verification.
    #[test]
    fn replayed_local_notarize_restores_verified_proposal_state() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        // Create a proposal where we (participant 0) are the leader.
        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(5), View::new(2));
        let proposal = Proposal::new(round_info, View::new(1), Sha256Digest::from([41u8; 32]));
        let notarize_local = Notarize::sign(&local_scheme, proposal.clone()).expect("notarize");

        // Replay the local notarize into a fresh round.
        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));
        round.replay(&Artifact::Notarize(notarize_local));

        // Proposal should be restored as verified (we are the leader).
        assert_eq!(round.proposal.proposal(), Some(&proposal));
        assert_eq!(round.proposal.status(), ProposalStatus::Verified);
        assert!(round.broadcast_notarize);

        // No verification request should be emitted.
        assert!(
            !round.try_verify(),
            "leader-owned replay should not request verification again"
        );

        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (added, equivocator) = round.add_notarization(notarization);
        assert!(added);
        assert!(equivocator.is_none());

        let candidate = round.try_certify().expect("certify candidate");
        assert_eq!(candidate, proposal);
    }

    #[test]
    fn construct_nullify_blocked_by_finalize() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        // Setup round and proposal
        let now = SystemTime::UNIX_EPOCH;
        let view = 2;
        let round_info = Rnd::new(Epoch::new(5), View::new(view));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([40u8; 32]));

        // Create finalized vote
        let finalize_local = Finalize::sign(&local_scheme, proposal).expect("finalize");

        // Replay finalize and verify nullify is blocked
        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));
        round.replay(&Artifact::Finalize(finalize_local));

        // Check that construct_nullify returns None
        assert!(round.construct_nullify().is_none());
    }

    #[test]
    fn try_certify_requires_notarization() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([1u8; 32]));

        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));
        assert!(round.set_proposal(proposal));
        assert!(round.verified());

        // No notarization yet - should skip
        assert!(round.try_certify().is_none());
    }

    #[test]
    fn try_certify_blocked_when_already_certified() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([1u8; 32]));

        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));
        assert!(round.set_proposal(proposal.clone()));
        assert!(round.verified());

        // Add notarization
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (added, _) = round.add_notarization(notarization);
        assert!(added);

        // First try_certify should succeed.
        let candidate = round.try_certify().expect("certify candidate");
        assert_eq!(candidate, proposal);

        // Set a certify handle then mark as certified
        let mut pool = AbortablePool::<()>::default();
        let handle = pool.push(futures::future::pending());
        round.set_certify_handle(handle);
        round.certified(true);

        // Second try_certify should skip - already certified
        assert!(round.try_certify().is_none());
    }

    #[test]
    fn try_certify_marks_locally_proposed_candidate() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([7u8; 32]));

        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));
        assert!(round.proposed(proposal.clone()));

        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (added, equivocator) = round.add_notarization(notarization);
        assert!(added);
        assert!(equivocator.is_none());

        let candidate = round.try_certify().expect("certify candidate");
        assert_eq!(candidate, proposal);
    }

    #[test]
    fn try_certify_blocked_when_handle_exists() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([1u8; 32]));

        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));
        assert!(round.set_proposal(proposal.clone()));
        assert!(round.verified());

        // Add notarization
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (added, _) = round.add_notarization(notarization);
        assert!(added);

        // First try_certify should succeed.
        let candidate = round.try_certify().expect("certify candidate");
        assert_eq!(candidate, proposal);

        // Set a certify handle (simulating in-flight certification)
        let mut pool = AbortablePool::<()>::default();
        let handle = pool.push(futures::future::pending());
        round.set_certify_handle(handle);

        // Second try_certify should skip - handle exists
        assert!(round.try_certify().is_none());
    }

    #[test]
    fn try_certify_blocked_after_abort() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([1u8; 32]));

        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));
        assert!(round.set_proposal(proposal.clone()));
        assert!(round.verified());

        // Add notarization
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (added, _) = round.add_notarization(notarization);
        assert!(added);

        // Set a certify handle
        let mut pool = AbortablePool::<()>::default();
        let handle = pool.push(futures::future::pending());
        round.set_certify_handle(handle);

        // try_certify blocked by handle
        assert!(round.try_certify().is_none());

        // Abort transitions to Aborted state
        round.abort_certify();

        // try_certify still blocked after abort (no re-certification allowed)
        assert!(round.try_certify().is_none());
    }

    #[test]
    fn try_certify_returns_proposal_from_certificate() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([1u8; 32]));

        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(1));
        // Don't set proposal yet

        // Add notarization (which includes the proposal in the certificate)
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (added, _) = round.add_notarization(notarization);
        assert!(added);

        // Has notarization and proposal came from certificate.
        let candidate = round.try_certify().expect("certify candidate");
        assert_eq!(candidate, proposal);
    }

    #[test]
    fn certified_after_abort_handles_race_condition() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([1u8; 32]));

        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));
        assert!(round.set_proposal(proposal.clone()));

        // Add notarization
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (added, _) = round.add_notarization(notarization);
        assert!(added);

        // Set a certify handle (simulating in-flight certification)
        let mut pool = AbortablePool::<()>::default();
        let handle = pool.push(futures::future::pending());
        round.set_certify_handle(handle);

        // Abort certification (simulating finalization arriving first)
        round.abort_certify();

        // Certification result arrives after abort (race condition).
        // This should not panic - the result is simply ignored.
        round.certified(true);
    }

    #[test]
    fn construct_finalize_requires_notarization() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([1u8; 32]));

        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));
        assert!(round.set_proposal(proposal.clone()));
        assert!(round.verified());

        // Construct notarize succeeds
        assert!(round.construct_notarize().is_some());

        // Certify the proposal before notarization. This should never happen in
        // practice (we only call certify after notarization) but ensures the
        // notarization check is functional.
        round.certified(true);

        // Construct finalize fails without notarization (even though certified)
        assert!(round.construct_finalize().is_none());

        // Add notarization
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (added, _) = round.add_notarization(notarization);
        assert!(added);

        // Now construct finalize succeeds
        assert!(round.construct_finalize().is_some());
    }

    #[test]
    fn construct_finalize_allows_certified_recovered_proposal() {
        let mut rng = test_rng();
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_info = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([3u8; 32]));

        let mut round = Round::new(local_scheme, round_info, now);
        round.set_leader(Participant::new(0));

        // Recover the proposal and notarization without running local verify.
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                .unwrap();
        let (added, equivocator) = round.add_notarization(notarization);
        assert!(added);
        assert!(equivocator.is_none());

        // Recovered proposals should not emit a late notarize vote.
        assert!(round.construct_notarize().is_none());

        // But a successful certification still allows us to help finalize.
        round.certified(true);
        assert!(round.construct_finalize().is_some());
    }
}
