use super::{Verifier, verifier::ProposalState};
use crate::{
    Reporter,
    simplex::{
        actors::span::ViewSpan,
        scheme::Scheme,
        types::{
            Activity, Attributable, Certificate, ConflictingFinalize, ConflictingNotarize, Kind,
            NullifyFinalize, ObservedVote, Outcome, Proposal, Vote, VoteTracker,
        },
    },
    types::{Participant, Round as Rnd},
};
use commonware_cryptography::Digest;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_utils::{N3f1, ordered::Quorum};
use rand_core::CryptoRng;
use std::sync::Arc;
use tracing::Span;

/// Per-view state for vote accumulation and certificate tracking.
pub struct Round<
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    blocker: B,
    reporter: R,
    /// The verifier attempts to recover notarizations and finalizations only
    /// from votes for one proposal. It initially filters to the first proposal
    /// observed from the known leader. Independently authenticated proposal
    /// evidence is authoritative and switches the filter.
    verifier: Verifier<S, D>,
    /// At most one vote of each kind per signer.
    ///
    /// Includes locally constructed votes and network votes that may not be
    /// verified. Used for duplicate detection, conflict reporting, and
    /// proposal-switch recovery.
    votes: VoteTracker<S, D>,

    /// Whether we've already sent the selected proposal to the voter.
    proposal_sent: bool,

    /// Root span of the view, shared with the voter's round.
    ///
    /// Pending until the voter announces the view via an update.
    span: ViewSpan,
}

impl<
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> Round<S, B, D, R>
{
    pub fn new(
        round: Rnd,
        scheme: Arc<S>,
        blocker: B,
        reporter: R,
        track_historical_votes: bool,
    ) -> Self {
        let quorum = scheme.participants().quorum::<N3f1>();
        let len = scheme.participants().len();
        Self {
            blocker,
            reporter,
            verifier: Verifier::new(round, scheme, quorum),

            votes: VoteTracker::new(len, track_historical_votes),

            proposal_sent: false,

            span: ViewSpan::new(),
        }
    }

    /// Returns the root span of the view.
    pub fn span(&self) -> Span {
        self.span.get()
    }

    /// Adopts the root span of the view from the voter.
    pub fn set_span(&mut self, span: Span) {
        self.span.adopt(span);
    }

    /// Closes the view's root span once the view is decided.
    ///
    /// The round is retained until it is no longer interesting, but its work no
    /// longer anchors a trace.
    pub fn close_span(&mut self) {
        self.span.close();
    }

    /// Returns true if we already have a certificate of `kind` for this view.
    pub const fn has_certificate(&self, kind: Kind) -> bool {
        self.verifier.has_certificate(kind)
    }

    /// Records a verified certificate.
    ///
    /// Completes its verifier phase and applies the configured vote retention
    /// policy. A notarization or finalization also establishes authoritative
    /// proposal evidence. Returns `true` when a notarization selects a new proposal,
    /// making buffered finalize votes eligible for processing.
    pub fn record_certificate(&mut self, certificate: &Certificate<S, D>) -> bool {
        let process_votes = match certificate {
            Certificate::Notarization(notarization) => {
                self.set_authoritative_proposal(&notarization.proposal)
            }
            Certificate::Finalization(finalization) => {
                // A finalization may replace the leader-selected proposal, but its
                // certificate makes reprocessing buffered finalize votes unnecessary.
                self.verifier
                    .set_proposal(ProposalState::Certificate(finalization.proposal.clone()));
                false
            }
            Certificate::Nullification(_) => false,
        };
        self.verifier.record_certificate(certificate.kind());
        self.release_votes(certificate.kind());
        process_votes
    }

    /// Applies the configured retention policy to a certified vote phase.
    fn release_votes(&mut self, kind: Kind) {
        match kind {
            Kind::Notarization => {
                let proposal = self
                    .verifier
                    .proposal()
                    .expect("notarization must establish a proposal");
                self.votes.release_notarizes(proposal);
            }
            Kind::Nullification => self.votes.release_nullifies(),
            Kind::Finalization => {
                let proposal = self
                    .verifier
                    .proposal()
                    .expect("finalization must establish a proposal");
                self.votes.release_finalizes(proposal);
            }
        }
    }

    /// Records and reports a vote after source-specific admission checks.
    ///
    /// Retained votes are forwarded to the verifier for certificate assembly.
    /// Compacted phases preserve duplicate suppression and proposal forwarding
    /// without recreating their released vote maps.
    pub(super) fn accept_vote(&mut self, message: Vote<S, D>, constructed: bool) -> Outcome {
        if constructed && let Vote::Finalize(finalize) = &message {
            // The voter only constructs a finalize after independently
            // authenticating the proposal.
            self.set_authoritative_proposal(&finalize.proposal);
        }

        let retained = match self.votes.record(&message, self.verifier.proposal()) {
            Outcome::Added { retained } => retained,
            Outcome::Duplicate { retained } => {
                if constructed && retained {
                    // Nullify is reconstructed for each retry. Notarize and finalize
                    // are one-shot local actions, so constructing either twice is a bug.
                    match &message {
                        Vote::Notarize(_) => panic!("duplicate notarize"),
                        Vote::Nullify(_) => {}
                        Vote::Finalize(_) => panic!("duplicate finalize"),
                    }
                }
                return Outcome::Duplicate { retained };
            }
            Outcome::Conflicting => {
                assert!(!constructed, "conflicting constructed vote");
                return Outcome::Conflicting;
            }
        };

        // Retained votes are signer-unique and contribute to certificate
        // assembly. Compacted phases preserve only signer facts, so new activity
        // is reported without forwarding the full vote to the verifier.
        let verifier_message = retained.then(|| message.clone());
        let activity = match message {
            Vote::Notarize(notarize) => Activity::Notarize(notarize),
            Vote::Nullify(nullify) => Activity::Nullify(nullify),
            Vote::Finalize(finalize) => Activity::Finalize(finalize),
        };
        self.reporter.report(activity);
        if let Some(message) = verifier_message {
            self.verifier.add(message, constructed);
        }
        Outcome::Added { retained }
    }

    /// Makes an independently authenticated proposal authoritative, restoring
    /// finalize votes filtered by a conflicting leader proposal.
    ///
    /// Returns whether the selected proposal changed.
    fn set_authoritative_proposal(&mut self, proposal: &Proposal<D>) -> bool {
        let update = self
            .verifier
            .set_proposal(ProposalState::Certificate(proposal.clone()));
        if update.replaced {
            // Matching tracked finalizes are unverified network votes: the conflicting
            // leader proposal filtered them, while constructed finalizes establish the
            // proposal before entering the tracker.
            for finalize in self
                .votes
                .iter_finalizes()
                .filter(|finalize| &finalize.proposal == proposal)
            {
                self.verifier.add(Vote::Finalize(finalize.clone()), false);
            }
        }
        update.changed
    }

    /// Adds a vote from the network to this round's verifier.
    pub fn add_network(&mut self, sender: S::PublicKey, message: Vote<S, D>) -> bool {
        // Check if sender is a participant
        let Some(index) = self.verifier.participants().index(&sender) else {
            commonware_p2p::block!(self.blocker, sender, "unknown participant");
            return false;
        };

        // Attempt to reserve
        match message {
            Vote::Notarize(notarize) => {
                // Verify sender is signer
                if index != notarize.signer() {
                    commonware_p2p::block!(self.blocker, sender, "notarize signer mismatch");
                    return false;
                }

                // Try to reserve
                match self.votes.notarize(index) {
                    Some(previous) => {
                        if previous.proposal != notarize.proposal {
                            let activity = ConflictingNotarize::new(previous.clone(), notarize);
                            self.reporter
                                .report(Activity::ConflictingNotarize(activity));
                            commonware_p2p::block!(self.blocker, sender, "conflicting notarize");
                        } else if previous != &notarize {
                            commonware_p2p::block!(self.blocker, sender, "invalid signature");
                        }
                        false
                    }
                    None => match self.accept_vote(Vote::Notarize(notarize), false) {
                        Outcome::Added { .. } => true,
                        Outcome::Duplicate { .. } => false,
                        Outcome::Conflicting => {
                            commonware_p2p::block!(self.blocker, sender, "conflicting notarize");
                            false
                        }
                    },
                }
            }
            Vote::Nullify(nullify) => {
                // Verify sender is signer
                if index != nullify.signer() {
                    commonware_p2p::block!(self.blocker, sender, "nullify signer mismatch");
                    return false;
                }

                // Check if finalized
                if let Some(previous) = self.votes.saw_finalize(index) {
                    if let ObservedVote::Retained(previous) = previous {
                        let activity = NullifyFinalize::new(nullify, previous.clone());
                        self.reporter.report(Activity::NullifyFinalize(activity));
                    }
                    commonware_p2p::block!(self.blocker, sender, "nullify after finalize");
                    return false;
                }

                // Try to reserve
                match self.votes.nullify(index) {
                    Some(previous) => {
                        if previous != &nullify {
                            commonware_p2p::block!(self.blocker, sender, "conflicting nullify");
                        }
                        false
                    }
                    None => match self.accept_vote(Vote::Nullify(nullify), false) {
                        Outcome::Added { .. } => true,
                        Outcome::Duplicate { .. } => false,
                        Outcome::Conflicting => {
                            unreachable!("nullify votes do not carry proposals")
                        }
                    },
                }
            }
            Vote::Finalize(finalize) => {
                // Verify sender is signer
                if index != finalize.signer() {
                    commonware_p2p::block!(self.blocker, sender, "finalize signer mismatch");
                    return false;
                }

                // Check if nullified
                if let Some(previous) = self.votes.saw_nullify(index) {
                    if let ObservedVote::Retained(previous) = previous {
                        let activity = NullifyFinalize::new(previous.clone(), finalize);
                        self.reporter.report(Activity::NullifyFinalize(activity));
                    }
                    commonware_p2p::block!(self.blocker, sender, "finalize after nullify");
                    return false;
                }

                // Try to reserve
                match self.votes.finalize(index) {
                    Some(previous) => {
                        if previous.proposal != finalize.proposal {
                            let activity = ConflictingFinalize::new(previous.clone(), finalize);
                            self.reporter
                                .report(Activity::ConflictingFinalize(activity));
                            commonware_p2p::block!(self.blocker, sender, "conflicting finalize");
                        } else if previous != &finalize {
                            commonware_p2p::block!(self.blocker, sender, "invalid signature");
                        }
                        false
                    }
                    None => match self.accept_vote(Vote::Finalize(finalize), false) {
                        Outcome::Added { .. } => true,
                        Outcome::Duplicate { .. } => false,
                        Outcome::Conflicting => {
                            commonware_p2p::block!(self.blocker, sender, "conflicting finalize");
                            false
                        }
                    },
                }
            }
        }
    }

    /// Sets the leader for this view. If the leader's notarize has already
    /// been received, this will also set the leader's proposal (filtering out
    /// votes for other proposals).
    pub fn set_leader(&mut self, leader: Participant) {
        // Certification drops the verifier's buffered notarizes, so read an
        // uncertified leader vote from the tracker.
        self.verifier
            .set_leader(leader, self.votes.notarize(leader));
    }

    /// Returns the proposal to forward to the voter, marking it sent (at most
    /// once per round). Returns `None` if we already forwarded one, the
    /// proposal is unknown, or the known leader is us.
    pub fn try_forward_proposal(&mut self, me: Participant) -> Option<Proposal<D>> {
        if self.proposal_sent {
            return None;
        }
        let proposal = self.verifier.proposal()?;
        if self.verifier.leader() == Some(me) {
            return None;
        }
        let proposal = proposal.clone();
        self.proposal_sent = true;
        Some(proposal)
    }

    /// Batch verifies the first kind of vote worth verifying (notarizes, then
    /// nullifies, then finalizes), or `None` if no kind is worthwhile.
    ///
    /// Returns the number of votes processed and the signers that failed
    /// verification.
    pub async fn try_verify<E: CryptoRng>(
        &mut self,
        rng: &mut E,
        strategy: &impl Strategy,
    ) -> Option<(usize, Vec<Participant>)> {
        if let Some(result) = self.verifier.try_verify_notarizes(rng, strategy).await {
            return Some(result);
        }
        if let Some(result) = self.verifier.try_verify_nullifies(rng, strategy).await {
            return Some(result);
        }
        self.verifier.try_verify_finalizes(rng, strategy).await
    }

    /// Returns whether `signer` has a nullify vote.
    pub fn has_nullify(&self, signer: Participant) -> bool {
        self.votes.has_nullify(signer)
    }

    /// Returns whether `participant` has not voted for `proposal` locally.
    ///
    /// Uses tracker membership, including compact state, because verification stops
    /// after the first quorum. Matching votes received later still inform forwarding.
    ///
    /// Both notarize and finalize votes are checked: a participant who sent
    /// either for the same proposal already has the block and does not need
    /// it forwarded. Votes for a conflicting proposal are treated as missing
    /// because those peers still need the winning block forwarded.
    pub fn is_missing_voter(&self, proposal: &Proposal<D>, participant: Participant) -> bool {
        if self.votes.has_notarize_for(participant, proposal) {
            return false;
        }

        !self.votes.has_finalize_for(participant, proposal)
    }

    /// Returns participant indices for which [`Self::is_missing_voter`] is true.
    pub fn missing_voters(&self, proposal: &Proposal<D>) -> Vec<Participant> {
        (0..self.verifier.participants().len())
            .map(Participant::from_usize)
            .filter(|&p| self.is_missing_voter(proposal, p))
            .collect()
    }

    /// Attempts to construct a certificate from verified votes: the first kind
    /// (notarization, then nullification, then finalization) with a verified
    /// quorum. Call repeatedly to drain every constructible kind.
    ///
    /// Once recovery starts, it consumes the verified votes. Do not cancel unless the round will
    /// also be discarded.
    pub async fn try_construct_certificate(
        &mut self,
        strategy: &impl Strategy,
    ) -> Option<Certificate<S, D>> {
        let certificate = self.verifier.try_construct_certificate(strategy).await?;
        self.record_certificate(&certificate);
        Some(certificate)
    }
}
