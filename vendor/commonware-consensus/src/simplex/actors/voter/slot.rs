use crate::simplex::types::Proposal;
use commonware_cryptography::Digest;
use tracing::warn;

/// Proposal verification status within a round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    None,
    Unverified,
    Verified,
    Equivocated,
}

/// Describes how a proposal slot changed after an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change<D>
where
    D: Digest,
{
    New,
    Unchanged,
    Equivocated {
        dropped: Proposal<D>,
        retained: Proposal<D>,
    },
    Skipped,
}

/// Tracks proposal state, build/verify flags, and conflicts.
#[derive(Default)]
pub struct Slot<D>
where
    D: Digest,
{
    proposal: Option<Proposal<D>>,
    status: Status,
    requested_build: bool,
    requested_verify: bool,
}

impl<D> Slot<D>
where
    D: Digest + Clone + PartialEq,
{
    pub const fn new() -> Self {
        Self {
            proposal: None,
            status: Status::None,
            requested_build: false,
            requested_verify: false,
        }
    }

    pub const fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.as_ref()
    }

    pub const fn status(&self) -> Status {
        self.status
    }

    /// Returns whether the slot contains a concrete proposal and no equivocation.
    pub fn has_unequivocated_proposal(&self) -> bool {
        self.proposal.is_some() && self.status != Status::Equivocated
    }

    pub const fn should_build(&self) -> bool {
        !self.requested_build && self.proposal.is_none()
    }

    pub const fn set_building(&mut self) {
        self.requested_build = true;
    }

    /// Records a proposal that has already been verified.
    ///
    /// Additional observations of the same proposal are ignored here.
    /// Conflicting proposals are handled separately as equivocation.
    fn verified(&mut self, proposal: Proposal<D>) {
        if let Some(existing) = &self.proposal {
            // This can happen if we receive a certificate for a conflicting proposal. Normally,
            // we would ignore this case but it is required to support [Twins](https://arxiv.org/abs/2004.10617) testing.
            warn!(
                ?existing,
                ?proposal,
                "ignoring verified proposal because slot already populated"
            );
            return;
        }

        // Otherwise, we record the proposal and flip the build/verify flags.
        self.proposal = Some(proposal);
        self.status = Status::Verified;
        self.requested_build = true;
        self.requested_verify = true;
    }

    /// Records a proposal built locally by this participant.
    pub fn built(&mut self, proposal: Proposal<D>) {
        self.verified(proposal);
    }

    /// Records a proposal we verified and voted for, but did not build locally.
    pub fn notarized(&mut self, proposal: Proposal<D>) {
        self.verified(proposal);
    }

    pub const fn request_verify(&mut self) -> bool {
        if self.requested_verify {
            return false;
        }
        self.requested_verify = true;
        true
    }

    pub fn mark_verified(&mut self) -> bool {
        if self.status != Status::Unverified {
            return false;
        }
        self.status = Status::Verified;
        true
    }

    pub fn update(&mut self, proposal: &Proposal<D>, recovered: bool) -> Change<D> {
        // Once we detect equivocation we refuse to record any additional
        // proposals, even if they target the original payload.
        if self.status == Status::Equivocated {
            return Change::Skipped;
        }

        // Recovered certificates authenticate the proposal, but they do not
        // automatically confer verification status (which may require ensuring
        // additional data is available).
        match &self.proposal {
            None => {
                self.proposal = Some(proposal.clone());
                self.status = Status::Unverified;
                Change::New
            }
            Some(existing) if existing == proposal => Change::Unchanged,
            Some(existing) => {
                let mut dropped = existing.clone();
                let mut retained = proposal.clone();
                if recovered {
                    // If we receive a certificate for a conflicting proposal, we replace
                    // the local proposal.
                    self.proposal = Some(retained.clone());
                    self.requested_build = true;
                    self.requested_verify = true;
                } else {
                    // If this isn't a certificate, we keep the proposal as-is.
                    (retained, dropped) = (dropped, retained);
                }
                self.status = Status::Equivocated;
                Change::Equivocated { dropped, retained }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::types::Proposal,
        types::{Epoch, Round as Rnd, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;

    #[test]
    fn request_build_behavior() {
        let mut slot = Slot::<Sha256Digest>::new();
        assert!(slot.should_build());
        assert!(slot.should_build());
        slot.set_building();
        assert!(!slot.should_build());

        let mut slot = Slot::<Sha256Digest>::new();
        let round = Rnd::new(Epoch::new(7), View::new(3));
        let proposal = Proposal::new(round, View::new(2), Sha256Digest::from([1u8; 32]));
        slot.built(proposal);
        assert!(!slot.should_build());
    }

    #[test]
    fn records_proposal_with_flags() {
        let mut slot = Slot::<Sha256Digest>::new();
        assert!(slot.proposal().is_none());

        let round = Rnd::new(Epoch::new(9), View::new(1));
        let proposal = Proposal::new(round, View::new(0), Sha256Digest::from([2u8; 32]));
        slot.built(proposal.clone());

        match slot.proposal() {
            Some(stored) => assert_eq!(stored, &proposal),
            None => panic!("proposal missing after recording"),
        }
        assert_eq!(slot.status(), Status::Verified);
        assert!(!slot.should_build());
        assert!(!slot.request_verify());
    }

    #[test]
    fn records_and_prevents_duplicate_build() {
        let mut slot = Slot::<Sha256Digest>::new();
        let round = Rnd::new(Epoch::new(1), View::new(2));
        let proposal = Proposal::new(round, View::new(1), Sha256Digest::from([10u8; 32]));

        slot.built(proposal.clone());

        assert_eq!(slot.proposal(), Some(&proposal));
        assert_eq!(slot.status(), Status::Verified);
        assert!(!slot.should_build());
        assert!(!slot.request_verify());
    }

    #[test]
    fn replay_allows_existing_proposal() {
        let mut slot = Slot::<Sha256Digest>::new();
        let round = Rnd::new(Epoch::new(17), View::new(6));
        let proposal = Proposal::new(round, View::new(5), Sha256Digest::from([11u8; 32]));

        slot.built(proposal.clone());
        slot.built(proposal.clone());

        assert!(!slot.should_build());
        assert_eq!(slot.status(), Status::Verified);
        assert_eq!(slot.proposal(), Some(&proposal));
    }

    #[test]
    fn update_preserves_status_when_equal() {
        let mut slot = Slot::<Sha256Digest>::new();
        let round = Rnd::new(Epoch::new(13), View::new(2));
        let proposal = Proposal::new(round, View::new(1), Sha256Digest::from([12u8; 32]));

        assert!(matches!(slot.update(&proposal, false), Change::New));
        assert!(matches!(slot.update(&proposal, true), Change::Unchanged));
        assert_eq!(slot.status(), Status::Unverified);

        assert!(slot.mark_verified());
        assert!(matches!(slot.update(&proposal, true), Change::Unchanged));
        assert_eq!(slot.status(), Status::Verified);
    }

    #[test]
    fn certificate_then_vote_detects_equivocation() {
        let mut slot = Slot::<Sha256Digest>::new();
        let round = Rnd::new(Epoch::new(21), View::new(4));
        let proposal_a = Proposal::new(round, View::new(2), Sha256Digest::from([13u8; 32]));
        let proposal_b = Proposal::new(round, View::new(2), Sha256Digest::from([14u8; 32]));

        assert!(matches!(slot.update(&proposal_a, true), Change::New));
        let result = slot.update(&proposal_b, false);
        match result {
            Change::Equivocated { dropped, retained } => {
                assert_eq!(retained, proposal_a);
                assert_eq!(dropped, proposal_b);
            }
            other => panic!("unexpected change: {other:?}"),
        }
        assert_eq!(slot.status(), Status::Equivocated);
        assert_eq!(slot.proposal(), Some(&proposal_a));
    }

    #[test]
    fn certificate_during_pending_propose_detects_equivocation() {
        let mut slot = Slot::<Sha256Digest>::new();
        let round = Rnd::new(Epoch::new(25), View::new(8));
        let compromised = Proposal::new(round, View::new(2), Sha256Digest::from([42u8; 32]));
        let honest = Proposal::new(round, View::new(2), Sha256Digest::from([15u8; 32]));

        assert!(slot.should_build());
        slot.set_building();
        assert!(!slot.should_build());

        // Compromised node produces a certificate before our local propose returns.
        assert!(matches!(slot.update(&compromised, true), Change::New));
        assert_eq!(slot.status(), Status::Unverified);
        assert_eq!(slot.proposal(), Some(&compromised));

        // Once we finally finish proposing our honest payload, the slot should just
        // ignore it (the equivocation was already detected when the certificate
        // arrived).
        slot.built(honest);
        assert_eq!(slot.status(), Status::Unverified);
        assert_eq!(slot.proposal(), Some(&compromised));
    }

    #[test]
    fn certificate_during_pending_verify_detects_equivocation() {
        let mut slot = Slot::<Sha256Digest>::new();
        let round = Rnd::new(Epoch::new(26), View::new(9));
        let leader_proposal = Proposal::new(round, View::new(4), Sha256Digest::from([16u8; 32]));
        let conflicting = Proposal::new(round, View::new(4), Sha256Digest::from([99u8; 32]));

        assert!(matches!(slot.update(&leader_proposal, false), Change::New));
        assert_eq!(slot.status(), Status::Unverified);
        assert!(slot.request_verify());
        assert!(!slot.request_verify());

        let change = slot.update(&conflicting, true);
        match change {
            Change::Equivocated { dropped, retained } => {
                assert_eq!(dropped, leader_proposal);
                assert_eq!(retained, conflicting);
            }
            other => panic!("expected equivocation, got {other:?}"),
        }
        assert_eq!(slot.status(), Status::Equivocated);
        // Verifier completion arriving afterwards must be ignored.
        assert!(!slot.mark_verified());
        assert!(matches!(slot.update(&conflicting, true), Change::Skipped));
    }

    #[test]
    fn certificates_override_votes() {
        let mut slot = Slot::<Sha256Digest>::new();
        let round = Rnd::new(Epoch::new(21), View::new(4));
        let proposal_a = Proposal::new(round, View::new(2), Sha256Digest::from([15u8; 32]));
        let proposal_b = Proposal::new(round, View::new(2), Sha256Digest::from([16u8; 32]));

        assert!(matches!(slot.update(&proposal_a, false), Change::New));
        match slot.update(&proposal_b, true) {
            Change::Equivocated { dropped, retained } => {
                assert_eq!(dropped, proposal_a);
                assert_eq!(retained, proposal_b);
            }
            other => panic!("certificate should override votes, got {other:?}"),
        }
        assert_eq!(slot.status(), Status::Equivocated);
        assert_eq!(slot.proposal(), Some(&proposal_b));
        assert!(!slot.should_build());
    }

    #[test]
    fn certificate_does_not_clear_equivocated() {
        let mut slot = Slot::<Sha256Digest>::new();
        let round = Rnd::new(Epoch::new(25), View::new(7));
        let proposal_a = Proposal::new(round, View::new(3), Sha256Digest::from([17u8; 32]));
        let proposal_b = Proposal::new(round, View::new(3), Sha256Digest::from([18u8; 32]));

        assert!(matches!(slot.update(&proposal_a, false), Change::New));
        assert!(matches!(
            slot.update(&proposal_b, true),
            Change::Equivocated { .. }
        ));
        assert!(matches!(slot.update(&proposal_b, true), Change::Skipped));
        assert_eq!(slot.status(), Status::Equivocated);
    }

    #[test]
    fn has_unequivocated_proposal_allows_recovered_unverified_and_blocks_equivocation() {
        let round = Rnd::new(Epoch::new(30), View::new(10));
        let proposal_a = Proposal::new(round, View::new(9), Sha256Digest::from([21u8; 32]));
        let proposal_b = Proposal::new(round, View::new(9), Sha256Digest::from([22u8; 32]));

        // Empty slots should not report a usable proposal.
        let mut slot = Slot::<Sha256Digest>::new();
        assert!(!slot.has_unequivocated_proposal());

        // Recovering a proposal from a certificate makes it available for finalize
        // gating even before the follower-side verify path runs.
        assert!(matches!(slot.update(&proposal_a, true), Change::New));
        assert!(slot.has_unequivocated_proposal());

        // A conflicting proposal immediately revokes that property.
        assert!(matches!(
            slot.update(&proposal_b, false),
            Change::Equivocated { .. }
        ));
        assert!(!slot.has_unequivocated_proposal());
    }
}
