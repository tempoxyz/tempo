use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::types::Round;
use reth_primitives_traits::SealedHeader;
use tempo_primitives::TempoHeader;

use crate::consensus::{
    Digest,
    block::{Block, round_from_context},
};

/// A forkchoice target ordered by its consensus finalization round.
///
/// Execution headers before TIP-1031 do not contain a consensus round. After
/// activation, every newly observed finalization has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Target {
    pub(super) round: Option<Round>,
    pub(super) digest: Digest,
}

impl Target {
    pub(super) fn from_header(header: &SealedHeader<TempoHeader>) -> Self {
        let tip = header.num_hash();
        Self {
            round: header.consensus_context.map(round_from_context),
            digest: Digest(tip.hash),
        }
    }

    pub(super) fn from_block(block: &Block) -> Self {
        Self::from_header(block.block().sealed_header())
    }

    pub(super) const fn from_finalization(round: Round, digest: Digest) -> Self {
        Self {
            round: Some(round),
            digest,
        }
    }

    /// Newly observed finalizations are post-TIP-1031 and always have a round.
    /// They therefore supersede a roundless genesis or pre-activation target.
    fn supersedes(&self, current: &Self) -> bool {
        match (self.round, current.round) {
            (Some(new), Some(old)) => new > old,
            // TIP-1031 is active. In supported startup states, a roundless
            // execution target is genesis; restoring partially synchronized
            // pre-TIP execution state is unsupported. Any newly verified
            // finalization therefore supersedes it.
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// Forkchoice targets tracked by the follower executor.
///
/// This represents the `(head, safe, finalized)` tuple accepted by Engine API
/// `forkchoiceUpdated`, with `safe` equal to `finalized`.
///
/// `head` follows the latest verified finalization certificate and can refer to
/// a block that marshal has not delivered yet. Setting it tells Reth to sync
/// toward that block. `finalized` follows marshal's ordered block delivery after
/// the executor submits the block as a payload.
///
/// The head target is always at least as new as the finalized target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ForkchoiceTargets {
    pub(super) head: Target,
    pub(super) finalized: Target,
}

impl ForkchoiceTargets {
    const fn new(target: Target) -> Self {
        Self {
            head: target,
            finalized: target,
        }
    }

    fn advance_head(&mut self, candidate: Target) {
        advance(&mut self.head, candidate);
    }

    fn advance_finalized(&mut self, candidate: Target) -> bool {
        let advanced = advance(&mut self.finalized, candidate);
        advance(&mut self.head, candidate);
        advanced
    }

    pub(super) fn rpc_state(self) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: self.head.digest.0,
            safe_block_hash: self.finalized.digest.0,
            finalized_block_hash: self.finalized.digest.0,
        }
    }
}

fn advance(current: &mut Target, candidate: Target) -> bool {
    if candidate.supersedes(current) {
        *current = candidate;
        true
    } else {
        false
    }
}

/// Forkchoice progress across submitted and latest targets.
pub(super) struct ForkchoiceTracker {
    submitted: ForkchoiceTargets,
    latest: ForkchoiceTargets,
}

impl ForkchoiceTracker {
    /// Creates a new tracker with the given target as both submitted and latest.
    pub(super) const fn new(target: Target) -> Self {
        let targets = ForkchoiceTargets::new(target);
        Self {
            submitted: targets,
            latest: targets,
        }
    }

    /// Moves the latest head to a later verified finalization.
    ///
    /// Finalizations can arrive out of order, so stale and equal-round targets are
    /// ignored.
    pub(super) fn advance_head(&mut self, candidate: Target) {
        self.latest.advance_head(candidate);
    }

    /// Moves the latest finalized target to a later block delivered by marshal.
    ///
    /// This also advances the head when needed, so finalized never moves ahead of
    /// head. Returns whether the finalized target advanced.
    pub(super) fn advance_finalized(&mut self, candidate: Target) -> bool {
        self.latest.advance_finalized(candidate)
    }

    /// Returns `true` if the latest targets have changed since the last known submitted state.
    pub(super) fn requires_update(&self) -> bool {
        self.latest != self.submitted
    }

    /// Returns the targets selected by [`Self::advance_head`] and
    /// [`Self::advance_finalized`] for the next forkchoice update.
    pub(super) const fn latest(&self) -> ForkchoiceTargets {
        self.latest
    }

    /// Saves the given targets as the last known submitted state.
    pub(super) fn note_submitted(&mut self, submitted: ForkchoiceTargets) {
        self.submitted = submitted;
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use commonware_consensus::types::{Epoch, View};
    use reth_primitives_traits::SealedHeader;
    use tempo_primitives::{TempoConsensusContext, TempoHeader, ed25519::PublicKey};

    use super::*;

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn digest(byte: u8) -> Digest {
        Digest(alloy_primitives::B256::with_last_byte(byte))
    }

    fn execution_header(
        height: u64,
        round: Option<Round>,
        digest: Digest,
    ) -> SealedHeader<TempoHeader> {
        let consensus_context = round.map(|round| TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: 0,
            proposer: PublicKey::from_seed(0),
        });
        SealedHeader::new(
            TempoHeader {
                inner: Header {
                    number: height,
                    ..Default::default()
                },
                consensus_context,
                ..Default::default()
            },
            digest.0,
        )
    }

    #[test]
    fn later_round_supersedes_earlier_round() {
        let newer = Target::from_finalization(round(9), digest(1));
        let older = Target::from_finalization(round(8), digest(2));
        assert!(newer.supersedes(&older));
        assert!(!older.supersedes(&newer));
    }

    #[test]
    fn equal_round_does_not_supersede() {
        let current = Target::from_finalization(round(8), digest(1));
        let conflicting = Target::from_finalization(round(8), digest(2));
        assert!(!conflicting.supersedes(&current));
    }

    #[test]
    fn finalized_target_supersedes_roundless_execution_target() {
        let header = execution_header(100, None, digest(1));
        let prefork = Target::from_header(&header);
        let finalized = Target::from_finalization(round(1), digest(2));
        assert!(finalized.supersedes(&prefork));
    }

    #[test]
    fn roundless_target_never_supersedes() {
        let roundless = Target::from_header(&execution_header(100, None, digest(1)));
        let finalized = Target::from_finalization(round(1), digest(2));
        assert!(!roundless.supersedes(&finalized));
        assert!(!roundless.supersedes(&roundless));
    }

    #[test]
    fn execution_target_uses_header_round() {
        let header = execution_header(100, Some(round(2)), digest(1));
        assert_eq!(Target::from_header(&header).round, Some(round(2)));
    }

    #[test]
    fn certified_target_advances_only_head() {
        let current = Target::from_finalization(round(1), digest(1));
        let mut tracker = ForkchoiceTracker::new(current);
        let candidate = Target::from_finalization(round(2), digest(2));

        tracker.advance_head(candidate);

        let targets = tracker.latest();
        assert_eq!(targets.head, candidate);
        assert_eq!(targets.finalized, current);
        assert!(tracker.requires_update());
    }

    #[test]
    fn durable_target_advances_both_lanes() {
        let current = Target::from_finalization(round(1), digest(1));
        let head = Target::from_finalization(round(3), digest(3));
        let finalized = Target::from_finalization(round(2), digest(2));
        let mut tracker = ForkchoiceTracker::new(current);
        tracker.advance_head(head);

        assert!(tracker.advance_finalized(finalized));

        let targets = tracker.latest();
        assert_eq!(targets.head, head);
        assert_eq!(targets.finalized, finalized);
    }

    #[test]
    fn finalized_lane_requires_update_when_head_is_unchanged() {
        let current = Target::from_finalization(round(1), digest(1));
        let head = Target::from_finalization(round(2), digest(2));
        let mut tracker = ForkchoiceTracker::new(current);
        tracker.advance_head(head);
        tracker.note_submitted(tracker.latest());
        assert!(!tracker.requires_update());

        assert!(tracker.advance_finalized(head));

        assert!(tracker.requires_update());
    }
}
