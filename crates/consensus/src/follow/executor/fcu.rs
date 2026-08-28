//! Forkchoice policy for follower execution.
//!
//! Certificates order the head by round. Marshal-delivered blocks order finality by height.

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::types::{Height, Round};
use reth_primitives_traits::SealedHeader;
use tempo_primitives::TempoHeader;

use crate::consensus::{
    Digest,
    block::{Block, round_from_context},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CertifiedHead {
    round: Round,
    digest: Digest,
}

impl CertifiedHead {
    fn from_header(header: &SealedHeader<TempoHeader>) -> Option<Self> {
        let round = header.consensus_context.map(round_from_context)?;
        Some(Self {
            round,
            digest: Digest(header.hash()),
        })
    }

    const fn from_certificate(round: Round, digest: Digest) -> Self {
        Self { round, digest }
    }

    fn supersedes(self, current: Self) -> bool {
        self.round > current.round
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FinalityTarget {
    height: Height,
    digest: Digest,
}

impl FinalityTarget {
    fn from_header(header: &SealedHeader<TempoHeader>) -> Self {
        let tip = header.num_hash();
        Self {
            height: Height::new(tip.number),
            digest: Digest(tip.hash),
        }
    }

    fn supersedes(self, current: Self) -> bool {
        self.height > current.height
    }
}

/// Engine API targets. Safe always follows finalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ForkchoiceTargets {
    pub(super) head: Digest,
    pub(super) finalized: Digest,
}

impl ForkchoiceTargets {
    fn anchored(target: FinalityTarget) -> Self {
        Self {
            head: target.digest,
            finalized: target.digest,
        }
    }

    pub(super) fn rpc_state(self) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: self.head.0,
            safe_block_hash: self.finalized.0,
            finalized_block_hash: self.finalized.0,
        }
    }
}

/// Preferred targets keep the certified head. If Reth reports `SYNCING`, the executor retries the
/// block anchor until `VALID` before it acknowledges the block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FinalityPlan {
    pub(super) preferred: ForkchoiceTargets,
    pub(super) block_anchor: ForkchoiceTargets,
}

pub(super) struct ForkchoiceTracker {
    submitted: ForkchoiceTargets,
    certified_head: Option<CertifiedHead>,
    finalized: FinalityTarget,
}

impl ForkchoiceTracker {
    pub(super) fn new(header: &SealedHeader<TempoHeader>) -> Self {
        let certified_head = CertifiedHead::from_header(header);
        let finalized = FinalityTarget::from_header(header);
        let submitted = Self::targets(certified_head, finalized);
        Self {
            submitted,
            certified_head,
            finalized,
        }
    }

    pub(super) fn observe_finalization(&mut self, round: Round, digest: Digest) {
        let candidate = CertifiedHead::from_certificate(round, digest);
        if self
            .certified_head
            .is_none_or(|current| candidate.supersedes(current))
        {
            self.certified_head = Some(candidate);
        }
    }

    pub(super) fn observe_block(&mut self, block: &Block) -> Option<FinalityPlan> {
        let header = block.block().sealed_header();
        let candidate = FinalityTarget::from_header(header);
        if !candidate.supersedes(self.finalized) {
            // Replayed blocks cannot move the certified head, even when their header has a later
            // round.
            return None;
        }

        self.finalized = candidate;
        if let Some(head) = CertifiedHead::from_header(header) {
            self.observe_finalization(head.round, head.digest);
        }

        Some(FinalityPlan {
            preferred: self.desired(),
            block_anchor: ForkchoiceTargets::anchored(candidate),
        })
    }

    pub(super) fn next_head_update(&self, heartbeat_due: bool) -> Option<ForkchoiceTargets> {
        let desired = self.desired();
        (desired != self.submitted || heartbeat_due).then_some(desired)
    }

    pub(super) fn note_submitted(&mut self, submitted: ForkchoiceTargets) {
        self.submitted = submitted;
    }

    fn desired(&self) -> ForkchoiceTargets {
        Self::targets(self.certified_head, self.finalized)
    }

    fn targets(head: Option<CertifiedHead>, finalized: FinalityTarget) -> ForkchoiceTargets {
        ForkchoiceTargets {
            head: head.map_or(finalized.digest, |target| target.digest),
            finalized: finalized.digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use commonware_consensus::types::{Epoch, View};
    use reth_node_core::primitives::SealedBlock;
    use reth_primitives_traits::SealedHeader;
    use tempo_primitives::{
        Block as TempoBlock, BlockBody, TempoConsensusContext, TempoHeader, ed25519::PublicKey,
    };

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
        SealedHeader::new(tempo_header(height, round), digest.0)
    }

    fn execution_block(height: u64, round: Option<Round>) -> Block {
        let block = TempoBlock {
            header: tempo_header(height, round),
            body: BlockBody::default(),
        };
        Block::from_execution_block(SealedBlock::seal_slow(block), None)
            .expect("test block should not contain BAL side data")
    }

    fn tempo_header(height: u64, round: Option<Round>) -> TempoHeader {
        let consensus_context = round.map(|round| TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: 0,
            proposer: PublicKey::from_seed(0),
        });
        TempoHeader {
            inner: Header {
                number: height,
                ..Default::default()
            },
            consensus_context,
            ..Default::default()
        }
    }

    #[test]
    fn later_round_supersedes_earlier_round() {
        let newer = CertifiedHead::from_certificate(round(9), digest(1));
        let older = CertifiedHead::from_certificate(round(8), digest(2));
        assert!(newer.supersedes(older));
        assert!(!older.supersedes(newer));
    }

    #[test]
    fn equal_round_does_not_supersede() {
        let current = CertifiedHead::from_certificate(round(8), digest(1));
        let conflicting = CertifiedHead::from_certificate(round(8), digest(2));
        assert!(!conflicting.supersedes(current));
    }

    #[test]
    fn roundless_header_has_no_certified_head() {
        let header = execution_header(100, None, digest(1));
        assert_eq!(CertifiedHead::from_header(&header), None);
    }

    #[test]
    fn certified_head_uses_header_round() {
        let header = execution_header(100, Some(round(2)), digest(1));
        assert_eq!(CertifiedHead::from_header(&header).unwrap().round, round(2));
    }

    #[test]
    fn later_block_height_supersedes_finality_target() {
        let current = FinalityTarget::from_header(&execution_header(100, None, digest(1)));
        let conflicting = FinalityTarget::from_header(&execution_header(100, None, digest(3)));
        let newer = FinalityTarget::from_header(&execution_header(101, None, digest(2)));
        assert!(newer.supersedes(current));
        assert!(!current.supersedes(newer));
        assert!(!conflicting.supersedes(current));
    }

    #[test]
    fn certificate_advances_only_head() {
        let current = execution_header(100, Some(round(1)), digest(1));
        let mut tracker = ForkchoiceTracker::new(&current);

        tracker.observe_finalization(round(2), digest(2));

        assert_eq!(
            tracker.next_head_update(false),
            Some(ForkchoiceTargets {
                head: digest(2),
                finalized: digest(1),
            })
        );
    }

    #[test]
    fn roundless_block_builds_finality_plan_without_moving_certified_head() {
        let current = execution_header(100, None, digest(1));
        let mut tracker = ForkchoiceTracker::new(&current);
        let certified = digest(3);
        tracker.observe_finalization(round(3), certified);

        let block = execution_block(101, None);
        let block_digest = block.digest();
        let plan = tracker
            .observe_block(&block)
            .expect("a later block should require finality work");

        assert_eq!(
            plan,
            FinalityPlan {
                preferred: ForkchoiceTargets {
                    head: certified,
                    finalized: block_digest,
                },
                block_anchor: ForkchoiceTargets {
                    head: block_digest,
                    finalized: block_digest,
                },
            }
        );

        tracker.note_submitted(plan.block_anchor);
        assert_eq!(tracker.next_head_update(false), Some(plan.preferred));

        tracker.note_submitted(plan.preferred);
        assert_eq!(tracker.next_head_update(false), None);
    }
}
