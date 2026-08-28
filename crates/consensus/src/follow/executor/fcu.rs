use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::types::{Height, Round};
use reth_primitives_traits::SealedHeader;
use tempo_primitives::TempoHeader;

use crate::consensus::{
    Digest,
    block::{Block, round_from_context},
};

/// A certified head, ordered by consensus round.
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

    fn from_block(block: &Block) -> Option<Self> {
        Self::from_header(block.block().sealed_header())
    }

    const fn from_finalization(round: Round, digest: Digest) -> Self {
        Self { round, digest }
    }

    fn supersedes(self, current: Self) -> bool {
        self.round > current.round
    }
}

/// A persisted block, ordered by execution height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DurableFinality {
    height: Height,
    digest: Digest,
}

impl DurableFinality {
    fn from_header(header: &SealedHeader<TempoHeader>) -> Self {
        let tip = header.num_hash();
        Self {
            height: Height::new(tip.number),
            digest: Digest(tip.hash),
        }
    }

    fn from_block(block: &Block) -> Self {
        Self::from_header(block.block().sealed_header())
    }

    fn supersedes(self, current: Self) -> bool {
        self.height > current.height
    }
}

/// Hashes sent in one Engine API forkchoice update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ForkchoiceTargets {
    pub(super) head: Digest,
    pub(super) finalized: Digest,
}

impl ForkchoiceTargets {
    fn anchored(target: DurableFinality) -> Self {
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

/// FCUs needed after a block advances durable finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FinalityPlan {
    pub(super) preferred: ForkchoiceTargets,
    pub(super) anchor: ForkchoiceTargets,
}

/// Forkchoice work associated with one delivered block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BlockForkchoice {
    None,
    Guide(ForkchoiceTargets),
    Finalize(FinalityPlan),
}

/// Forkchoice progress across certified heads and persisted blocks.
pub(super) struct ForkchoiceTracker {
    submitted: ForkchoiceTargets,
    head: Option<CertifiedHead>,
    finalized: DurableFinality,
}

impl ForkchoiceTracker {
    pub(super) fn new(header: &SealedHeader<TempoHeader>) -> Self {
        let head = CertifiedHead::from_header(header);
        let finalized = DurableFinality::from_header(header);
        let submitted = Self::targets(head, finalized);
        Self {
            submitted,
            head,
            finalized,
        }
    }

    /// Moves the head to a later verified certificate.
    pub(super) fn observe_certificate(&mut self, round: Round, digest: Digest) {
        let candidate = CertifiedHead::from_finalization(round, digest);
        if self
            .head
            .is_none_or(|current| candidate.supersedes(current))
        {
            self.head = Some(candidate);
        }
    }

    /// Plans the forkchoice work for one delivered block.
    pub(super) fn plan_block(&mut self, block: &Block, force: bool) -> BlockForkchoice {
        let candidate = DurableFinality::from_block(block);
        let advances_finality = candidate.supersedes(self.finalized);
        if advances_finality {
            self.finalized = candidate;
            if let Some(head) = CertifiedHead::from_block(block) {
                self.observe_certificate(head.round, head.digest);
            }
        }

        let preferred = self.desired();
        if advances_finality {
            return BlockForkchoice::Finalize(FinalityPlan {
                preferred,
                anchor: ForkchoiceTargets::anchored(candidate),
            });
        }

        if preferred != self.submitted || force {
            BlockForkchoice::Guide(preferred)
        } else {
            BlockForkchoice::None
        }
    }

    /// Returns the current targets when an update or heartbeat is due.
    pub(super) fn plan_update(&self, force: bool) -> Option<ForkchoiceTargets> {
        let desired = self.desired();
        (desired != self.submitted || force).then_some(desired)
    }

    /// Saves the targets from the last completed forkchoice request.
    pub(super) fn note_submitted(&mut self, submitted: ForkchoiceTargets) {
        self.submitted = submitted;
    }

    fn desired(&self) -> ForkchoiceTargets {
        Self::targets(self.head, self.finalized)
    }

    fn targets(head: Option<CertifiedHead>, finalized: DurableFinality) -> ForkchoiceTargets {
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
        let newer = CertifiedHead::from_finalization(round(9), digest(1));
        let older = CertifiedHead::from_finalization(round(8), digest(2));
        assert!(newer.supersedes(older));
        assert!(!older.supersedes(newer));
    }

    #[test]
    fn equal_round_does_not_supersede() {
        let current = CertifiedHead::from_finalization(round(8), digest(1));
        let conflicting = CertifiedHead::from_finalization(round(8), digest(2));
        assert!(!conflicting.supersedes(current));
    }

    #[test]
    fn roundless_header_has_no_certified_head() {
        let header = execution_header(100, None, digest(1));
        assert_eq!(CertifiedHead::from_header(&header), None);
    }

    #[test]
    fn execution_head_uses_header_round() {
        let header = execution_header(100, Some(round(2)), digest(1));
        assert_eq!(CertifiedHead::from_header(&header).unwrap().round, round(2));
    }

    #[test]
    fn later_durable_height_supersedes() {
        let current = DurableFinality::from_header(&execution_header(100, None, digest(1)));
        let conflicting = DurableFinality::from_header(&execution_header(100, None, digest(3)));
        let newer = DurableFinality::from_header(&execution_header(101, None, digest(2)));
        assert!(newer.supersedes(current));
        assert!(!current.supersedes(newer));
        assert!(!conflicting.supersedes(current));
    }

    #[test]
    fn certified_target_advances_only_head() {
        let current = execution_header(100, Some(round(1)), digest(1));
        let mut tracker = ForkchoiceTracker::new(&current);

        tracker.observe_certificate(round(2), digest(2));

        assert_eq!(
            tracker.plan_update(false),
            Some(ForkchoiceTargets {
                head: digest(2),
                finalized: digest(1),
            })
        );
    }

    #[test]
    fn roundless_durable_block_keeps_certified_head_and_builds_anchor() {
        let current = execution_header(100, None, digest(1));
        let mut tracker = ForkchoiceTracker::new(&current);
        let certified = digest(3);
        tracker.observe_certificate(round(3), certified);

        let block = execution_block(101, None);
        let durable = block.digest();
        let BlockForkchoice::Finalize(plan) = tracker.plan_block(&block, false) else {
            panic!("a later durable block should require finality work");
        };

        assert_eq!(
            plan,
            FinalityPlan {
                preferred: ForkchoiceTargets {
                    head: certified,
                    finalized: durable,
                },
                anchor: ForkchoiceTargets {
                    head: durable,
                    finalized: durable,
                },
            }
        );

        tracker.note_submitted(plan.anchor);
        assert_eq!(tracker.plan_update(false), Some(plan.preferred));

        tracker.note_submitted(plan.preferred);
        assert_eq!(tracker.plan_update(false), None);
    }
}
