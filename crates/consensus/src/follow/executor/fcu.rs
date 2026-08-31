//! Forkchoice policy for follower execution.
//!
//! Certificates order the head by round. Marshal-delivered blocks order finality by height.

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{
    CertifiableBlock as _, Heightable as _,
    types::{Height, Round},
};
use reth_primitives_traits::SealedHeader;
use tempo_primitives::TempoHeader;

use crate::consensus::{
    Digest,
    block::{Block, round_from_context},
};

/// Follower forkchoice state. Safe always follows finalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Forkchoice {
    head: (Round, Digest),
    finalized: (Height, Round, Digest),
}

impl Forkchoice {
    pub(super) fn new(header: &SealedHeader<TempoHeader>) -> Self {
        let tip = header.num_hash();
        let digest = Digest(tip.hash);

        // Post-activation headers carry consensus context. Round zero is a safe fallback for legacy
        // or genesis headers because any certified post-activation round supersedes it.
        let round = header
            .consensus_context
            .map(round_from_context)
            .unwrap_or_else(Round::zero);

        Self {
            head: (round, digest),
            finalized: (Height::new(tip.number), round, digest),
        }
    }

    pub(super) const fn head_digest(self) -> Digest {
        self.head.1
    }

    pub(super) const fn finalized_digest(self) -> Digest {
        self.finalized.2
    }

    pub(super) fn update_head(&mut self, round: Round, digest: Digest) {
        if round > self.finalized.1 && round > self.head.0 {
            self.head = (round, digest);
        }
    }

    pub(super) fn update_finalized(&mut self, block: &Block) -> bool {
        let height = block.height();
        if height <= self.finalized.0 {
            return false;
        }

        let digest = block.digest();

        // Post-activation blocks always carry consensus context. If one does not,
        // `context()` safely falls back to the sentinel round zero.
        let round = block.context().round;
        self.finalized = (height, round, digest);

        if self.head.0 <= round {
            self.head = (round, digest);
        }

        true
    }
}

impl From<Forkchoice> for ForkchoiceState {
    fn from(forkchoice: Forkchoice) -> Self {
        Self {
            head_block_hash: forkchoice.head_digest().0,
            safe_block_hash: forkchoice.finalized_digest().0,
            finalized_block_hash: forkchoice.finalized_digest().0,
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
        let mut forkchoice = Forkchoice::new(&execution_header(100, Some(round(8)), digest(1)));
        forkchoice.update_head(round(9), digest(2));
        assert_eq!(forkchoice.head, (round(9), digest(2)));

        forkchoice.update_head(round(8), digest(3));
        assert_eq!(forkchoice.head, (round(9), digest(2)));
    }

    #[test]
    fn equal_round_does_not_supersede() {
        let mut forkchoice = Forkchoice::new(&execution_header(100, Some(round(8)), digest(1)));
        forkchoice.update_head(round(8), digest(2));
        assert_eq!(forkchoice.head, (round(8), digest(1)));
    }

    #[test]
    fn roundless_header_uses_round_zero() {
        let header = execution_header(100, None, digest(1));
        assert_eq!(Forkchoice::new(&header).head, (Round::zero(), digest(1)));
    }

    #[test]
    fn certified_head_uses_header_round() {
        let header = execution_header(100, Some(round(2)), digest(1));
        assert_eq!(Forkchoice::new(&header).head, (round(2), digest(1)));
    }

    #[test]
    fn later_block_height_advances_finality() {
        let mut forkchoice = Forkchoice::new(&execution_header(100, None, digest(1)));
        assert!(!forkchoice.update_finalized(&execution_block(100, None)));
        assert!(forkchoice.update_finalized(&execution_block(101, None)));
        assert_eq!(forkchoice.finalized.0, Height::new(101));
    }

    #[test]
    fn certificate_advances_only_head() {
        let current = execution_header(100, Some(round(1)), digest(1));
        let mut forkchoice = Forkchoice::new(&current);

        forkchoice.update_head(round(2), digest(2));

        assert_eq!(forkchoice.head, (round(2), digest(2)));
        assert_eq!(
            forkchoice.finalized,
            (Height::new(100), round(1), digest(1))
        );
    }

    #[test]
    fn head_must_supersede_finalized_round() {
        let current = execution_header(100, Some(round(1)), digest(1));
        let mut forkchoice = Forkchoice::new(&current);
        forkchoice.update_head(round(2), digest(2));

        let finalized = execution_block(101, Some(round(2)));
        let finalized_digest = finalized.digest();
        assert!(forkchoice.update_finalized(&finalized));
        assert_eq!(forkchoice.head, (round(2), finalized_digest));

        forkchoice.update_head(round(2), digest(3));
        assert_eq!(forkchoice.head, (round(2), finalized_digest));

        forkchoice.update_head(round(3), digest(4));
        assert_eq!(forkchoice.head, (round(3), digest(4)));
    }

    #[test]
    fn roundless_block_advances_finality_without_moving_certified_head() {
        let current = execution_header(100, None, digest(1));
        let mut forkchoice = Forkchoice::new(&current);
        let certified = digest(3);
        forkchoice.update_head(round(3), certified);

        let block = execution_block(101, None);
        let block_digest = block.digest();
        assert!(forkchoice.update_finalized(&block));

        assert_eq!(forkchoice.head_digest(), certified);
        assert_eq!(forkchoice.finalized_digest(), block_digest);
    }
}
