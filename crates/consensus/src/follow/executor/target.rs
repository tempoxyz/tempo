use commonware_consensus::types::{Height, Round};
use eyre::OptionExt as _;
use reth_primitives_traits::SealedHeader;
use tempo_primitives::TempoHeader;

use crate::{
    alias::marshal::StartupTip,
    consensus::{
        Digest,
        block::{Block, round_from_context},
    },
};

/// A possible forkchoice target.
///
/// A certificate gives us a round and digest before we know the block height.
/// Genesis is the only target without a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Target {
    pub(super) round: Option<Round>,
    pub(super) height: Option<Height>,
    pub(super) digest: Digest,
}

impl Target {
    pub(super) fn from_header(header: &SealedHeader<TempoHeader>) -> eyre::Result<Self> {
        let tip = header.num_hash();
        let round = if tip.number == 0 {
            None
        } else {
            // Followers only support post-TIP-1031 execution targets, except genesis.
            Some(
                header
                    .consensus_context
                    .map(round_from_context)
                    .ok_or_eyre("finalized execution block is missing its consensus context")?,
            )
        };
        Ok(Self {
            round,
            height: Some(Height::new(tip.number)),
            digest: Digest(tip.hash),
        })
    }

    pub(super) fn from_block(block: &Block) -> Self {
        Self::from_header(block.block().sealed_header())
            .expect("finalized execution block is missing its consensus context")
    }

    pub(super) const fn certified(round: Round, digest: Digest) -> Self {
        Self {
            round: Some(round),
            height: None,
            digest,
        }
    }

    pub(super) const fn finalized(round: Round, height: Height, digest: Digest) -> Self {
        Self {
            round: Some(round),
            height: Some(height),
            digest,
        }
    }

    /// Compares rounds when both targets have one. Otherwise, it compares
    /// heights when both targets have one. A target with only a round can
    /// replace genesis because no block can be older than genesis.
    pub(super) fn supersedes(&self, current: &Self) -> bool {
        if let (Some(new), Some(old)) = (self.round, current.round)
            && new != old
        {
            return new > old;
        }

        if let (Some(new), Some(old)) = (self.height, current.height) {
            return new > old;
        }

        self.round.is_some() && current.height == Some(Height::zero())
    }
}

impl From<StartupTip> for Target {
    fn from(tip: StartupTip) -> Self {
        Self {
            round: tip.round,
            height: Some(tip.height),
            digest: tip.digest,
        }
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
    fn rounds_take_precedence_over_heights() {
        let newer = Target::finalized(round(9), Height::new(1), digest(1));
        let older = Target::finalized(round(8), Height::new(100), digest(2));
        assert!(newer.supersedes(&older));
        assert!(!older.supersedes(&newer));
    }

    #[test]
    fn certified_tip_supersedes_a_lower_round() {
        let certified = Target::certified(round(9), digest(1));
        let finalized = Target::finalized(round(8), Height::new(80), digest(2));
        assert!(certified.supersedes(&finalized));
        assert!(!finalized.supersedes(&certified));
    }

    #[test]
    fn identical_targets_do_not_supersede() {
        let target = Target::finalized(round(8), Height::new(80), digest(1));
        assert!(!target.supersedes(&target));
    }

    #[test]
    fn equal_rounds_fall_back_to_height() {
        let higher = Target::finalized(round(8), Height::new(81), digest(1));
        let lower = Target::finalized(round(8), Height::new(80), digest(2));
        assert!(higher.supersedes(&lower));
        assert!(!lower.supersedes(&higher));
    }

    #[test]
    fn certified_tip_does_not_supersede_newer_execution_target() {
        let header = execution_header(100, Some(round(2)), digest(1));
        let dispatched = Target::from_header(&header).expect("header should have a round");
        let certified = Target::certified(round(1), digest(2));
        assert!(!certified.supersedes(&dispatched));
    }

    #[test]
    fn certified_tip_supersedes_genesis() {
        let header = execution_header(0, None, digest(1));
        let genesis = Target::from_header(&header).expect("genesis needs no round");
        let certified = Target::certified(round(1), digest(2));
        assert!(certified.supersedes(&genesis));
    }

    #[test]
    fn non_genesis_execution_target_requires_round() {
        let header = execution_header(1, None, digest(1));
        assert!(Target::from_header(&header).is_err());
    }
}
