use commonware_consensus::types::Round;
use reth_primitives_traits::SealedHeader;
use tempo_primitives::TempoHeader;

use crate::consensus::{
    Digest,
    block::{Block, round_from_context},
};

/// A possible finalized forkchoice target.
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
    pub(super) fn supersedes(&self, current: &Self) -> bool {
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
}
