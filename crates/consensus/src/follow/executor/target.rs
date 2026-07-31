use commonware_consensus::types::{Height, Round};

use crate::{alias::marshal::StartupTip, consensus::Digest};

/// A possible forkchoice target.
///
/// A certificate gives us a round and digest before we know the block height.
/// Execution gives us a height and digest but no round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Target {
    pub(super) round: Option<Round>,
    pub(super) height: Option<Height>,
    pub(super) digest: Digest,
}

impl Target {
    pub(super) const fn from_execution(height: Height, digest: Digest) -> Self {
        Self {
            round: None,
            height: Some(height),
            digest,
        }
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
    use commonware_consensus::types::{Epoch, View};

    use super::*;

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn digest(byte: u8) -> Digest {
        Digest(alloy_primitives::B256::with_last_byte(byte))
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
    fn roundless_target_is_ordered_by_height() {
        let dispatched = Target::from_execution(Height::new(100), digest(1));
        let behind = Target::finalized(round(1), Height::new(50), digest(2));
        assert!(!behind.supersedes(&dispatched));

        let ahead = Target::finalized(round(1), Height::new(101), digest(3));
        assert!(ahead.supersedes(&dispatched));
    }

    #[test]
    fn certified_tip_does_not_supersede_roundless_target() {
        let dispatched = Target::from_execution(Height::new(100), digest(1));
        let certified = Target::certified(round(1), digest(2));
        assert!(!certified.supersedes(&dispatched));
    }

    #[test]
    fn certified_tip_supersedes_genesis() {
        let genesis = Target::from_execution(Height::zero(), digest(1));
        let certified = Target::certified(round(1), digest(2));
        assert!(certified.supersedes(&genesis));
    }
}
