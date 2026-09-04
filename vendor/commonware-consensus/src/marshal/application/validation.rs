//! Shared validation helpers for marshal verification and certification.
//!
//! This module centralizes pure invariant checks shared across marshal verification
//! and certification flows.

use crate::{
    marshal::core::{Mailbox, Variant},
    types::{Epoch, Epocher, Height, Round},
};
use commonware_cryptography::certificate::Scheme;
use std::sync::Arc;

/// Which marshal cache should hold a structurally valid candidate.
///
/// This selects where candidate bytes are stored; it is not, by itself, an
/// application-validity claim. Some callers start this store after structural
/// checks and before application verification completes so the sync can overlap
/// app work. Their certification gate must still combine the app verdict with
/// store durability before allowing a finalize vote.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Stage {
    /// Store in `verified_blocks`.
    Verified,
    /// Store in `notarized_blocks`.
    Certified,
}

impl Stage {
    /// Store `block` in the marshal cache for the provided stage, returning once it
    /// is durably persisted (`false` if marshal could not accept it).
    pub(crate) async fn store<S: Scheme, V: Variant>(
        self,
        marshal: &Mailbox<S, V>,
        round: Round,
        block: Arc<V::Block>,
    ) -> bool {
        match self {
            Self::Verified => marshal.verified(round, block).await,
            Self::Certified => marshal.certified(round, block).await,
        }
    }
}

/// Returns true if the block is at an epoch boundary (last block in its epoch).
#[inline]
fn is_at_epoch_boundary<ES: Epocher>(epocher: &ES, block_height: Height, epoch: Epoch) -> bool {
    epocher.last(epoch).is_some_and(|last| last == block_height)
}

/// Returns true when a verify-time re-proposal is valid for the given epoch.
///
/// Re-proposals are only valid for the last block of the epoch.
#[inline]
pub(crate) fn is_valid_reproposal_at_verify<ES: Epocher>(
    epocher: &ES,
    block_height: Height,
    epoch: Epoch,
) -> bool {
    is_at_epoch_boundary(epocher, block_height, epoch)
}

/// Infers whether a certify-time block should be treated as a re-proposal.
///
/// During certification we may only have the block's embedded round, not the
/// consensus context used at verify time. We treat the block as a re-proposal
/// when it is an epoch-boundary block, the certify view is later than the
/// embedded view, and both rounds are in the same epoch.
#[inline]
pub(crate) fn is_inferred_reproposal_at_certify<ES: Epocher>(
    epocher: &ES,
    block_height: Height,
    embedded_round: Round,
    certify_round: Round,
) -> bool {
    is_at_epoch_boundary(epocher, block_height, embedded_round.epoch())
        && certify_round.view() > embedded_round.view()
        && certify_round.epoch() == embedded_round.epoch()
}

/// Returns true when `block_height` is mapped to `expected_epoch` by `epocher`.
///
/// If the height is not covered by the epoch strategy, this returns false.
#[inline]
pub(crate) fn is_block_in_expected_epoch<ES: Epocher>(
    epocher: &ES,
    block_height: Height,
    expected_epoch: Epoch,
) -> bool {
    epocher
        .containing(block_height)
        .is_some_and(|bounds| bounds.epoch() == expected_epoch)
}

/// Returns true when `block_height` is exactly the successor of `parent_height`.
#[inline]
pub(crate) fn has_contiguous_height(parent_height: Height, block_height: Height) -> bool {
    parent_height.next() == block_height
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FixedEpocher, View};
    use commonware_utils::NZU64;

    #[test]
    fn test_is_valid_reproposal_at_verify() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert!(is_valid_reproposal_at_verify(
            &epocher,
            Height::new(9),
            Epoch::new(0)
        ));
        assert!(!is_valid_reproposal_at_verify(
            &epocher,
            Height::new(8),
            Epoch::new(0)
        ));

        // Out-of-range epoch is never a valid re-proposal boundary.
        assert!(!is_valid_reproposal_at_verify(
            &epocher,
            Height::new(0),
            Epoch::new(u64::MAX)
        ));
    }

    #[test]
    fn test_is_inferred_reproposal_at_certify() {
        let epocher = FixedEpocher::new(NZU64!(10));
        let embedded = Round::new(Epoch::new(0), View::new(9));

        // Boundary block, later view, same epoch.
        assert!(is_inferred_reproposal_at_certify(
            &epocher,
            Height::new(9),
            embedded,
            Round::new(Epoch::new(0), View::new(10)),
        ));

        // Same view is not inferred as re-proposal.
        assert!(!is_inferred_reproposal_at_certify(
            &epocher,
            Height::new(9),
            embedded,
            Round::new(Epoch::new(0), View::new(9)),
        ));

        // Cross-epoch is not inferred as re-proposal.
        assert!(!is_inferred_reproposal_at_certify(
            &epocher,
            Height::new(9),
            embedded,
            Round::new(Epoch::new(1), View::new(10)),
        ));

        // Non-boundary block is not inferred as re-proposal, even with later view.
        assert!(!is_inferred_reproposal_at_certify(
            &epocher,
            Height::new(8),
            Round::new(Epoch::new(0), View::new(8)),
            Round::new(Epoch::new(0), View::new(9)),
        ));
    }

    #[test]
    fn test_is_block_in_expected_epoch() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert!(is_block_in_expected_epoch(
            &epocher,
            Height::new(7),
            Epoch::new(0)
        ));
        assert!(!is_block_in_expected_epoch(
            &epocher,
            Height::new(7),
            Epoch::new(1)
        ));

        // Height at u64::MAX is out of range for this epocher due to last-height overflow.
        assert!(!is_block_in_expected_epoch(
            &epocher,
            Height::new(u64::MAX),
            Epoch::new(0)
        ));
    }

    #[test]
    fn test_has_contiguous_height() {
        assert!(has_contiguous_height(Height::new(6), Height::new(7)));
        assert!(!has_contiguous_height(Height::new(6), Height::new(8)));
    }
}
