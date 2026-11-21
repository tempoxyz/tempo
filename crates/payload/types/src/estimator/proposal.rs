//! Prepared proposal pacing allowance.

use std::time::Duration;

/// A prepared proposal's return allowance. This is a pacing target, not a timeout;
/// required payload work may finish after it.
#[derive(Debug)]
pub struct ProposalBudget {
    return_budget: Duration,
    /// None in fixed-reservation mode, which records every returned proposal.
    overrun_tolerance: Option<Duration>,
}

impl ProposalBudget {
    pub(super) fn new(
        target_block_time: Duration,
        network_reservation: Duration,
        preparation: Duration,
        overrun_tolerance: Option<Duration>,
    ) -> Self {
        debug_assert!(network_reservation < target_block_time);
        Self {
            return_budget: (target_block_time - network_reservation)
                .min(target_block_time.saturating_sub(preparation)),
            overrun_tolerance,
        }
    }

    /// Time from opening the header's proposal window until planned return.
    /// Preparation caps the allowance at one target interval after proposal entry.
    pub fn return_budget(&self) -> Duration {
        self.return_budget
    }

    pub(super) fn overran(&self, elapsed: Duration) -> bool {
        self.overrun_tolerance
            .is_some_and(|tolerance| elapsed > self.return_budget.saturating_add(tolerance))
    }
}
