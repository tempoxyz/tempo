//! Prepared proposal pacing allowance.

use std::time::Duration;

/// A prepared proposal's return allowance. This is a pacing target, not a timeout;
/// required payload work may finish after it.
#[derive(Debug)]
pub struct ProposalBudget {
    return_budget: Duration,
    /// Time the proposal needs outside the build: preparing it and reaching the voters.
    outside_build: Duration,
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
            outside_build: preparation.saturating_add(network_reservation),
            overrun_tolerance,
        }
    }

    /// Time from opening the header's proposal window until planned return.
    /// Preparation caps the allowance at one target interval after proposal entry.
    pub fn return_budget(&self) -> Duration {
        self.return_budget
    }

    /// Time from opening the header's proposal window until a returned proposal reaches the
    /// voters after `leader_timeout`, which they measure from the start of the view.
    ///
    /// Unlike [`Self::return_budget`] this is a deadline: a proposal returned later is lost to
    /// a nullified view. Zero means the deadline has already passed. Preparation is counted
    /// from the start of the proposal, so the caller subtracts any time the view had already
    /// run by then.
    pub fn build_timeout(&self, leader_timeout: Duration) -> Duration {
        leader_timeout.saturating_sub(self.outside_build)
    }

    pub(super) fn overran(&self, elapsed: Duration) -> bool {
        self.overrun_tolerance
            .is_some_and(|tolerance| elapsed > self.return_budget.saturating_add(tolerance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_timeout_leaves_time_to_prepare_and_reach_voters() {
        let budget = ProposalBudget::new(
            Duration::from_millis(550),
            Duration::from_millis(50),
            Duration::from_millis(20),
            None,
        );

        assert_eq!(
            budget.build_timeout(Duration::from_millis(1200)),
            Duration::from_millis(1130)
        );
        // A leader timeout that leaves no time to build has already passed.
        assert_eq!(
            budget.build_timeout(Duration::from_millis(60)),
            Duration::ZERO
        );
    }
}
