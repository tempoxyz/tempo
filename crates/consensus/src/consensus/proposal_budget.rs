//! Consensus proposal pacing policy.

use std::time::Duration;

/// The pacing allowance counted from a monotonic sample alongside the header timestamp.
///
/// Preparation before that sample is excluded from the normal allowance, but reduces
/// it when necessary to keep the planned deadline within one target interval of
/// proposal entry. Required build work can overrun this allowance; it is not a timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalBudget {
    target_block_time: Duration,
    post_header_allowance: Duration,
}

impl ProposalBudget {
    /// Reserves `network_budget` from the target block interval for propagation.
    ///
    /// The pacing allowance is zero when the network budget equals or exceeds the
    /// target interval. Zero allowances do not cancel required build work.
    pub fn new(target_block_time: Duration, network_budget: Duration) -> Self {
        Self {
            target_block_time,
            post_header_allowance: target_block_time.saturating_sub(network_budget),
        }
    }

    /// Returns the allowance after monotonically measured preparation.
    pub(crate) fn pacing_allowance(&self, preparation: Duration) -> Duration {
        self.post_header_allowance
            .min(self.target_block_time.saturating_sub(preparation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::PacingClock as _;
    use commonware_runtime::{Clock as _, Runner as _, deterministic};

    #[test]
    fn preparation_caps_the_post_header_allowance() {
        let budget = ProposalBudget::new(Duration::from_millis(500), Duration::from_millis(50));
        for (preparation, expected) in [
            (0, 450),
            (50, 450),
            (100, 400),
            (499, 1),
            (500, 0),
            (600, 0),
        ] {
            assert_eq!(
                budget.pacing_allowance(Duration::from_millis(preparation)),
                Duration::from_millis(expected),
            );
        }
    }

    #[test]
    fn exhausted_network_budget_leaves_no_pacing_allowance() {
        for (target, network) in [(500, 500), (500, 600), (0, 0)] {
            let budget = ProposalBudget::new(
                Duration::from_millis(target),
                Duration::from_millis(network),
            );
            assert_eq!(budget.pacing_allowance(Duration::ZERO), Duration::ZERO);
        }
    }

    #[test]
    fn preparation_uses_the_injected_clock() {
        deterministic::Runner::default().start(|context| async move {
            let budget = ProposalBudget::new(Duration::from_millis(500), Duration::from_millis(50));
            let started = context.pacing_now();
            context.sleep(Duration::from_millis(600)).await;
            assert_eq!(
                budget.pacing_allowance(context.pacing_elapsed(started)),
                Duration::ZERO
            );
        });
    }
}
