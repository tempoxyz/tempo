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
