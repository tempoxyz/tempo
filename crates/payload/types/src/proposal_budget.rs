//! Proposal pacing window and preparation limit.

use std::time::Duration;

/// The proposal window derived from the current network reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalBudget {
    /// Target wall-clock time between blocks.
    pub target_block_time: Duration,
    /// Time reserved for the chain's wait after the proposal window closes:
    /// until the next leader stamps the header of the block built on top of
    /// this one.
    pub network_reserve: Duration,
    /// Local proposal return budget, counted from when the proposal window
    /// opens, the clock reading the header timestamp is taken from:
    /// `target_block_time - network_reserve`, or less after a long
    /// preparation, see [`Self::after_preparation`].
    pub return_budget: Duration,
}

impl ProposalBudget {
    /// The proposal window that `network_reserve` leaves of `target_block_time`.
    pub fn new(target_block_time: Duration, network_reserve: Duration) -> Self {
        Self {
            target_block_time,
            network_reserve,
            return_budget: target_block_time.saturating_sub(network_reserve),
        }
    }

    /// The budget of a proposal whose window opened `preparation` after the
    /// proposal started.
    ///
    /// Preparation before the header stamp belongs to the previous block's interval
    /// and is not charged against the return budget, but the peers' proposal
    /// timeout started before it, so the window still closes no later than one
    /// target block time after the proposal started.
    pub fn after_preparation(mut self, preparation: Duration) -> Self {
        self.return_budget = self
            .return_budget
            .min(self.target_block_time.saturating_sub(preparation));
        self
    }
}
