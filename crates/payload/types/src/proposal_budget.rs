//! Proposal pacing window, preparation limit, and overrun guard.

use std::time::Duration;

use crate::estimator::DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE;

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
    /// How far the proposal may run past `return_budget` and still take a
    /// network sample, see [`crate::EstimatorConfig::return_budget_overrun_tolerance`].
    pub overrun_tolerance: Duration,
}

impl ProposalBudget {
    /// The proposal window that `network_reserve` leaves of `target_block_time`,
    /// with the default overrun tolerance.
    pub fn new(target_block_time: Duration, network_reserve: Duration) -> Self {
        Self {
            target_block_time,
            network_reserve,
            return_budget: target_block_time.saturating_sub(network_reserve),
            overrun_tolerance: DEFAULT_RETURN_BUDGET_OVERRUN_TOLERANCE,
        }
    }

    /// Sets how far the proposal may run past its return budget and still
    /// take a network sample.
    pub fn with_overrun_tolerance(mut self, overrun_tolerance: Duration) -> Self {
        self.overrun_tolerance = overrun_tolerance;
        self
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

    /// Whether a proposal that returns `spent` after its window opened
    /// overran its return budget, so that it must take no network sample,
    /// see [`crate::Estimator::on_proposal_returned`].
    ///
    /// A proposal that spent at most `overrun_tolerance` more than its return
    /// budget counts as having met it.
    pub fn overran(&self, spent: Duration) -> bool {
        spent > self.return_budget.saturating_add(self.overrun_tolerance)
    }
}
