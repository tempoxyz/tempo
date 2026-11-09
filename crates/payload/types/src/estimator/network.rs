//! Network reservation learned from finalized successors of own proposals.

use super::{
    ProposalKey, ProposalTiming,
    config::{EstimatorConfig, NetworkReservation},
};
use crate::samples::{is_expired, prune_samples, record_sample, sample_percentile, step_toward};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// Number of completed own proposals retained for network learning.
const NETWORK_SAMPLE_CAPACITY: usize = 16;
/// Each network sample expires ten minutes after it was recorded.
const NETWORK_SAMPLE_TTL: Duration = Duration::from_secs(10 * 60);
/// Longer observations are treated as stalls or clock skew, not propagation.
const MAX_NETWORK_SAMPLE: Duration = Duration::from_secs(5);
/// Maximum movement between consecutive own proposals.
const MAX_NETWORK_RESERVATION_STEP: Duration = Duration::from_millis(100);
/// Unmatched proposals expire after ten seconds.
const PENDING_PROPOSAL_TTL: Duration = Duration::from_secs(10);
/// Upper bound on own proposals waiting for a finalized successor.
const MAX_PENDING_PROPOSALS: usize = 8;

/// Bounded network reservation learned from finalized successors.
#[derive(Debug)]
pub(super) struct NetworkTracker {
    samples: VecDeque<(Instant, Duration)>,
    pending: VecDeque<PendingProposal>,
    minimum_reservation: Duration,
    maximum_reservation: Duration,
    current_reservation: Duration,
    percentile: usize,
    fast_rise: bool,
}

impl NetworkTracker {
    pub(super) fn new(config: &EstimatorConfig) -> Self {
        let maximum_reservation = match config.network_reservation_policy {
            NetworkReservation::Adaptive => config.network_budget_max,
            NetworkReservation::Fixed => config.network_budget,
        };
        Self {
            samples: VecDeque::with_capacity(NETWORK_SAMPLE_CAPACITY),
            pending: VecDeque::with_capacity(MAX_PENDING_PROPOSALS),
            minimum_reservation: config.network_budget,
            maximum_reservation,
            current_reservation: config.network_budget,
            percentile: usize::from(config.network_reserve_percentile),
            fast_rise: config.network_reserve_fast_rise,
        }
    }

    fn prune(&mut self, now: Instant) {
        prune_samples(&mut self.samples, now, NETWORK_SAMPLE_TTL);
        self.pending
            .retain(|pending| !is_expired(pending.returned_at, now, PENDING_PROPOSAL_TTL));
    }

    /// Replaces a duplicate return and bounds retained unmatched proposals.
    pub(super) fn proposal_returned(
        &mut self,
        now: Instant,
        return_budget: Duration,
        timing: ProposalTiming,
    ) {
        self.prune(now);
        self.pending.retain(|pending| pending.key != timing.key);
        if self.pending.len() == MAX_PENDING_PROPOSALS {
            self.pending.pop_front();
        }
        self.pending.push_back(PendingProposal {
            key: timing.key,
            returned_at: now,
            window_opened_millis: timing.window_opened_millis,
            returned_millis: timing.returned_millis,
            return_budget,
        });
    }

    /// Consumes a matching parent, retaining only consecutive, plausible samples.
    pub(super) fn child_finalized(
        &mut self,
        now: Instant,
        parent: ProposalKey,
        child: ProposalKey,
        child_timestamp_millis: u64,
    ) -> bool {
        self.prune(now);
        let Some(index) = self
            .pending
            .iter()
            .position(|pending| pending.key == parent)
        else {
            return false;
        };
        let pending = self
            .pending
            .remove(index)
            .expect("index was found in the same deque");
        // Skipped views or epoch changes include consensus recovery, not ordinary propagation.
        if child.epoch != parent.epoch || parent.view.checked_add(1) != Some(child.view) {
            return false;
        }
        // A child stamped before the parent's return is not a usable clock observation.
        if child_timestamp_millis < pending.returned_millis {
            return false;
        }
        let network_sample = Duration::from_millis(
            child_timestamp_millis.saturating_sub(pending.window_opened_millis),
        )
        .saturating_sub(pending.return_budget);
        if network_sample > MAX_NETWORK_SAMPLE {
            return false;
        }
        record_sample::<_, NETWORK_SAMPLE_CAPACITY>(
            &mut self.samples,
            now,
            network_sample,
            NETWORK_SAMPLE_TTL,
        );
        true
    }

    /// Expires feedback and takes one bounded step toward the configured percentile, or the minimum
    /// with fewer than four samples, to avoid selecting the maximum. Two
    /// consecutive samples optionally raise the target to at least the smaller of those
    /// two, so a single outlier cannot force a rise in a sparse window.
    pub(super) fn reserve_for_proposal(&mut self, now: Instant) -> Duration {
        self.prune(now);
        let target = sample_percentile(&self.samples, self.percentile).map_or(
            self.minimum_reservation,
            |percentile| {
                let percentile = if self.samples.len() < 4 {
                    self.minimum_reservation
                } else {
                    percentile
                };
                let mut newest = self.samples.iter().rev().map(|(_, value)| *value);
                let observed = match (newest.next(), newest.next()) {
                    (Some(last), Some(previous)) if self.fast_rise => {
                        percentile.max(last.min(previous))
                    }
                    _ => percentile,
                };
                observed.clamp(self.minimum_reservation, self.maximum_reservation)
            },
        );
        self.current_reservation = step_toward(
            self.current_reservation,
            target,
            MAX_NETWORK_RESERVATION_STEP,
        );
        debug_assert!(
            self.current_reservation >= self.minimum_reservation
                && self.current_reservation <= self.maximum_reservation
        );
        self.current_reservation
    }
}

#[derive(Debug)]
struct PendingProposal {
    key: ProposalKey,
    returned_at: Instant,
    window_opened_millis: u64,
    returned_millis: u64,
    return_budget: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_percentile_fast_rise_and_cap_control_reservation() {
        let now = Instant::now();
        for (percentile, fast_rise, expected) in
            [(50, false, 50), (50, true, 150), (100, false, 150)]
        {
            let config = EstimatorConfig {
                network_reserve_percentile: percentile,
                network_reserve_fast_rise: fast_rise,
                network_budget_max: Duration::from_millis(180),
                ..EstimatorConfig::default()
            };
            let mut tracker = NetworkTracker::new(&config);
            for sample in [50, 50, 50, 50, 250, 250] {
                tracker
                    .samples
                    .push_back((now, Duration::from_millis(sample)));
            }
            assert_eq!(
                tracker.reserve_for_proposal(now),
                Duration::from_millis(expected)
            );
            assert_eq!(
                tracker.reserve_for_proposal(now),
                Duration::from_millis(if expected == 50 { 50 } else { 180 })
            );
        }
    }

    #[test]
    fn fixed_policy_ignores_learning_controls() {
        let config = EstimatorConfig {
            network_reservation_policy: NetworkReservation::Fixed,
            ..EstimatorConfig::default()
        };
        let now = Instant::now();
        let mut tracker = NetworkTracker::new(&config);
        for _ in 0..4 {
            tracker.samples.push_back((now, Duration::from_millis(250)));
        }
        assert_eq!(tracker.reserve_for_proposal(now), config.network_budget);
        tracker.prune(now + NETWORK_SAMPLE_TTL + Duration::from_nanos(1));
        assert!(tracker.samples.is_empty());
    }
}
