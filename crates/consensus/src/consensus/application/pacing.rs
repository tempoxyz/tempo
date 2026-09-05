//! Local feedback for proposal pacing. Only our own healthy rounds train the
//! controller, so each proposer learns its own network/validation overhead.
//! All measurements use the local monotonic clock, never block timestamps.

use std::time::{Duration, Instant};

use commonware_consensus::types::{Round, View};

const MIN_BUDGET: Duration = Duration::from_millis(50);
const MAX_STEP: Duration = Duration::from_millis(10);
const OVERRUN_TOLERANCE: Duration = Duration::from_millis(10);

pub(super) struct Pacing {
    target: Duration,
    budget: Duration,
    last: Option<(Round, Instant)>,
    last_nullified: Option<Round>,
    pending: Option<Sample>,
}

struct Sample {
    round: Round,
    parent: Round,
    budget: Duration,
    returned: bool,
}

impl Pacing {
    pub(super) fn new(target: Duration, budget: Duration) -> Self {
        Self {
            target,
            budget: budget.clamp(MIN_BUDGET.min(target), target),
            last: None,
            last_nullified: None,
            pending: None,
        }
    }

    pub(super) fn begin(&mut self, round: Round, parent: View) -> Duration {
        // A nullified view or an epoch transition is not a healthy interval.
        self.pending = self.last.and_then(|(last, _)| {
            (last.epoch() == round.epoch()
                && last.view() == parent
                && parent.next() == round.view()
                && self
                    .last_nullified
                    .is_none_or(|nullified| nullified < round))
            .then_some(Sample {
                round,
                parent: last,
                budget: self.budget,
                returned: false,
            })
        });
        self.budget
    }

    pub(super) fn returned(&mut self, round: Round, elapsed: Duration) {
        if let Some(sample) = &mut self.pending
            && sample.round == round
        {
            // Do not compensate for local builder or persistence overruns.
            sample.returned = elapsed <= sample.budget.saturating_add(OVERRUN_TOLERANCE);
        }
    }

    pub(super) fn nullified(&mut self, round: Round) {
        self.last_nullified = Some(self.last_nullified.map_or(round, |last| last.max(round)));
        if self.last.is_none_or(|(last, _)| round > last) {
            self.pending = None;
        }
    }

    pub(super) fn notarized(&mut self, round: Round, now: Instant) {
        if self.last.is_some_and(|(last, _)| round <= last) {
            return;
        }
        if let Some(sample) = self.pending.take()
            && sample.round == round
            && sample.returned
            && let Some((parent, start)) = self.last
            && parent == sample.parent
            && let Some(interval) = now.checked_duration_since(start)
            // Long stalls and catch-up bursts must not train normal pacing.
            && interval >= self.target / 2
            && interval <= self.target.saturating_mul(2)
        {
            // A slow integral controller: at most 10ms per local proposal,
            // and only one eighth of the observed error. Bounds prevent windup
            // when the target is infeasible and preserve some local work time.
            if interval > self.target {
                let step = ((interval - self.target) / 8).min(MAX_STEP);
                self.budget = self.budget.saturating_sub(step);
            } else {
                let step = ((self.target - interval) / 8).min(MAX_STEP);
                self.budget = self.budget.saturating_add(step);
            }
            self.budget = self.budget.clamp(MIN_BUDGET.min(self.target), self.target);
            tracing::info!(
                %round,
                interval_ms = interval.as_secs_f64() * 1000.0,
                proposal_budget_ms = self.budget.as_secs_f64() * 1000.0,
                target_ms = self.target.as_secs_f64() * 1000.0,
                "adjusted adaptive proposal pacing"
            );
        }
        self.last = Some((round, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::Epoch;

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn sample(pacing: &mut Pacing, view: u64, now: &mut Instant, overhead: Duration) {
        let budget = pacing.begin(round(view), View::new(view - 1));
        pacing.returned(round(view), budget);
        *now += budget + overhead;
        pacing.notarized(round(view), *now);
    }

    #[test]
    fn converges_and_recovers_when_network_latency_changes() {
        let mut pacing = Pacing::new(Duration::from_millis(550), Duration::from_millis(500));
        let mut now = Instant::now();
        pacing.notarized(round(1), now);
        for view in 2..82 {
            sample(&mut pacing, view, &mut now, Duration::from_millis(210));
        }
        assert!(pacing.budget.abs_diff(Duration::from_millis(340)) < Duration::from_millis(1));
        for view in 82..162 {
            sample(&mut pacing, view, &mut now, Duration::from_millis(50));
        }
        assert!(pacing.budget.abs_diff(Duration::from_millis(500)) < Duration::from_millis(1));
    }

    #[test]
    fn ignores_other_proposers_duplicates_skips_and_local_overruns() {
        let initial = Duration::from_millis(500);
        let mut pacing = Pacing::new(Duration::from_millis(550), initial);
        let mut now = Instant::now();
        pacing.notarized(round(1), now);
        // Another proposer must not change our budget.
        now += Duration::from_millis(700);
        pacing.notarized(round(2), now);
        pacing.notarized(round(2), now);
        pacing.notarized(round(1), now);
        assert_eq!(pacing.budget, initial);
        // Local persistence took too long.
        pacing.begin(round(3), View::new(2));
        pacing.returned(round(3), Duration::from_millis(600));
        now += Duration::from_millis(800);
        pacing.notarized(round(3), now);
        assert_eq!(pacing.budget, initial);
        // A skipped view and a cancellation must not train the controller.
        pacing.nullified(round(4));
        pacing.begin(round(5), View::new(3));
        pacing.returned(round(5), initial);
        now += Duration::from_millis(700);
        pacing.notarized(round(5), now);
        pacing.begin(round(6), View::new(5));
        now += Duration::from_millis(700);
        pacing.notarized(round(6), now);
        assert_eq!(pacing.budget, initial);
    }

    #[test]
    fn limits_steps_and_preserves_budget_at_infeasible_targets() {
        let mut pacing = Pacing::new(Duration::from_millis(550), Duration::from_millis(500));
        let mut now = Instant::now();
        pacing.notarized(round(1), now);
        sample(&mut pacing, 2, &mut now, Duration::from_millis(300));
        assert_eq!(pacing.budget, Duration::from_millis(490));
        for view in 3..103 {
            sample(&mut pacing, view, &mut now, Duration::from_millis(600));
        }
        assert_eq!(pacing.budget, MIN_BUDGET);
        let tiny = Pacing::new(Duration::from_millis(1), Duration::ZERO);
        assert_eq!(tiny.budget, Duration::from_millis(1));
    }

    #[test]
    fn ignores_stalls_and_epoch_transitions() {
        let initial = Duration::from_millis(500);
        let mut pacing = Pacing::new(Duration::from_millis(550), initial);
        let mut now = Instant::now();
        pacing.notarized(round(1), now);
        sample(&mut pacing, 2, &mut now, Duration::from_secs(5));
        assert_eq!(pacing.budget, initial);
        let next_epoch = Round::new(Epoch::new(1), View::new(3));
        pacing.begin(next_epoch, View::new(2));
        pacing.returned(next_epoch, initial);
        pacing.notarized(next_epoch, now + Duration::from_millis(700));
        assert_eq!(pacing.budget, initial);
    }

    #[test]
    fn rotating_proposers_learn_their_own_overhead() {
        let target = Duration::from_millis(550);
        let overheads = [100, 150, 210, 250, 300].map(Duration::from_millis);
        let mut proposers = overheads.map(|_| Pacing::new(target, Duration::from_millis(500)));
        let mut now = Instant::now();
        for pacing in &mut proposers {
            pacing.notarized(round(1), now);
        }
        for view in 2..502 {
            let leader = (view as usize) % proposers.len();
            let budget = proposers[leader].begin(round(view), View::new(view - 1));
            proposers[leader].returned(round(view), budget);
            now += budget + overheads[leader];
            for pacing in &mut proposers {
                pacing.notarized(round(view), now);
            }
        }
        for (pacing, overhead) in proposers.iter().zip(overheads) {
            assert!(pacing.budget.abs_diff(target - overhead) < Duration::from_millis(1));
        }
    }

    #[test]
    fn late_proposal_after_nullification_does_not_train() {
        let initial = Duration::from_millis(500);
        let mut pacing = Pacing::new(Duration::from_millis(550), initial);
        let mut now = Instant::now();
        pacing.notarized(round(1), now);
        pacing.nullified(round(2));
        sample(&mut pacing, 2, &mut now, Duration::from_millis(210));
        assert_eq!(pacing.budget, initial);
    }
}
