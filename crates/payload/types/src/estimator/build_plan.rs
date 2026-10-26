//! Stop decisions for paced payload builds.

use std::time::Duration;

use super::BuildTimeMultiplier;
use crate::{ValidationLatencyEstimate, ValidationLatencyWorkload};

/// Point-in-time inputs for one payload build's stop decision.
///
/// Reusing a plan keeps the same multiplier, dry build finish and validation
/// feedback for every decision within that build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildPlan {
    /// Remaining proposal budget handed to this build.
    pub build_budget: Duration,
    build_time_multiplier: BuildTimeMultiplier,
    dry_finish: Duration,
    validation_latency: Option<ValidationLatencyEstimate>,
}

/// Projected total duration of a build and its validation, including elapsed time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadBudgetDecision {
    /// Replayable proposer work projected from the work done so far.
    pub predicted_builder_work: Duration,
    /// Validator replay work, capped at the builder projection and falling back
    /// to it when validation feedback is absent or unusable.
    pub predicted_validator_work: Duration,
    /// Projected total time of the build and its replay: the idle time so
    /// far plus the projected builder and validator work, including the work
    /// already done.
    pub total_reserved: Duration,
}

impl BuildPlan {
    /// Creates a plan from a build time multiplier, a dry build finish and
    /// validation feedback.
    ///
    /// `build_time_multiplier` projects total replayable build work, including
    /// finalization, from the work performed so far: 1.35 projects 135 ms from
    /// 100 ms. `dry_finish` is the least builder work left once the build has
    /// waited for transactions. `build_budget` includes time already elapsed in
    /// the build. If `validation_latency` is `None` or cannot estimate the
    /// current workload, validation reserves the full projected builder work.
    pub(super) fn new(
        build_budget: Duration,
        build_time_multiplier: BuildTimeMultiplier,
        dry_finish: Duration,
        validation_latency: Option<ValidationLatencyEstimate>,
    ) -> Self {
        Self {
            build_budget,
            build_time_multiplier,
            dry_finish,
            validation_latency,
        }
    }

    /// The build time multiplier in use.
    pub fn build_time_multiplier(&self) -> BuildTimeMultiplier {
        self.build_time_multiplier
    }

    /// The least builder work reserved after the work done so far once this
    /// build has waited for transactions; zero before any dry build finished.
    pub fn dry_finish(&self) -> Duration {
        self.dry_finish
    }

    /// The validation latency estimate in use, or `None` before feedback is available.
    pub fn validation_latency(&self) -> Option<ValidationLatencyEstimate> {
        self.validation_latency
    }

    /// Projects the total duration of the build and its validation.
    ///
    /// `elapsed` is wall-clock time spent in the builder so far, `idle_elapsed` the
    /// part of it spent waiting for transactions, which validators do not replay.
    /// Builder work is projected with the multiplier, and once the build has
    /// waited for transactions, is at least the work so far plus the dry build
    /// finish. Validator feedback is capped at that projection.
    /// Absent or unusable feedback falls back to the builder projection. The total
    /// includes work already performed, with proposer idle time counted once.
    pub fn decision(
        &self,
        elapsed: Duration,
        idle_elapsed: Duration,
        current_workload: ValidationLatencyWorkload,
    ) -> PayloadBudgetDecision {
        let work_elapsed = elapsed.saturating_sub(idle_elapsed);
        let mut predicted_builder_work = self.build_time_multiplier.apply(work_elapsed);
        if !idle_elapsed.is_zero() {
            predicted_builder_work =
                predicted_builder_work.max(work_elapsed.saturating_add(self.dry_finish));
        }

        let predicted_validator_work = self
            .validation_latency
            .and_then(|estimate| estimate.estimate(current_workload))
            .map(|estimate| estimate.min(predicted_builder_work))
            .unwrap_or(predicted_builder_work);
        let total_reserved = idle_elapsed
            .saturating_add(predicted_builder_work)
            .saturating_add(predicted_validator_work);
        PayloadBudgetDecision {
            predicted_builder_work,
            predicted_validator_work,
            total_reserved,
        }
    }

    /// Whether the projected total meets or exceeds this plan's build budget.
    pub fn exhausted(&self, decision: &PayloadBudgetDecision) -> bool {
        decision.total_reserved >= self.build_budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValidationLatencyEstimator;

    fn multiplier(value: f64) -> BuildTimeMultiplier {
        BuildTimeMultiplier::new(value).unwrap()
    }

    fn validation_latency_estimate(
        workload: ValidationLatencyWorkload,
        elapsed: Duration,
    ) -> Option<ValidationLatencyEstimate> {
        let mut estimator = ValidationLatencyEstimator::default();
        estimator.observe(1, workload, elapsed);
        estimator.estimate()
    }

    #[test]
    fn payload_budget_accounts_for_leader_idle_once() {
        let decision = BuildPlan::new(Duration::MAX, multiplier(1.35), Duration::ZERO, None)
            .decision(
                Duration::from_millis(100),
                Duration::ZERO,
                ValidationLatencyWorkload::default(),
            );
        assert_eq!(decision.predicted_builder_work, Duration::from_millis(135));
        assert_eq!(
            decision.predicted_validator_work,
            Duration::from_millis(135)
        );
        assert_eq!(decision.total_reserved, Duration::from_millis(270));

        let decision = BuildPlan::new(Duration::MAX, multiplier(1.35), Duration::ZERO, None)
            .decision(
                Duration::from_millis(350),
                Duration::from_millis(250),
                ValidationLatencyWorkload::default(),
            );
        assert_eq!(decision.predicted_builder_work, Duration::from_millis(135));
        assert_eq!(
            decision.predicted_validator_work,
            Duration::from_millis(135)
        );
        assert_eq!(decision.total_reserved, Duration::from_millis(520));
    }

    #[test]
    fn payload_budget_uses_validator_feedback_when_available() {
        let workload = ValidationLatencyWorkload::new(100, 0);
        let validation_latency = validation_latency_estimate(workload, Duration::from_millis(80));
        let decision = BuildPlan::new(
            Duration::MAX,
            multiplier(1.35),
            Duration::ZERO,
            validation_latency,
        )
        .decision(Duration::from_millis(100), Duration::ZERO, workload);

        assert_eq!(decision.predicted_builder_work, Duration::from_millis(135));
        assert_eq!(decision.predicted_validator_work, Duration::from_millis(80));
        assert_eq!(decision.total_reserved, Duration::from_millis(215));
    }

    #[test]
    fn payload_budget_caps_scaled_validator_feedback_at_builder_projection() {
        let validation_latency = validation_latency_estimate(
            ValidationLatencyWorkload::new(100, 10),
            Duration::from_millis(100),
        );
        let decision = BuildPlan::new(
            Duration::MAX,
            multiplier(1.35),
            Duration::ZERO,
            validation_latency,
        )
        .decision(
            Duration::from_millis(100),
            Duration::ZERO,
            ValidationLatencyWorkload::new(200, 10),
        );

        assert_eq!(
            decision.predicted_validator_work,
            Duration::from_millis(135)
        );
        assert_eq!(decision.total_reserved, Duration::from_millis(270));
    }

    #[test]
    fn payload_budget_reserves_dry_finish_after_waiting() {
        let plan = BuildPlan::new(
            Duration::MAX,
            BuildTimeMultiplier::default(),
            Duration::from_millis(30),
            None,
        );

        // A build that never waited only projects with the multiplier.
        let decision = plan.decision(
            Duration::from_millis(100),
            Duration::ZERO,
            ValidationLatencyWorkload::default(),
        );
        assert_eq!(decision.predicted_builder_work, Duration::from_millis(115));

        // After waiting, at least the dry build finish follows the work so far.
        let decision = plan.decision(
            Duration::from_millis(110),
            Duration::from_millis(100),
            ValidationLatencyWorkload::default(),
        );
        assert_eq!(decision.predicted_builder_work, Duration::from_millis(40));
        assert_eq!(decision.total_reserved, Duration::from_millis(180));
    }
}
