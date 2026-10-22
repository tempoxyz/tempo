//! Stop decisions for paced payload builds.

use std::time::Duration;

use crate::{ValidationLatencyEstimate, ValidationLatencyWorkload};

/// Fixed-point scale for build time multipliers.
pub const BUILD_TIME_MULTIPLIER_SCALE: u64 = 1_000_000;

/// Point-in-time inputs for one payload build's stop decision.
///
/// Reusing a plan keeps the same multiplier and validation feedback for every
/// decision within that build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildPlan {
    /// Remaining proposal budget handed to this build.
    pub build_budget: Duration,
    multiplier_scaled: u64,
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
    /// Creates a plan from a fixed-point multiplier and validation feedback.
    ///
    /// `multiplier_scaled` uses [`BUILD_TIME_MULTIPLIER_SCALE`] units per 1.0:
    /// `1_350_000` projects 135 ms of total replayable build work, including
    /// finalization, from 100 ms of work performed so far.
    /// `build_budget` includes time already elapsed in the build. If
    /// `validation_latency` is `None` or cannot estimate the current workload,
    /// validation reserves the full projected builder work.
    ///
    /// # Panics
    ///
    /// Panics if `multiplier_scaled` is below [`BUILD_TIME_MULTIPLIER_SCALE`],
    /// which would project less work than has already been performed.
    pub fn new(
        build_budget: Duration,
        multiplier_scaled: u64,
        validation_latency: Option<ValidationLatencyEstimate>,
    ) -> Self {
        assert!(
            multiplier_scaled >= BUILD_TIME_MULTIPLIER_SCALE,
            "build time multiplier must be >= 1.0"
        );

        Self {
            build_budget,
            multiplier_scaled,
            validation_latency,
        }
    }

    /// The build time multiplier in use.
    pub fn build_time_multiplier(&self) -> f64 {
        self.multiplier_scaled as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64
    }

    /// Projects the total duration of the build and its validation.
    ///
    /// `elapsed` is wall-clock time spent in the builder so far, `idle_elapsed` the
    /// part of it spent waiting for transactions, which validators do not replay.
    /// Builder work is projected with the multiplier; validator work comes from
    /// feedback, capped at the builder projection. Absent or unusable feedback
    /// falls back to the builder projection. The total includes work already
    /// performed, with proposer idle time counted once.
    pub fn decision(
        &self,
        elapsed: Duration,
        idle_elapsed: Duration,
        current_workload: ValidationLatencyWorkload,
    ) -> PayloadBudgetDecision {
        let work_elapsed = elapsed.saturating_sub(idle_elapsed);
        let predicted_builder_work = scaled_duration(work_elapsed, self.multiplier_scaled);

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

fn scaled_duration(elapsed: Duration, multiplier: u64) -> Duration {
    Duration::from_nanos(
        (elapsed.as_nanos().saturating_mul(u128::from(multiplier))
            / u128::from(BUILD_TIME_MULTIPLIER_SCALE))
        .min(u128::from(u64::MAX)) as u64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValidationLatencyEstimator;

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
        let decision = BuildPlan::new(Duration::MAX, 1_350_000, None).decision(
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

        let decision = BuildPlan::new(Duration::MAX, 1_350_000, None).decision(
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
        let decision = BuildPlan::new(Duration::MAX, 1_350_000, validation_latency).decision(
            Duration::from_millis(100),
            Duration::ZERO,
            workload,
        );

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
        let decision = BuildPlan::new(Duration::MAX, 1_350_000, validation_latency).decision(
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
}
