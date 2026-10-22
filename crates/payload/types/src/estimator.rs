//! Shared build-time and validation feedback for paced payloads.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::{
    BUILD_TIME_MULTIPLIER_SCALE, BuildPlan, ValidationLatencyEstimator, ValidationLatencyWorkload,
};

/// Initial ratio of total replayable build work to work at transaction cutoff.
///
/// For example, `1.35` means "when cutoff work is 100 ms, expect the completed
/// replayable build work to be about 135 ms".
pub const DEFAULT_BUILD_TIME_MULTIPLIER: f64 = 1.35;
const MAX_BUILD_TIME_MULTIPLIER: u64 = 1_700_000;
const BUILD_TIME_MULTIPLIER_DECAY: u64 = 8;

/// Cloneable pacing feedback shared by consensus and the payload builder.
#[derive(Clone, Debug)]
pub struct Estimator {
    inner: Arc<EstimatorInner>,
}

#[derive(Debug)]
struct EstimatorInner {
    multiplier: AtomicU64,
    validation: Mutex<ValidationLatencyEstimator>,
}

impl Estimator {
    /// Creates feedback with the configured initial build multiplier.
    pub fn new(multiplier: f64) -> Self {
        Self {
            inner: Arc::new(EstimatorInner {
                multiplier: AtomicU64::new(scaled_build_time_multiplier(multiplier)),
                validation: Mutex::new(ValidationLatencyEstimator::default()),
            }),
        }
    }

    /// Records successful local execution-layer verification, keyed by height.
    pub fn on_block_verified(
        &self,
        height: u64,
        workload: ValidationLatencyWorkload,
        elapsed: Duration,
    ) {
        self.inner
            .validation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observe(height, workload, elapsed);
    }

    /// Snapshots feedback once for a paced payload build.
    pub fn build_plan(&self, build_budget: Duration) -> BuildPlan {
        BuildPlan::new(
            build_budget,
            self.inner.multiplier.load(Ordering::Relaxed),
            self.inner
                .validation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .estimate(),
        )
    }

    /// Learns replayable finish work after a paced build completes.
    pub fn on_build_finished(&self, total_work: Duration, work_at_tx_cutoff: Duration) {
        let Some(observed) = observed_build_time_multiplier(total_work, work_at_tx_cutoff) else {
            return;
        };
        let _ = self
            .inner
            .multiplier
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(decay_build_time_multiplier(current, observed))
            });
    }
}

/// Converts a human-readable build-work multiplier into the fixed-point representation.
fn scaled_build_time_multiplier(multiplier: f64) -> u64 {
    assert!(
        multiplier.is_finite() && multiplier >= 1.0,
        "build time multiplier must be finite and >= 1.0"
    );

    (multiplier * BUILD_TIME_MULTIPLIER_SCALE as f64).round() as u64
}

/// Computes the observed total-work to tx-cutoff-work multiplier.
///
/// `work_at_tx_cutoff` is measured when pool transaction execution stops.
/// `total_work` is measured after finalization finishes. Their ratio captures
/// `builder_finish` without needing a separate fixed reserve.
fn observed_build_time_multiplier(
    total_work: Duration,
    work_at_tx_cutoff: Duration,
) -> Option<u64> {
    if work_at_tx_cutoff == Duration::ZERO {
        return None;
    }

    let multiplier = total_work
        .as_nanos()
        .saturating_mul(u128::from(BUILD_TIME_MULTIPLIER_SCALE))
        / work_at_tx_cutoff.as_nanos();
    Some(multiplier.min(u128::from(MAX_BUILD_TIME_MULTIPLIER)) as u64)
}

/// Updates the multiplier, immediately rising but slowly decaying.
fn decay_build_time_multiplier(current: u64, observed: u64) -> u64 {
    if observed >= current {
        observed
    } else {
        let decay = ((current - observed) / BUILD_TIME_MULTIPLIER_DECAY).max(1);
        current.saturating_sub(decay).max(observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_350_000;

    #[test]
    fn observed_build_multiplier_tracks_tail_cost() {
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(135), Duration::from_millis(100)),
            Some(DEFAULT_BUILD_TIME_MULTIPLIER_SCALED)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(100), Duration::from_millis(100)),
            Some(1_000_000)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(250), Duration::from_millis(100)),
            Some(MAX_BUILD_TIME_MULTIPLIER)
        );
        assert_eq!(decay_build_time_multiplier(1_500_000, 1_300_000), 1_475_000);
    }

    #[test]
    fn build_multiplier_scales_decimal_values() {
        assert_eq!(
            scaled_build_time_multiplier(DEFAULT_BUILD_TIME_MULTIPLIER),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED
        );
    }
}
