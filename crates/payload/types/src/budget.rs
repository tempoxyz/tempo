use std::{collections::BTreeMap, time::Duration};
use tracing::debug;

/// Number of recent successful EL validation timings to retain.
const VALIDATION_LATENCY_SAMPLE_WINDOW: usize = 64;
/// Fixed-point scale for validation workload multipliers.
const VALIDATION_LATENCY_WORKLOAD_SCALE: u128 = 1_000_000;

/// Point-in-time marshal persistence cost per encoded block byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MarshalPersistEstimator {
    ns_per_byte: u64,
}

impl MarshalPersistEstimator {
    /// Creates an estimator from a raw nanoseconds-per-byte rate.
    pub fn from_ns_per_byte(ns_per_byte: u64) -> Self {
        Self { ns_per_byte }
    }

    /// The learned persistence cost in nanoseconds per encoded byte.
    pub fn ns_per_byte(self) -> u64 {
        self.ns_per_byte
    }

    /// Estimates marshal persistence time for an encoded block size.
    pub fn estimate(self, block_size_bytes: usize) -> Duration {
        let nanos = u128::from(self.ns_per_byte).saturating_mul(block_size_bytes as u128);
        Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
    }
}

/// Gas and transaction count used to estimate validation latency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidationLatencyWorkload {
    gas_used: u64,
    transaction_count: usize,
}

impl ValidationLatencyWorkload {
    /// Creates a validation workload from gas and transaction count.
    pub fn new(gas_used: u64, transaction_count: usize) -> Self {
        Self {
            gas_used,
            transaction_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValidationLatencySample {
    workload: ValidationLatencyWorkload,
    elapsed: Duration,
}

fn insert_count<T: Copy + Ord>(counts: &mut BTreeMap<T, usize>, value: T) {
    *counts.entry(value).or_default() += 1;
}

fn remove_count<T: Copy + Ord>(counts: &mut BTreeMap<T, usize>, value: T) {
    let count = counts
        .get_mut(&value)
        .expect("validation latency sample index out of sync");
    *count -= 1;
    if *count == 0 {
        counts.remove(&value);
    }
}

fn percentile_rank(len: usize, numerator: usize, denominator: usize) -> Option<usize> {
    debug_assert!(numerator > 0);
    debug_assert!(denominator > 0);
    debug_assert!(numerator <= denominator);

    if len == 0 {
        return None;
    }
    Some((len * numerator).div_ceil(denominator))
}

fn percentile_from_counts<T: Copy + Ord>(
    counts: &BTreeMap<T, usize>,
    len: usize,
    numerator: usize,
    denominator: usize,
) -> Option<T> {
    let target = percentile_rank(len, numerator, denominator)?;
    let mut seen = 0;
    for (value, count) in counts {
        seen += *count;
        if seen >= target {
            return Some(*value);
        }
    }
    debug_assert!(false, "validation latency sample index out of sync");
    None
}

fn scale_above_baseline(current: u128, baseline: u128) -> Option<u128> {
    if current == 0 {
        return Some(VALIDATION_LATENCY_WORKLOAD_SCALE);
    }
    if baseline == 0 {
        return None;
    }
    if current <= baseline {
        return Some(VALIDATION_LATENCY_WORKLOAD_SCALE);
    }

    Some(current.saturating_mul(VALIDATION_LATENCY_WORKLOAD_SCALE) / baseline)
}

fn scale_duration(elapsed: Duration, scale: u128) -> Duration {
    let nanos = elapsed
        .as_nanos()
        .saturating_mul(scale)
        .saturating_add(VALIDATION_LATENCY_WORKLOAD_SCALE.saturating_sub(1))
        / VALIDATION_LATENCY_WORKLOAD_SCALE;
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

/// Point-in-time validation latency estimate from recent proposal validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidationLatencyEstimate {
    elapsed: Duration,
    p90_gas_used: u64,
    p90_transaction_count: usize,
}

impl ValidationLatencyEstimate {
    /// The recent P90 validation time this estimate is floored at.
    pub fn elapsed(self) -> Duration {
        self.elapsed
    }

    /// Estimates validation latency for the supplied workload.
    ///
    /// Recent elapsed validation feedback is the floor so faster replay feedback
    /// still reclaims budget without shrinking smaller current blocks. If the
    /// current block carries more gas or transactions than the recent P90 workload,
    /// the estimate scales up by that excess. Encoded bytes are intentionally
    /// not used here because BAL sidecar bytes are charged through marshal
    /// persistence, not execution-layer validation work.
    pub fn estimate(self, workload: ValidationLatencyWorkload) -> Option<Duration> {
        if self.elapsed == Duration::ZERO {
            return None;
        }

        let scale = [
            scale_above_baseline(u128::from(workload.gas_used), u128::from(self.p90_gas_used)),
            scale_above_baseline(
                workload.transaction_count as u128,
                self.p90_transaction_count as u128,
            ),
        ]
        .into_iter()
        .flatten()
        .max()?;
        Some(scale_duration(self.elapsed, scale))
    }
}

/// Tracks recent local execution-layer block validation latency.
///
/// The validation latency estimate uses the recent P90 successful proposal
/// validation as an absolute floor, then scales that floor up when the current
/// workload exceeds the recent P90 gas or transaction count. This avoids
/// combining independent per-unit rates from different workloads while still
/// reserving validator headroom when the builder grows beyond the workloads
/// that produced the feedback.
#[derive(Clone, Debug, Default)]
pub struct ValidationLatencyEstimator {
    /// Samples are kept in id order for retention; count maps are keyed by
    /// observed values so estimate snapshots can read percentiles without
    /// sorting.
    sample_window: Vec<(u64, ValidationLatencySample)>,
    elapsed_counts: BTreeMap<Duration, usize>,
    gas_used_counts: BTreeMap<u64, usize>,
    transaction_count_counts: BTreeMap<usize, usize>,
}

impl ValidationLatencyEstimator {
    fn insert_sample_counts(&mut self, sample: ValidationLatencySample) {
        insert_count(&mut self.elapsed_counts, sample.elapsed);
        insert_count(&mut self.gas_used_counts, sample.workload.gas_used);
        insert_count(
            &mut self.transaction_count_counts,
            sample.workload.transaction_count,
        );
    }

    fn remove_sample_counts(&mut self, sample: ValidationLatencySample) {
        remove_count(&mut self.elapsed_counts, sample.elapsed);
        remove_count(&mut self.gas_used_counts, sample.workload.gas_used);
        remove_count(
            &mut self.transaction_count_counts,
            sample.workload.transaction_count,
        );
    }

    fn insert_sample(&mut self, sample_id: u64, sample: ValidationLatencySample) {
        let insert_index = match self
            .sample_window
            .binary_search_by_key(&sample_id, |(id, _)| *id)
        {
            Ok(index) => {
                let (_, replaced) = self.sample_window.remove(index);
                self.remove_sample_counts(replaced);
                index
            }
            Err(index) => index,
        };

        self.insert_sample_counts(sample);
        self.sample_window.insert(insert_index, (sample_id, sample));
        while self.sample_window.len() > VALIDATION_LATENCY_SAMPLE_WINDOW {
            let (_, evicted) = self.sample_window.remove(0);
            self.remove_sample_counts(evicted);
        }
    }

    /// Records local time spent validating a block through the execution layer.
    pub fn observe(
        &mut self,
        sample_id: u64,
        workload: ValidationLatencyWorkload,
        elapsed: Duration,
    ) {
        if elapsed == Duration::ZERO {
            return;
        }

        let sample = ValidationLatencySample { workload, elapsed };
        self.insert_sample(sample_id, sample);

        debug!(
            sample_id,
            workload = ?workload,
            elapsed = ?elapsed,
            estimate = ?self.estimate(),
            samples = self.sample_window.len(),
            "updated validation latency estimate"
        );
    }

    /// Estimates validation time for `workload` from the observed per-unit
    /// rates, scaling down for smaller blocks as well as up for larger ones.
    ///
    /// The estimate is the larger of the median nanoseconds-per-gas and
    /// nanoseconds-per-transaction rates applied to `workload`, capped at the
    /// pacing estimate from [`Self::estimate`] so it never exceeds the
    /// conservative figure. Returns `None` without samples or for an empty
    /// workload.
    pub fn workload_estimate(&self, workload: ValidationLatencyWorkload) -> Option<Duration> {
        if self.sample_window.is_empty()
            || (workload.gas_used == 0 && workload.transaction_count == 0)
        {
            return None;
        }
        fn median(mut values: Vec<u128>) -> Option<u128> {
            if values.is_empty() {
                return None;
            }
            values.sort_unstable();
            Some(values[(values.len() - 1) / 2])
        }
        let per_gas = median(
            self.sample_window
                .iter()
                .filter(|(_, sample)| sample.workload.gas_used > 0)
                .map(|(_, sample)| {
                    sample.elapsed.as_nanos() * VALIDATION_LATENCY_WORKLOAD_SCALE
                        / u128::from(sample.workload.gas_used)
                })
                .collect(),
        )
        .map(|rate| {
            rate.saturating_mul(u128::from(workload.gas_used)) / VALIDATION_LATENCY_WORKLOAD_SCALE
        });
        let per_tx = median(
            self.sample_window
                .iter()
                .filter(|(_, sample)| sample.workload.transaction_count > 0)
                .map(|(_, sample)| {
                    sample.elapsed.as_nanos() * VALIDATION_LATENCY_WORKLOAD_SCALE
                        / sample.workload.transaction_count as u128
                })
                .collect(),
        )
        .map(|rate| {
            rate.saturating_mul(workload.transaction_count as u128)
                / VALIDATION_LATENCY_WORKLOAD_SCALE
        });
        let nanos = per_gas.into_iter().chain(per_tx).max()?;
        let estimate = Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64);
        Some(
            match self.estimate().and_then(|floor| floor.estimate(workload)) {
                Some(ceiling) => estimate.min(ceiling),
                None => estimate,
            },
        )
    }

    /// Returns the current estimate for execution-layer block validation work.
    ///
    /// `None` means this node has not yet observed any successful validations.
    /// Callers should fall back to their conservative validator-work estimate in
    /// that case.
    pub fn estimate(&self) -> Option<ValidationLatencyEstimate> {
        let sample_count = self.sample_window.len();
        let p90_elapsed = percentile_from_counts(&self.elapsed_counts, sample_count, 9, 10)?;
        Some(ValidationLatencyEstimate {
            elapsed: p90_elapsed,
            p90_gas_used: percentile_from_counts(&self.gas_used_counts, sample_count, 9, 10)
                .unwrap_or_default(),
            p90_transaction_count: percentile_from_counts(
                &self.transaction_count_counts,
                sample_count,
                9,
                10,
            )
            .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimate_with_sample(
        sample_workload: ValidationLatencyWorkload,
        current_workload: ValidationLatencyWorkload,
    ) -> Option<Duration> {
        let mut estimator = ValidationLatencyEstimator::default();
        estimator.observe(1, sample_workload, Duration::from_millis(100));
        estimator
            .estimate()
            .and_then(|estimate| estimate.estimate(current_workload))
    }

    #[test]
    fn validation_latency_estimate_uses_recent_p90_elapsed() {
        let mut estimator = ValidationLatencyEstimator::default();
        let sample_workload = ValidationLatencyWorkload::new(100, 0);
        let current_workload = ValidationLatencyWorkload::new(100, 0);
        for (sample_id, elapsed) in [(1, 10), (2, 20), (3, 30), (4, 40)] {
            estimator.observe(sample_id, sample_workload, Duration::from_nanos(elapsed));
        }
        assert_eq!(
            estimator
                .estimate()
                .and_then(|estimate| estimate.estimate(current_workload)),
            Some(Duration::from_nanos(40))
        );

        estimator = ValidationLatencyEstimator::default();
        for elapsed in 1..=VALIDATION_LATENCY_SAMPLE_WINDOW as u64 {
            estimator.observe(
                elapsed,
                ValidationLatencyWorkload::new(1, 0),
                Duration::from_nanos(elapsed),
            );
        }
        estimator.observe(
            10_000,
            ValidationLatencyWorkload::new(1, 0),
            Duration::from_nanos(10_000),
        );
        assert_eq!(
            estimator
                .estimate()
                .and_then(|estimate| estimate.estimate(ValidationLatencyWorkload::new(1, 0))),
            Some(Duration::from_nanos(59))
        );
    }

    #[test]
    fn validation_latency_estimate_replaces_existing_sample_id() {
        let mut estimator = ValidationLatencyEstimator::default();
        let workload = ValidationLatencyWorkload::new(100, 0);

        estimator.observe(1, workload, Duration::from_millis(100));
        estimator.observe(1, workload, Duration::from_millis(200));

        assert_eq!(
            estimator
                .estimate()
                .and_then(|estimate| estimate.estimate(workload)),
            Some(Duration::from_millis(200))
        );
    }

    #[test]
    fn validation_latency_estimate_does_not_scale_down() {
        assert_eq!(
            estimate_with_sample(
                ValidationLatencyWorkload::new(1_000, 10),
                ValidationLatencyWorkload::new(400, 4)
            ),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn validation_latency_estimate_scales_up_by_gas_or_transactions() {
        let sample = ValidationLatencyWorkload::new(1_000, 10);

        assert_eq!(
            estimate_with_sample(sample, ValidationLatencyWorkload::new(1_500, 10)),
            Some(Duration::from_millis(150))
        );
        assert_eq!(
            estimate_with_sample(sample, ValidationLatencyWorkload::new(1_000, 15)),
            Some(Duration::from_millis(150))
        );
    }

    #[test]
    fn workload_estimate_scales_down_for_smaller_blocks() {
        let mut estimator = ValidationLatencyEstimator::default();
        assert_eq!(
            estimator.workload_estimate(ValidationLatencyWorkload::new(1_000, 10)),
            None
        );
        // Ten blocks of 10k transactions and 1 Ggas validate in 180 ms.
        for id in 0..10 {
            estimator.observe(
                id,
                ValidationLatencyWorkload::new(1_000_000_000, 10_000),
                Duration::from_millis(180),
            );
        }
        // A block half the size is credited half the time.
        assert_eq!(
            estimator.workload_estimate(ValidationLatencyWorkload::new(500_000_000, 5_000)),
            Some(Duration::from_millis(90))
        );
        // Whichever unit is the larger share drives the estimate.
        assert_eq!(
            estimator.workload_estimate(ValidationLatencyWorkload::new(250_000_000, 5_000)),
            Some(Duration::from_millis(90))
        );
        // Larger blocks never exceed the pacing estimate, which scales up too.
        assert_eq!(
            estimator.workload_estimate(ValidationLatencyWorkload::new(2_000_000_000, 20_000)),
            Some(Duration::from_millis(360))
        );
        assert_eq!(
            estimator.workload_estimate(ValidationLatencyWorkload::new(0, 0)),
            None
        );
    }

    #[test]
    fn validation_latency_estimate_requires_non_empty_workload_feedback() {
        let empty = ValidationLatencyWorkload::new(0, 0);

        assert_eq!(
            estimate_with_sample(empty, ValidationLatencyWorkload::new(0, 0)),
            Some(Duration::from_millis(100))
        );
        assert_eq!(
            estimate_with_sample(empty, ValidationLatencyWorkload::new(1_000, 10)),
            None
        );
    }
}
