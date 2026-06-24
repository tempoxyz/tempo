use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tracing::debug;

/// How quickly the learned marshal persistence rate decays when blocks get cheaper.
const RATE_DECAY: u64 = 8;
/// Ignore tiny blocks so fixed archive overhead does not become a large-block byte cost.
const MIN_SAMPLE_BYTES: usize = 128 * 1024;
/// Number of recent successful EL validation timings to retain.
const VALIDATION_LATENCY_SAMPLE_WINDOW: usize = 64;
/// Fixed-point scale for validation workload multipliers.
const VALIDATION_LATENCY_WORKLOAD_SCALE: u128 = 1_000_000;

static MARSHAL_PERSIST_NS_PER_BYTE: AtomicU64 = AtomicU64::new(0);

/// Returns the current estimate of consensus marshal persistence cost.
///
/// This is a point-in-time snapshot. Callers use it before building or
/// returning a proposal so the same estimate is applied consistently to that
/// decision.
pub fn marshal_persist_estimate() -> MarshalPersistEstimator {
    MarshalPersistEstimator::from_ns_per_byte(MARSHAL_PERSIST_NS_PER_BYTE.load(Ordering::Relaxed))
}

/// Records time spent persisting an encoded block through consensus marshal.
///
/// The observation is stored as nanoseconds per encoded block byte. Large
/// blocks teach future build and return budgets how much size-dependent
/// persistence time to reserve for both proposers and validators.
/// Consensus records this from local `marshal.proposed` time after persisting a
/// proposal.
pub fn observe_marshal_persist(block_size_bytes: usize, elapsed: Duration) {
    if block_size_bytes < MIN_SAMPLE_BYTES || elapsed == Duration::ZERO {
        return;
    }

    let block_size = block_size_bytes as u128;
    let observed = elapsed
        .as_nanos()
        .saturating_add(block_size.saturating_sub(1))
        / block_size;
    let observed = observed.min(u128::from(u64::MAX)) as u64;

    let _ =
        MARSHAL_PERSIST_NS_PER_BYTE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(if current == 0 || observed >= current {
                observed
            } else {
                let decay = ((current - observed) / RATE_DECAY).max(1);
                current.saturating_sub(decay).max(observed)
            })
        });
    debug!(
        block_size_bytes,
        elapsed = ?elapsed,
        observed_ns_per_byte = observed,
        estimated_ns_per_byte = MARSHAL_PERSIST_NS_PER_BYTE.load(Ordering::Relaxed),
        "updated marshal persistence estimate"
    );
}

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
    elapsed_per_transaction: Option<Duration>,
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

fn scale_proportionally(current: u128, baseline: u128) -> Option<u128> {
    if current == 0 {
        return (baseline != 0).then_some(0);
    }
    if baseline == 0 {
        return None;
    }

    Some(
        current
            .saturating_mul(VALIDATION_LATENCY_WORKLOAD_SCALE)
            .div_ceil(baseline),
    )
}

fn scale_duration(elapsed: Duration, scale: u128) -> Duration {
    let nanos = elapsed
        .as_nanos()
        .saturating_mul(scale)
        .saturating_add(VALIDATION_LATENCY_WORKLOAD_SCALE.saturating_sub(1))
        / VALIDATION_LATENCY_WORKLOAD_SCALE;
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

fn duration_per_transaction(elapsed: Duration, transaction_count: usize) -> Option<Duration> {
    if transaction_count == 0 {
        return None;
    }

    let nanos = elapsed
        .as_nanos()
        .saturating_add(transaction_count as u128 - 1)
        / transaction_count as u128;
    Some(Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64))
}

fn scale_duration_by_count(
    elapsed_per_transaction: Duration,
    transaction_count: usize,
) -> Duration {
    let nanos = elapsed_per_transaction
        .as_nanos()
        .saturating_mul(transaction_count as u128);
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

/// Point-in-time validation latency estimate from recent proposal validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidationLatencyEstimate {
    elapsed: Duration,
    p90_gas_used: u64,
    p90_transaction_count: usize,
    p50_elapsed_per_transaction: Option<Duration>,
}

impl ValidationLatencyEstimate {
    /// Creates a bootstrap estimate from a per-transaction validation cost.
    ///
    /// This is used before local async validation samples are available. It
    /// intentionally uses transaction count as the scaling dimension because
    /// optimistic payloads do not execute transactions while building and
    /// therefore carry no meaningful builder-side gas-used signal.
    pub fn from_per_transaction(elapsed_per_transaction: Duration) -> Self {
        Self {
            elapsed: elapsed_per_transaction,
            p90_gas_used: 0,
            p90_transaction_count: 1,
            p50_elapsed_per_transaction: Some(elapsed_per_transaction),
        }
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
        if workload.transaction_count > 0 && self.p90_transaction_count == 0 {
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

    /// Estimates validation latency proportionally to the supplied workload.
    ///
    /// Optimistic payload builders use this for transaction selection because
    /// they need the incremental validator work selected so far. In particular,
    /// an empty workload must not inherit the full recent block validation
    /// latency, or the builder can stop before selecting any transactions.
    pub fn estimate_proportional(self, workload: ValidationLatencyWorkload) -> Option<Duration> {
        if self.elapsed == Duration::ZERO {
            return None;
        }
        if workload.gas_used == 0 && workload.transaction_count == 0 {
            return Some(Duration::ZERO);
        }
        if workload.transaction_count > 0 {
            if let Some(elapsed_per_transaction) = self.p50_elapsed_per_transaction {
                return Some(scale_duration_by_count(
                    elapsed_per_transaction,
                    workload.transaction_count,
                ));
            }
            return None;
        }

        let scale = [
            scale_proportionally(u128::from(workload.gas_used), u128::from(self.p90_gas_used)),
            scale_proportionally(
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
/// The full-block validation latency estimate uses the recent P90 successful
/// proposal validation as an absolute floor, then scales that floor up when the
/// current workload exceeds the recent P90 gas or transaction count. The
/// optimistic proportional estimate uses paired P50 per-transaction validation
/// cost so isolated slow validation samples do not collapse future block size.
#[derive(Clone, Debug, Default)]
pub struct ValidationLatencyEstimator {
    /// Samples are kept in id order for retention; count maps are keyed by
    /// observed values so estimate snapshots can read percentiles without
    /// sorting.
    sample_window: Vec<(u64, ValidationLatencySample)>,
    elapsed_counts: BTreeMap<Duration, usize>,
    gas_used_counts: BTreeMap<u64, usize>,
    transaction_count_counts: BTreeMap<usize, usize>,
    elapsed_per_transaction_counts: BTreeMap<Duration, usize>,
}

impl ValidationLatencyEstimator {
    fn insert_sample_counts(&mut self, sample: ValidationLatencySample) {
        insert_count(&mut self.elapsed_counts, sample.elapsed);
        insert_count(&mut self.gas_used_counts, sample.workload.gas_used);
        insert_count(
            &mut self.transaction_count_counts,
            sample.workload.transaction_count,
        );
        if let Some(elapsed_per_transaction) = sample.elapsed_per_transaction {
            insert_count(
                &mut self.elapsed_per_transaction_counts,
                elapsed_per_transaction,
            );
        }
    }

    fn remove_sample_counts(&mut self, sample: ValidationLatencySample) {
        remove_count(&mut self.elapsed_counts, sample.elapsed);
        remove_count(&mut self.gas_used_counts, sample.workload.gas_used);
        remove_count(
            &mut self.transaction_count_counts,
            sample.workload.transaction_count,
        );
        if let Some(elapsed_per_transaction) = sample.elapsed_per_transaction {
            remove_count(
                &mut self.elapsed_per_transaction_counts,
                elapsed_per_transaction,
            );
        }
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

        let sample = ValidationLatencySample {
            workload,
            elapsed,
            elapsed_per_transaction: duration_per_transaction(elapsed, workload.transaction_count),
        };
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

    /// Returns the current estimate for execution-layer block validation work.
    ///
    /// `None` means this node has not yet observed any successful validations.
    /// Callers should fall back to their conservative validator-work estimate in
    /// that case.
    pub fn estimate(&self) -> Option<ValidationLatencyEstimate> {
        let sample_count = self.sample_window.len();
        let p90_elapsed = percentile_from_counts(&self.elapsed_counts, sample_count, 9, 10)?;
        let per_transaction_sample_count: usize =
            self.elapsed_per_transaction_counts.values().sum();
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
            p50_elapsed_per_transaction: percentile_from_counts(
                &self.elapsed_per_transaction_counts,
                per_transaction_sample_count,
                1,
                2,
            ),
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
    fn observes_large_blocks_and_ignores_tiny_samples() {
        MARSHAL_PERSIST_NS_PER_BYTE.store(0, Ordering::Relaxed);
        observe_marshal_persist(MIN_SAMPLE_BYTES, Duration::from_millis(13));

        assert_eq!(
            marshal_persist_estimate().estimate(MIN_SAMPLE_BYTES),
            Duration::from_nanos(13_107_200)
        );

        observe_marshal_persist(MIN_SAMPLE_BYTES - 1, Duration::from_millis(1));
        observe_marshal_persist(1_000_000, Duration::ZERO);

        assert_eq!(
            marshal_persist_estimate().estimate(MIN_SAMPLE_BYTES),
            Duration::from_nanos(13_107_200)
        );
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
    fn bootstrap_validation_latency_scales_by_transaction_count() {
        let estimate = ValidationLatencyEstimate::from_per_transaction(Duration::from_micros(50));

        assert_eq!(
            estimate.estimate(ValidationLatencyWorkload::new(0, 5_000)),
            Some(Duration::from_millis(250))
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
    fn proportional_validation_latency_scales_down_to_current_workload() {
        let mut estimator = ValidationLatencyEstimator::default();
        estimator.observe(
            1,
            ValidationLatencyWorkload::new(1_000, 10),
            Duration::from_millis(100),
        );
        let estimate = estimator.estimate().expect("validation estimate");

        assert_eq!(
            estimate.estimate_proportional(ValidationLatencyWorkload::new(0, 0)),
            Some(Duration::ZERO)
        );
        assert_eq!(
            estimate.estimate_proportional(ValidationLatencyWorkload::new(500, 5)),
            Some(Duration::from_millis(50))
        );
    }

    #[test]
    fn proportional_validation_latency_uses_p50_paired_transaction_cost() {
        let mut estimator = ValidationLatencyEstimator::default();
        for (sample_id, elapsed_ms) in [(1, 100), (2, 110), (3, 120), (4, 1_000)] {
            estimator.observe(
                sample_id,
                ValidationLatencyWorkload::new(0, 1_000),
                Duration::from_millis(elapsed_ms),
            );
        }
        let estimate = estimator.estimate().expect("validation estimate");

        assert_eq!(
            estimate.estimate_proportional(ValidationLatencyWorkload::new(0, 5_000)),
            Some(Duration::from_millis(550))
        );
    }

    #[test]
    fn proportional_validation_latency_ignores_empty_samples() {
        let mut estimator = ValidationLatencyEstimator::default();
        estimator.observe(
            1,
            ValidationLatencyWorkload::new(0, 0),
            Duration::from_secs(1),
        );
        estimator.observe(
            2,
            ValidationLatencyWorkload::new(0, 1_000),
            Duration::from_millis(100),
        );
        let estimate = estimator.estimate().expect("validation estimate");

        assert_eq!(
            estimate.estimate_proportional(ValidationLatencyWorkload::new(0, 5_000)),
            Some(Duration::from_millis(500))
        );

        let mut empty_estimator = ValidationLatencyEstimator::default();
        empty_estimator.observe(
            1,
            ValidationLatencyWorkload::new(0, 0),
            Duration::from_secs(1),
        );
        let empty_estimate = empty_estimator.estimate().expect("validation estimate");

        assert_eq!(
            empty_estimate.estimate_proportional(ValidationLatencyWorkload::new(0, 5_000)),
            None
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
        assert_eq!(
            estimate_with_sample(empty, ValidationLatencyWorkload::new(0, 10)),
            None
        );
    }
}
