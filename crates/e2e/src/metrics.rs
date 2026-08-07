//! Metrics parsing and assertion helpers for e2e tests.

use std::{collections::HashSet, fmt::Debug, str::FromStr, time::Duration};

use commonware_runtime::{Clock as _, deterministic::Context};

use crate::TestingNode;

const PEERS_BLOCKED: &str = "peers_blocked";
const LATEST_EPOCH: &str = "epoch_manager_latest_epoch";
const LATEST_PARTICIPANTS: &str = "epoch_manager_latest_participants";
const PROCESSED_HEIGHT: &str = "marshal_processed_height";
const DKG_FAILURES: &str = "dkg_manager_ceremony_failures_total";

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, PartialEq)]
struct Sample {
    name: String,
    value: String,
}

impl Sample {
    fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        let mut parts = line.split_whitespace();
        let key = parts.next().expect("metric sample has no name");
        let value = parts
            .next()
            .unwrap_or_else(|| panic!("metric sample `{key}` has no value"));

        let name = key.split_once('{').map_or(key, |(name, _)| name);

        Some(Self {
            name: name.to_owned(),
            value: value.to_owned(),
        })
    }

    fn value<T>(&self) -> T
    where
        T: FromStr,
        T::Err: Debug,
    {
        self.value.parse().expect("metrics parses into type")
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Metrics {
    samples: Vec<Sample>,
}

pub trait MetricScope {
    fn metric_prefix(&self) -> String;
}

pub trait MetricsExt {
    fn to_metrics(&self) -> Metrics;
}

impl<T> MetricsExt for T
where
    T: commonware_runtime::Metrics,
{
    fn to_metrics(&self) -> Metrics {
        Metrics::from_context(self)
    }
}

impl<TClock> MetricScope for TestingNode<TClock>
where
    TClock: commonware_runtime::Clock,
{
    fn metric_prefix(&self) -> String {
        Self::metric_prefix(self)
    }
}

impl Metrics {
    /// Samples metrics from a Commonware runtime context.
    pub fn from_context(context: &impl commonware_runtime::Metrics) -> Self {
        let samples = context.encode().lines().filter_map(Sample::parse).collect();
        Self { samples }
    }

    pub fn value<T>(&self, metric_suffix: &str) -> Option<T>
    where
        T: FromStr,
        T::Err: Debug,
    {
        self.samples
            .iter()
            .find(|s| s.name.ends_with(metric_suffix))
            .map(Sample::value)
    }

    pub fn values<'a, T>(&'a self, metric_suffix: &'a str) -> impl Iterator<Item = T> + 'a
    where
        T: FromStr + 'a,
        T::Err: Debug,
    {
        self.samples
            .iter()
            .filter(move |s| s.name.ends_with(metric_suffix))
            .map(Sample::value)
    }

    /// Returns metrics for a metric-emitting runtime scope.
    pub fn for_scope(&self, scope: &impl MetricScope) -> Self {
        let prefix = format!("{}_", scope.metric_prefix());
        let samples = self
            .samples
            .iter()
            .filter(|s| s.name.starts_with(&prefix))
            .cloned()
            .collect();
        Self { samples }
    }

    /// Counts consensus instances whose processed height is at least `target_height`.
    #[track_caller]
    pub fn consensus_at_height(&self, target_height: u64) -> usize {
        self.values::<u64>(PROCESSED_HEIGHT)
            .filter(|height| *height >= target_height)
            .count()
    }

    /// Counts consensus instances whose latest epoch is at least `target_epoch`.
    #[track_caller]
    pub fn consensus_at_epoch(&self, target_epoch: u64) -> usize {
        self.values::<u64>(LATEST_EPOCH)
            .filter(|epoch| *epoch >= target_epoch)
            .count()
    }

    pub fn latest_consensus_epoch(&self) -> Option<u64> {
        self.value::<u64>(LATEST_EPOCH)
    }

    pub fn latest_consensus_height(&self) -> Option<u64> {
        self.value::<u64>(PROCESSED_HEIGHT)
    }

    pub fn consensus_before_epoch(&self, upper_bound: u64) -> bool {
        self.values::<u64>(LATEST_EPOCH)
            .all(|epoch| epoch < upper_bound)
    }

    pub fn has_consensus_participants(&self, target: u64) -> bool {
        self.values::<u64>(LATEST_PARTICIPANTS)
            .any(|participants| participants == target)
    }

    /// Asserts that all `peers_blocked` metrics are zero.
    #[track_caller]
    pub fn assert_no_blocked_peers(&self) {
        assert!(
            self.values::<u64>(PEERS_BLOCKED)
                .all(|blocked_peers| blocked_peers == 0)
        );
    }

    /// Asserts that all DKG ceremony failure counters are zero.
    #[track_caller]
    pub fn assert_no_dkg_failures(&self) {
        assert!(
            self.values::<u64>(DKG_FAILURES)
                .all(|failures| failures == 0)
        );
    }
}

pub fn assert_no_duplicate_definitions(context: &impl commonware_runtime::Metrics) {
    let mut definitions = HashSet::new();
    let metrics = context.encode();

    for definition in metrics.lines().filter(|line| line.starts_with('#')) {
        assert!(
            definitions.insert(definition),
            "metric `{definition}` is duplicate"
        );
    }
}

/// Polls context metrics until `predicate` returns true.
pub async fn wait_for_metrics(context: &Context, predicate: impl FnMut(&Metrics) -> bool) {
    wait_for_metrics_with_interval(context, DEFAULT_POLL_INTERVAL, predicate).await;
}

/// Polls context metrics at `poll_interval` until `predicate` returns true.
pub async fn wait_for_metrics_with_interval(
    context: &Context,
    poll_interval: Duration,
    mut predicate: impl FnMut(&Metrics) -> bool,
) {
    loop {
        let metrics = context.to_metrics();
        if predicate(&metrics) {
            return;
        }

        context.sleep(poll_interval).await;
    }
}

/// Polls until a metric scope reaches `target_height`.
pub async fn wait_for_height(context: &Context, scope: &impl MetricScope, target_height: u64) {
    wait_for_height_with_interval(context, scope, target_height, DEFAULT_POLL_INTERVAL).await;
}

/// Polls at `poll_interval` until a metric scope reaches `target_height`.
pub async fn wait_for_height_with_interval(
    context: &Context,
    scope: &impl MetricScope,
    target_height: u64,
    poll_interval: Duration,
) {
    wait_for_metrics_with_interval(context, poll_interval, |metrics| {
        metrics.for_scope(scope).consensus_at_height(target_height) > 0
    })
    .await;
}

pub async fn wait_for_participants(context: &Context, target: u64) {
    wait_for_participants_with_interval(context, target, DEFAULT_POLL_INTERVAL).await;
}

pub async fn wait_for_participants_with_interval(
    context: &Context,
    target: u64,
    poll_interval: Duration,
) {
    wait_for_metrics_with_interval(context, poll_interval, |metrics| {
        metrics.has_consensus_participants(target)
    })
    .await;
}
