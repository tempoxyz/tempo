//! Unified telemetry module for exporting metrics from both consensus and execution layers.
//!
//! This module bridges Prometheus-format metrics to OTLP by polling metrics from:
//! - Commonware's runtime context (`context.encode()`)
//! - Reth's prometheus recorder (`handle.render()`)

use std::{collections::HashMap, sync::Arc};

use commonware_runtime::{Handle, Metrics as _, Spawner as _, tokio::Context};
use eyre::WrapErr as _;
use jiff::SignedDuration;
use opentelemetry::{KeyValue, metrics::MeterProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};
use parking_lot::Mutex;
use reth_node_metrics::recorder::install_prometheus_recorder;

/// Configuration for unified OTLP metrics export.
pub struct OtlpMetricsConfig {
    /// The OTLP endpoint URL (e.g., `https://metrics.example.com/v1/metrics`).
    pub endpoint: String,
    /// The interval at which to export metrics.
    pub interval: SignedDuration,
    /// Labels to add to all metrics as resource attributes (e.g., consensus_pubkey).
    pub labels: HashMap<String, String>,
}

/// Handle to the OTLP metrics exporter that must be held for the lifetime of the export.
pub struct OtlpMetricsHandle {
    _meter_provider: SdkMeterProvider,
    _task: Handle<()>,
}

/// Installs a unified OTLP metrics exporter that periodically pushes both consensus and
/// execution metrics.
///
/// This bridges Prometheus-format metrics to OTLP by polling:
/// - `context.encode()` for commonware/consensus metrics
/// - `install_prometheus_recorder().handle().render()` for reth/execution metrics
///
/// Returns an `OtlpMetricsHandle` that must be held for the lifetime of the export.
pub fn install_otlp_metrics(
    context: Context,
    config: OtlpMetricsConfig,
) -> eyre::Result<OtlpMetricsHandle> {
    let resource_attributes: Vec<KeyValue> = config
        .labels
        .iter()
        .map(|(k, v)| KeyValue::new(k.clone(), v.clone()))
        .chain(std::iter::once(KeyValue::new("service.name", "tempo")))
        .collect();

    let resource = Resource::builder()
        .with_attributes(resource_attributes)
        .build();

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(&config.endpoint)
        .build()
        .wrap_err("failed to build OTLP metrics exporter")?;

    let interval: std::time::Duration = config
        .interval
        .try_into()
        .wrap_err("metrics interval must be positive")?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(interval)
        .build();

    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    let meter = meter_provider.meter("tempo");

    // Cache for dynamically created counters (and Histograms).
    //
    // When reported, Histograms are already aggregated into a collection of counters, thus
    // we don't have a way to reconstruct the observations to recreate an opentelemetry
    // Histogram with the individual observations.
    //
    // Note: VictoriaMetrics/Grafana will recognize the prometheus bucket labeling format
    // and will treat these metrics as histograms.
    let counters: Arc<Mutex<HashMap<String, opentelemetry::metrics::Counter<f64>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Cache for dynamically created gauges
    let gauges: Arc<Mutex<HashMap<String, opentelemetry::metrics::Gauge<f64>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Get handle to reth's prometheus recorder
    let reth_recorder = install_prometheus_recorder();

    // Poll at half the export interval to ensure fresh data for each export
    let poll_interval = interval / 2;
    let task = context.spawn(move |context| async move {
        use commonware_runtime::Clock as _;

        // Track last counter values to compute deltas (OTLP counters expect deltas, not absolutes)
        let mut last_counter_values: HashMap<(String, Vec<(String, String)>), f64> = HashMap::new();

        loop {
            context.sleep(poll_interval).await;

            // Collect metrics from both sources
            let consensus_metrics_encoded = context.encode();
            let reth_metrics_encoded = reth_recorder.handle().render();
            let metrics = consensus_metrics_encoded
                .lines()
                .chain(reth_metrics_encoded.lines())
                .collect::<Vec<_>>();

            // Parse TYPE comments to determine metric types
            let metric_types = parse_prometheus_types(metrics.iter().copied());

            // Process metric values
            for line in metrics {
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }

                if let Some((name_labels, value_str)) = line.rsplit_once(' ')
                    && let Ok(value) = value_str.parse::<f64>()
                {
                    let (metric_name, labels) = parse_prometheus_metric(name_labels);
                    let base_name = strip_prometheus_suffix(&metric_name);

                    let attributes: Vec<KeyValue> = labels
                        .iter()
                        .map(|(k, v)| KeyValue::new(k.clone(), v.clone()))
                        .collect();

                    let metric_type = metric_types.get(base_name).copied();
                    if is_counter_type(metric_type) {
                        let counter = {
                            let mut cache = counters.lock();
                            cache
                                .entry(metric_name.clone())
                                .or_insert_with(|| meter.f64_counter(metric_name.clone()).build())
                                .clone()
                        };

                        // Compute delta from last value (counters are cumulative in Prometheus)
                        let key = (metric_name, labels);
                        let last_value = last_counter_values.get(&key).copied().unwrap_or(0.0);
                        let delta = (value - last_value).max(0.0);
                        last_counter_values.insert(key, value);

                        if delta >= 0.0 {
                            counter.add(delta, &attributes);
                        }
                    } else {
                        // Gauge
                        let gauge = {
                            let mut cache = gauges.lock();
                            cache
                                .entry(metric_name.clone())
                                .or_insert_with(|| meter.f64_gauge(metric_name).build())
                                .clone()
                        };

                        gauge.record(value, &attributes);
                    }
                }
            }
        }
    });

    Ok(OtlpMetricsHandle {
        _meter_provider: meter_provider,
        _task: task,
    })
}

/// Parse a prometheus metric line like `metric_name{label="value"} 123`
/// Returns (metric_name, vec of (label_name, label_value))
fn parse_prometheus_metric(name_labels: &str) -> (String, Vec<(String, String)>) {
    if let Some(brace_start) = name_labels.find('{') {
        let name = name_labels[..brace_start].to_string();
        let labels_str = &name_labels[brace_start + 1..];
        let labels_str = labels_str.trim_end_matches('}');

        let mut labels = Vec::new();
        for part in labels_str.split(',') {
            if let Some((k, v)) = part.split_once('=') {
                let v = v.trim_matches('"');
                labels.push((k.to_string(), v.to_string()));
            }
        }
        (name, labels)
    } else {
        (name_labels.to_string(), Vec::new())
    }
}

/// Parse `# TYPE metric_name type` lines from Prometheus text format.
/// Returns a map of metric base name -> type string.
fn parse_prometheus_types<'a>(lines: impl Iterator<Item = &'a str>) -> HashMap<String, &'a str> {
    let mut types = HashMap::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("# TYPE ")
            && let Some((name, type_str)) = rest.split_once(' ')
        {
            types.insert(name.to_string(), type_str);
        }
    }
    types
}

/// Strip known Prometheus suffixes to find the base metric name for type lookup.
fn strip_prometheus_suffix(metric_name: &str) -> &str {
    metric_name
        .strip_suffix("_total")
        .or_else(|| metric_name.strip_suffix("_count"))
        .or_else(|| metric_name.strip_suffix("_sum"))
        .or_else(|| metric_name.strip_suffix("_bucket"))
        .unwrap_or(metric_name)
}

/// Determine if a metric should be treated as a counter based on its type.
/// Counters and histograms (which are collections of counters) return true.
fn is_counter_type(metric_type: Option<&str>) -> bool {
    matches!(metric_type, Some("counter") | Some("histogram"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PROMETHEUS_OUTPUT: &str = r#"# HELP runtime_tasks_spawned Total number of tasks spawned.
# TYPE runtime_tasks_spawned counter
runtime_tasks_spawned_total{name="",kind="Root",execution="Shared"} 42
# HELP runtime_tasks_running Number of tasks currently running.
# TYPE runtime_tasks_running gauge
runtime_tasks_running{name="worker",kind="Task",execution="Dedicated"} 5
# HELP http_request_duration Request duration histogram.
# TYPE http_request_duration histogram
http_request_duration_bucket{le="0.1"} 10
http_request_duration_bucket{le="0.5"} 25
http_request_duration_bucket{le="1.0"} 30
http_request_duration_bucket{le="+Inf"} 35
http_request_duration_sum 42.5
http_request_duration_count 35
# HELP runtime_process_rss Resident set size.
# TYPE runtime_process_rss gauge
runtime_process_rss 8224768
# EOF
"#;

    #[test]
    fn test_parse_prometheus_metric_no_labels() {
        let (name, labels) = parse_prometheus_metric("my_metric");
        assert_eq!(name, "my_metric");
        assert!(labels.is_empty());
    }

    #[test]
    fn test_parse_prometheus_metric_with_labels() {
        let (name, labels) = parse_prometheus_metric(r#"my_metric{foo="bar",baz="qux"}"#);
        assert_eq!(name, "my_metric");
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0], ("foo".to_string(), "bar".to_string()));
        assert_eq!(labels[1], ("baz".to_string(), "qux".to_string()));
    }

    #[test]
    fn test_parse_prometheus_metric_single_label() {
        let (name, labels) = parse_prometheus_metric(r#"counter{id="123"}"#);
        assert_eq!(name, "counter");
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], ("id".to_string(), "123".to_string()));
    }

    #[test]
    fn test_parse_prometheus_types() {
        let types = parse_prometheus_types(SAMPLE_PROMETHEUS_OUTPUT.lines());

        assert_eq!(types.get("runtime_tasks_spawned"), Some(&"counter"));
        assert_eq!(types.get("runtime_tasks_running"), Some(&"gauge"));
        assert_eq!(types.get("http_request_duration"), Some(&"histogram"));
        assert_eq!(types.get("runtime_process_rss"), Some(&"gauge"));
        assert_eq!(types.get("nonexistent"), None);
    }

    #[test]
    fn test_strip_prometheus_suffix() {
        assert_eq!(strip_prometheus_suffix("requests_total"), "requests");
        assert_eq!(
            strip_prometheus_suffix("http_duration_count"),
            "http_duration"
        );
        assert_eq!(
            strip_prometheus_suffix("http_duration_sum"),
            "http_duration"
        );
        assert_eq!(
            strip_prometheus_suffix("http_duration_bucket"),
            "http_duration"
        );
        assert_eq!(strip_prometheus_suffix("memory_usage"), "memory_usage");
        assert_eq!(strip_prometheus_suffix("total_requests"), "total_requests");
    }

    #[test]
    fn test_is_counter_type() {
        assert!(is_counter_type(Some("counter")));
        assert!(is_counter_type(Some("histogram")));
        assert!(!is_counter_type(Some("gauge")));
        assert!(!is_counter_type(Some("summary")));
        assert!(!is_counter_type(None));
    }
}
