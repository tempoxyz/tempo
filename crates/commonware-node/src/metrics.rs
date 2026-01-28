use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use jiff::SignedDuration;

use axum::{
    Extension, Router,
    body::Body,
    http::{Response, StatusCode, header},
    routing::get,
};
use commonware_runtime::{Handle, Metrics as _, Spawner as _, tokio::Context};
use eyre::WrapErr as _;
use opentelemetry::{KeyValue, metrics::MeterProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};
use parking_lot::Mutex;
use tokio::net::TcpListener;

/// Installs a metrics server so that commonware can publish its metrics.
///
/// This is lifted straight from [`commonware_runtime::tokio::telemetry::init`],
/// because it also wants to install a tracing subscriber, which clashes with
/// reth ethereum cli doing the same thing.
pub fn install(context: Context, listen_addr: SocketAddr) -> Handle<eyre::Result<()>> {
    context.spawn(move |context| async move {
        // Create a tokio listener for the metrics server.
        //
        // We explicitly avoid using a runtime `Listener` because
        // it will track bandwidth used for metrics and apply a policy
        // for read/write timeouts fit for a p2p network.
        let listener = TcpListener::bind(listen_addr)
            .await
            .wrap_err("failed to bind provided address")?;

        // Create a router for the metrics server
        let app = Router::new()
            .route(
                "/metrics",
                get(|Extension(ctx): Extension<Context>| async move {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
                        .body(Body::from(ctx.encode()))
                        .expect("Failed to create response")
                }),
            )
            .layer(Extension(context));

        // Serve the metrics over HTTP.
        //
        // `serve` will spawn its own tasks using `tokio::spawn` (and there is no way to specify
        // it to do otherwise). These tasks will not be tracked like metrics spawned using `Spawner`.
        axum::serve(listener, app.into_make_service())
            .await
            .map_err(Into::into)
    })
}

/// Configuration for OTLP metrics export.
pub struct OtlpConfig {
    /// The OTLP endpoint URL (e.g., `https://metrics.example.com/v1/metrics`).
    pub endpoint: String,
    /// The interval at which to export metrics.
    pub interval: SignedDuration,
    /// Labels to add to all metrics as resource attributes (e.g., node_id, consensus_pubkey).
    pub labels: HashMap<String, String>,
}

/// Handle to the OTLP metrics exporter that must be held for the lifetime of the export.
pub struct OtlpMetricsHandle {
    _meter_provider: SdkMeterProvider,
    _task: Handle<()>,
}

/// Installs an OTLP metrics exporter that periodically pushes consensus metrics.
///
/// This bridges commonware's Prometheus-format metrics to OTLP by polling
/// `context.encode()` and recording values via dynamically-created gauges.
/// Each metric preserves its original name from the Prometheus output.
///
/// Returns an `OtlpMetricsHandle` that must be held for the lifetime of the export.
pub fn install_otlp(context: Context, config: OtlpConfig) -> eyre::Result<OtlpMetricsHandle> {
    let resource_attributes: Vec<KeyValue> = config
        .labels
        .iter()
        .map(|(k, v)| KeyValue::new(k.clone(), v.clone()))
        .chain(std::iter::once(KeyValue::new(
            "service.name",
            "tempo-consensus",
        )))
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

    let meter = meter_provider.meter("tempo-consensus");

    // Cache for dynamically created counters
    let counters: Arc<Mutex<HashMap<String, opentelemetry::metrics::Counter<f64>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Cache for dynamically created gauges (including histograms)
    let gauges: Arc<Mutex<HashMap<String, opentelemetry::metrics::Gauge<f64>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Poll at half the export interval to ensure fresh data for each export
    let poll_interval = interval / 2;
    let task = context.spawn(move |context| async move {
        use commonware_runtime::Clock as _;

        // Track last counter values to compute deltas (OTLP counters expect deltas, not absolutes)
        let mut last_counter_values: HashMap<(String, Vec<(String, String)>), f64> = HashMap::new();

        loop {
            context.sleep(poll_interval).await;

            let encoded = context.encode();

            // Parse TYPE comments to determine metric types
            let metric_types = parse_prometheus_types(&encoded);

            // Process metric values
            for line in encoded.lines() {
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

                        if delta > 0.0 {
                            counter.add(delta, &attributes);
                        }
                    } else {
                        // Gauge - use gauge (histograms are handled as counters above)
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
fn parse_prometheus_types(text: &str) -> HashMap<String, &str> {
    let mut types = HashMap::new();
    for line in text.lines() {
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
    fn test_parse_prometheus_metric_histogram_bucket() {
        let (name, labels) = parse_prometheus_metric(r#"http_request_duration_bucket{le="0.5"}"#);
        assert_eq!(name, "http_request_duration_bucket");
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], ("le".to_string(), "0.5".to_string()));
    }

    #[test]
    fn test_parse_prometheus_types() {
        let types = parse_prometheus_types(SAMPLE_PROMETHEUS_OUTPUT);

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

    #[test]
    fn test_counter_detection_from_prometheus_output() {
        let types = parse_prometheus_types(SAMPLE_PROMETHEUS_OUTPUT);

        // Counter metric
        let base = strip_prometheus_suffix("runtime_tasks_spawned_total");
        assert_eq!(base, "runtime_tasks_spawned");
        assert!(is_counter_type(types.get(base).copied()));

        // Gauge metric
        let base = strip_prometheus_suffix("runtime_tasks_running");
        assert_eq!(base, "runtime_tasks_running");
        assert!(!is_counter_type(types.get(base).copied()));

        // Histogram bucket -> should be treated as counter
        let base = strip_prometheus_suffix("http_request_duration_bucket");
        assert_eq!(base, "http_request_duration");
        assert!(is_counter_type(types.get(base).copied()));

        // Histogram count -> should be treated as counter
        let base = strip_prometheus_suffix("http_request_duration_count");
        assert_eq!(base, "http_request_duration");
        assert!(is_counter_type(types.get(base).copied()));

        // Histogram sum -> should be treated as counter
        let base = strip_prometheus_suffix("http_request_duration_sum");
        assert_eq!(base, "http_request_duration");
        assert!(is_counter_type(types.get(base).copied()));
    }
}
