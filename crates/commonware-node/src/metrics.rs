use std::{collections::HashMap, net::SocketAddr, sync::Arc};

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
        let listener = TcpListener::bind(listen_addr)
            .await
            .wrap_err("failed to bind provided address")?;

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
    pub interval: jiff::SignedDuration,
    /// Labels to add to all metrics as resource attributes.
    pub labels: HashMap<String, String>,
}

/// Handle to the OTLP metrics bridge that must be held for the lifetime of the export.
pub struct OtlpMetricsHandle {
    _meter_provider: SdkMeterProvider,
    _task: tokio::task::JoinHandle<()>,
}

/// Installs an OTLP metrics exporter that periodically pushes consensus metrics.
///
/// This bridges commonware's Prometheus-format metrics to OTLP by polling
/// `context.encode()` and recording values via dynamically-created gauges.
/// Each metric preserves its original name from the Prometheus output.
///
/// Returns an `OtlpMetricsHandle` that must be held for the lifetime of the export.
pub fn install_otlp(context: Context, config: OtlpConfig) -> eyre::Result<OtlpMetricsHandle> {
    // Build resource attributes from labels
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

    // Configure OTLP exporter
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

    // Cache for dynamically created gauges - we create them on first encounter
    let gauges: Arc<Mutex<HashMap<String, opentelemetry::metrics::Gauge<f64>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    tracing::info!(
        endpoint = %config.endpoint,
        interval = ?config.interval,
        "OTLP metrics exporter started"
    );

    // Spawn a task that polls commonware metrics and records them to OpenTelemetry.
    // Poll at half the export interval to ensure fresh data for each export.
    let poll_interval = interval / 2;
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;

            let encoded = context.encode();

            for line in encoded.lines() {
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }

                if let Some((name_labels, value_str)) = line.rsplit_once(' ')
                    && let Ok(value) = value_str.parse::<f64>()
                {
                    let (metric_name, labels) = parse_prometheus_metric(name_labels);

                    // Get or create gauge for this metric (preserving original name)
                    let gauge = {
                        let mut cache = gauges.lock();
                        cache
                            .entry(metric_name.clone())
                            .or_insert_with(|| meter.f64_gauge(metric_name).build())
                            .clone()
                    };

                    let attributes: Vec<KeyValue> = labels
                        .into_iter()
                        .map(|(k, v)| KeyValue::new(k, v))
                        .collect();

                    gauge.record(value, &attributes);
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
