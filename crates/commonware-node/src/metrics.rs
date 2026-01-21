use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

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
    pub interval: Duration,
    /// Labels to add to all metrics (e.g., node_id, consensus_pubkey).
    pub labels: HashMap<String, String>,
}

/// Installs an OTLP metrics exporter that periodically pushes consensus metrics.
///
/// This creates an OpenTelemetry MeterProvider with an OTLP exporter and periodically
/// reads metrics from the commonware context, converting them to OpenTelemetry format.
pub fn install_otlp(context: Context, config: OtlpConfig) -> Handle<eyre::Result<()>> {
    context.spawn(move |context| async move {
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

        // Create periodic reader with configured interval
        let reader = PeriodicReader::builder(exporter)
            .with_interval(config.interval)
            .build();

        // Build meter provider
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(reader)
            .build();

        let meter = meter_provider.meter("tempo-consensus");

        // Create gauges for the metrics we want to export
        // We'll parse the prometheus text format and update these gauges
        let metrics_context = Arc::new(context);
        let meter = Arc::new(meter);

        // Create an observable gauge that reads from the context on each export
        let ctx_clone = metrics_context.clone();
        let _gauge = meter
            .f64_observable_gauge("consensus_metrics")
            .with_description("Consensus layer metrics from commonware runtime")
            .with_callback(move |observer| {
                let encoded = ctx_clone.encode();
                // Parse prometheus format and report individual metrics
                for line in encoded.lines() {
                    if line.starts_with('#') || line.is_empty() {
                        continue;
                    }
                    if let Some((name_labels, value_str)) = line.rsplit_once(' ')
                        && let Ok(value) = value_str.parse::<f64>()
                    {
                        // Extract metric name and labels
                        let (name, labels) = parse_prometheus_metric(name_labels);
                        let attributes: Vec<KeyValue> = labels
                            .into_iter()
                            .map(|(k, v)| KeyValue::new(k, v))
                            .collect();
                        observer.observe(value, &attributes);

                        // Also record with the original metric name as an attribute
                        let mut attrs_with_name = attributes.clone();
                        attrs_with_name.push(KeyValue::new("metric_name", name));
                        observer.observe(value, &attrs_with_name);
                    }
                }
            })
            .build();

        tracing::info!(
            endpoint = %config.endpoint,
            interval = ?config.interval,
            "OTLP metrics exporter started"
        );

        // Keep the meter provider alive
        // The periodic reader will automatically export metrics at the configured interval
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
