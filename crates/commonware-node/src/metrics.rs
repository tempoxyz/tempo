use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Extension, Router,
    body::Body,
    http::{Response, StatusCode, header},
    routing::get,
};
use commonware_runtime::{Handle, Metrics as _, Spawner as _, tokio::Context};
use eyre::WrapErr as _;
use opentelemetry::KeyValue;
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

/// Creates an OTLP metrics exporter that periodically pushes consensus metrics.
///
/// Returns a `SdkMeterProvider` that handles periodic export via OTLP. The provider
/// spawns its own background task for exports; the caller should hold onto it for
/// the lifetime of the application.
pub fn install_otlp(_context: Context, config: OtlpConfig) -> eyre::Result<SdkMeterProvider> {
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

    tracing::info!(
        endpoint = %config.endpoint,
        interval = ?config.interval,
        "OTLP metrics exporter configured"
    );

    Ok(meter_provider)
}
