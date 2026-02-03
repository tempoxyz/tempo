//! Unified telemetry module for exporting metrics from both consensus and execution layers.
//!
//! This module pushes Prometheus-format metrics directly to Victoria Metrics by polling:
//! - Commonware's runtime context (`context.encode()`)
//! - Reth's prometheus recorder (`handle.render()`)

use commonware_runtime::{Metrics as _, Spawner as _, tokio::Context};
use eyre::WrapErr as _;
use jiff::SignedDuration;
use reth_node_metrics::recorder::install_prometheus_recorder;
use reth_tracing::tracing;
use url::Url;

/// Configuration for Prometheus metrics push export.
pub struct PrometheusMetricsConfig {
    /// The Prometheus export endpoint.
    pub endpoint: Url,
    /// The interval at which to push metrics.
    pub interval: SignedDuration,
    /// Optional Authorization header value
    pub auth_header: Option<String>,
}

/// Spawns a task that periodically pushes both consensus and execution metrics to Victoria Metrics.
///
/// This concatenates Prometheus-format metrics from both sources and pushes them directly
/// to Victoria Metrics' Prometheus import endpoint.
///
/// The task runs for the lifetime of the consensus runtime.
pub fn install_prometheus_metrics(
    context: Context,
    config: PrometheusMetricsConfig,
) -> eyre::Result<()> {
    let interval: std::time::Duration = config
        .interval
        .try_into()
        .wrap_err("invalid metrics duration")?;

    let client = reqwest::Client::new();

    let endpoint = config.endpoint.to_string();
    let auth_header = config.auth_header;

    let reth_recorder = install_prometheus_recorder();
    context.spawn(move |context| async move {
        use commonware_runtime::Clock as _;

        tracing::info_span!("metrics_exporter", %endpoint).in_scope(|| tracing::info!("started"));

        loop {
            context.sleep(interval).await;

            // Collect metrics from both sources
            let consensus_metrics = context.encode();
            let reth_metrics = reth_recorder.handle().render();
            let body = format!("{consensus_metrics}\n{reth_metrics}");

            // Push to Victoria Metrics
            let mut request = client
                .post(&endpoint)
                .header("Content-Type", "text/plain")
                .body(body);

            if let Some(ref auth) = auth_header {
                request = request.header("Authorization", auth);
            }

            let res = request.send().await;
            tracing::info_span!("metrics_exporter", %endpoint).in_scope(|| match res {
                Ok(response) if !response.status().is_success() => {
                    tracing::warn!(status = %response.status(), "metrics endpoint returned failure")
                }
                Err(reason) => tracing::warn!(%reason, "metrics export failed"),
                _ => {}
            });
        }
    });

    Ok(())
}
