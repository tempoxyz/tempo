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
use std::collections::HashMap;
use url::Url;

/// Configuration for Prometheus metrics push export.
pub struct PrometheusMetricsConfig {
    /// The Prometheus export endpoint.
    pub endpoint: Url,
    /// The interval at which to push metrics.
    pub interval: SignedDuration,
    /// Optional Authorization header value
    pub auth_header: Option<String>,
    /// Extra labels to append to every metrics
    pub extra_labels: HashMap<String, String>,
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

            let consensus_metrics = context.encode();
            let reth_metrics = reth_recorder.handle().render();
            let all_metrics = format!("{consensus_metrics}\n{reth_metrics}");

            let body = attach_labels(&all_metrics, &config.extra_labels);

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

fn attach_labels(metrics: &str, labels: &HashMap<String, String>) -> String {
    if labels.is_empty() {
        return metrics.to_string();
    }

    let extra_labels = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{v}\""))
        .collect::<Vec<_>>()
        .join(",");

    let mut result = String::with_capacity(metrics.len());
    for line in metrics.lines() {
        if line.starts_with('#') || line.is_empty() {
            result += &format!("{line}\n");
            continue;
        }

        if let Some(brace) = line.find('{') {
            let (name, rest) = line.split_at(brace + 1);
            result += &format!("{name}{extra_labels},{rest}\n");
        } else if let Some(space) = line.find(' ') {
            let (name, rest) = line.split_at(space);
            result += &format!("{name}{{{extra_labels}}}{rest}\n");
        } else {
            result += &format!("{line}\n");
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn empty_labels_returns_unchanged() {
        let input = "http_requests_total 42\n";
        assert_eq!(attach_labels(input, &HashMap::new()), input);
    }

    #[test]
    fn adds_labels_to_metric_without_existing_labels() {
        let input = "http_requests_total 42\n";
        let result = attach_labels(input, &labels(&[("env", "prod")]));
        assert_eq!(result, "http_requests_total{env=\"prod\"} 42\n");
    }

    #[test]
    fn inserts_labels_into_metric_with_existing_labels() {
        let input = "http_requests_total{method=\"GET\"} 42\n";
        let result = attach_labels(input, &labels(&[("env", "prod")]));
        assert_eq!(
            result,
            "http_requests_total{env=\"prod\",method=\"GET\"} 42\n"
        );
    }

    #[test]
    fn preserves_comment_lines() {
        let input = "# HELP http_requests_total Total requests\n# TYPE http_requests_total counter\nhttp_requests_total 42\n";
        let result = attach_labels(input, &labels(&[("env", "prod")]));
        assert!(result.starts_with(
            "# HELP http_requests_total Total requests\n# TYPE http_requests_total counter\n"
        ));
        assert!(result.contains("http_requests_total{env=\"prod\"} 42\n"));
    }

    #[test]
    fn preserves_empty_lines() {
        let input = "http_requests_total 1\n\nhttp_errors_total 2\n";
        let result = attach_labels(input, &labels(&[("env", "prod")]));
        assert!(result.contains("\n\n"));
    }
}
