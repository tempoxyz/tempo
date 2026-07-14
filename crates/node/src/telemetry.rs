//! Unified telemetry module for exporting metrics from both consensus and execution layers.
//!
//! This module pushes Prometheus-format metrics directly to Victoria Metrics by polling:
//! - Commonware's runtime context (`context.encode()`)
//! - Reth's prometheus recorder (`handle.render()`)

use commonware_runtime::{Metrics as _, Spawner as _, tokio::Context};
use eyre::WrapErr as _;
use jiff::SignedDuration;
use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::info::Info,
    registry::Registry,
};
use reth_node_metrics::recorder::install_prometheus_recorder;
use reth_tracing::tracing;
use std::path::{Path, PathBuf};
use sysinfo::{Disks, System};
use url::Url;

#[derive(Clone, Debug, EncodeLabelSet, Hash, PartialEq, Eq)]
struct HardwareInfo {
    cpu_vendor: String,
    cpu_brand: String,
    physical_core_count: usize,
    logical_core_count: usize,
    total_memory_bytes: u64,
    datadir_file_system: String,
    static_files_file_system: String,
    consensus_file_system: String,
}

fn file_system_for_path(disks: &Disks, path: &Path) -> String {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    disks
        .iter()
        .filter(|disk| path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().components().count())
        .map(|disk| disk.file_system().to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Collects non-identifying hardware metadata and encodes it as a Prometheus info metric.
///
/// Disk names and mount sources are deliberately not collected because they can expose internal
/// infrastructure details for network-mounted filesystems.
fn hardware_metrics(config: &PrometheusMetricsConfig) -> eyre::Result<String> {
    let system = System::new_all();
    let cpu = system.cpus().first();
    let disks = Disks::new_with_refreshed_list();

    let labels = HardwareInfo {
        cpu_vendor: cpu.map_or_else(String::new, |cpu| cpu.vendor_id().to_owned()),
        cpu_brand: cpu.map_or_else(String::new, |cpu| cpu.brand().to_owned()),
        physical_core_count: System::physical_core_count().unwrap_or_default(),
        logical_core_count: system.cpus().len(),
        total_memory_bytes: system
            .cgroup_limits()
            .map_or_else(|| system.total_memory(), |limits| limits.total_memory),
        datadir_file_system: file_system_for_path(&disks, &config.datadir),
        static_files_file_system: file_system_for_path(&disks, &config.static_files_dir),
        consensus_file_system: file_system_for_path(&disks, &config.consensus_dir),
    };

    let mut registry = Registry::default();
    registry.register(
        "tempo_hardware",
        "Static, non-identifying hardware information for the Tempo node",
        Info::new(labels),
    );

    let mut encoded = String::new();
    encode(&mut encoded, &registry).wrap_err("failed to encode hardware metrics")?;
    Ok(encoded)
}

/// Configuration for Prometheus metrics push export.
pub struct PrometheusMetricsConfig {
    /// The Prometheus export endpoint.
    pub endpoint: Url,
    /// The interval at which to push metrics.
    pub interval: SignedDuration,
    /// Optional Authorization header value
    pub auth_header: Option<String>,
    /// Consensus Identifier for this node.
    pub consensus_pubkey: Option<String>,
    /// Peer Id for this node.
    pub peer_id: String,
    /// Resolved execution data directory.
    pub datadir: PathBuf,
    /// Resolved static files directory.
    pub static_files_dir: PathBuf,
    /// Resolved consensus data directory.
    pub consensus_dir: PathBuf,
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

    let mut extra_label = format!("peer_id={}", config.peer_id);
    if let Some(pubkey) = config.consensus_pubkey {
        extra_label.push_str(&format!(",consensus_pubkey={pubkey}"));
    }

    let mut endpoint = config.endpoint;
    endpoint
        .query_pairs_mut()
        .append_pair("extra_label", &extra_label);

    let url = endpoint.to_string();
    let client = reqwest::Client::new();
    let hardware_metrics = hardware_metrics(&config)?;
    let auth_header = config.auth_header;

    let reth_recorder = install_prometheus_recorder();
    context.spawn(move |context| async move {
        use commonware_runtime::Clock as _;

        tracing::info_span!("metrics_exporter", %url).in_scope(|| tracing::info!("started"));

        loop {
            context.sleep(interval).await;

            let consensus_metrics = context.encode();
            let reth_metrics = reth_recorder.handle().render();
            let body = format!("{consensus_metrics}\n{reth_metrics}\n{hardware_metrics}");

            // Push to Victoria Metrics
            let mut request = client
                .post(&url)
                .header("Content-Type", "text/plain")
                .body(body);

            if let Some(ref auth) = auth_header {
                request = request.header("Authorization", auth);
            }

            let res = request.send().await;
            tracing::info_span!("metrics_exporter", %url).in_scope(|| match res {
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
