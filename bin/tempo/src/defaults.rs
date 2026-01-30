use base64::{Engine, prelude::BASE64_STANDARD};
use jiff::SignedDuration;
use reth_cli_commands::download::DownloadDefaults;
use reth_ethereum::node::core::args::{DefaultPayloadBuilderValues, DefaultTxPoolValues};
use std::{borrow::Cow, time::Duration};
use tempo_chainspec::hardfork::TempoHardfork;
use url::Url;

pub(crate) const DEFAULT_DOWNLOAD_URL: &str = "https://snapshots.tempoxyz.dev/42431";

/// Default OTLP logs filter level for telemetry.
const DEFAULT_LOGS_OTLP_FILTER: &str = "debug";

/// CLI arguments for telemetry configuration.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub(crate) struct TelemetryArgs {
    /// Enables telemetry export (OTLP logs & Prometheus metrics push). Coupled
    /// to VictoriaMetrics which supports both with different api paths.
    ///
    /// The URL must include credentials: `https://user:pass@metrics.example.com`
    #[arg(long, value_name = "URL")]
    pub telemetry_url: Option<String>,

    /// The interval at which to push Prometheus metrics.
    #[arg(long, default_value = "10s")]
    pub telemetry_metrics_interval: SignedDuration,
}

/// Telemetry configuration derived from a unified telemetry URL.
#[derive(Debug, Clone)]
pub(crate) struct TelemetryConfig {
    /// OTLP logs endpoint (without credentials).
    pub logs_otlp_url: Url,
    /// OTLP logs filter level.
    pub logs_otlp_filter: String,
    /// Prometheus metrics push endpoint (without credentials).
    /// Used for both consensus and execution metrics.
    pub metrics_prometheus_url: String,
    /// The interval at which to push Prometheus metrics.
    pub metrics_prometheus_interval: SignedDuration,
    /// Authorization header for metrics push (e.g., "Basic <base64>").
    pub metrics_auth_header: Option<String>,
}

fn init_download_urls() {
    let download_defaults = DownloadDefaults {
        available_snapshots: vec![
            Cow::Borrowed("https://snapshots.tempoxyz.dev/42431 (moderato)"),
            Cow::Borrowed("https://snapshots.tempoxyz.dev/42429 (andantino)"),
        ],
        default_base_url: Cow::Borrowed(DEFAULT_DOWNLOAD_URL),
        long_help: None,
    };

    download_defaults
        .try_init()
        .expect("failed to initialize download URLs");
}

fn init_payload_builder_defaults() {
    DefaultPayloadBuilderValues::default()
        .with_interval(Duration::from_millis(100))
        .with_max_payload_tasks(16)
        .with_deadline(4)
        .try_init()
        .expect("failed to initialize payload builder defaults");
}

fn init_txpool_defaults() {
    DefaultTxPoolValues::default()
        .with_pending_max_count(50000)
        .with_basefee_max_count(50000)
        .with_queued_max_count(50000)
        .with_pending_max_size(100)
        .with_basefee_max_size(100)
        .with_queued_max_size(100)
        .with_no_locals(true)
        .with_max_queued_lifetime(Duration::from_secs(120))
        .with_max_new_pending_txs_notifications(150000)
        .with_max_account_slots(150000)
        .with_pending_tx_listener_buffer_size(50000)
        .with_new_tx_listener_buffer_size(50000)
        .with_disable_transactions_backup(true)
        .with_additional_validation_tasks(8)
        .with_minimal_protocol_basefee(TempoHardfork::default().base_fee())
        .with_minimum_priority_fee(Some(0))
        .with_max_batch_size(50000)
        .try_init()
        .expect("failed to initialize txpool defaults");
}

pub(crate) fn init_defaults() {
    init_download_urls();
    init_payload_builder_defaults();
    init_txpool_defaults();
}

/// Parses the telemetry args into a [`TelemetryConfig`].
///
/// Returns `None` if telemetry is not enabled (no URL provided).
pub(crate) fn parse_telemetry_config(
    args: &TelemetryArgs,
) -> eyre::Result<Option<TelemetryConfig>> {
    let Some(ref telemetry_url) = args.telemetry_url else {
        return Ok(None);
    };

    let mut url =
        Url::parse(telemetry_url).map_err(|e| eyre::eyre!("--telemetry-url: invalid URL: {e}"))?;

    // Extract credentials - both username and password are required
    let username = url.username();
    let password = url.password();
    if username.is_empty() || password.is_none() {
        return Err(eyre::eyre!(
            "--telemetry-url must include credentials (username and password).\n\
             Format: https://user:pass@metrics.example.com"
        ));
    }

    // Build auth header for metrics push and OTLP logs
    let credentials = format!("{}:{}", username, password.unwrap());
    let encoded = BASE64_STANDARD.encode(credentials.as_bytes());
    let auth_header = format!("Basic {encoded}");

    // Set OTEL_EXPORTER_OTLP_HEADERS for OTLP logs authentication
    // SAFETY: This is called at startup before any other threads are spawned
    if std::env::var_os("OTEL_EXPORTER_OTLP_HEADERS").is_none() {
        let header_value = format!("Authorization={auth_header}");
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_HEADERS", header_value);
        }
    }

    // Build URL without credentials for OTLP
    url.set_username("").ok();
    url.set_password(None).ok();
    let base_url_no_creds = url.as_str().trim_end_matches('/');

    // Build logs OTLP URL (Victoria Metrics OTLP path)
    let logs_otlp_url = Url::parse(&format!("{base_url_no_creds}/opentelemetry/v1/logs"))
        .map_err(|e| eyre::eyre!("failed to construct logs OTLP URL: {e}"))?;

    // Build Victoria Metrics Prometheus import URL
    let metrics_prometheus_url = format!("{base_url_no_creds}/api/v1/import/prometheus");

    Ok(Some(TelemetryConfig {
        logs_otlp_url,
        logs_otlp_filter: DEFAULT_LOGS_OTLP_FILTER.to_string(),
        metrics_prometheus_url,
        metrics_prometheus_interval: args.telemetry_metrics_interval,
        metrics_auth_header: Some(auth_header),
    }))
}
