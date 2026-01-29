use base64::{Engine, prelude::BASE64_STANDARD};
use reth_cli_commands::download::DownloadDefaults;
use reth_ethereum::node::core::args::{DefaultPayloadBuilderValues, DefaultTxPoolValues};
use std::{borrow::Cow, time::Duration};
use tempo_chainspec::hardfork::TempoHardfork;
use url::Url;

pub(crate) const DEFAULT_DOWNLOAD_URL: &str = "https://snapshots.tempoxyz.dev/42431";

/// Default OTLP logs filter level for telemetry.
const DEFAULT_LOGS_OTLP_FILTER: &str = "debug";

/// Telemetry configuration derived from a unified telemetry URL.
#[derive(Debug, Clone)]
pub(crate) struct TelemetryConfig {
    /// OTLP logs endpoint (without credentials).
    pub logs_otlp_url: Url,
    /// OTLP logs filter level.
    pub logs_otlp_filter: String,
    /// Unified metrics OTLP endpoint (without credentials).
    /// Used for both consensus and execution metrics.
    pub metrics_otlp_url: String,
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

/// Parses the telemetry URL into a [`TelemetryConfig`].
pub(crate) fn parse_telemetry_config(telemetry_url: &str) -> eyre::Result<TelemetryConfig> {
    // Parse the URL
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

    // Set OTEL_EXPORTER_OTLP_HEADERS for OTLP authentication
    let credentials = format!("{}:{}", username, password.unwrap());
    if std::env::var_os("OTEL_EXPORTER_OTLP_HEADERS").is_none() {
        let encoded = BASE64_STANDARD.encode(credentials.as_bytes());
        let header_value = format!("Authorization=Basic {encoded}");
        // SAFETY: This is called at startup before any other threads are spawned
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_HEADERS", header_value);
        }
    }

    // Build URL without credentials for OTLP
    url.set_username("").ok();
    url.set_password(None).ok();
    let base_url_no_creds = url.as_str().trim_end_matches('/');

    // Build logs OTLP URL (standard OTLP HTTP path)
    let logs_otlp_url = Url::parse(&format!("{base_url_no_creds}/v1/logs"))
        .map_err(|e| eyre::eyre!("failed to construct logs OTLP URL: {e}"))?;

    // Build unified metrics OTLP URL (standard OTLP HTTP path)
    let metrics_otlp_url = format!("{base_url_no_creds}/v1/metrics");

    Ok(TelemetryConfig {
        logs_otlp_url,
        logs_otlp_filter: DEFAULT_LOGS_OTLP_FILTER.to_string(),
        metrics_otlp_url,
    })
}
