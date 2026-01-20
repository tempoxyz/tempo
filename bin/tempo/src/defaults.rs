use base64::{Engine, prelude::BASE64_STANDARD};
use reth_cli_commands::download::DownloadDefaults;
use reth_ethereum::node::core::args::{DefaultPayloadBuilderValues, DefaultTxPoolValues};
use std::{borrow::Cow, time::Duration};
use url::Url;

pub(crate) const DEFAULT_DOWNLOAD_URL: &str = "https://snapshots.tempoxyz.dev/42431";

/// Default OTLP logs filter level for telemetry.
pub(crate) const DEFAULT_LOGS_OTLP_FILTER: &str = "debug";

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
        .with_minimal_protocol_basefee(0)
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

/// Extracts the telemetry URL from CLI args or environment variable.
///
/// Looks for `--telemetry-url <url>` or `--telemetry-url=<url>` in the args.
/// Falls back to the `TELEMETRY_URL` environment variable if not found in args.
/// Returns None if not found in either.
fn extract_telemetry_url(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        // Handle --telemetry-url=<value>
        if let Some(value) = arg.strip_prefix("--telemetry-url=") {
            return Some(value.to_string());
        }
        // Handle --telemetry-url <value>
        if arg == "--telemetry-url"
            && let Some(value) = iter.next()
        {
            return Some(value.to_string());
        }
    }
    // Fall back to environment variable
    std::env::var("TELEMETRY_URL").ok()
}

/// Expands `--telemetry-url` (or `TELEMETRY_URL` env var) into the equivalent telemetry arguments.
///
/// When `--telemetry-url=<url>` is present (e.g., `--telemetry-url=https://user:pass@metrics`),
/// or the `TELEMETRY_URL` environment variable is set, this function expands it to:
/// - `--logs-otlp=https://<host>/opentelemetry/v1/logs`
/// - `--logs-otlp.filter=debug`
/// - `--metrics.prometheus.push.url=https://<user:pass>@<host>/api/v1/import/prometheus`
/// - `--consensus.metrics-otlp=https://<host>/opentelemetry/v1/metrics`
///
/// Also sets `OTEL_EXPORTER_OTLP_HEADERS` with the base64-encoded credentials for OTLP auth.
///
/// The URL must include credentials in the format `https://user:pass@host`.
pub(crate) fn expand_telemetry_args(args: Vec<String>) -> eyre::Result<Vec<String>> {
    let telemetry_url = match extract_telemetry_url(&args) {
        Some(url) => url,
        None => return Ok(args),
    };

    // Parse the URL
    let mut url =
        Url::parse(&telemetry_url).map_err(|e| eyre::eyre!("--telemetry-url: invalid URL: {e}"))?;

    // Extract credentials - both username and password are required
    let username = url.username();
    let password = url.password();

    if username.is_empty() || password.is_none() {
        return Err(eyre::eyre!(
            "--telemetry-url must include credentials (username and password).\n\
             Format: https://user:pass@metrics.example.com"
        ));
    }

    let credentials = format!("{}:{}", username, password.unwrap());

    // Set OTEL_EXPORTER_OTLP_HEADERS for OTLP authentication
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

    // Build prometheus URL with credentials
    let prometheus_push_url = format!(
        "{}://{credentials}@{}{}/api/v1/import/prometheus",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port().map(|p| format!(":{p}")).unwrap_or_default()
    );

    // Filter out --telemetry-url and its value, then add expanded args
    let mut expanded: Vec<String> = Vec::new();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--telemetry-url" {
            // Skip the next argument (the value)
            iter.next();
            continue;
        }
        if arg.starts_with("--telemetry-url=") {
            continue;
        }
        expanded.push(arg);
    }

    // Add the telemetry arguments
    #[cfg(feature = "otlp")]
    {
        expanded.push(format!(
            "--logs-otlp={base_url_no_creds}/opentelemetry/v1/logs"
        ));
        expanded.push(format!("--logs-otlp.filter={DEFAULT_LOGS_OTLP_FILTER}"));
    }
    #[cfg(not(feature = "otlp"))]
    {
        return Err(eyre::eyre!(
            "--telemetry-url requires the 'otlp' feature to be enabled.\n\
             Rebuild with: cargo build --features otlp"
        ));
    }

    expanded.push(format!(
        "--metrics.prometheus.push.url={prometheus_push_url}"
    ));

    // Also push consensus metrics via OTLP to the same base URL
    expanded.push(format!(
        "--consensus.metrics-otlp={base_url_no_creds}/opentelemetry/v1/metrics"
    ));

    Ok(expanded)
}
