use base64::{Engine, prelude::BASE64_STANDARD};
use eyre::Context as _;
use jiff::SignedDuration;
use std::str::FromStr;
use url::Url;

/// Default OTLP logs filter level for telemetry.
const DEFAULT_LOGS_OTLP_FILTER: &str = "debug";

/// CLI arguments for telemetry configuration.
#[derive(Debug, Clone, clap::Args)]
pub(crate) struct TelemetryArgs {
    /// Enables telemetry export (OTLP logs & Prometheus metrics push). Coupled
    /// to VictoriaMetrics which supports both with different api paths.
    ///
    /// The URL must include credentials: `https://user:pass@metrics.example.com`
    #[arg(
        long,
        value_name = "URL",
        conflicts_with = "logs_otlp",
        env = "TEMPO_TELEMETRY_URL"
    )]
    pub(crate) telemetry_url: Option<UrlWithAuth>,

    /// The interval at which to push Prometheus metrics.
    #[arg(long, default_value = "10s")]
    pub(crate) telemetry_metrics_interval: SignedDuration,
}

impl TelemetryArgs {
    /// Converts the telemetry args into a [`TelemetryConfig`].
    ///
    /// Returns `None` if telemetry is not enabled (no URL provided).
    pub(crate) fn try_to_config(&self) -> eyre::Result<Option<TelemetryConfig>> {
        let Some(telemetry_url) = self.telemetry_url.clone().map(Url::from) else {
            return Ok(None);
        };

        // Extract credentials - both username and password are required
        let username = telemetry_url.username();
        let password = telemetry_url.password().expect("ensured when parsing args");

        // Build auth header for metrics push and OTLP logs
        let credentials = format!("{username}:{password}");
        let encoded = BASE64_STANDARD.encode(credentials.as_bytes());
        let auth_header = format!("Basic {encoded}");

        // Set OTEL_EXPORTER_OTLP_HEADERS for OTLP logs authentication
        if std::env::var_os("OTEL_EXPORTER_OTLP_HEADERS").is_none() {
            let header_value = format!("Authorization={auth_header}");
            // SAFETY: Must be called at startup before any other threads are spawned
            unsafe {
                std::env::set_var("OTEL_EXPORTER_OTLP_HEADERS", header_value);
            }
        }

        // Build URL without credentials
        let mut base_url_no_creds = telemetry_url.clone();
        base_url_no_creds.set_username("").ok();
        base_url_no_creds.set_password(None).ok();

        // Build logs OTLP URL (Victoria Metrics OTLP path)
        let logs_otlp_url = base_url_no_creds
            .join("opentelemetry/v1/logs")
            .wrap_err("failed to construct logs OTLP URL")?;

        // Build metrics prometheus URL (Victoria Metrics Prometheus import path)
        let metrics_prometheus_url = base_url_no_creds
            .join("api/v1/import/prometheus")
            .wrap_err("failed to construct metrics URL")?;

        Ok(Some(TelemetryConfig {
            logs_otlp_url,
            logs_otlp_filter: DEFAULT_LOGS_OTLP_FILTER.to_string(),
            metrics_prometheus_url,
            metrics_prometheus_interval: self.telemetry_metrics_interval,
            metrics_auth_header: Some(auth_header),
        }))
    }
}

/// A `Url` with username and password set.
#[derive(Clone, Debug)]
pub(crate) struct UrlWithAuth(Url);
impl FromStr for UrlWithAuth {
    type Err = Box<dyn std::error::Error + Send + Sync + 'static>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = s.parse::<Url>()?;
        if url.username().is_empty() || url.password().is_none() {
            return Err("URL must include username and password".into());
        }
        Ok(Self(url))
    }
}
impl From<UrlWithAuth> for Url {
    fn from(value: UrlWithAuth) -> Self {
        value.0
    }
}

/// Telemetry configuration derived from a unified telemetry URL.
#[derive(Debug, Clone)]
pub(crate) struct TelemetryConfig {
    /// OTLP logs endpoint (without credentials).
    pub(crate) logs_otlp_url: Url,
    /// OTLP logs filter level.
    pub(crate) logs_otlp_filter: String,
    /// Prometheus metrics push endpoint (without credentials).
    /// Used for both consensus and execution metrics.
    pub(crate) metrics_prometheus_url: Url,
    /// The interval at which to push Prometheus metrics.
    pub(crate) metrics_prometheus_interval: SignedDuration,
    /// Authorization header for metrics push
    pub(crate) metrics_auth_header: Option<String>,
}
