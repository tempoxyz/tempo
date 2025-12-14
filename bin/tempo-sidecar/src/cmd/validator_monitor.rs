use crate::monitor::prometheus_metrics;
use alloy::{primitives::Address, providers::ProviderBuilder};
use clap::Parser;
use eyre::{Context, Result, eyre};
use metrics::{counter, describe_counter, describe_gauge, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use poem::{EndpointExt, Route, Server, get, listener::TcpListener};
use reqwest::Url;
use std::collections::HashMap;
use tempo_precompiles::{
    VALIDATOR_CONFIG_ADDRESS,
    validator_config::IValidatorConfig::{self, IValidatorConfigInstance},
};
use tokio::signal;
use tracing::{error, info, instrument};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about = "Monitor Tempo testnet validators", long_about = None)]
pub struct ValidatorMonitorArgs {
    /// RPC endpoint URL
    #[arg(short, long, required = true)]
    rpc_url: Url,

    /// Poll interval in seconds (minimum 1)
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    poll_interval: u64,

    /// Chain ID for metrics labeling
    #[arg(short, long, required = true)]
    chain_id: String,

    /// Prometheus metrics port
    #[arg(short, long, required = true)]
    port: u16,
}

/// Validator information
#[derive(Debug, Clone)]
struct ValidatorInfo {
    address: Address,
    public_key: String,
    active: bool,
    index: u64,
    inbound_address: String,
    outbound_address: String,
}

pub struct ValidatorMonitor {
    rpc_url: Url,
    poll_interval: u64,
    validators: HashMap<Address, ValidatorInfo>,
}

impl ValidatorMonitor {
    pub fn new(rpc_url: Url, poll_interval: u64) -> Self {
        Self {
            rpc_url,
            poll_interval,
            validators: HashMap::new(),
        }
    }

    /// Fetch all validators from the ValidatorConfig precompile
    #[instrument(name = "validator_monitor::update_validators", skip(self))]
    async fn update_validators(&mut self) -> Result<()> {
        let provider = ProviderBuilder::new()
            .connect(self.rpc_url.as_str())
            .await?;

        let validator_config: IValidatorConfigInstance<_, _> =
            IValidatorConfig::new(VALIDATOR_CONFIG_ADDRESS, provider);

        let validators = validator_config
            .getValidators()
            .call()
            .await
            .map_err(|e| eyre!("Failed to fetch validators: {}", e))?;

        info!(count = validators.len(), "Fetched validators");

        for validator in validators {
            let address = validator.validatorAddress;

            // Only upsert - if validator is removed on-chain, it stays in our map
            // This ensures stale validators continue to affect metrics
            self.validators
                .entry(address)
                .and_modify(|v| {
                    v.public_key = format!("{:?}", validator.publicKey);
                    v.active = validator.active;
                    v.index = validator.index;
                    v.inbound_address = validator.inboundAddress.clone();
                    v.outbound_address = validator.outboundAddress.clone();
                })
                .or_insert_with(|| ValidatorInfo {
                    address,
                    public_key: format!("{:?}", validator.publicKey),
                    active: validator.active,
                    index: validator.index,
                    inbound_address: validator.inboundAddress,
                    outbound_address: validator.outboundAddress,
                });
        }

        Ok(())
    }

    /// Update Prometheus metrics based on current validator state
    #[instrument(name = "validator_monitor::update_metrics", skip(self))]
    async fn update_metrics(&self) {
        let total_validators = self.validators.len();
        let active_validators = self.validators.values().filter(|v| v.active).count();

        gauge!("tempo_validator_total_count").set(total_validators as f64);
        gauge!("tempo_validator_active_count").set(active_validators as f64);

        for validator in self.validators.values() {
            let labels = [
                ("validator_address", validator.address.to_string()),
                ("validator_index", validator.index.to_string()),
            ];

            // Validator status
            gauge!("tempo_validator_active", &labels).set(if validator.active { 1.0 } else { 0.0 });
        }
    }

    /// Main worker loop
    #[instrument(name = "validator_monitor::worker", skip(self))]
    pub async fn worker(&mut self) {
        loop {
            info!("Updating validator data");

            if let Err(e) = self.update_validators().await {
                error!("Failed to update validators: {}", e);
                counter!("tempo_validator_monitor_errors", "type" => "update_validators")
                    .increment(1);
            }

            self.update_metrics().await;

            tokio::time::sleep(std::time::Duration::from_secs(self.poll_interval)).await;
        }
    }
}

impl ValidatorMonitorArgs {
    pub async fn run(self) -> eyre::Result<()> {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .init();

        let builder = PrometheusBuilder::new().add_global_label("chain_id", self.chain_id.clone());
        let metrics_handle = builder
            .install_recorder()
            .context("failed to install recorder")?;

        let mut monitor = ValidatorMonitor::new(self.rpc_url, self.poll_interval);

        // Describe metrics
        describe_gauge!(
            "tempo_validator_total_count",
            "Total number of validators in the validator set"
        );
        describe_gauge!(
            "tempo_validator_active_count",
            "Number of active validators"
        );
        describe_gauge!(
            "tempo_validator_active",
            "Whether the validator is active (1) or inactive (0)"
        );
        describe_counter!(
            "tempo_validator_monitor_errors",
            "Number of errors encountered while monitoring validators"
        );

        let app = Route::new().at(
            "/metrics",
            get(prometheus_metrics).data(metrics_handle.clone()),
        );

        let addr = format!("0.0.0.0:{}", self.port);

        let mut monitor_handle = tokio::spawn(async move {
            monitor.worker().await;
        });

        let server = Server::new(TcpListener::bind(addr));
        let mut server_handle = tokio::spawn(async move { server.run(app).await });

        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .context("failed to install SIGINT handler")?;

        // Wait for either a signal or task failure
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down gracefully");
            }
            result = &mut monitor_handle => {
                match result {
                    Ok(_) => error!("Monitor task exited unexpectedly"),
                    Err(e) => error!("Monitor task failed: {}", e),
                }
            }
            result = &mut server_handle => {
                match result {
                    Ok(Ok(_)) => error!("Server task exited unexpectedly"),
                    Ok(Err(e)) => error!("Server task failed: {}", e),
                    Err(e) => error!("Server task panicked: {}", e),
                }
            }
        }

        // Abort remaining tasks
        monitor_handle.abort();
        server_handle.abort();

        info!("Shutdown complete");
        Ok(())
    }
}
