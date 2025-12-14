use crate::monitor::prometheus_metrics;
use alloy::{
    consensus::BlockHeader,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
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

    /// Poll interval in seconds
    #[arg(long, default_value_t = 10)]
    poll_interval: u64,

    /// Chain ID for metrics labeling
    #[arg(short, long, required = true)]
    chain_id: String,

    /// Prometheus metrics port
    #[arg(short, long, required = true)]
    port: u16,

    /// Maximum number of blocks to scan per poll interval for block production tracking.
    /// Set to 0 to disable block production tracking.
    #[arg(long, default_value_t = 100)]
    history_blocks: u64,
}

/// Validator information with tracking data
#[derive(Debug, Clone)]
struct ValidatorInfo {
    address: Address,
    public_key: String,
    active: bool,
    index: u64,
    inbound_address: String,
    outbound_address: String,
    blocks_produced: u64,
}

pub struct ValidatorMonitor {
    rpc_url: Url,
    poll_interval: u64,
    history_blocks: u64,
    validators: HashMap<Address, ValidatorInfo>,
    last_block_number: u64,
}

impl ValidatorMonitor {
    pub fn new(rpc_url: Url, poll_interval: u64, history_blocks: u64) -> Self {
        Self {
            rpc_url,
            poll_interval,
            history_blocks,
            validators: HashMap::new(),
            last_block_number: 0,
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
                    blocks_produced: 0,
                });
        }

        Ok(())
    }

    /// Track block production by checking recent blocks
    #[instrument(name = "validator_monitor::track_block_production", skip(self))]
    async fn track_block_production(&mut self) -> Result<()> {
        let provider = ProviderBuilder::new()
            .connect(self.rpc_url.as_str())
            .await?;

        let current_block = provider
            .get_block_number()
            .await
            .map_err(|e| eyre!("Failed to get block number: {}", e))?;

        // On first run, just set the last block number
        if self.last_block_number == 0 {
            self.last_block_number = current_block.saturating_sub(1);
            return Ok(());
        }

        // Skip block tracking if history_blocks is 0
        if self.history_blocks == 0 {
            info!("Block production tracking disabled (history_blocks = 0)");
            self.last_block_number = current_block;
            return Ok(());
        }

        // Track blocks since last check (up to history_blocks limit)
        let start_block = self.last_block_number + 1;
        // Calculate end_block: scan at most history_blocks
        let end_block = current_block.min(start_block.saturating_add(self.history_blocks - 1));

        // If start_block > current_block, handle reorg/node reset scenario
        if start_block > current_block {
            info!(
                last_block = self.last_block_number,
                current_block = current_block,
                "Chain height decreased (possible reorg/reset), resetting tracking position"
            );
            self.last_block_number = current_block;
            return Ok(());
        }

        info!(
            start = start_block,
            end = end_block,
            count = end_block - start_block + 1,
            "Tracking block production"
        );

        for block_num in start_block..=end_block {
            // Get block with transactions to see the beneficiary (validator)
            match provider.get_block_by_number(block_num.into()).await {
                Ok(Some(block)) => {
                    // The block author/beneficiary is the validator who produced this block
                    let author = block.header.beneficiary();
                    if let Some(validator) = self.validators.get_mut(&author) {
                        validator.blocks_produced += 1;
                    }
                }
                Ok(None) => {
                    error!(block = block_num, "Block not found");
                    counter!("tempo_validator_monitor_errors", "type" => "block_not_found")
                        .increment(1);
                }
                Err(e) => {
                    error!(block = block_num, error = %e, "Failed to fetch block");
                    counter!("tempo_validator_monitor_errors", "type" => "rpc_error").increment(1);
                }
            }
        }

        self.last_block_number = end_block;
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

            // Blocks produced (using gauge since we track absolute count)
            gauge!("tempo_validator_blocks_produced_total", &labels)
                .set(validator.blocks_produced as f64);
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

            if let Err(e) = self.track_block_production().await {
                error!("Failed to track block production: {}", e);
                counter!("tempo_validator_monitor_errors", "type" => "track_blocks").increment(1);
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

        let mut monitor =
            ValidatorMonitor::new(self.rpc_url, self.poll_interval, self.history_blocks);

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
        describe_gauge!(
            "tempo_validator_blocks_produced_total",
            "Total number of blocks produced by this validator"
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
