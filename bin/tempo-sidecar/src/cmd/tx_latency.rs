use alloy::{
    primitives::B256,
    providers::{Provider, ProviderBuilder, WsConnect},
};
use clap::Parser;
use eyre::{Context, Result};
use futures::StreamExt;
use metrics::{describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use poem::{EndpointExt, Route, Server, get, listener::TcpListener};
use reqwest::Url;
use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::signal;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, warn};

use crate::monitor::prometheus_metrics;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct TxLatencyArgs {
    /// RPC endpoint for the node.
    #[arg(short, long, required = true)]
    rpc_url: Url,

    /// Chain identifier for labeling metrics.
    #[arg(short, long, required = true)]
    chain_id: String,

    /// Poll interval (ms) for checking pending transactions and receipts.
    #[arg(long, default_value_t = 1_000)]
    poll_interval_ms: u64,

    /// Port to expose Prometheus metrics on.
    #[arg(short, long, required = true)]
    port: u16,

    /// Maximum age (seconds) to track pending transactions before expiring them.
    #[arg(long, default_value_t = 600)]
    max_pending_age_secs: u64,
}

struct TransactionLatencyMonitor {
    rpc_url: Url,
    poll_interval: Duration,
    max_pending_age: Duration,
    pending: HashMap<B256, u128>,
}

impl TransactionLatencyMonitor {
    fn new(rpc_url: Url, poll_interval: Duration, max_pending_age: Duration) -> Self {
        Self {
            rpc_url,
            poll_interval,
            max_pending_age,
            pending: HashMap::new(),
        }
    }

    async fn watch_transactions(&mut self) -> Result<()> {
        let rpc_url = self.rpc_url.to_string();
        let mut provider = ProviderBuilder::new()
            .connect_ws(WsConnect::new(rpc_url.clone()))
            .await
            .context("failed to connect websocket provider")?;
        let mut subscription = provider
            .subscribe_pending_transactions()
            .await
            .context("failed to subscribe to pending transactions")?;
        let mut stream = subscription.into_stream();

        let mut receipt_interval = tokio::time::interval(self.poll_interval);
        receipt_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe_hash = stream.next() => {
                    match maybe_hash {
                        Some(hash) => { self.pending.entry(hash).or_insert_with(Self::now_millis); }
                        None => {
                            warn!("pending transaction stream ended; reconnecting");
                            provider = ProviderBuilder::new()
                                .connect_ws(WsConnect::new(rpc_url.clone()))
                                .await
                                .context("failed to reconnect websocket provider")?;
                            subscription = provider
                                .subscribe_pending_transactions()
                                .await
                                .context("failed to resubscribe to pending transactions")?;
                            stream = subscription.into_stream();
                            continue;
                        }
                    }
                }
                _ = receipt_interval.tick() => {
                    self.observe_pending(&provider).await?;
                }
            }
        }
    }

    async fn observe_pending<P>(&mut self, provider: &P) -> Result<()>
    where
        P: Provider,
    {
        gauge!("tempo_tx_latency_pending_observed").set(self.pending.len() as f64);

        let tracked_hashes: Vec<B256> = self.pending.keys().cloned().collect();

        for hash in tracked_hashes {
            match provider.get_transaction_receipt(hash).await {
                Ok(Some(receipt)) => {
                    if let Some(seen_at) = self.pending.get(&hash).copied() {
                        match receipt.block_hash {
                            Some(block_hash) => {
                                match provider.get_block_by_hash(block_hash).await {
                                    Ok(Some(block)) => {
                                        let landing_millis =
                                            Self::header_timestamp_millis(&block.header);
                                        let latency_secs =
                                            Self::latency_seconds(seen_at, landing_millis);

                                        histogram!("tempo_tx_landing_latency_seconds")
                                            .record(latency_secs);
                                        self.pending.remove(&hash);
                                    }
                                    Ok(None) => debug!("block not found for confirmed transaction"),
                                    Err(err) => {
                                        debug!(err = %err, "failed to fetch block for receipt")
                                    }
                                }
                            }
                            None => debug!("receipt missing block hash"),
                        }
                    }
                }
                Ok(None) => continue,
                Err(err) => debug!(err = %err, "failed to fetch transaction receipt"),
            }
        }

        let now = Self::now_millis();
        let max_age_millis = self.max_pending_age.as_millis() as u128;
        let before_cleanup = self.pending.len();
        self.pending
            .retain(|_, seen_at| now.saturating_sub(*seen_at) <= max_age_millis);

        if self.pending.len() < before_cleanup {
            debug!(
                removed = before_cleanup - self.pending.len(),
                "dropped stale pending transactions"
            );
        }

        Ok(())
    }

    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default()
    }

    fn header_timestamp_millis(header: &impl alloy::consensus::BlockHeader) -> u128 {
        header.timestamp().saturating_mul(1000) as u128
    }

    fn latency_seconds(seen_at_millis: u128, landing_millis: u128) -> f64 {
        landing_millis.saturating_sub(seen_at_millis) as f64 / 1000.0
    }
}

impl TxLatencyArgs {
    pub async fn run(self) -> Result<()> {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();

        let builder = PrometheusBuilder::new().add_global_label("chain_id", self.chain_id.clone());
        let metrics_handle = builder
            .install_recorder()
            .context("failed to install recorder")?;

        describe_histogram!(
            "tempo_tx_landing_latency_seconds",
            "Latency between seeing a transaction in the pool and it landing in a block"
        );
        describe_gauge!(
            "tempo_tx_latency_pending_observed",
            "Number of observed pending transactions awaiting inclusion"
        );

        let app = Route::new().at(
            "/metrics",
            get(prometheus_metrics).data(metrics_handle.clone()),
        );

        let addr = format!("0.0.0.0:{}", self.port);

        let mut monitor = TransactionLatencyMonitor::new(
            self.rpc_url,
            Duration::from_millis(self.poll_interval_ms),
            Duration::from_secs(self.max_pending_age_secs),
        );

        let monitor_handle = tokio::spawn(async move {
            if let Err(err) = monitor.watch_transactions().await {
                error!(err = %err, "tx latency monitor exited with error");
            }
        });

        let server = Server::new(TcpListener::bind(addr));
        let server_handle = tokio::spawn(async move { server.run(app).await });

        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .context("failed to install SIGINT handler")?;

        tokio::select! {
            _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down gracefully"),
            _ = sigint.recv() => tracing::info!("Received SIGINT, shutting down gracefully"),
        }

        monitor_handle.abort();
        server_handle.abort();

        tracing::info!("Shutdown complete");
        Ok(())
    }
}
