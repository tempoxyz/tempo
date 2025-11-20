use alloy::primitives::B256;
use clap::Parser;
use eyre::{Context, Result, eyre};
use metrics::{describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use poem::{EndpointExt, Route, Server, get, handler, listener::TcpListener};
use reqwest::Url;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::signal;
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

#[derive(Serialize)]
struct RpcRequest<'a, P> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: P,
}

struct TransactionLatencyMonitor {
    rpc_url: Url,
    client: reqwest::Client,
    poll_interval: Duration,
    max_pending_age: Duration,
    pending: HashMap<B256, Instant>,
}

impl TransactionLatencyMonitor {
    fn new(rpc_url: Url, poll_interval: Duration, max_pending_age: Duration) -> Self {
        Self {
            rpc_url,
            client: reqwest::Client::new(),
            poll_interval,
            max_pending_age,
            pending: HashMap::new(),
        }
    }

    async fn create_pending_filter(&self) -> Result<String> {
        self.rpc_call("eth_newPendingTransactionFilter", json!([]))
            .await
            .context("failed to create pending transaction filter")
    }

    async fn rpc_call<R, P>(&self, method: &str, params: P) -> Result<R>
    where
        R: DeserializeOwned,
        P: Serialize,
    {
        let body = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };

        let response: Value = self
            .client
            .post(self.rpc_url.clone())
            .json(&body)
            .send()
            .await
            .context("failed to send rpc request")?
            .error_for_status()
            .context("rpc response had an error status")?
            .json()
            .await
            .context("failed to deserialize rpc response")?;

        if let Some(error) = response.get("error") {
            return Err(eyre!("rpc error: {error}"));
        }

        let result = response
            .get("result")
            .ok_or_else(|| eyre!("missing result in rpc response"))?
            .clone();

        Ok(serde_json::from_value(result).context("failed to parse rpc response result")?)
    }

    async fn watch_transactions(&mut self) -> Result<()> {
        let mut filter_id = self.create_pending_filter().await?;

        loop {
            let pending_hashes: Vec<String> = match self
                .rpc_call("eth_getFilterChanges", json!([filter_id]))
                .await
            {
                Ok(hashes) => hashes,
                Err(err) => {
                    error!(err = %err, "failed to fetch filter changes");
                    match self.create_pending_filter().await {
                        Ok(new_filter) => {
                            warn!("recreated pending transaction filter after error");
                            filter_id = new_filter;
                        }
                        Err(create_err) => {
                            error!(err = %create_err, "failed to recreate pending filter");
                        }
                    }
                    tokio::time::sleep(self.poll_interval).await;
                    continue;
                }
            };

            for hash in pending_hashes {
                if let Ok(parsed_hash) = hash.parse::<B256>() {
                    self.pending.entry(parsed_hash).or_insert_with(Instant::now);
                }
            }

            gauge!("tempo_tx_latency_pending_observed").set(self.pending.len() as f64);

            let tracked_hashes: Vec<B256> = self.pending.keys().cloned().collect();

            for hash in tracked_hashes {
                let hash_hex = format!("{hash:#x}");
                let receipt: Option<Value> = match self
                    .rpc_call("eth_getTransactionReceipt", json!([hash_hex]))
                    .await
                {
                    Ok(receipt) => receipt,
                    Err(err) => {
                        debug!(err = %err, "failed to fetch transaction receipt");
                        continue;
                    }
                };

                if receipt.is_some() {
                    if let Some(seen_at) = self.pending.remove(&hash) {
                        let latency = seen_at.elapsed();
                        histogram!("tempo_tx_landing_latency_seconds")
                            .record(latency.as_secs_f64());
                    }
                }
            }

            let now = Instant::now();
            let before_cleanup = self.pending.len();
            self.pending
                .retain(|_, seen_at| now.duration_since(*seen_at) <= self.max_pending_age);

            if self.pending.len() < before_cleanup {
                debug!(
                    removed = before_cleanup - self.pending.len(),
                    "dropped stale pending transactions"
                );
            }

            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

#[handler]
async fn metrics_handler(
    handle: poem::web::Data<&metrics_exporter_prometheus::PrometheusHandle>,
) -> poem::Response {
    prometheus_metrics(handle).await
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
            get(metrics_handler).data(metrics_handle.clone()),
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
