use alloy_consensus::transaction::TxHashRef as _;
use crate::monitor::prometheus_metrics;
use alloy::{
    primitives::map::B256Map,
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
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempo_alloy::{TempoNetwork, primitives::{TempoHeader, TempoTxEnvelope}};
use tokio::signal;
use tracing::{debug, error, warn};

const PAYMENT_LATENCY_WINDOW: usize = 100;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct TxLatencyArgs {
    /// RPC endpoint for the node.
    #[arg(short, long, required = true)]
    rpc_url: Url,

    /// Chain identifier for labeling metrics.
    #[arg(short, long, required = true)]
    chain_id: String,

    /// Port to expose Prometheus metrics on.
    #[arg(short, long, required = true)]
    port: u16,

    /// Maximum age (seconds) to track pending transactions before expiring them.
    #[arg(long, default_value_t = 600)]
    max_pending_age_secs: u64,

    /// Hardfork identifier for lane classification (reserved for future v2 classifier).
    #[arg(long, default_value = "t5")]
    hardfork: String,

    /// SLO target for payment-lane landing latency in seconds.
    #[arg(long, default_value_t = 1.0)]
    payment_slo_target_secs: f64,
}

struct TransactionLatencyMonitor {
    rpc_url: Url,
    max_pending_age: Duration,
    /// Hash → (first_seen_millis, envelope). Envelope is None until the tx lands in a block
    /// because subscribe_pending_transactions emits hashes only; the full envelope is resolved
    /// from the mined block.
    pending: B256Map<(u128, Option<TempoTxEnvelope>)>,
    /// Rolling window of the last PAYMENT_LATENCY_WINDOW payment-lane latencies (seconds).
    payment_latencies: VecDeque<f64>,
    payment_slo_target_secs: f64,
}

impl TransactionLatencyMonitor {
    fn new(rpc_url: Url, max_pending_age: Duration, payment_slo_target_secs: f64) -> Self {
        Self {
            rpc_url,
            max_pending_age,
            pending: Default::default(),
            payment_latencies: VecDeque::new(),
            payment_slo_target_secs,
        }
    }

    async fn watch_transactions(&mut self) -> Result<()> {
        let rpc_url = self.rpc_url.to_string();
        let mut provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_ws(WsConnect::new(rpc_url.clone()))
            .await
            .context("failed to connect websocket provider")?;
        let mut pending_txs_sub = provider
            .subscribe_pending_transactions()
            .await
            .context("failed to subscribe to pending transactions")?;

        let mut block_subscription = provider
            .subscribe_full_blocks()
            .channel_size(1000)
            .into_stream()
            .await
            .context("failed to create block stream")?;

        let mut stream = pending_txs_sub.into_stream();

        loop {
            tokio::select! {
                maybe_hash = stream.next() => {
                    match maybe_hash {
                        Some(hash) => {
                            self.pending.entry(hash).or_insert_with(|| (Self::now_millis(), None));
                        }
                        None => {
                            warn!("pending transaction stream ended; reconnecting");
                            provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                                .connect_ws(WsConnect::new(rpc_url.clone()))
                                .await
                                .context("failed to reconnect websocket provider")?;
                            pending_txs_sub = provider
                                .subscribe_pending_transactions()
                                .await
                                .context("failed to resubscribe to pending transactions")?;
                            stream = pending_txs_sub.into_stream();
                            continue;
                        }
                    }
                },
                maybe_block = block_subscription.next() => {
                    if let Some(Ok(block)) = maybe_block {
                        let header = block.header.inner.into_consensus();
                        let mined_txs: B256Map<TempoTxEnvelope> = block
                            .transactions
                            .into_transactions()
                            .map(|tx| {
                                let hash = *tx.inner.tx_hash();
                                let envelope = tx.inner.into_inner();
                                (hash, envelope)
                            })
                            .collect();
                        self.on_mined_block(header, mined_txs);
                    }
                }
            }
        }
    }

    fn on_mined_block(&mut self, header: TempoHeader, mined_txs: B256Map<TempoTxEnvelope>) {
        gauge!("tempo_tx_latency_pending_observed").set(self.pending.len() as f64);
        if self.pending.is_empty() {
            return;
        }

        let block_ts = header.timestamp_millis() as u128;
        let mut payment_latencies_this_block: Vec<f64> = Vec::new();

        self.pending.retain(|hash, (seen_at, _)| {
            if let Some(envelope) = mined_txs.get(hash) {
                let latency_secs = Self::latency_seconds(*seen_at, block_ts);
                let lane = if envelope.is_payment() { "payment" } else { "non_payment" };
                histogram!("tempo_tx_landing_latency_seconds", "lane" => lane).record(latency_secs);
                if envelope.is_payment() {
                    payment_latencies_this_block.push(latency_secs);
                }
                false
            } else {
                true
            }
        });

        for lat in payment_latencies_this_block {
            if self.payment_latencies.len() >= PAYMENT_LATENCY_WINDOW {
                self.payment_latencies.pop_front();
            }
            self.payment_latencies.push_back(lat);
        }

        if !self.payment_latencies.is_empty() {
            let miss_count = self
                .payment_latencies
                .iter()
                .filter(|&&lat| lat > self.payment_slo_target_secs)
                .count();
            let miss_rate = miss_count as f64 / self.payment_latencies.len() as f64;
            gauge!("tempo_payment_lane_slo_miss_rate").set(miss_rate);
        }

        let now = Self::now_millis();
        let max_age_millis = self.max_pending_age.as_millis();
        let before_cleanup = self.pending.len();
        self.pending.retain(|_, (seen_at, _)| now.saturating_sub(*seen_at) <= max_age_millis);

        if self.pending.len() < before_cleanup {
            debug!(
                removed = before_cleanup - self.pending.len(),
                "dropped stale pending transactions"
            );
        }
    }

    fn now_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default()
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
            "Latency between seeing a transaction in the pool and it landing in a block (lane: payment | non_payment)"
        );
        describe_gauge!(
            "tempo_tx_latency_pending_observed",
            "Number of observed pending transactions awaiting inclusion"
        );
        describe_gauge!(
            "tempo_payment_lane_slo_miss_rate",
            "Fraction of payment-lane transactions (rolling last 100) that exceeded the SLO target latency"
        );

        let app = Route::new().at(
            "/metrics",
            get(prometheus_metrics).data(metrics_handle.clone()),
        );

        let addr = format!("0.0.0.0:{}", self.port);

        tracing::info!(
            hardfork = %self.hardfork,
            payment_slo_target_secs = self.payment_slo_target_secs,
            "starting tx latency monitor"
        );

        let mut monitor = TransactionLatencyMonitor::new(
            self.rpc_url,
            Duration::from_secs(self.max_pending_age_secs),
            self.payment_slo_target_secs,
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
