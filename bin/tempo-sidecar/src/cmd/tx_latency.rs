use crate::monitor::prometheus_metrics;
use alloy::{
    primitives::map::{B256Map, B256Set},
    providers::{Provider, ProviderBuilder, WsConnect},
};
use clap::Parser;
use eyre::{Context, Result, eyre};
use futures::StreamExt;
use metrics::{describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use poem::{EndpointExt, Route, Server, get, listener::TcpListener};
use reqwest::Url;
use std::{
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempo_alloy::{TempoNetwork, primitives::TempoHeader};
use tokio::{signal, task::JoinHandle};
use tracing::{debug, warn};

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
}

struct TransactionLatencyMonitor {
    rpc_url: Url,
    max_pending_age: Duration,
    /// Keeps track of the transactions that were emitted over the pending event stream.
    pending: B256Map<u128>,
}

impl TransactionLatencyMonitor {
    fn new(rpc_url: Url, max_pending_age: Duration) -> Self {
        Self {
            rpc_url,
            max_pending_age,
            pending: Default::default(),
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
                        Some(hash) => { self.pending.entry(hash).or_insert_with(Self::now_millis); }
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
                         self.on_mined_block(block.header.inner.into_consensus(), block.transactions.hashes().collect());
                    }
                }
            }
        }
    }

    fn on_mined_block(&mut self, header: TempoHeader, mined_txs: B256Set) {
        gauge!("tempo_tx_latency_pending_observed").set(self.pending.len() as f64);
        if self.pending.is_empty() {
            return;
        }
        self.pending.retain(|hash, seen_at| {
            if mined_txs.contains(hash) {
                let latency_secs =
                    Self::latency_seconds(*seen_at, header.timestamp_millis() as u128);
                histogram!("tempo_tx_landing_latency_seconds").record(latency_secs);
                false
            } else {
                true
            }
        });

        let now = Self::now_millis();
        let max_age_millis = self.max_pending_age.as_millis();
        let before_cleanup = self.pending.len();
        self.pending
            .retain(|_, seen_at| now.saturating_sub(*seen_at) <= max_age_millis);

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
            Duration::from_secs(self.max_pending_age_secs),
        );

        let monitor_handle = tokio::spawn(async move { monitor.watch_transactions().await });

        let server = Server::new(TcpListener::bind(addr));
        let server_handle = tokio::spawn(async move { server.run(app).await });

        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .context("failed to install SIGINT handler")?;

        let shutdown = async move {
            tokio::select! {
                _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down gracefully"),
                _ = sigint.recv() => tracing::info!("Received SIGINT, shutting down gracefully"),
            }
        };

        let result = wait_for_shutdown_or_monitor_failure(monitor_handle, shutdown).await;

        server_handle.abort();

        tracing::info!("Shutdown complete");
        result
    }
}

/// Waits for either a graceful shutdown signal or the transaction latency monitor task ending.
///
/// The monitor task is expected to run indefinitely; it only completes when it hits an
/// unrecoverable error (or panics), so any completion of `monitor_handle` before `shutdown`
/// resolves is treated as fatal and its error is propagated so the process exits non-zero.
async fn wait_for_shutdown_or_monitor_failure(
    monitor_handle: JoinHandle<Result<()>>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    tokio::pin!(monitor_handle);

    tokio::select! {
        _ = shutdown => {
            monitor_handle.abort();
            Ok(())
        }
        result = &mut monitor_handle => match result {
            Ok(Ok(())) => Err(eyre!("tx latency monitor task exited unexpectedly")),
            Ok(Err(err)) => Err(err).context("tx latency monitor failed"),
            Err(join_err) => Err(eyre::Report::new(join_err)).context("tx latency monitor task panicked"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Once, time::Duration};

    /// Installs the process-level rustls crypto provider exactly once.
    ///
    /// `main()` normally does this before any TLS-capable transport is built; tests bypass
    /// `main()`, so `watch_transactions` needs it installed explicitly before it can construct a
    /// websocket provider.
    fn ensure_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Regression test for https://github.com/tempoxyz/tempo/issues/6898: an unrecoverable
    /// monitor failure must surface as an `Err`, matching the issue's own repro
    /// (`--rpc-url ws://127.0.0.1:9`), rather than being silently swallowed.
    #[tokio::test]
    async fn watch_transactions_errors_on_unreachable_endpoint() {
        ensure_crypto_provider();

        let rpc_url: Url = "ws://127.0.0.1:9".parse().expect("valid url");
        let mut monitor = TransactionLatencyMonitor::new(rpc_url, Duration::from_secs(600));

        let result = tokio::time::timeout(Duration::from_secs(10), monitor.watch_transactions())
            .await
            .expect("watch_transactions should fail fast on a refused connection, not hang");

        let err = result.expect_err("an unreachable websocket endpoint must produce an Err");
        assert!(
            err.to_string()
                .contains("failed to connect websocket provider"),
            "unexpected error: {err}"
        );
    }

    /// A monitor task that ends (here, with an error) before shutdown is requested must cause
    /// `wait_for_shutdown_or_monitor_failure` to return that error, so the caller's process exits
    /// non-zero instead of idling until a signal arrives.
    #[tokio::test]
    async fn monitor_failure_is_propagated_before_shutdown() {
        let monitor_handle =
            tokio::spawn(async { Err(eyre!("failed to connect websocket provider")) });
        let shutdown = std::future::pending::<()>();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_shutdown_or_monitor_failure(monitor_handle, shutdown),
        )
        .await
        .expect("a failed monitor task must not make wait_for_shutdown_or_monitor_failure hang");

        let err = result.expect_err("a failed monitor task must produce an Err");
        assert!(
            err.chain().any(|cause| cause
                .to_string()
                .contains("failed to connect websocket provider")),
            "unexpected error chain: {err:#}"
        );
    }

    /// Graceful shutdown must still return `Ok`, and must abort the monitor task rather than
    /// leaking it.
    #[tokio::test]
    async fn shutdown_signal_returns_ok_and_stops_monitor() {
        let monitor_handle = tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok(())
        });
        let shutdown = async {};

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_shutdown_or_monitor_failure(monitor_handle, shutdown),
        )
        .await
        .expect("shutdown must not make wait_for_shutdown_or_monitor_failure hang");

        assert!(
            result.is_ok(),
            "graceful shutdown must return Ok: {result:?}"
        );
    }
}
