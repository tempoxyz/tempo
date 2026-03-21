use crate::monitor::dex::{DexMonitor, prometheus_metrics};
use clap::Parser;
use eyre::Context;
use metrics::{describe_counter, describe_gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use poem::{EndpointExt, Route, Server, get, listener::TcpListener};
use reqwest::Url;
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct DexMonitorArgs {
    #[arg(short, long, required_unless_present = "demo")]
    rpc_url: Option<Url>,

    #[arg(long, default_value_t = 5)]
    poll_interval: u64,

    #[arg(short, long, default_value = "1")]
    chain_id: String,

    #[arg(short, long, required = true)]
    port: u16,

    /// Run with simulated data for dashboard demonstration
    #[arg(long, default_value_t = false)]
    demo: bool,
}

impl DexMonitorArgs {
    pub async fn run(self) -> eyre::Result<()> {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .init();

        let builder = PrometheusBuilder::new().add_global_label("chain_id", self.chain_id.clone());
        let metrics_handle = builder
            .install_recorder()
            .context("failed to install recorder")?;

        describe_gauge!(
            "tempo_dex_spread_ticks",
            "Spread between best ask and best bid in ticks"
        );
        describe_gauge!(
            "tempo_dex_best_bid_liquidity",
            "Total liquidity at the best bid tick"
        );
        describe_gauge!(
            "tempo_dex_best_ask_liquidity",
            "Total liquidity at the best ask tick"
        );
        describe_gauge!(
            "tempo_dex_slippage_bps",
            "Estimated slippage for a $1000 swap in basis points"
        );
        describe_gauge!(
            "tempo_dex_total_orders",
            "Total number of orders ever created in the DEX"
        );
        describe_counter!(
            "tempo_dex_monitor_errors",
            "Number of errors encountered while fetching DEX data"
        );

        let monitor_handle = if self.demo {
            tracing::info!("starting in DEMO mode with simulated data");
            let mut monitor = DexMonitor::new_demo(self.poll_interval);
            tokio::spawn(async move {
                monitor.demo_worker().await;
            })
        } else {
            let rpc_url = self
                .rpc_url
                .ok_or_else(|| eyre::eyre!("--rpc-url is required in live mode"))?;
            let mut monitor = DexMonitor::new(rpc_url, self.poll_interval)
                .await
                .context("failed to initialize DEX monitor")?;
            tokio::spawn(async move {
                monitor.worker().await;
            })
        };

        let app = Route::new().at(
            "/metrics",
            get(prometheus_metrics).data(metrics_handle.clone()),
        );

        let addr = format!("0.0.0.0:{}", self.port);

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
