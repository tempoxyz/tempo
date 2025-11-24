use crate::monitor::{Monitor, prometheus_metrics};
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
pub struct MonitorArgs {
    #[arg(short, long, required = true)]
    rpc_url: Url,

    #[arg(long, default_value_t = 5)]
    poll_interval: u64,

    #[arg(short, long, required = true)]
    chain_id: String,

    #[arg(short, long, required = true)]
    port: u16,
}

impl MonitorArgs {
    pub async fn run(self) -> eyre::Result<()> {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .init();

        let builder = PrometheusBuilder::new().add_global_label("chain_id", self.chain_id.clone());
        let metrics_handle = builder
            .install_recorder()
            .context("failed to install recorder")?;

        let mut monitor = Monitor::new(self.rpc_url, self.poll_interval);

        describe_gauge!(
            "tempo_fee_amm_user_reserves",
            "User token reserves in the FeeAMM pool"
        );
        describe_gauge!(
            "tempo_fee_amm_validator_reserves",
            "Validator token reserves in the FeeAMM pool"
        );

        describe_counter!(
            "tempo_fee_amm_errors",
            "Number of errors encountered while fetching FeeAMM data"
        );

        let app = Route::new().at(
            "/metrics",
            get(prometheus_metrics).data(metrics_handle.clone()),
        );

        let addr = format!("0.0.0.0:{}", self.port);

        let monitor_handle = tokio::spawn(async move {
            monitor.worker().await;
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

        // Abort tasks
        monitor_handle.abort();
        server_handle.abort();

        tracing::info!("Shutdown complete");
        Ok(())
    }
}
