use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use clap::Parser;
use eyre::Result;
use tempo_bootnode::{BootnodeConfig, BootnodeServer, load_or_generate_key};
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "tempo-bootnode",
    about = "Internal bootnode with dynamic peer registration"
)]
struct Args {
    /// Address to bind the discovery UDP socket.
    #[arg(long, default_value = "0.0.0.0:30303")]
    discovery_addr: SocketAddr,

    /// Address to bind the HTTP API.
    #[arg(long, default_value = "0.0.0.0:8080")]
    http_addr: SocketAddr,

    /// Path to the node key file (hex-encoded 32-byte secret key).
    /// If not provided, generates a new key.
    /// If path doesn't exist, generates and saves a new key.
    #[arg(long)]
    node_key: Option<PathBuf>,

    /// External IP address to advertise (for NAT traversal).
    /// If not provided, will not perform NAT resolution.
    #[arg(long)]
    external_ip: Option<IpAddr>,

    /// Lookup interval in seconds.
    #[arg(long, default_value = "30")]
    lookup_interval_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tempo_eyre::install()?;
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let secret_key = load_or_generate_key(args.node_key.as_deref())?;

    let mut config = BootnodeConfig::new(args.discovery_addr, args.http_addr)
        .with_secret_key(secret_key)
        .with_lookup_interval_secs(args.lookup_interval_secs);

    if let Some(ip) = args.external_ip {
        config = config.with_external_ip(ip);
    }

    info!("Starting bootnode...");
    info!("Discovery address: {}", args.discovery_addr);
    info!("HTTP API address: {}", args.http_addr);

    let server = BootnodeServer::new(config).await?;
    server.run().await
}
