//! Bridge sidecar binary.

use clap::Parser;
use eyre::Result;
use std::path::PathBuf;

use tempo_native_bridge::{config::Config, sidecar::BridgeSidecar};

#[derive(Parser, Debug)]
#[command(name = "bridge-sidecar")]
#[command(about = "Tempo Bridge Sidecar - signs and aggregates cross-chain attestations")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "bridge-sidecar.toml")]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// Run the bridge sidecar
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("bridge_sidecar=info".parse()?),
        )
        .init();

    let args = Args::parse();

    match args.cmd {
        Command::Run => {
            tracing::info!(config = ?args.config, "loading configuration");

            let config = Config::load(&args.config)?;

            let signer = config
                .signer
                .as_ref()
                .ok_or_else(|| eyre::eyre!("[signer] section required in standalone mode"))?;

            tracing::info!(
                chains = config.chains.len(),
                epoch = config.threshold.epoch,
                validator_index = signer.validator_index,
                "starting bridge sidecar"
            );

            let sidecar = BridgeSidecar::new(config).await?;
            sidecar.run().await?;
        }
    }

    Ok(())
}
