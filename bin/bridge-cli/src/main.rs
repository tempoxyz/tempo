use clap::Parser;
use opts::{BridgeCli, BridgeSubcommand};

mod cmd;
mod opts;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = BridgeCli::parse();

    match args.cmd {
        BridgeSubcommand::Status(cmd) => cmd.run().await,
        BridgeSubcommand::Deposits(cmd) => cmd.run().await,
        BridgeSubcommand::Burns(cmd) => cmd.run().await,
        BridgeSubcommand::Retry(cmd) => cmd.run().await,
        BridgeSubcommand::Unlock(cmd) => cmd.run().await,
        BridgeSubcommand::Health(cmd) => cmd.run().await,
    }
}
