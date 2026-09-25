use clap::{Parser, Subcommand};
use eyre::Result;
use txgen_tempo::{
    auth_token_map::{run_auth_token_map, AuthTokenMapArgs},
    TempoAdapter,
};

#[derive(Parser)]
#[command(name = "txgen-tempo", about = "Tempo transaction generator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(flatten)]
    Txgen(txgen_cli::Command),
    /// Generate or refresh a Tempo Zone private-RPC authorization-token map
    AuthTokenMap(AuthTokenMapArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Txgen(command) => txgen_cli::run_command(TempoAdapter::new(), command).await,
        Command::AuthTokenMap(args) => run_auth_token_map(args).await,
    }
}
