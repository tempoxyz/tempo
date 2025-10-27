//! xtask is a Swiss army knife of tools that help with running and testing tempo.

use clap::Parser;
use eyre::WrapErr as _;

mod consensus_config;
mod genesis;

use crate::{
    consensus_config::{GenerateConfig, generate_config},
    genesis::GenesisArgs,
};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();
    match args.action {
        Action::GenerateConfig(cfg) => generate_config(cfg).wrap_err("failed generating config"),
        Action::GenerateGenesis(args) => args.run().await.wrap_err("failed generating genesis"),
    }
}

#[derive(Debug, clap::Parser)]
#[command(author)]
#[command(version)]
#[command(about)]
#[command(long_about = None)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
    GenerateConfig(GenerateConfig),
    GenerateGenesis(GenesisArgs),
}
