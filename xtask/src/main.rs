//! xtask is a Swiss army knife of tools that help with running and testing tempo.
use crate::{
    consensus_config::{GenerateConfig, generate_config},
    devnet::{DevnetConfig, generate_devnet_configs},
    genesis::GenesisArgs,
};

use clap::Parser;
use eyre::Context;

mod consensus_config;
mod devnet;
mod genesis;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();
    match args.action {
        Action::GenerateConfig(cfg) => generate_config(cfg).wrap_err("failed generating config"),
        Action::GenerateGenesis(args) => args.run().await.wrap_err("failed generating genesis"),
        Action::GenerateDevnet(cfg) => {
            generate_devnet_configs(cfg).wrap_err("failed generating devnet configs")
        }
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
#[allow(clippy::enum_variant_names)]
enum Action {
    GenerateConfig(GenerateConfig),
    GenerateGenesis(GenesisArgs),
    GenerateDevnet(DevnetConfig),
}
