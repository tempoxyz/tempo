use crate::opts::{TempoSidecar, TempoSidecarSubcommand};
use clap::Parser;

mod cmd;
pub mod monitor;
mod opts;
mod synthetic_load;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default rustls crypto provider");

    let args = TempoSidecar::parse();

    match args.cmd {
        TempoSidecarSubcommand::FeeAMMMonitor(cmd) => cmd.run().await,
        TempoSidecarSubcommand::SimpleArb(cmd) => cmd.run().await,
        TempoSidecarSubcommand::SyntheticLoad(cmd) => cmd.run().await,
        TempoSidecarSubcommand::TxLatencyMonitor(cmd) => cmd.run().await,
    }
}
