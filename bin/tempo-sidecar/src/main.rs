use crate::opts::{TempoSidecar, TempoSidecarSubcommand};
use clap::Parser;

mod cmd;
pub mod monitor;
mod opts;
mod synthetic_load;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = TempoSidecar::parse();

    match args.cmd {
        TempoSidecarSubcommand::FeeAMMMonitor(cmd) => cmd.run().await,
        TempoSidecarSubcommand::SimpleArb(cmd) => cmd.run().await,
        TempoSidecarSubcommand::SyntheticLoad(cmd) => cmd.run().await,
        TempoSidecarSubcommand::TxLatencyMonitor(cmd) => cmd.run().await,
        TempoSidecarSubcommand::ValidatorMonitor(cmd) => cmd.run().await,
    }
}
