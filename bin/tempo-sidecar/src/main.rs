use clap::Parser;
use crate::opts::{TempoSidecar, TempoSidecarSubcommand};

pub mod monitor;
mod opts;
mod cmd;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = TempoSidecar::parse();

    match args.cmd {
        TempoSidecarSubcommand::FeeAMMMonitor(cmd) => cmd.run().await,
    }
}