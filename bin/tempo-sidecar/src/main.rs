use crate::opts::{TempoSidecar, TempoSidecarSubcommand};
use clap::Parser;

mod cmd;
pub mod monitor;
mod opts;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = TempoSidecar::parse();

    match args.cmd {
        TempoSidecarSubcommand::FeeAMMMonitor(cmd) => cmd.run().await,
    }
}
