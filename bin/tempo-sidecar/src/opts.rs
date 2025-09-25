use crate::cmd::monitor::MonitorArgs;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct TempoSidecar {
    // TODO: add node args
    #[command(subcommand)]
    pub cmd: TempoSidecarSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum TempoSidecarSubcommand {
    FeeAMMMonitor(MonitorArgs),
}
