use crate::cmd::{
    monitor::MonitorArgs, simple_arb::SimpleArbArgs, synthetic_load::SyntheticLoadArgs,
    tx_latency::TxLatencyArgs,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub(crate) struct TempoSidecar {
    // TODO: add node args
    #[command(subcommand)]
    pub(crate) cmd: TempoSidecarSubcommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum TempoSidecarSubcommand {
    FeeAMMMonitor(MonitorArgs),
    SimpleArb(SimpleArbArgs),
    SyntheticLoad(SyntheticLoadArgs),
    TxLatencyMonitor(TxLatencyArgs),
}
