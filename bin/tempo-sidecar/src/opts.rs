use crate::cmd::{
    monitor::MonitorArgs, simple_arb::SimpleArbArgs, synthetic_load::SyntheticLoadArgs,
    tx_latency::TxLatencyArgs, validator_monitor::ValidatorMonitorArgs,
};
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
    SimpleArb(SimpleArbArgs),
    SyntheticLoad(SyntheticLoadArgs),
    TxLatencyMonitor(TxLatencyArgs),
    ValidatorMonitor(ValidatorMonitorArgs),
}
