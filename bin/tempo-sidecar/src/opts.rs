use crate::cmd::{
    monitor::MonitorArgs, payment_lane_bench::PaymentLaneBenchArgs, simple_arb::SimpleArbArgs,
    synthetic_load::SyntheticLoadArgs, tx_latency::TxLatencyArgs,
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
    PaymentLaneBench(PaymentLaneBenchArgs),
    SimpleArb(SimpleArbArgs),
    SyntheticLoad(SyntheticLoadArgs),
    TxLatencyMonitor(TxLatencyArgs),
}
