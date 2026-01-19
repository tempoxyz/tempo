use crate::cmd::{
    burns::BurnsArgs, deposits::DepositsArgs, health::HealthArgs, retry::RetryArgs,
    status::StatusArgs, unlock::UnlockArgs,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "bridge")]
#[command(version, about = "CLI for Tempo stablecoin bridge operations", long_about = None)]
pub struct BridgeCli {
    #[command(subcommand)]
    pub cmd: BridgeSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum BridgeSubcommand {
    /// Show bridge status (pending deposits/burns count, last processed blocks)
    Status(StatusArgs),

    /// List pending deposits
    Deposits(DepositsArgs),

    /// List pending burns
    Burns(BurnsArgs),

    /// Force retry a stuck transaction
    Retry(RetryArgs),

    /// Manual unlock with proof
    Unlock(UnlockArgs),

    /// Check RPC connectivity and quorum health
    Health(HealthArgs),
}
