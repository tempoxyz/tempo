use crate::cmd::{GenesisArgs, TPSArgs};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct TempoBench {
    // TODO: add node args
    #[command(subcommand)]
    pub cmd: TempoBenchSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum TempoBenchSubcommand {
    RunMaxTPS(TPSArgs),
    GenerateGenesis(GenesisArgs),
}
