use crate::cmd::{genesis::GenesisArgs, max_tps::MaxTPSArgs};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct TempoBench {
    #[command(subcommand)]
    pub cmd: TempoBenchSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum TempoBenchSubcommand {
    RunMaxTPS(MaxTPSArgs),
    GenerateGenesis(GenesisArgs),
}
