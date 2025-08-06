use crate::cmd::{CrescendoArgs, GenesisArgs};
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
    Crescendo(CrescendoArgs),
    GenerateGenesis(GenesisArgs),
}
