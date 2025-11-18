use crate::cmd::{
    max_tps::MaxTpsArgs, opcodes::OpcodesArgs, precompiles::PrecompilesArgs,
    state_bloat::StateBloatArgs,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct TempoBench {
    #[command(subcommand)]
    pub cmd: TempoBenchSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum TempoBenchSubcommand {
    /// A benchmark that fills blocks with TIP20 transfers
    RunMaxTps(MaxTpsArgs),

    /// A benchmark that tests opcodes
    Opcodes(OpcodesArgs),

    /// Runs benchmarking for our precompiles
    Precompiles(PrecompilesArgs),

    /// State bloating benchmarking - creates many accounts and then runs a benchmark
    StateBloat(StateBloatArgs),
}
