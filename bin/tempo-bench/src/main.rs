mod cmd;
mod crescendo;
mod opts;
mod utils;

use clap::Parser;
use mimalloc::MiMalloc;
use opts::{TempoBench, TempoBenchSubcommand};

#[global_allocator]
// Increases RPS by ~5.5% at the time of
// writing. ~3.3% faster than jemalloc.
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = TempoBench::parse();

    match args.cmd {
        TempoBenchSubcommand::Crescendo(cmd) => cmd.run().await,
        TempoBenchSubcommand::GenerateGenesis(cmd) => cmd.run().await,
    }
}
