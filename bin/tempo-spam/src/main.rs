//! tempo-spam: Comprehensive transaction generator for Tempo testnet
//!
//! This tool generates diverse transactions covering all major codepaths in the Tempo system.
//! The goal is to ensure re-execution tests hit comprehensive code coverage similar to
//! the invariant fuzz tests in `tips/ref-impls/test/invariants/`.

mod actions;
mod cmd;

use clap::Parser;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = cmd::TempoSpam::parse();
    args.cmd.run().await
}
