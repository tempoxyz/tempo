//! State Bloat benchmarking - creates many TIP20s

use clap::Parser;

/// Run state bloat benchmarking
#[derive(Parser, Debug)]
pub struct StateBloatArgs {}

impl StateBloatArgs {
    pub async fn run(&self) -> eyre::Result<()> {
        Ok(())
    }
}
