//! Opcode benchmarking - sends

use clap::Parser;

/// Run opcode benchmarking
#[derive(Parser, Debug)]
pub struct OpcodesArgs {}

impl OpcodesArgs {
    pub async fn run(&self) -> eyre::Result<()> {
        Ok(())
    }
}
