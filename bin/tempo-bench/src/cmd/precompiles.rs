//! Precompile benchmarking
//!
//! Benchmarking for precompiles, we have:
//! * TIP20
//! * TIP20 Factory
//! * TIP403 Registry
//! * TIP Fee manager
//! * TIP Account Registrar
//! * TIP Stablecoin Exchange
//! * TIP Nonce Precompile
//! * TIP Validator Config

use clap::Parser;

/// Run precompile benchmarking
#[derive(Parser, Debug)]
pub struct PrecompilesArgs {}

impl PrecompilesArgs {
    pub async fn run(&self) -> eyre::Result<()> {
        Ok(())
    }
}
