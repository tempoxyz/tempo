//! End-to-end tests for the stablecoin bridge.
//!
//! These tests simulate the full bridge flow:
//! 1. Deploy contracts on Anvil (origin chain)
//! 2. Initialize bridge precompile on Tempo
//! 3. Deposit on origin -> mint on Tempo
//! 4. Burn on Tempo -> unlock on origin

mod utils;

mod burn_flow;
mod deposit_flow;
mod security;
