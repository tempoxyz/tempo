//! Integration tests for bridge-exex.
//!
//! These tests simulate end-to-end bridge flows:
//! 1. Full deposit → register → sign → finalize → mint flow
//! 2. Full burn → header relay → proof → unlock flow
//! 3. Reorg handling
//! 4. Multi-validator signing scenarios

mod anvil;
mod fixtures;
mod integration;
