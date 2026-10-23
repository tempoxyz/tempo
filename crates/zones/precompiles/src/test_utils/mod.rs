//! Shared test utilities for precompile and EVM integration tests.

pub mod l1_reader;
mod outbox;

pub use l1_reader::MockL1Reader;
pub use outbox::{setup_outbox, withdrawal_call};

#[cfg(test)]
mod local;
#[cfg(test)]
pub(crate) use local::*;
