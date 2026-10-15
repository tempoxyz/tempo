//! Shared test utilities for precompile and EVM integration tests.

pub mod l1_reader;
pub use l1_reader::MockL1Reader;

#[cfg(test)]
mod local;
#[cfg(test)]
pub(crate) use local::*;
