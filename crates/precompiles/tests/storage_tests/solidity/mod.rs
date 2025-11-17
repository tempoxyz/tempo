//! Solidity compatibility tests.
//!
//! This module tests that the `contract` macro-generated storage layouts match their
//! Solidity counterparts by comparing against the expected solc-generated outputs.

mod precompiles;
mod primitives;
mod utils;

use super::*;
use tempo_precompiles_macros::Storable;

// Helper struct for struct test (defined at module level, used in primitives.rs)
#[derive(Debug, Clone, PartialEq, Eq, Storable)]
pub(crate) struct TestBlockInner {
    pub field1: U256,
    pub field2: U256,
    pub field3: u64,
}

/// Helper function to construct paths to testdata files
pub(crate) fn testdata(filename: &str) -> std::path::PathBuf {
    let testdata = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("testdata");

    if filename.ends_with(".sol") {
        testdata.join("solidity").join(filename)
    } else {
        testdata.join(filename)
    }
}
