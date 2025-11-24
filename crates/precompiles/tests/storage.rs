//! Test suite for the storage primitives.
//!
//! This integration test suite verifies the correctness of the storage abstractions,
//! including packing rules, layout generation, and Solidity compatibility.

// Re-export modules that macro-generated code expects
pub mod storage_primitives {
    pub use tempo_precompiles::storage::*;
}
pub use storage_primitives as storage;
pub use tempo_precompiles::error;

// Import the storage test modules
mod storage_tests;
