#[macro_use]
extern crate proptest_state_machine;

// Re-export modules that macro-generated code expects
pub mod storage_primitives {
    pub use tempo_precompiles::storage::*;
}
pub use storage_primitives as storage;
pub use tempo_precompiles::error;

mod invariant_tests;
