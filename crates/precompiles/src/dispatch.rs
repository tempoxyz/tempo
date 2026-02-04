//! Dispatch helpers for precompile implementations.
//!
//! Re-exports from lib.rs for macro compatibility.

pub use crate::{
    dispatch_call, input_cost, metadata, mutate, mutate_void, unknown_selector, view, Precompile,
};

#[cfg(test)]
pub use crate::expect_precompile_revert;
