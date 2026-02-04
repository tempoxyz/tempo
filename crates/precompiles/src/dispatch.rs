//! Dispatch helpers for precompile implementations.
//!
//! Re-exports from lib.rs for macro compatibility.

pub use crate::{
    Precompile, dispatch_call, input_cost, metadata, metadata_with_sender, mutate,
    mutate_no_sender, mutate_void, mutate_void_no_sender, unknown_selector, view, view_with_sender,
};

#[cfg(test)]
pub use crate::expect_precompile_revert;
