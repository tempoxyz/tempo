//! Historical execution corpus for Tempo: capture a finite archive range once into an
//! object store, then replay it without the source database, or read its blocks as fuzz inputs.
//!
//! The corpus format, its store and reading blocks as fuzz inputs need no EVM; capturing and
//! replaying, which execute blocks, are in [`replay`] behind the default `replay` feature.

pub mod code;
pub mod fuzz;
pub mod gc;
#[cfg(feature = "replay")]
pub mod replay;
pub mod store;
pub mod types;
