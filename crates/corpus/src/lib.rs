//! Historical execution corpus for Tempo: capture a finite archive range once into an
//! object store, then replay it without the source database, or read its blocks as fuzz inputs.
//!
//! The format, store and fuzz reads need no EVM. Capture and replay, which execute blocks, are in
//! [`exec`] behind the default `exec` feature.

pub mod code;
#[cfg(feature = "exec")]
pub mod exec;
pub mod fuzz;
pub mod gc;
#[cfg(feature = "index")]
pub mod index;
pub mod store;
pub mod targets;
pub mod types;
