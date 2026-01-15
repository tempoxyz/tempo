//! Result type for `#[abi]` trait methods.
//!
//! This module provides a `Result` type alias for use in `#[abi]`-generated traits
//! when the `precompile` feature is enabled.

use core::convert::Infallible;

/// Placeholder result type for `#[abi]` trait methods.
///
/// This type is used by the `#[abi]` macro to generate trait signatures.
/// In the actual precompile runtime (`tempo-precompiles`), this should be
/// shadowed by importing `crate::error::Result` which uses `TempoPrecompileError`.
#[cfg(feature = "precompile")]
pub type Result<T> = core::result::Result<T, Infallible>;
