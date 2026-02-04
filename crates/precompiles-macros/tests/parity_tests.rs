//! Parity tests comparing `#[abi]` macro output against `sol!` macro.
//!
//! These tests verify that `#[abi]` produces identical ABI behavior to alloy's `sol!`
//! for regression detection and confidence in codegen correctness.

mod parity;
