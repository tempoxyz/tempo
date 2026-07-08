//! Tempo Tempo Monitor.
//!
//! This crate contains monitor-owned protocol proof types and processing
//! boundaries. Core modules intentionally avoid Reth types; Reth integration is
//! isolated behind the `reth` feature in [`crate::reth`].

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod diagnostics;
pub mod entity;
pub mod input;
pub mod invariants;

#[cfg(feature = "activity")]
pub mod activity;

#[cfg(feature = "store")]
pub mod processor;
#[cfg(feature = "store")]
pub mod store;

#[cfg(feature = "reth")]
pub mod reth;
