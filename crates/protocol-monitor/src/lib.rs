//! Tempo Protocol Monitor.
//!
//! This crate contains monitor-owned protocol proof types and processing
//! boundaries. Core modules intentionally avoid Reth types; Reth integration is
//! isolated behind the `reth` feature in [`crate::reth`].

#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod block_view;
pub mod common;
pub mod coverage;
pub mod findings;
pub mod invariants;
pub mod processor;
pub mod reports;

#[cfg(feature = "activity")]
pub mod activity;
#[cfg(feature = "reth")]
pub mod reth;
#[cfg(feature = "store")]
pub mod store;
