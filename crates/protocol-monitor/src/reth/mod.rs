//! Reth ExEx adapter for finalized-block protocol monitoring.
//!
//! This module is enabled by the `reth` feature and is the only place that may
//! touch Reth ExEx contexts, notifications, providers, blocks, and receipts.

mod error;
mod finality;
mod finalized_loop;

#[cfg(test)]
mod tests;

pub use error::{AdapterError, AdapterResult};
pub use finality::FinalizedWatermark;
pub use finalized_loop::{
    FinalizedBlockSource, FinalizedLoop, FinalizedLoopConfig, FinishedHeightSink,
};

/// ExEx identifier used by the protocol monitor.
pub const EXEX_ID: &str = "protocol-monitor";
