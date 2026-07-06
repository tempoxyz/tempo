//! Reth ExEx adapter for finalized-block protocol monitoring.
//!
//! This module is enabled by the `reth` feature and is the only place that may
//! touch Reth ExEx contexts, notifications, providers, blocks, and receipts.

mod error;
mod exex;
mod finality;
mod finalized_loop;
mod provider;

#[cfg(test)]
mod tests;

pub use error::{AdapterError, AdapterResult};
pub use exex::{ProtocolMonitorExExConfig, RethFinishedHeightSink, run_protocol_monitor_exex};
pub use finality::FinalizedWatermark;
pub use finalized_loop::{
    FinalizedBlockSource, FinalizedLoop, FinalizedLoopConfig, FinishedHeightSink,
};
pub use provider::RethFinalizedBlockSource;

/// ExEx identifier used by the protocol monitor.
pub const EXEX_ID: &str = "protocol-monitor";
