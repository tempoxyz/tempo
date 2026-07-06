//! Reth ExEx adapter for finalized-block protocol monitoring.
//!
//! This module is enabled by the `reth` feature and is the only place that may
//! touch Reth ExEx contexts, notifications, providers, blocks, and receipts.

/// ExEx identifier used by the protocol monitor.
pub const EXEX_ID: &str = "protocol-monitor";
