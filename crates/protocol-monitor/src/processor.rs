//! Finalized block processor and atomic commit construction.
//!
//! The processor builds monitor-owned block views, runs checks, computes
//! coverage/finding/report rows, and hands a single block commit to the store.
