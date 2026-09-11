//! Shared implementation for finalized traffic mirroring, auditing, and profiling.

pub mod audit;
pub mod config;
pub mod mirror;
pub mod profile;
pub mod source;
pub mod state;
#[doc(hidden)]
pub mod store;

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
