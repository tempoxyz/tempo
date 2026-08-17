//! CL-driven follow mode for Tempo nodes.
//!
//! This module provides a follow implementation that syncs from an upstream
//! node (validator or another follower).

mod driver;
pub mod engine;
pub(crate) mod executor;
mod resolver;
mod stubs;
#[cfg(test)]
pub(crate) mod test_utils;
pub mod upstream;

pub use engine::Config;
