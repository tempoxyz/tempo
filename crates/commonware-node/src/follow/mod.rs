//! CL-driven follow mode for Tempo nodes.
//!
//! This module provides a follow implementation that syncs from an upstream
//! node (validator or another follower).

mod driver;
pub mod engine;
pub(crate) mod resolver;
mod stubs;
mod upstream;

pub use engine::Config;
pub use upstream::{LocalUpstream, UpstreamNode};
pub(crate) use upstream::WsUpstream;
