//! CL-driven follow mode for Tempo nodes.
//!
//! This module provides a follow implementation that syncs from an upstream
//! node (validator or another follower). The upstream is abstracted via the
//! [`UpstreamNode`](upstream::UpstreamNode) trait, with a WebSocket-based
//! production implementation ([`WsUpstream`](upstream::WsUpstream)) and the
//! possibility of in-process direct access for testing.
//!
//! # Architecture
//!
//! ```text
//!
//!                       upstream (trait UpstreamNode)
//!                          │                  ▲
//!              subscribe & │                  │ fetch block
//!              fetch block │                  │ by height/hash
//!                          ▼                  │
//! ┌─────────────────────────────────────┐     │
//! │              Driver                 │     │
//! │  (subscribe to finalization events, │     │
//! │   DKG scheme extraction,            │     │
//! │   verify + push to marshal & feed)  │     │
//! └─────────────┬───────────────────────┘     │
//!               │ verified block +            │
//!               │ Activity::Finalization      │
//!               │                             │
//!        ┌──────┴──────┐                      │
//!        ▼             ▼                      │
//! ┌────────────┐  ┌────────────┐              │
//! │  Marshal   │  │ Feed Actor │              │
//! │   Actor    │  └─────┬──────┘              │
//! └──────┬─────┘        │                     │
//!        │              ▼                     │
//!        │       ┌─────────────────┐          │
//!        │       │   Feed State    │          │
//!        │       │ (consensus RPC) │          │
//!        │       └─────────────────┘          │
//!        │                                    │
//!        ├──── gap repair ───► ┌───────────────────┐
//!        │                     │  FollowResolver   │─┘
//!        │                     │ (local EL + upstream)
//!        │                     └───────────────────┘
//!        ▼
//! ┌────────────────┐
//! │ Executor Actor │
//! │ (payload+fcu)  │
//! └───────┬────────┘
//!         │
//!         ▼
//! ┌─────────────────┐
//! │    Reth (EL)    │
//! └─────────────────┘
//! ```

mod driver;
pub mod engine;
pub(crate) mod resolver;
mod stubs;
pub mod upstream;

pub use engine::Builder;
pub use upstream::{LocalUpstream, UpstreamNode, WsUpstream};
