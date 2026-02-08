//! CL-driven follow mode for Tempo nodes.
//!
//! This module provides a follow implementation that syncs via WebSocket
//! from an upstream node (validator or another follower) instead of P2P.
//!
//! # Architecture
//!
//! ```text
//!
//!                           upstream WebSocket
//!                                  |
//!                                  |
//!                                  ▼
//!                          ┌─────────────────┐
//!                          │  RPC Resolver   │ <───────────────────────┐
//!                          └──────┬──────────┘                         │
//!                   subscribe &   │                                    |
//!                   fetch blocks  │                                    |
//!                                 ▼                                    |
//! ┌─────────────────────────────────────────────────────────────┐      |
//! │                      Driver                                 │      |
//! │  (sequential sync, DKG scheme extraction, push to marshal)  │      |
//! └──────────────────────────┬──────────────────────────────────┘      |
//!                            │ Verified + Activity::Finalization       |
//!                            │                                         |
//!                            │                                         |
//!                            ▼                                         |
//!                 ┌─────────────────┐           gap repair             |
//!                 │  Marshal Actor  │ ─────────────────────────────────┘
//!                 └─────────────────┘
//!                     │
//!           ┌─────────┴────────────────────┐
//!           ▼                              ▼
//!    ┌────────────────┐        ┌─────────────────┐
//!    │ Executor Actor │        │ Feed State      │
//!    │ (payload+fcu)  │        │ (consensus RPC) │
//!    └────────────────┘        └─────────────────┘
//!           │
//!           ▼
//!    ┌─────────────────┐
//!    │ Reth (EL)       │
//!    └─────────────────┘
//! ```

mod driver;
pub mod engine;
pub mod resolver;
mod stubs;

pub use engine::{Builder, Engine};
pub use resolver::RpcResolver;
