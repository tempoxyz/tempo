//! Redacted zone RPC server.
//!
//! Provides an authenticated JSON-RPC endpoint that sits in front of the
//! standard reth RPC, adding per-caller privacy redactions and access control.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod auth;
pub mod config;
pub mod debug;
pub mod error;
pub mod filter;
pub mod handlers;
mod metrics;
pub mod policy;
pub mod provider;
pub mod server;
pub mod subscription;
pub mod types;
mod ws;

pub use config::RedactedRpcConfig;
pub use debug::{ZoneDebugApi, ZoneDebugApiRpcServer};
pub use handlers::ZoneRpcApi;
pub use provider::{ZoneProvider, ZoneProviderConfig};
pub use server::start_redacted_rpc;
pub use subscription::{BoxWsSubscriptionFut, WsSubscriptionStream};
