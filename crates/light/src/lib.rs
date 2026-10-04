//! Native Tempo light-client verification building blocks.
//!
//! These APIs do not discover trust anchors from RPC and never execute or forward `eth_call`.
//! The optional `client` feature adds bounded HTTP transport and checkpoint-backed latest reads.

#[cfg(feature = "client")]
pub mod checkpoint;
#[cfg(feature = "client")]
pub mod client;
pub mod config;
#[cfg(feature = "rpc-server")]
pub mod server;
pub mod token;
#[cfg(feature = "client")]
pub mod transport;

pub mod cache;
pub mod head;
pub mod proof;

pub use cache::VerifiedCache;
pub use head::{HeadTracker, Snapshot};

pub use tempo_finality::{CertifiedHeader, FinalizationVerifier, NetworkIdentity};
