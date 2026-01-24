//! Tempo Native Bridge
//!
//! Cross-chain messaging using BLS threshold signatures.
//!
//! ## Components
//!
//! - **message**: Message types and attestation hash computation
//! - **attestation**: Partial and aggregated signature types
//! - **signer**: BLS threshold signing using validator key shares
//! - **sidecar**: The bridge sidecar (watcher, aggregator, submitter)
//! - **config**: Configuration types
//! - **error**: Error types

pub mod attestation;
pub mod config;
pub mod eip2537;
pub mod error;
pub mod gossip;
pub mod message;
pub mod service;
pub mod sidecar;
pub mod signer;

pub use gossip::{BridgeGossip, BridgeGossipMessage, MessageContext, NoOpGossip};
pub use service::{BridgeService, BridgeServiceConfig};
