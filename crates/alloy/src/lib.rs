//! Tempo types for Alloy.
//!
//! # Getting Started
//!
//! To use `tempo-alloy`, add the crate as a dependency in your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! tempo-alloy = { git = "https://github.com/tempoxyz/tempo" }
//! ```
//!
//! # Development Status
//!
//! `tempo-alloy` is currently in development and is not yet ready for production use.
//!
//! # Usage
//!
//! To get started, instantiate a provider with [`TempoNetwork`]:
//!
//! ```rust
//! use alloy::{
//!     providers::{Provider, ProviderBuilder},
//!     transports::TransportError,
//! };
//! use tempo_alloy::TempoNetwork;
//!
//! async fn build_provider() -> Result<impl Provider<TempoNetwork>, TransportError> {
//!     ProviderBuilder::new_with_network::<TempoNetwork>()
//!         .connect("https://rpc.testnet.tempo.xyz")
//!         .await
//! }
//! ```

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod network;
pub use network::*;

/// Provider traits.
pub mod provider;

pub mod rpc;

#[doc(inline)]
pub use tempo_primitives as primitives;

#[doc(inline)]
pub use tempo_contracts as contracts;
