//! Certified follow mode for Tempo nodes.
//!
//! This module provides a block provider that wraps RPC block fetching with
//! finalization certificate verification and storage. This enables follow-mode
//! nodes to:
//!
//! 1. Fetch blocks from an upstream RPC endpoint
//! 2. Fetch and store finalization certificates for each block
//! 3. Serve consensus RPCs (`consensus_getFinalization`, `consensus_getLatest`)
//!
//! ## Architecture
//!
//! - [`FollowFeedState`]: Manages storage and implements `ConsensusFeed` for RPC queries
//! - [`CertifiedBlockProvider`]: Wraps `RpcBlockProvider` to fetch and store certificates
//!
//! ## Usage
//!
//! ```ignore
//! // Create feed state with storage
//! let feed_state = FollowFeedState::new(&storage_dir, shutdown_token).await?;
//! feed_state.init_from_storage().await;
//!
//! // Create the provider
//! let provider = CertifiedBlockProvider::new(rpc_url, feed_state.clone()).await?;
//!
//! builder
//!     .launch_with_debug_capabilities()
//!     .with_debug_block_provider(provider)
//!     .await?;
//! ```

mod provider;
mod state;
mod storage;

pub use provider::CertifiedBlockProvider;
pub use state::FollowFeedState;
