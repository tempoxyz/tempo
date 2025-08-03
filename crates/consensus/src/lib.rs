//! # Reth-Malachite
//!
//! A blockchain node implementation that combines Reth's execution layer with Malachite's
//! Byzantine Fault Tolerant (BFT) consensus engine.
//!
//! ## Architecture
//!
//! This crate follows the Tendermint architecture pattern with a clear separation between:
//!
//! ### Consensus Layer (Malachite)
//! - Handles validator coordination and block agreement
//! - Implements the BFT consensus protocol
//! - Manages consensus-specific P2P networking
//! - Located in the `consensus` module
//!
//! ### Application Layer (Reth)
//! - Executes transactions using the EVM
//! - Manages blockchain state and storage
//! - Builds blocks when requested by consensus
//! - Located in the `app` module
//!
//! ## Communication Model
//!
//! The consensus and application layers communicate through channels:
//! ```text
//! Consensus Engine                    Application (Reth)
//!       |                                    |
//!       |---- GetValue Request ------------->|
//!       |<--- Proposed Block ----------------|
//!       |                                    |
//!       |---- ReceivedProposalPart -------->|
//!       |<--- Processed Proposal ------------|
//!       |                                    |
//!       |---- Decided (commit) ------------>|
//!       |<--- Start Next Height -------------|
//! ```
//!
//! ## Main Modules
//!
//! - **`app`**: The application layer that interfaces with Reth's execution engine
//! - **`consensus`**: Infrastructure for running the Malachite consensus engine
//! - **`context`**: Type definitions that bridge Malachite and Reth types
//! - **`provider`**: Cryptographic providers for signing and verification
//! - **`cli`**: Command-line interface and chain specification
//! - **`consensus_utils`**: Utilities for consensus integration with Reth's node builder
//! - **`store`**: Persistent storage for consensus-related data
//! - **`codec`**: Encoding/decoding implementations for consensus messages
//! - **`types`**: Core type definitions used throughout the crate
//! - **`height`**: Height-related utilities and conversions
//! - **`proto`**: Generated protobuf types for Malachite communication
//! - **`utils`**: General utility functions
//!
//! ## Usage
//!
//! The main entry point is `bin/reth-malachite.rs` which:
//! 1. Initializes the Reth node infrastructure
//! 2. Starts the Malachite consensus engine
//! 3. Connects them through the channel-based communication layer

pub mod app;
pub mod cli;
pub mod codec;
pub mod consensus;
pub mod consensus_utils;
pub mod context;
pub mod height;
pub mod proto;
pub mod provider;
pub mod store;
pub mod types;
pub mod utils;

pub use consensus_utils::*;
pub use context::*;
pub use height::*;
pub use provider::*;
pub use types::*;
pub use utils::*;
