//! # Application Module
//!
//! This module represents the "application" in the Tendermint/Malachite architecture.
//! It contains the execution layer logic that processes transactions, manages blockchain state,
//! and produces blocks when requested by the consensus engine.
//!
//! ## Architecture Overview
//!
//! In the Tendermint architecture, there is a clear separation between:
//! - **Consensus Engine**: Responsible for agreeing on the order of transactions (Malachite)
//! - **Application**: Responsible for executing transactions and maintaining state (Reth)
//!
//! This module implements the application side, specifically:
//! - Block production and validation
//! - State management and storage
//! - Transaction execution
//! - Interaction with Reth's execution layer
//!
//! ## Key Components
//!
//! - **`State`**: The core application state that manages the current blockchain state,
//!   handles block proposals, and interfaces with Reth's storage layer
//! - **`node`**: Defines the `TempoNode` type that integrates with Reth's node infrastructure
//!
//! ## Consensus Interface
//!
//! The application communicates with the consensus engine through channels, receiving
//! messages like:
//! - `GetValue`: Request to propose a new block
//! - `ReceivedProposalPart`: Incoming block proposal from another validator
//! - `Decided`: Notification that consensus has decided on a block
//! - `GetValidatorSet`: Request for the validator set at a specific height
//!
//! ## Integration with Reth
//!
//! This module bridges Malachite's consensus with Reth's execution engine:
//! - Uses Reth's transaction pool for block building
//! - Leverages Reth's state database for storage
//! - Integrates with Reth's P2P network for transaction gossip
//! - Utilizes Reth's EVM for transaction execution

pub mod config_loader;
pub mod node;
pub mod state;

// Re-export commonly used types from state module
pub use state::{
    Config, Genesis, Role, State, ValidatorInfo, decode_block, decode_value,
    decode_value_with_block, encode_block, encode_value, encode_value_with_block, reload_log_level,
};
