//! Store module for persisting consensus-related data using reth's database infrastructure.
//!
//! This module provides storage functionality for:
//! - Decided values (committed blocks with their certificates)
//! - Undecided proposals (pending block proposals)
//! - Consensus state information
//!
//! The store integrates with reth's database layer to provide persistent storage
//! for the consensus engine's data requirements.

mod block_store;
mod reth_store;
pub mod tables;
mod wrapper;

pub use block_store::BlockStore;
pub use reth_store::{RethStore, StoreError};
pub use tables::{BlockKey, DecidedValue, StoredBlock, StoredProposal};
// Store is intentionally not exported publicly - access is controlled through State
pub(crate) use wrapper::Store;
