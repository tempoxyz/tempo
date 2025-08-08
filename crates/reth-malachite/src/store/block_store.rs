//! Block storage interface for storing and retrieving full blocks by hash.
//!
//! This module provides the abstraction for storing blocks separately from
//! consensus proposals. This separation allows the consensus layer to work
//! with lightweight block hashes while still maintaining access to full block
//! data when needed for execution.

use alloy_primitives::B256;
use eyre::Result;
use reth_primitives::Block;

/// Trait for storing and retrieving blocks by their hash.
///
/// This is used to store full block data separately from consensus proposals,
/// which only need to reference blocks by hash.
pub trait BlockStore: Send + Sync {
    /// Store a block indexed by its hash.
    ///
    /// # Arguments
    /// * `block` - The block to store (hash is computed from the block)
    ///
    /// # Returns
    /// * `Ok(())` if the block was stored successfully
    /// * `Err` if there was a storage error
    fn store_block(&self, block: Block) -> Result<()>;

    /// Retrieve a block by its hash.
    ///
    /// # Arguments
    /// * `hash` - The hash of the block to retrieve
    ///
    /// # Returns
    /// * `Ok(Some(block))` if the block was found
    /// * `Ok(None)` if the block was not found
    /// * `Err` if there was a storage error
    fn get_block(&self, hash: &B256) -> Result<Option<Block>>;

    /// Check if a block exists in storage.
    ///
    /// # Arguments
    /// * `hash` - The hash of the block to check
    ///
    /// # Returns
    /// * `Ok(true)` if the block exists
    /// * `Ok(false)` if the block does not exist
    /// * `Err` if there was a storage error
    fn has_block(&self, hash: &B256) -> Result<bool>;

    /// Remove a block from storage.
    ///
    /// This is used for cleanup of blocks that are no longer needed.
    /// Since Malachite provides finality, we don't need to handle reorgs.
    ///
    /// # Arguments
    /// * `hash` - The hash of the block to remove
    ///
    /// # Returns
    /// * `Ok(())` if the block was removed or didn't exist
    /// * `Err` if there was a storage error
    fn remove_block(&self, hash: &B256) -> Result<()>;
}
