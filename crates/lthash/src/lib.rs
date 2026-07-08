//! Lthash-based state-root computation for Tempo (TIP-1078 prototype).
//!
//! Replaces trie-based state roots with a homomorphic lthash accumulator: every account and
//! storage slot maps to an element, block execution adds and removes elements, and the block's
//! state root is the accumulator's checksum.
//!
//! [`TempoLthashStateRootStrategy`] plugs this into the engine's state-root jobs on both the
//! validation and the payload-build path. Finished accumulators flow through the
//! [`LthashStore`]: an in-memory overlay holds them until block batches are persisted, at
//! which point the [`LthashPersistenceHook`] flushes them to the
//! [`tables::LthashAccumulators`] table and prunes the overlay.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod accumulator;
mod error;
mod overlay;
mod persistence;
mod store;
mod strategy;
pub mod tables;
mod task;

pub use persistence::LthashPersistenceHook;
pub use store::{LthashStore, LthashStoreConfig};
pub use strategy::TempoLthashStateRootStrategy;

#[cfg(test)]
pub(crate) mod test_util {
    use alloy_primitives::U256;
    use reth_primitives_traits::Account;

    /// Shorthand account for accumulator tests.
    pub(crate) fn account(nonce: u64, balance: u64) -> Account {
        Account {
            nonce,
            balance: U256::from(balance),
            bytecode_hash: None,
        }
    }
}
