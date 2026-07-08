//! Monitor-owned durable store schema and commit API.
//!
//! This module is enabled by the `store` feature. `monitor_head` advances only
//! through [`MonitorStore::commit_block`]. The in-memory backend is a
//! correctness/test backend for the store API; MDBX can implement the same
//! trait without changing processor proof-path code.

mod codecs;
mod commit;
mod mdbx;
mod memory;
mod outbox;
mod rows;
mod schema;
mod validation;

#[cfg(test)]
mod tests;

pub use commit::*;
pub use mdbx::{MdbxMonitorStore, MdbxMonitorStoreConfig};
pub use memory::InMemoryMonitorStore;
pub use outbox::*;
pub use rows::*;
pub use schema::*;

use crate::{facts::BlockNumHash, findings::FindingKey};

pub type Result<T> = std::result::Result<T, StoreError>;

/// Store boundary for finalized-block proof state.
///
/// Implementations must make `commit_block` atomic and must not expose any
/// other API that can advance `monitor_head`. `FinishedHeight(N)` is only legal
/// after a successful commit for block `N` or after observing an already durable
/// head at or beyond `N` during idempotent restart handling.
pub trait MonitorStore {
    /// Return schema readiness and table metadata.
    fn schema_status(&self) -> Result<SchemaStatus>;

    /// Return the last fully committed finalized block, if any.
    fn monitor_head(&self) -> Result<Option<BlockNumHash>>;

    /// Atomically persist one finalized block commit and advance `monitor_head`.
    ///
    /// Implementations must validate block continuity, reject structurally
    /// invalid rows, and treat recommits of an already durable block as
    /// idempotent without duplicating finding or outbox transitions.
    fn commit_block(&self, commit: BlockCommit) -> Result<()>;

    /// Look up durable finalized block metadata by block number.
    fn finalized_block(&self, number: u64) -> Result<Option<FinalizedBlockRecord>>;

    /// Look up the current durable finding lifecycle state.
    fn finding_state(&self, key: &FindingKey) -> Result<Option<FindingState>>;

    /// Return pending report outbox rows in delivery order.
    fn pending_outbox(&self, limit: usize) -> Result<Vec<OutboxRow>>;

    /// Mark a report outbox row delivered after the block commit has completed.
    ///
    /// Delivery state must not participate in `monitor_head` advancement.
    fn mark_outbox_delivered(&self, sequence: u64, delivery: DeliveryRecord) -> Result<()>;
}

impl<T: MonitorStore> MonitorStore for std::sync::Arc<T> {
    fn schema_status(&self) -> Result<SchemaStatus> {
        (**self).schema_status()
    }
    fn monitor_head(&self) -> Result<Option<BlockNumHash>> {
        (**self).monitor_head()
    }
    fn commit_block(&self, commit: BlockCommit) -> Result<()> {
        (**self).commit_block(commit)
    }
    fn finalized_block(&self, number: u64) -> Result<Option<FinalizedBlockRecord>> {
        (**self).finalized_block(number)
    }
    fn finding_state(&self, key: &FindingKey) -> Result<Option<FindingState>> {
        (**self).finding_state(key)
    }
    fn pending_outbox(&self, limit: usize) -> Result<Vec<OutboxRow>> {
        (**self).pending_outbox(limit)
    }
    fn mark_outbox_delivered(&self, sequence: u64, delivery: DeliveryRecord) -> Result<()> {
        (**self).mark_outbox_delivered(sequence, delivery)
    }
}
