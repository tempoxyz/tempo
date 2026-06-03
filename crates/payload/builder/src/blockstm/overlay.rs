//! Committed-prefix overlay and validation helpers.

use crate::blockstm::rw_set::{
    BlockStmAccessKey, BlockStmReadSet, BlockStmValue, BlockStmWriteSet,
};
use alloy_primitives::map::HashMap;

/// A Block-STM version: transaction index plus incarnation number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockStmVersion {
    /// Transaction index in the preset serialization order.
    pub tx_index: usize,
    /// Incarnation number for that transaction.
    pub incarnation: usize,
}

impl BlockStmVersion {
    /// Creates a version from a transaction index and incarnation number.
    pub const fn new(tx_index: usize, incarnation: usize) -> Self {
        Self {
            tx_index,
            incarnation,
        }
    }
}

/// Whether a version contains a usable value or an aborted incarnation estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockStmOverlayStatus {
    /// Finished incarnation with a concrete value.
    Value,
    /// Aborted incarnation write-set retained only as a dependency estimate.
    Estimate,
}

/// A committed overlay value and the transaction index that wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockStmOverlayValue {
    /// Version that produced this entry.
    pub version: BlockStmVersion,
    /// Committed value.
    pub value: BlockStmValue,
    /// Whether this entry is concrete or only an estimate.
    pub status: BlockStmOverlayStatus,
}

/// Base state plus multi-version Block-STM writes.
#[derive(Debug, Clone, Default)]
pub struct BlockStmOverlay {
    base: HashMap<BlockStmAccessKey, BlockStmValue>,
    versions: HashMap<BlockStmAccessKey, Vec<BlockStmOverlayValue>>,
    commit_order: Vec<(usize, BlockStmAccessKey, BlockStmValue)>,
}

impl BlockStmOverlay {
    /// Creates an overlay from deterministic base values.
    pub fn new(base: impl IntoIterator<Item = (BlockStmAccessKey, BlockStmValue)>) -> Self {
        Self {
            base: base.into_iter().collect(),
            versions: HashMap::default(),
            commit_order: Vec::new(),
        }
    }

    /// Inserts or replaces a base value.
    pub fn set_base(&mut self, key: BlockStmAccessKey, value: impl Into<BlockStmValue>) {
        self.base.insert(key, value.into());
    }

    /// Reads the serial-prefix value visible to `tx_index`.
    pub fn read(&self, key: BlockStmAccessKey, tx_index: usize) -> BlockStmValue {
        self.read_entry(key, tx_index)
            .filter(|entry| entry.status == BlockStmOverlayStatus::Value)
            .map(|entry| entry.value)
            .or_else(|| self.base.get(&key).copied())
            .unwrap_or_default()
    }

    /// Reads the nearest prior version visible to `tx_index`.
    pub fn read_entry(
        &self,
        key: BlockStmAccessKey,
        tx_index: usize,
    ) -> Option<BlockStmOverlayValue> {
        self.versions
            .get(&key)?
            .iter()
            .copied()
            .filter(|entry| entry.version.tx_index < tx_index)
            .max_by_key(|entry| entry.version)
    }

    /// Validates the attempt reads against all committed earlier writes.
    pub fn validate_reads(
        &self,
        tx_index: usize,
        reads: &BlockStmReadSet,
    ) -> Result<(), BlockStmAccessKey> {
        for (key, read_value) in reads.iter() {
            if let Some(committed) = self.read_entry(*key, tx_index) {
                if committed.status == BlockStmOverlayStatus::Estimate {
                    return Err(*key);
                }
                if committed.value != *read_value {
                    return Err(*key);
                }
            }
        }
        Ok(())
    }

    /// Commits writes for `tx_index` in write-set order.
    pub fn commit(&mut self, tx_index: usize, writes: &BlockStmWriteSet) {
        self.commit_version(BlockStmVersion::new(tx_index, 0), writes);
    }

    /// Commits writes for one transaction incarnation in write-set order.
    pub fn commit_version(&mut self, version: BlockStmVersion, writes: &BlockStmWriteSet) {
        for (key, value) in writes.ordered() {
            let versions = self.versions.entry(key).or_default();
            versions.retain(|entry| entry.version.tx_index != version.tx_index);
            versions.push(BlockStmOverlayValue {
                version,
                value,
                status: BlockStmOverlayStatus::Value,
            });
            self.commit_order.push((version.tx_index, key, value));
        }
    }

    /// Marks an aborted incarnation's writes as estimates for dependency tracking.
    pub fn mark_estimate(&mut self, version: BlockStmVersion, writes: &BlockStmWriteSet) {
        for (key, value) in writes.ordered() {
            let versions = self.versions.entry(key).or_default();
            versions.retain(|entry| entry.version.tx_index != version.tx_index);
            versions.push(BlockStmOverlayValue {
                version,
                value,
                status: BlockStmOverlayStatus::Estimate,
            });
        }
    }

    /// Returns committed value for a key.
    pub fn committed_value(&self, key: &BlockStmAccessKey) -> Option<BlockStmOverlayValue> {
        self.versions
            .get(key)?
            .iter()
            .copied()
            .filter(|entry| entry.status == BlockStmOverlayStatus::Value)
            .max_by_key(|entry| entry.version)
    }

    /// Returns the merged writes in serial commit order.
    pub fn commit_order(&self) -> &[(usize, BlockStmAccessKey, BlockStmValue)] {
        &self.commit_order
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};

    fn addr(n: u64) -> Address {
        Address::from_word(B256::from(U256::from(n)))
    }

    fn storage(n: u64) -> BlockStmAccessKey {
        BlockStmAccessKey::Storage {
            address: addr(1),
            slot: U256::from(n),
        }
    }

    #[test]
    fn blockstm_overlay_reads_base_state_when_no_prior_write() {
        let key = storage(0);
        let overlay = BlockStmOverlay::new([(key, 7u64.into())]);
        let mut reads = BlockStmReadSet::default();
        let value = overlay.read(key, 1);
        reads.record(key, value);

        assert_eq!(value, 7u64.into());
        assert_eq!(reads.get(&key), Some(7u64.into()));
    }

    #[test]
    fn blockstm_overlay_reads_own_write_before_base() {
        let key = storage(0);
        let overlay = BlockStmOverlay::new([(key, 7u64.into())]);
        let mut writes = BlockStmWriteSet::default();
        let mut reads = BlockStmReadSet::default();
        writes.record(key, 9u64);
        let value = writes.get(&key).unwrap_or_else(|| overlay.read(key, 1));
        reads.record(key, value);

        assert_eq!(value, 9u64.into());
        assert_eq!(reads.get(&key), Some(9u64.into()));
        assert!(overlay.validate_reads(1, &reads).is_ok());
    }

    #[test]
    fn blockstm_overlay_reads_committed_prefix_write() {
        let key = storage(0);
        let mut overlay = BlockStmOverlay::new([(key, 7u64.into())]);
        let mut writes = BlockStmWriteSet::default();
        writes.record(key, 9u64);
        overlay.commit(0, &writes);

        assert_eq!(overlay.read(key, 1), 9u64.into());
    }

    #[test]
    fn blockstm_overlay_does_not_read_later_index_speculative_write() {
        let key = storage(0);
        let overlay = BlockStmOverlay::new([(key, 7u64.into())]);
        let mut later_writes = BlockStmWriteSet::default();
        later_writes.record(key, 11u64);

        assert_eq!(overlay.read(key, 1), 7u64.into());
        assert_eq!(later_writes.get(&key), Some(11u64.into()));
    }

    #[test]
    fn blockstm_overlay_discards_old_attempt_on_reexecution() {
        let key = storage(0);
        let mut overlay = BlockStmOverlay::default();
        let mut stale = BlockStmWriteSet::default();
        stale.record(key, 1u64);
        let mut fresh = BlockStmWriteSet::default();
        fresh.record(key, 2u64);

        overlay.mark_estimate(BlockStmVersion::new(1, 0), &stale);
        assert_eq!(
            overlay.read_entry(key, 2).unwrap().status,
            BlockStmOverlayStatus::Estimate
        );

        overlay.commit_version(BlockStmVersion::new(1, 1), &fresh);

        assert_eq!(overlay.committed_value(&key).unwrap().value, 2u64.into());
        assert_eq!(
            overlay.committed_value(&key).unwrap().version,
            BlockStmVersion::new(1, 1)
        );
        assert_ne!(
            overlay.committed_value(&key).unwrap().value,
            stale.get(&key).unwrap()
        );
    }

    #[test]
    fn blockstm_overlay_estimate_invalidates_later_reads_until_reexecution_commits() {
        let key = storage(0);
        let mut overlay = BlockStmOverlay::default();
        let mut stale_writes = BlockStmWriteSet::default();
        stale_writes.record(key, 1u64);
        overlay.mark_estimate(BlockStmVersion::new(1, 0), &stale_writes);

        let mut later_reads = BlockStmReadSet::default();
        later_reads.record(key, 0u64);
        assert_eq!(overlay.validate_reads(2, &later_reads), Err(key));

        let mut fresh_writes = BlockStmWriteSet::default();
        fresh_writes.record(key, 2u64);
        overlay.commit_version(BlockStmVersion::new(1, 1), &fresh_writes);

        let mut refreshed_reads = BlockStmReadSet::default();
        refreshed_reads.record(key, 2u64);
        assert!(overlay.validate_reads(2, &refreshed_reads).is_ok());
    }

    #[test]
    fn blockstm_overlay_validates_account_storage_and_code_keys() {
        let account = BlockStmAccessKey::Account(addr(1));
        let storage_key = storage(0);
        let code = BlockStmAccessKey::Code { address: addr(2) };
        let unrelated = storage(9);
        let mut overlay = BlockStmOverlay::default();
        let mut writes = BlockStmWriteSet::default();
        writes.record(account, 1u64);
        writes.record(storage_key, 1u64);
        writes.record(code, 1u64);
        overlay.commit(0, &writes);

        for key in [account, storage_key, code] {
            let mut reads = BlockStmReadSet::default();
            reads.record(key, 0u64);
            assert_eq!(overlay.validate_reads(1, &reads), Err(key));
        }

        let mut reads = BlockStmReadSet::default();
        reads.record(unrelated, 0u64);
        assert!(overlay.validate_reads(1, &reads).is_ok());
    }

    #[test]
    fn blockstm_overlay_merges_committed_writes_in_index_order() {
        let a = storage(1);
        let b = storage(2);
        let mut overlay = BlockStmOverlay::default();
        let mut w0 = BlockStmWriteSet::default();
        w0.record(a, 1u64);
        let mut w1 = BlockStmWriteSet::default();
        w1.record(b, 2u64);
        w1.record(a, 3u64);

        overlay.commit(0, &w0);
        overlay.commit(1, &w1);

        let committed: Vec<_> = overlay
            .commit_order()
            .iter()
            .map(|(idx, key, value)| (*idx, *key, *value))
            .collect();
        assert_eq!(
            committed,
            vec![
                (0, a, 1u64.into()),
                (1, b, 2u64.into()),
                (1, a, 3u64.into())
            ]
        );
        assert_eq!(overlay.committed_value(&a).unwrap().value, 3u64.into());
    }
}
