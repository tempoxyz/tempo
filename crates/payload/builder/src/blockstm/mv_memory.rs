//! Concurrent multi-version memory for Block-STM execution.

use crate::blockstm::{
    overlay::{BlockStmOverlayStatus, BlockStmOverlayValue, BlockStmVersion},
    rw_set::{BlockStmAccessKey, BlockStmReadSet, BlockStmValue, BlockStmWriteSet},
};
use alloy_primitives::{Address, map::HashMap};
use reth_revm::state::AccountInfo;
use std::{
    hash::{Hash, Hasher},
    sync::{Mutex, RwLock},
};

const DEFAULT_SHARDS: usize = 64;

/// Shared multi-version memory keyed by Block-STM access key.
#[derive(Debug)]
pub struct BlockStmMvMemory {
    base: HashMap<BlockStmAccessKey, BlockStmValue>,
    shards: Vec<RwLock<HashMap<BlockStmAccessKey, Vec<BlockStmOverlayValue>>>>,
    account_shards: Vec<RwLock<HashMap<Address, Vec<BlockStmAccountOverlayValue>>>>,
    commit_order: Mutex<Vec<(usize, BlockStmAccessKey, BlockStmValue)>>,
}

/// An account-info version used by the production MV state view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStmAccountOverlayValue {
    /// Version that produced this account value.
    pub version: BlockStmVersion,
    /// Full account metadata needed by subsequent EVM executions.
    pub info: AccountInfo,
    /// Whether this account value is concrete or only an estimate.
    pub status: BlockStmOverlayStatus,
}

impl Default for BlockStmMvMemory {
    fn default() -> Self {
        Self::new([])
    }
}

impl BlockStmMvMemory {
    /// Creates concurrent memory from deterministic base values.
    pub fn new(base: impl IntoIterator<Item = (BlockStmAccessKey, BlockStmValue)>) -> Self {
        Self::with_shards(base, DEFAULT_SHARDS)
    }

    /// Creates concurrent memory with an explicit shard count.
    pub fn with_shards(
        base: impl IntoIterator<Item = (BlockStmAccessKey, BlockStmValue)>,
        shard_count: usize,
    ) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            base: base.into_iter().collect(),
            shards: (0..shard_count)
                .map(|_| RwLock::new(HashMap::default()))
                .collect(),
            account_shards: (0..shard_count)
                .map(|_| RwLock::new(HashMap::default()))
                .collect(),
            commit_order: Mutex::new(Vec::new()),
        }
    }

    /// Inserts or replaces a base value before the memory is shared.
    pub fn set_base(&mut self, key: BlockStmAccessKey, value: impl Into<BlockStmValue>) {
        self.base.insert(key, value.into());
    }

    /// Reads the latest concrete prior value visible to `tx_index`.
    pub fn read(&self, key: BlockStmAccessKey, tx_index: usize) -> BlockStmValue {
        self.read_entry(key, tx_index)
            .filter(|entry| entry.status == BlockStmOverlayStatus::Value)
            .map(|entry| entry.value)
            .or_else(|| self.base.get(&key).copied())
            .unwrap_or_default()
    }

    /// Reads the nearest prior version visible to `tx_index`, including estimates.
    pub fn read_entry(
        &self,
        key: BlockStmAccessKey,
        tx_index: usize,
    ) -> Option<BlockStmOverlayValue> {
        let shard = self
            .shard_for(&key)
            .read()
            .expect("Block-STM MV shard poisoned");
        shard
            .get(&key)?
            .iter()
            .copied()
            .filter(|entry| entry.version.tx_index < tx_index)
            .max_by_key(|entry| entry.version)
    }

    /// Validates an attempt's reads against prior versions visible to `tx_index`.
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

    /// Publishes writes for `tx_index` incarnation 0.
    pub fn commit(&self, tx_index: usize, writes: &BlockStmWriteSet) {
        self.commit_version(BlockStmVersion::new(tx_index, 0), writes);
    }

    /// Publishes writes for one concrete transaction incarnation.
    pub fn commit_version(&self, version: BlockStmVersion, writes: &BlockStmWriteSet) {
        self.publish_value(version, writes);
        let mut commit_order = self
            .commit_order
            .lock()
            .expect("Block-STM commit order poisoned");
        commit_order.extend(
            writes
                .ordered()
                .map(|(key, value)| (version.tx_index, key, value)),
        );
    }

    /// Publishes speculative concrete writes without recording final commit order.
    pub fn publish_value(&self, version: BlockStmVersion, writes: &BlockStmWriteSet) {
        self.publish_version(version, writes, BlockStmOverlayStatus::Value);
    }

    /// Publishes full account values for one concrete transaction incarnation.
    pub fn publish_account_values(
        &self,
        version: BlockStmVersion,
        accounts: &HashMap<Address, AccountInfo>,
    ) {
        self.publish_account_versions(version, accounts, BlockStmOverlayStatus::Value);
    }

    /// Keeps an aborted incarnation write-set as estimates for dependency tracking.
    pub fn mark_estimate(&self, version: BlockStmVersion, writes: &BlockStmWriteSet) {
        self.publish_version(version, writes, BlockStmOverlayStatus::Estimate);
    }

    /// Keeps aborted account writes as estimates for dependency tracking.
    pub fn mark_account_estimates(
        &self,
        version: BlockStmVersion,
        accounts: &HashMap<Address, AccountInfo>,
    ) {
        self.publish_account_versions(version, accounts, BlockStmOverlayStatus::Estimate);
    }

    /// Reads the nearest prior account version visible to `tx_index`, including estimates.
    pub fn account_entry(
        &self,
        address: Address,
        tx_index: usize,
    ) -> Option<BlockStmAccountOverlayValue> {
        let shard = self
            .account_shard_for(&address)
            .read()
            .expect("Block-STM MV account shard poisoned");
        shard
            .get(&address)?
            .iter()
            .filter(|entry| entry.version.tx_index < tx_index)
            .max_by_key(|entry| entry.version)
            .cloned()
    }

    /// Returns the latest concrete version for a key.
    pub fn committed_value(&self, key: &BlockStmAccessKey) -> Option<BlockStmOverlayValue> {
        let shard = self
            .shard_for(key)
            .read()
            .expect("Block-STM MV shard poisoned");
        shard
            .get(key)?
            .iter()
            .copied()
            .filter(|entry| entry.status == BlockStmOverlayStatus::Value)
            .max_by_key(|entry| entry.version)
    }

    /// Returns committed writes in publication order.
    pub fn commit_order(&self) -> Vec<(usize, BlockStmAccessKey, BlockStmValue)> {
        self.commit_order
            .lock()
            .expect("Block-STM commit order poisoned")
            .clone()
    }

    fn publish_version(
        &self,
        version: BlockStmVersion,
        writes: &BlockStmWriteSet,
        status: BlockStmOverlayStatus,
    ) {
        for (key, value) in writes.ordered() {
            let mut shard = self
                .shard_for(&key)
                .write()
                .expect("Block-STM MV shard poisoned");
            let versions = shard.entry(key).or_default();
            versions.retain(|entry| entry.version.tx_index != version.tx_index);
            versions.push(BlockStmOverlayValue {
                version,
                value,
                status,
            });
        }
    }

    fn publish_account_versions(
        &self,
        version: BlockStmVersion,
        accounts: &HashMap<Address, AccountInfo>,
        status: BlockStmOverlayStatus,
    ) {
        for (address, info) in accounts {
            let mut shard = self
                .account_shard_for(address)
                .write()
                .expect("Block-STM MV account shard poisoned");
            let versions = shard.entry(*address).or_default();
            versions.retain(|entry| entry.version.tx_index != version.tx_index);
            versions.push(BlockStmAccountOverlayValue {
                version,
                info: info.clone(),
                status,
            });
        }
    }

    fn shard_for(
        &self,
        key: &BlockStmAccessKey,
    ) -> &RwLock<HashMap<BlockStmAccessKey, Vec<BlockStmOverlayValue>>> {
        &self.shards[self.shard_index(key)]
    }

    fn account_shard_for(
        &self,
        address: &Address,
    ) -> &RwLock<HashMap<Address, Vec<BlockStmAccountOverlayValue>>> {
        &self.account_shards[self.account_shard_index(address)]
    }

    fn shard_index(&self, key: &BlockStmAccessKey) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }

    fn account_shard_index(&self, address: &Address) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        address.hash(&mut hasher);
        (hasher.finish() as usize) % self.account_shards.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};
    use std::thread;

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
    fn blockstm_mv_memory_reads_base_state_when_no_prior_write() {
        let key = storage(0);
        let memory = BlockStmMvMemory::new([(key, 7u64.into())]);

        assert_eq!(memory.read(key, 1), 7u64.into());
    }

    #[test]
    fn blockstm_mv_memory_replaces_stale_incarnation() {
        let key = storage(0);
        let memory = BlockStmMvMemory::default();
        let mut stale = BlockStmWriteSet::default();
        stale.record(key, 1u64);
        let mut fresh = BlockStmWriteSet::default();
        fresh.record(key, 2u64);

        memory.mark_estimate(BlockStmVersion::new(1, 0), &stale);
        assert_eq!(
            memory.read_entry(key, 2).unwrap().status,
            BlockStmOverlayStatus::Estimate
        );

        memory.commit_version(BlockStmVersion::new(1, 1), &fresh);

        let committed = memory.committed_value(&key).unwrap();
        assert_eq!(committed.value, 2u64.into());
        assert_eq!(committed.version, BlockStmVersion::new(1, 1));
    }

    #[test]
    fn blockstm_mv_memory_estimate_invalidates_later_reads() {
        let key = storage(0);
        let memory = BlockStmMvMemory::default();
        let mut writes = BlockStmWriteSet::default();
        writes.record(key, 1u64);
        memory.mark_estimate(BlockStmVersion::new(1, 0), &writes);

        let mut reads = BlockStmReadSet::default();
        reads.record(key, 0u64);

        assert_eq!(memory.validate_reads(2, &reads), Err(key));
    }

    #[test]
    fn blockstm_mv_memory_tracks_account_estimates_and_values() {
        let address = addr(9);
        let memory = BlockStmMvMemory::default();
        let mut accounts = HashMap::default();
        accounts.insert(
            address,
            AccountInfo {
                nonce: 1,
                balance: U256::from(100),
                ..Default::default()
            },
        );

        memory.mark_account_estimates(BlockStmVersion::new(1, 0), &accounts);
        let estimate = memory.account_entry(address, 2).unwrap();
        assert_eq!(estimate.version, BlockStmVersion::new(1, 0));
        assert_eq!(estimate.status, BlockStmOverlayStatus::Estimate);

        accounts.insert(
            address,
            AccountInfo {
                nonce: 2,
                balance: U256::from(90),
                ..Default::default()
            },
        );
        memory.publish_account_values(BlockStmVersion::new(1, 1), &accounts);
        let value = memory.account_entry(address, 2).unwrap();
        assert_eq!(value.version, BlockStmVersion::new(1, 1));
        assert_eq!(value.status, BlockStmOverlayStatus::Value);
        assert_eq!(value.info.nonce, 2);
    }

    #[test]
    fn blockstm_mv_memory_accepts_parallel_version_publication() {
        let memory = BlockStmMvMemory::with_shards([], 8);
        let key = storage(0);

        thread::scope(|scope| {
            for tx_index in 0..64usize {
                let memory = &memory;
                thread::Builder::new()
                    .name(format!("blockstm-test-{}", tx_index + 1))
                    .spawn_scoped(scope, move || {
                        let mut writes = BlockStmWriteSet::default();
                        writes.record(key, tx_index as u64);
                        memory.commit_version(BlockStmVersion::new(tx_index, 0), &writes);
                    })
                    .expect("spawn Block-STM MV memory test worker");
            }
        });

        assert_eq!(memory.read(key, 64), 63u64.into());
        assert_eq!(memory.committed_value(&key).unwrap().value, 63u64.into());
    }
}
