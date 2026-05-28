//! Read/write set primitives used by Block-STM validation.

use alloy_primitives::{
    Address, B256, U256,
    map::{HashMap, HashSet},
};

/// A state key that can be tracked by Block-STM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockStmAccessKey {
    /// Account metadata such as balance, nonce, or code hash.
    Account(Address),
    /// One EVM storage slot.
    Storage { address: Address, slot: U256 },
    /// Code reachable through an account's code hash.
    Code { address: Address },
    /// Raw bytecode by hash.
    CodeHash(B256),
}

/// Value recorded for validation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockStmValue(pub B256);

impl From<u64> for BlockStmValue {
    fn from(value: u64) -> Self {
        Self(B256::from(U256::from(value)))
    }
}

impl From<U256> for BlockStmValue {
    fn from(value: U256) -> Self {
        Self(B256::from(value))
    }
}

impl From<B256> for BlockStmValue {
    fn from(value: B256) -> Self {
        Self(value)
    }
}

impl BlockStmValue {
    /// Interprets the recorded 32-byte value as a big-endian integer.
    pub fn as_u256(self) -> U256 {
        U256::from_be_bytes(self.0.0)
    }
}

/// Reads captured by one speculative attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockStmReadSet {
    reads: HashMap<BlockStmAccessKey, BlockStmValue>,
}

impl BlockStmReadSet {
    /// Records a read if the key was not already read by this attempt.
    pub fn record(&mut self, key: BlockStmAccessKey, value: impl Into<BlockStmValue>) {
        self.reads.entry(key).or_insert_with(|| value.into());
    }

    /// Returns the recorded value for `key`.
    pub fn get(&self, key: &BlockStmAccessKey) -> Option<BlockStmValue> {
        self.reads.get(key).copied()
    }

    /// Returns true if this read set records `key`.
    pub fn contains_key(&self, key: &BlockStmAccessKey) -> bool {
        self.reads.contains_key(key)
    }

    /// Returns all read dependencies.
    pub fn iter(&self) -> impl Iterator<Item = (&BlockStmAccessKey, &BlockStmValue)> {
        self.reads.iter()
    }

    /// Returns the number of recorded read dependencies.
    pub fn len(&self) -> usize {
        self.reads.len()
    }

    /// Returns a copy without keys that are covered by a semantic resolver.
    pub fn without_keys<'a>(&self, ignored: impl IntoIterator<Item = &'a BlockStmAccessKey>) -> Self
    where
        BlockStmAccessKey: 'a,
    {
        let ignored = ignored.into_iter().copied().collect::<HashSet<_>>();
        Self {
            reads: self
                .reads
                .iter()
                .filter(|(key, _)| !ignored.contains(key))
                .map(|(key, value)| (*key, *value))
                .collect(),
        }
    }

    /// Returns true when no reads were recorded.
    pub fn is_empty(&self) -> bool {
        self.reads.is_empty()
    }
}

/// Writes captured by one speculative attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockStmWriteSet {
    writes: HashMap<BlockStmAccessKey, BlockStmValue>,
    order: Vec<BlockStmAccessKey>,
}

impl BlockStmWriteSet {
    /// Records or replaces a write while preserving first-write order.
    pub fn record(&mut self, key: BlockStmAccessKey, value: impl Into<BlockStmValue>) {
        if !self.writes.contains_key(&key) {
            self.order.push(key);
        }
        self.writes.insert(key, value.into());
    }

    /// Returns the attempted write value for `key`.
    pub fn get(&self, key: &BlockStmAccessKey) -> Option<BlockStmValue> {
        self.writes.get(key).copied()
    }

    /// Returns true if this write set writes `key`.
    pub fn contains_key(&self, key: &BlockStmAccessKey) -> bool {
        self.writes.contains_key(key)
    }

    /// Returns writes in deterministic first-write order.
    pub fn ordered(&self) -> impl Iterator<Item = (BlockStmAccessKey, BlockStmValue)> + '_ {
        let mut seen: HashSet<BlockStmAccessKey> = HashSet::default();
        self.order
            .iter()
            .copied()
            .filter(move |key| seen.insert(*key))
            .filter_map(|key| self.writes.get(&key).copied().map(|value| (key, value)))
    }

    /// Returns all writes sorted by key.
    pub fn iter(&self) -> impl Iterator<Item = (&BlockStmAccessKey, &BlockStmValue)> {
        self.writes.iter()
    }

    /// Returns the number of recorded writes.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns a copy without keys that are covered by a semantic resolver.
    pub fn without_keys<'a>(&self, ignored: impl IntoIterator<Item = &'a BlockStmAccessKey>) -> Self
    where
        BlockStmAccessKey: 'a,
    {
        let ignored = ignored.into_iter().copied().collect::<HashSet<_>>();
        let mut writes = Self::default();
        for (key, value) in self.ordered() {
            if !ignored.contains(&key) {
                writes.record(key, value);
            }
        }
        writes
    }

    /// Returns true when no writes were recorded.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
}
