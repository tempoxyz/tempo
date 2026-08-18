use alloy_consensus::transaction::{SignerRecoverable, TxHashRef};
use alloy_primitives::{
    B256,
    map::{B256Map, Entry, HashMap},
};
use smallvec::SmallVec;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, RwLock},
    time::Instant,
};
use tempo_primitives::TempoTxEnvelope;
use tracing::info;

const MAX_PENDING_BLOCKS: usize = 256;

/// An expiring nonce identifier and its consensus expiry timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiringNonceEntry {
    /// TIP-1009 sender-scoped replay identifier.
    pub replay_id: B256,
    /// The transaction's `validBefore` timestamp.
    pub valid_before: u64,
}

/// A block and the expiring nonce identifiers it consumed.
#[derive(Debug, Clone)]
pub struct ExpiringNonceBlock {
    /// Block hash.
    pub hash: B256,
    /// Parent block hash.
    pub parent_hash: B256,
    /// Consensus block timestamp.
    pub timestamp: u64,
    /// Expiring nonce identifiers consumed by the block.
    pub entries: Vec<ExpiringNonceEntry>,
}

/// Errors returned while resolving history-derived expiring nonce state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpiringNonceHistoryError {
    /// The cache cannot prove that it covers every live ancestor of the requested parent.
    #[error("missing expiring nonce history for parent {parent_hash}")]
    MissingHistory {
        /// Parent whose history is incomplete.
        parent_hash: B256,
    },
    /// A canonical expiring nonce transaction could not be decoded into a replay entry.
    #[error("invalid expiring nonce transaction in canonical history: {0}")]
    InvalidTransaction(&'static str),
    /// Sender recovery failed for a canonical transaction.
    #[error("failed recovering expiring nonce transaction sender")]
    SenderRecovery,
}

#[derive(Debug, Clone, Copy)]
struct Inclusion {
    block_hash: B256,
    valid_before: u64,
}

#[derive(Debug, Clone)]
struct BlockRecord {
    parent_hash: B256,
    timestamp: u64,
    replay_ids: Vec<B256>,
    /// Distance from this cache segment's anchor, when the parent lineage is known.
    height: Option<u64>,
    /// Ancestors at distances 1, 2, 4, ... for logarithmic branch membership checks.
    jumps: SmallVec<[B256; 8]>,
    /// Earliest candidate timestamp at which all ancestry missing before this block is expired.
    complete_at: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct Anchor {
    /// The earliest candidate timestamp for which history before this anchor cannot be live.
    complete_at: u64,
}

#[derive(Debug)]
struct PendingBlock {
    sequence: u64,
    transaction_hashes: Arc<[B256]>,
    entries: Vec<ExpiringNonceEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingKey {
    parent_hash: B256,
    timestamp: u64,
}

#[derive(Debug)]
struct HistoryInner {
    blocks: B256Map<BlockRecord>,
    blocks_by_timestamp: BTreeMap<u64, SmallVec<[B256; 2]>>,
    children: B256Map<SmallVec<[B256; 2]>>,
    inclusions: B256Map<SmallVec<[Inclusion; 1]>>,
    anchors: B256Map<Anchor>,
    pending_blocks: HashMap<PendingKey, SmallVec<[PendingBlock; 1]>>,
    pending_order: VecDeque<(u64, PendingKey)>,
    next_pending_sequence: u64,
    pending_count: usize,
    retained_identifiers: usize,
    highest_timestamp: u64,
}

impl Default for HistoryInner {
    fn default() -> Self {
        let mut anchors = B256Map::default();
        anchors.insert(B256::ZERO, Anchor { complete_at: 0 });
        Self {
            blocks: B256Map::default(),
            blocks_by_timestamp: BTreeMap::new(),
            children: B256Map::default(),
            inclusions: B256Map::default(),
            anchors,
            pending_blocks: HashMap::default(),
            pending_order: VecDeque::new(),
            next_pending_sequence: 0,
            pending_count: 0,
            retained_identifiers: 0,
            highest_timestamp: 0,
        }
    }
}

/// Fork-aware cache of expiring nonce replay identifiers derived from block history.
///
/// This cache is not consensus state. Every entry is reconstructible from block bodies and the
/// cache fails closed when it cannot prove that the requested parent has complete recent history.
#[derive(Debug, Clone)]
pub struct ExpiringNonceHistory {
    inner: Arc<RwLock<HistoryInner>>,
    max_expiry_secs: u64,
}

impl Default for ExpiringNonceHistory {
    fn default() -> Self {
        Self::new(300)
    }
}

impl ExpiringNonceHistory {
    /// Creates an empty history cache rooted at the zero hash.
    pub fn new(max_expiry_secs: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HistoryInner::default())),
            max_expiry_secs,
        }
    }

    /// Benchmark-only access to the pending payload cache.
    #[cfg(feature = "bench")]
    #[doc(hidden)]
    pub fn bench_cache_pending_block(
        &self,
        parent_hash: B256,
        timestamp: u64,
        transaction_hashes: Vec<B256>,
        entries: Vec<ExpiringNonceEntry>,
    ) {
        self.cache_pending_block(parent_hash, timestamp, transaction_hashes, entries);
    }

    /// Benchmark-only access to pending payload resolution.
    #[cfg(feature = "bench")]
    #[doc(hidden)]
    pub fn bench_entries_for_block(
        &self,
        parent_hash: B256,
        timestamp: u64,
        transactions: &[TempoTxEnvelope],
    ) -> Result<(Vec<ExpiringNonceEntry>, bool), ExpiringNonceHistoryError> {
        self.entries_for_block(parent_hash, timestamp, transactions)
    }

    /// Builds a cache from an oldest-to-newest contiguous block sequence.
    ///
    /// `complete_at` is the earliest timestamp at which history before the first block cannot
    /// contain a live replay identifier. A startup rebuild derives it from the excluded
    /// predecessor after scanning its configured retention horizon.
    pub fn from_blocks(
        max_expiry_secs: u64,
        complete_at: u64,
        blocks: impl IntoIterator<Item = ExpiringNonceBlock>,
    ) -> Self {
        let history = Self::new(max_expiry_secs);
        let mut blocks = blocks.into_iter().peekable();
        if let Some(first) = blocks.peek() {
            history
                .inner
                .write()
                .expect("expiring nonce history lock poisoned")
                .anchors
                .insert(first.parent_hash, Anchor { complete_at });
        }
        for block in blocks {
            history.record_block(block);
        }
        history
    }

    /// Extracts an expiring nonce entry from a signed transaction.
    pub fn entry_from_transaction(
        tx: &TempoTxEnvelope,
    ) -> Result<Option<ExpiringNonceEntry>, ExpiringNonceHistoryError> {
        let Some(aa) = tx.as_aa() else {
            return Ok(None);
        };
        if !aa.tx().is_expiring_nonce_tx() {
            return Ok(None);
        }
        let valid_before =
            tx.valid_before()
                .ok_or(ExpiringNonceHistoryError::InvalidTransaction(
                    "missing validBefore",
                ))?;
        let sender = tx
            .recover_signer()
            .map_err(|_| ExpiringNonceHistoryError::SenderRecovery)?;
        Ok(Some(ExpiringNonceEntry {
            replay_id: aa.expiring_nonce_hash(sender),
            valid_before,
        }))
    }

    /// Caches the replay entries collected while building a local payload until its final block
    /// hash is available to the assembler.
    pub(crate) fn cache_pending_block(
        &self,
        parent_hash: B256,
        timestamp: u64,
        transaction_hashes: Vec<B256>,
        entries: Vec<ExpiringNonceEntry>,
    ) {
        let key = PendingKey {
            parent_hash,
            timestamp,
        };
        debug_assert_eq!(transaction_hashes.len(), entries.len());
        let mut inner = self
            .inner
            .write()
            .expect("expiring nonce history lock poisoned");
        if inner.pending_blocks.get(&key).is_some_and(|pending| {
            pending
                .iter()
                .any(|block| block.transaction_hashes.as_ref() == transaction_hashes)
        }) {
            return;
        }
        let sequence = inner.next_pending_sequence;
        inner.next_pending_sequence = inner.next_pending_sequence.wrapping_add(1);
        inner
            .pending_blocks
            .entry(key)
            .or_default()
            .push(PendingBlock {
                sequence,
                transaction_hashes: transaction_hashes.into(),
                entries,
            });
        inner.pending_count += 1;
        inner.pending_order.push_back((sequence, key));
        Self::trim_pending_locked(&mut inner);
    }

    /// Resolves replay entries for an assembled payload, reusing the entries collected during
    /// execution and falling back to sender recovery when the bounded pending cache missed.
    pub(crate) fn entries_for_block(
        &self,
        parent_hash: B256,
        timestamp: u64,
        transactions: &[TempoTxEnvelope],
    ) -> Result<(Vec<ExpiringNonceEntry>, bool), ExpiringNonceHistoryError> {
        let key = PendingKey {
            parent_hash,
            timestamp,
        };
        let candidates = self
            .inner
            .read()
            .expect("expiring nonce history lock poisoned")
            .pending_blocks
            .get(&key)
            .map(|pending| {
                pending
                    .iter()
                    .map(|block| (block.sequence, Arc::clone(&block.transaction_hashes)))
                    .collect::<SmallVec<[_; 1]>>()
            })
            .unwrap_or_default();
        let matching_sequence = candidates
            .iter()
            .find(|(_, transaction_hashes)| Self::pending_matches(transaction_hashes, transactions))
            .map(|(sequence, _)| *sequence);
        if let Some(sequence) = matching_sequence {
            let mut inner = self
                .inner
                .write()
                .expect("expiring nonce history lock poisoned");
            if let Some(pending) = Self::remove_pending_locked(&mut inner, key, sequence) {
                Self::trim_pending_locked(&mut inner);
                return Ok((pending.entries, true));
            }
        }

        let entries = transactions
            .iter()
            .filter_map(|tx| Self::entry_from_transaction(tx).transpose())
            .collect::<Result<Vec<_>, _>>()?;
        Ok((entries, false))
    }

    fn pending_matches(transaction_hashes: &[B256], transactions: &[TempoTxEnvelope]) -> bool {
        transactions
            .iter()
            .filter_map(|tx| {
                tx.as_aa()
                    .is_some_and(|aa| aa.tx().is_expiring_nonce_tx())
                    .then_some(*tx.tx_hash())
            })
            .eq(transaction_hashes.iter().copied())
    }

    fn remove_pending_locked(
        inner: &mut HistoryInner,
        key: PendingKey,
        sequence: u64,
    ) -> Option<PendingBlock> {
        let (pending, remove_key) = {
            let blocks = inner.pending_blocks.get_mut(&key)?;
            let position = blocks.iter().position(|block| block.sequence == sequence)?;
            let pending = blocks.swap_remove(position);
            (pending, blocks.is_empty())
        };
        if remove_key {
            inner.pending_blocks.remove(&key);
        }
        inner.pending_count -= 1;
        Some(pending)
    }

    fn trim_pending_locked(inner: &mut HistoryInner) {
        while let Some(&(sequence, key)) = inner.pending_order.front() {
            let is_live = inner
                .pending_blocks
                .get(&key)
                .is_some_and(|pending| pending.iter().any(|block| block.sequence == sequence));
            if is_live && inner.pending_count <= MAX_PENDING_BLOCKS {
                break;
            }
            inner.pending_order.pop_front();
            if is_live {
                Self::remove_pending_locked(inner, key, sequence);
            }
        }

        // Out-of-order payload completion can leave tombstones behind a live entry. Compact only
        // when those tombstones grow large enough, keeping the common in-order path O(1).
        if inner.pending_order.len() > MAX_PENDING_BLOCKS * 2 {
            inner.pending_order.retain(|(sequence, key)| {
                inner
                    .pending_blocks
                    .get(key)
                    .is_some_and(|pending| pending.iter().any(|block| block.sequence == *sequence))
            });
        }
    }

    /// Records a block and its replay identifiers.
    ///
    /// Recording is idempotent. Completeness is checked when a descendant performs a lookup, so
    /// sequential sync can record intermediate blocks before their older history is available.
    pub fn record_block(&self, block: ExpiringNonceBlock) {
        let started = Instant::now();
        let lock_started = Instant::now();
        let mut inner = self
            .inner
            .write()
            .expect("expiring nonce history lock poisoned");
        let lock_wait = lock_started.elapsed();
        if inner.blocks.contains_key(&block.hash) {
            return;
        }

        let block_hash = block.hash;
        let parent_hash = block.parent_hash;
        let timestamp = block.timestamp;
        let entry_count = block.entries.len();
        let mut replay_ids = Vec::with_capacity(entry_count);
        for entry in block.entries {
            replay_ids.push(entry.replay_id);
            inner
                .inclusions
                .entry(entry.replay_id)
                .or_default()
                .push(Inclusion {
                    block_hash: block.hash,
                    valid_before: entry.valid_before,
                });
        }
        inner.retained_identifiers += entry_count;
        inner.highest_timestamp = inner.highest_timestamp.max(block.timestamp);
        let complete_at = inner
            .anchors
            .get(&block.parent_hash)
            .map(|anchor| anchor.complete_at)
            .or_else(|| {
                inner
                    .blocks
                    .get(&block.parent_hash)
                    .and_then(|parent| parent.complete_at)
            });
        let (height, jumps) = Self::lineage_for_parent(&inner, block.parent_hash);
        inner.blocks.insert(
            block.hash,
            BlockRecord {
                parent_hash: block.parent_hash,
                timestamp: block.timestamp,
                replay_ids,
                height,
                jumps,
                complete_at,
            },
        );
        inner
            .blocks_by_timestamp
            .entry(timestamp)
            .or_default()
            .push(block_hash);
        inner
            .children
            .entry(parent_hash)
            .or_default()
            .push(block_hash);
        self.propagate_completeness_locked(&mut inner, block_hash, false);
        let (pruned_blocks, pruned_identifiers) = self.prune_locked(&mut inner);
        let retained_blocks = inner.blocks.len();
        let retained_unique_identifiers = inner.inclusions.len();
        drop(inner);

        info!(
            target: "tempo::expiring_nonce_history",
            %block_hash,
            %parent_hash,
            timestamp,
            entry_count,
            retained_blocks,
            retained_unique_identifiers,
            pruned_blocks,
            pruned_identifiers,
            ?lock_wait,
            elapsed = ?started.elapsed(),
            "recorded expiring nonce history overlay"
        );
    }

    /// Returns whether `replay_id` was consumed by a live ancestor of `parent_hash`.
    pub fn contains(
        &self,
        parent_hash: B256,
        replay_id: B256,
        candidate_timestamp: u64,
    ) -> Result<bool, ExpiringNonceHistoryError> {
        let inner = self
            .inner
            .read()
            .expect("expiring nonce history lock poisoned");
        self.ensure_complete_locked(&inner, parent_hash, candidate_timestamp)?;

        let Some(inclusions) = inner.inclusions.get(&replay_id) else {
            return Ok(false);
        };
        for inclusion in inclusions {
            if inclusion.valid_before > candidate_timestamp
                && self.is_ancestor_locked(
                    &inner,
                    inclusion.block_hash,
                    parent_hash,
                    candidate_timestamp,
                )?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns the number of replay identifiers currently retained across all cached branches.
    pub fn retained_identifiers(&self) -> usize {
        self.inner
            .read()
            .expect("expiring nonce history lock poisoned")
            .retained_identifiers
    }

    /// Returns the number of block overlays retained by the cache.
    pub fn retained_blocks(&self) -> usize {
        self.inner
            .read()
            .expect("expiring nonce history lock poisoned")
            .blocks
            .len()
    }

    /// Returns whether the cache already contains an overlay for `block_hash`.
    pub fn contains_block(&self, block_hash: B256) -> bool {
        self.inner
            .read()
            .expect("expiring nonce history lock poisoned")
            .blocks
            .contains_key(&block_hash)
    }

    fn ensure_complete_locked(
        &self,
        inner: &HistoryInner,
        parent_hash: B256,
        candidate_timestamp: u64,
    ) -> Result<(), ExpiringNonceHistoryError> {
        let complete_at = if let Some(anchor) = inner.anchors.get(&parent_hash) {
            Some(anchor.complete_at)
        } else if let Some(block) = inner.blocks.get(&parent_hash) {
            if block.timestamp.saturating_add(self.max_expiry_secs) <= candidate_timestamp {
                return Ok(());
            }
            block.complete_at
        } else {
            None
        };
        if complete_at.is_some_and(|timestamp| candidate_timestamp >= timestamp) {
            Ok(())
        } else {
            Err(ExpiringNonceHistoryError::MissingHistory { parent_hash })
        }
    }

    fn lineage_for_parent(
        inner: &HistoryInner,
        parent_hash: B256,
    ) -> (Option<u64>, SmallVec<[B256; 8]>) {
        let mut jumps = SmallVec::new();
        jumps.push(parent_hash);

        if inner.anchors.contains_key(&parent_hash) {
            return (Some(0), jumps);
        }
        let Some(parent) = inner.blocks.get(&parent_hash) else {
            return (None, SmallVec::new());
        };
        let Some(height) = parent.height else {
            return (None, SmallVec::new());
        };

        let mut level = 1;
        while let Some(ancestor) = jumps
            .get(level - 1)
            .and_then(|ancestor| inner.blocks.get(ancestor))
            .and_then(|ancestor| ancestor.jumps.get(level - 1))
            .copied()
        {
            jumps.push(ancestor);
            level += 1;
        }
        (Some(height + 1), jumps)
    }

    fn is_ancestor_locked(
        &self,
        inner: &HistoryInner,
        ancestor_hash: B256,
        descendant_hash: B256,
        candidate_timestamp: u64,
    ) -> Result<bool, ExpiringNonceHistoryError> {
        if let (Some(ancestor), Some(descendant)) = (
            inner.blocks.get(&ancestor_hash),
            inner.blocks.get(&descendant_hash),
        ) && let (Some(ancestor_height), Some(descendant_height)) =
            (ancestor.height, descendant.height)
        {
            if ancestor_height > descendant_height {
                return Ok(false);
            }

            let mut cursor = descendant_hash;
            let mut distance = descendant_height - ancestor_height;
            while distance != 0 {
                let level = (u64::BITS - 1 - distance.leading_zeros()) as usize;
                let Some(next) = inner
                    .blocks
                    .get(&cursor)
                    .and_then(|block| block.jumps.get(level))
                else {
                    return self.is_ancestor_linear_locked(
                        inner,
                        ancestor_hash,
                        descendant_hash,
                        candidate_timestamp,
                    );
                };
                cursor = *next;
                distance -= 1 << level;
            }
            return Ok(cursor == ancestor_hash);
        }

        self.is_ancestor_linear_locked(inner, ancestor_hash, descendant_hash, candidate_timestamp)
    }

    fn is_ancestor_linear_locked(
        &self,
        inner: &HistoryInner,
        ancestor_hash: B256,
        descendant_hash: B256,
        candidate_timestamp: u64,
    ) -> Result<bool, ExpiringNonceHistoryError> {
        let mut cursor = descendant_hash;
        loop {
            if cursor == ancestor_hash {
                return Ok(true);
            }
            if let Some(anchor) = inner.anchors.get(&cursor) {
                return if candidate_timestamp >= anchor.complete_at {
                    Ok(false)
                } else {
                    Err(ExpiringNonceHistoryError::MissingHistory {
                        parent_hash: descendant_hash,
                    })
                };
            }
            let Some(block) = inner.blocks.get(&cursor) else {
                return Err(ExpiringNonceHistoryError::MissingHistory {
                    parent_hash: descendant_hash,
                });
            };
            if block.timestamp.saturating_add(self.max_expiry_secs) <= candidate_timestamp {
                return Ok(false);
            }
            cursor = block.parent_hash;
        }
    }

    fn prune_locked(&self, inner: &mut HistoryInner) -> (usize, usize) {
        // Keep two validity windows so ordinary reorganizations can reuse their existing branch
        // overlays. Older branch requests fail closed and can be rebuilt from persisted bodies.
        let retention = self.max_expiry_secs.saturating_mul(2);
        let cutoff = inner.highest_timestamp.saturating_sub(retention);
        if cutoff == 0 {
            return (0, 0);
        }

        let mut removed_blocks = 0;
        let mut removed_identifiers = 0;
        while inner
            .blocks_by_timestamp
            .first_key_value()
            .is_some_and(|(timestamp, _)| *timestamp < cutoff)
        {
            let (_, hashes) = inner
                .blocks_by_timestamp
                .pop_first()
                .expect("an expired timestamp was just observed");
            for hash in hashes {
                let Some(block) = inner.blocks.remove(&hash) else {
                    continue;
                };
                removed_blocks += 1;
                removed_identifiers += block.replay_ids.len();
                inner.retained_identifiers -= block.replay_ids.len();
                for replay_id in &block.replay_ids {
                    if let Entry::Occupied(mut entry) = inner.inclusions.entry(*replay_id) {
                        let inclusions = entry.get_mut();
                        inclusions.retain(|inclusion| inclusion.block_hash != hash);
                        if inclusions.is_empty() {
                            entry.remove();
                        }
                    }
                }

                let mut remove_parent_children = false;
                if let Some(siblings) = inner.children.get_mut(&block.parent_hash) {
                    siblings.retain(|child| *child != hash);
                    remove_parent_children = siblings.is_empty();
                }
                if remove_parent_children {
                    inner.children.remove(&block.parent_hash);
                    if block.parent_hash != B256::ZERO {
                        inner.anchors.remove(&block.parent_hash);
                    }
                }

                let has_retained_child = inner.children.get(&hash).is_some_and(|children| {
                    children
                        .iter()
                        .any(|child| inner.blocks.contains_key(child))
                });
                if has_retained_child {
                    inner.anchors.insert(
                        hash,
                        Anchor {
                            complete_at: block.timestamp.saturating_add(self.max_expiry_secs),
                        },
                    );
                    self.propagate_completeness_locked(inner, hash, true);
                } else {
                    inner.children.remove(&hash);
                    inner.anchors.remove(&hash);
                }
            }
        }

        (removed_blocks, removed_identifiers)
    }

    fn propagate_completeness_locked(
        &self,
        inner: &mut HistoryInner,
        parent_hash: B256,
        overwrite: bool,
    ) {
        let Some(complete_at) = inner
            .anchors
            .get(&parent_hash)
            .map(|anchor| anchor.complete_at)
            .or_else(|| {
                inner
                    .blocks
                    .get(&parent_hash)
                    .and_then(|block| block.complete_at)
            })
        else {
            return;
        };

        if !inner.children.contains_key(&parent_hash) {
            return;
        }

        let mut pending = VecDeque::from([parent_hash]);
        let children = &inner.children;
        let blocks = &mut inner.blocks;
        while let Some(parent_hash) = pending.pop_front() {
            let Some(children) = children.get(&parent_hash) else {
                continue;
            };
            for child_hash in children {
                let Some(child) = blocks.get_mut(child_hash) else {
                    continue;
                };
                if overwrite || child.complete_at.is_none() {
                    child.complete_at = Some(complete_at);
                    pending.push_back(*child_hash);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(value: u8) -> B256 {
        B256::repeat_byte(value)
    }

    fn block(
        hash_value: u8,
        parent_value: u8,
        timestamp: u64,
        entries: Vec<ExpiringNonceEntry>,
    ) -> ExpiringNonceBlock {
        ExpiringNonceBlock {
            hash: hash(hash_value),
            parent_hash: if parent_value == 0 {
                B256::ZERO
            } else {
                hash(parent_value)
            },
            timestamp,
            entries,
        }
    }

    #[test]
    fn detects_live_replay_on_same_branch() {
        let history = ExpiringNonceHistory::new(300);
        let entry = ExpiringNonceEntry {
            replay_id: hash(9),
            valid_before: 350,
        };
        history.record_block(block(1, 0, 100, vec![entry]));

        assert!(history.contains(hash(1), hash(9), 200).unwrap());
        assert!(!history.contains(hash(1), hash(9), 350).unwrap());
    }

    #[test]
    fn isolates_competing_forks() {
        let history = ExpiringNonceHistory::new(300);
        history.record_block(block(1, 0, 100, Vec::new()));
        history.record_block(block(
            2,
            1,
            101,
            vec![ExpiringNonceEntry {
                replay_id: hash(9),
                valid_before: 350,
            }],
        ));
        history.record_block(block(3, 1, 101, Vec::new()));

        assert!(history.contains(hash(2), hash(9), 200).unwrap());
        assert!(!history.contains(hash(3), hash(9), 200).unwrap());
    }

    #[test]
    fn fails_closed_when_recent_parent_history_is_missing() {
        let history = ExpiringNonceHistory::new(300);
        history.record_block(block(2, 1, 100, Vec::new()));

        assert_eq!(
            history.contains(hash(2), hash(9), 101),
            Err(ExpiringNonceHistoryError::MissingHistory {
                parent_hash: hash(2)
            })
        );
    }

    #[test]
    fn late_parent_completes_already_recorded_descendants() {
        let history = ExpiringNonceHistory::new(300);
        history.record_block(block(2, 1, 101, Vec::new()));
        history.record_block(block(1, 0, 100, Vec::new()));

        assert!(!history.contains(hash(2), hash(9), 102).unwrap());
    }

    #[test]
    fn rebuilt_anchor_is_complete_at_head_timestamp() {
        let history = ExpiringNonceHistory::from_blocks(
            300,
            400,
            [block(
                2,
                1,
                200,
                vec![ExpiringNonceEntry {
                    replay_id: hash(9),
                    valid_before: 450,
                }],
            )],
        );

        assert!(history.contains(hash(2), hash(9), 400).unwrap());
        assert_eq!(
            history.contains(hash(2), hash(8), 399),
            Err(ExpiringNonceHistoryError::MissingHistory {
                parent_hash: hash(2)
            })
        );
    }

    #[test]
    fn pruning_preserves_fail_closed_boundary() {
        let history = ExpiringNonceHistory::new(10);
        history.record_block(block(
            1,
            0,
            1,
            vec![ExpiringNonceEntry {
                replay_id: hash(9),
                valid_before: 11,
            }],
        ));
        history.record_block(block(2, 1, 2, Vec::new()));
        history.record_block(block(3, 2, 22, Vec::new()));

        assert_eq!(
            history.contains(hash(2), hash(9), 10),
            Err(ExpiringNonceHistoryError::MissingHistory {
                parent_hash: hash(2)
            })
        );
        assert!(!history.contains(hash(2), hash(9), 11).unwrap());
        assert_eq!(history.retained_identifiers(), 0);
    }

    #[test]
    fn candidate_timestamp_does_not_mutate_parent_history() {
        let history = ExpiringNonceHistory::new(300);
        history.record_block(block(
            1,
            0,
            100,
            vec![ExpiringNonceEntry {
                replay_id: hash(9),
                valid_before: 350,
            }],
        ));

        assert!(!history.contains(hash(1), hash(9), 350).unwrap());
        assert!(history.contains(hash(1), hash(9), 200).unwrap());
    }

    #[test]
    fn consumes_pending_local_block_entries() {
        let history = ExpiringNonceHistory::new(300);
        history.cache_pending_block(hash(1), 100, Vec::new(), Vec::new());

        let (entries, pending_cache_hit) = history
            .entries_for_block(hash(1), 100, &[])
            .expect("pending entries should resolve");
        assert!(pending_cache_hit);
        assert!(entries.is_empty());

        let (_, pending_cache_hit) = history
            .entries_for_block(hash(1), 100, &[])
            .expect("empty blocks can be reconstructed without recovery");
        assert!(!pending_cache_hit);
    }
}
