use alloy_consensus::transaction::SignerRecoverable;
use alloy_primitives::{B256, map::B256Map};
use smallvec::SmallVec;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, RwLock},
    time::Instant,
};
use tempo_primitives::TempoTxEnvelope;
use tracing::info;

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

#[derive(Debug, Clone)]
struct BlockRecord {
    parent_hash: B256,
    timestamp: u64,
    entries: Vec<ExpiringNonceEntry>,
    /// Earliest candidate timestamp at which all ancestry missing before this block is expired.
    complete_at: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct Anchor {
    /// The earliest candidate timestamp for which history before this anchor cannot be live.
    complete_at: u64,
}

#[derive(Debug)]
struct HistoryInner {
    /// Live replay identifiers on the canonical branch.
    live: B256Map<u64>,
    /// Expiry buckets for canonical entries. Stale bucket entries are ignored during collection.
    expirations: BTreeMap<u64, Vec<B256>>,
    blocks: B256Map<BlockRecord>,
    blocks_by_timestamp: BTreeMap<u64, SmallVec<[B256; 2]>>,
    children: B256Map<SmallVec<[B256; 2]>>,
    anchors: B256Map<Anchor>,
    canonical_head: B256,
    canonical_timestamp: u64,
    canonical_complete_at: u64,
    retained_identifiers: usize,
}

impl Default for HistoryInner {
    fn default() -> Self {
        let mut anchors = B256Map::default();
        anchors.insert(B256::ZERO, Anchor { complete_at: 0 });
        Self {
            live: B256Map::default(),
            expirations: BTreeMap::new(),
            blocks: B256Map::default(),
            blocks_by_timestamp: BTreeMap::new(),
            children: B256Map::default(),
            anchors,
            canonical_head: B256::ZERO,
            canonical_timestamp: 0,
            canonical_complete_at: 0,
            retained_identifiers: 0,
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
        let mut head = None;
        for block in blocks {
            head = Some(block.hash);
            history.record_block(block);
        }
        if let Some(head) = head {
            history
                .set_canonical_head(head)
                .expect("contiguous rebuilt expiring nonce history");
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
        let entries = block.entries;
        let entry_count = entries.len();
        inner.retained_identifiers += entry_count;
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
        inner.blocks.insert(
            block.hash,
            BlockRecord {
                parent_hash: block.parent_hash,
                timestamp: block.timestamp,
                entries,
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
        let retained_blocks = inner.blocks.len();
        let retained_unique_identifiers = inner.live.len();
        drop(inner);

        info!(
            target: "tempo::expiring_nonce_history",
            %block_hash,
            %parent_hash,
            timestamp,
            entry_count,
            retained_blocks,
            retained_unique_identifiers,
            ?lock_wait,
            elapsed = ?started.elapsed(),
            "cached expiring nonce block overlay"
        );
    }

    /// Returns whether `replay_id` was consumed by a live ancestor of `parent_hash`.
    ///
    /// The canonical-head path is a single lookup in the live replay map. Cached block overlays are
    /// consulted only when validating a side branch.
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
        if parent_hash == inner.canonical_head {
            if candidate_timestamp < inner.canonical_complete_at {
                return Err(ExpiringNonceHistoryError::MissingHistory { parent_hash });
            }
            return Ok(inner
                .live
                .get(&replay_id)
                .is_some_and(|valid_before| *valid_before > candidate_timestamp));
        }

        self.contains_on_side_branch_locked(&inner, parent_hash, replay_id, candidate_timestamp)
    }

    /// Moves the live replay map to a cached canonical block.
    ///
    /// Extending the current head applies only the new block and expired timing-wheel bucket.
    /// Reorganizations reconcile the small cached suffix outside the transaction lookup path.
    pub fn set_canonical_head(&self, block_hash: B256) -> Result<(), ExpiringNonceHistoryError> {
        let mut inner = self
            .inner
            .write()
            .expect("expiring nonce history lock poisoned");
        if block_hash == inner.canonical_head {
            return Ok(());
        }

        let block =
            inner
                .blocks
                .get(&block_hash)
                .ok_or(ExpiringNonceHistoryError::MissingHistory {
                    parent_hash: block_hash,
                })?;
        let timestamp = block.timestamp;
        let complete_at = block
            .complete_at
            .ok_or(ExpiringNonceHistoryError::MissingHistory {
                parent_hash: block_hash,
            })?;

        if block.parent_hash == inner.canonical_head {
            Self::expire_live_locked(&mut inner, timestamp);
            Self::apply_block_locked(&mut inner, block_hash, timestamp);
        } else {
            let new_suffix = self.live_suffix_locked(&inner, block_hash, timestamp)?;
            inner.live.clear();
            inner.expirations.clear();
            for hash in new_suffix.into_iter().rev() {
                Self::apply_block_locked(&mut inner, hash, timestamp);
            }
            Self::expire_live_locked(&mut inner, timestamp);
        }

        inner.canonical_head = block_hash;
        inner.canonical_timestamp = timestamp;
        inner.canonical_complete_at = complete_at;
        self.prune_locked(&mut inner);
        Ok(())
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

    fn contains_on_side_branch_locked(
        &self,
        inner: &HistoryInner,
        parent_hash: B256,
        replay_id: B256,
        candidate_timestamp: u64,
    ) -> Result<bool, ExpiringNonceHistoryError> {
        self.ensure_complete_locked(inner, parent_hash, candidate_timestamp)?;
        let mut cursor = parent_hash;
        loop {
            if let Some(anchor) = inner.anchors.get(&cursor) {
                return if candidate_timestamp >= anchor.complete_at {
                    Ok(false)
                } else {
                    Err(ExpiringNonceHistoryError::MissingHistory { parent_hash })
                };
            }
            let Some(block) = inner.blocks.get(&cursor) else {
                return Err(ExpiringNonceHistoryError::MissingHistory { parent_hash });
            };
            if block.timestamp.saturating_add(self.max_expiry_secs) <= candidate_timestamp {
                return Ok(false);
            }
            if block.entries.iter().any(|entry| {
                entry.replay_id == replay_id && entry.valid_before > candidate_timestamp
            }) {
                return Ok(true);
            }
            cursor = block.parent_hash;
        }
    }

    fn live_suffix_locked(
        &self,
        inner: &HistoryInner,
        head: B256,
        timestamp: u64,
    ) -> Result<Vec<B256>, ExpiringNonceHistoryError> {
        let mut suffix = Vec::new();
        let mut cursor = head;
        loop {
            if inner.anchors.contains_key(&cursor) {
                return Ok(suffix);
            }
            let block = inner
                .blocks
                .get(&cursor)
                .ok_or(ExpiringNonceHistoryError::MissingHistory { parent_hash: head })?;
            if block.timestamp.saturating_add(self.max_expiry_secs) <= timestamp {
                return Ok(suffix);
            }
            suffix.push(cursor);
            cursor = block.parent_hash;
        }
    }

    fn apply_block_locked(inner: &mut HistoryInner, block_hash: B256, timestamp: u64) {
        let HistoryInner {
            live,
            expirations,
            blocks,
            ..
        } = inner;
        let block = blocks
            .get(&block_hash)
            .expect("canonical block is present in replay cache");
        for entry in &block.entries {
            if entry.valid_before > timestamp {
                live.insert(entry.replay_id, entry.valid_before);
                expirations
                    .entry(entry.valid_before)
                    .or_default()
                    .push(entry.replay_id);
            }
        }
    }

    fn expire_live_locked(inner: &mut HistoryInner, timestamp: u64) {
        while inner
            .expirations
            .first_key_value()
            .is_some_and(|(valid_before, _)| *valid_before <= timestamp)
        {
            let (_, replay_ids) = inner
                .expirations
                .pop_first()
                .expect("an expired replay bucket was just observed");
            for replay_id in replay_ids {
                if inner
                    .live
                    .get(&replay_id)
                    .is_some_and(|valid_before| *valid_before <= timestamp)
                {
                    inner.live.remove(&replay_id);
                }
            }
        }
    }

    fn prune_locked(&self, inner: &mut HistoryInner) -> (usize, usize) {
        // Keep two validity windows so ordinary reorganizations can reuse their existing branch
        // overlays. Older branch requests fail closed and can be rebuilt from persisted bodies.
        let retention = self.max_expiry_secs.saturating_mul(2);
        let cutoff = inner.canonical_timestamp.saturating_sub(retention);
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
                removed_identifiers += block.entries.len();
                inner.retained_identifiers -= block.entries.len();

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
        history.set_canonical_head(hash(1)).unwrap();

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
        history.set_canonical_head(hash(2)).unwrap();

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
        history.set_canonical_head(hash(2)).unwrap();

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
        history.set_canonical_head(hash(1)).unwrap();
        history.record_block(block(2, 1, 2, Vec::new()));
        history.set_canonical_head(hash(2)).unwrap();
        history.record_block(block(3, 2, 22, Vec::new()));
        history.set_canonical_head(hash(3)).unwrap();

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
        history.set_canonical_head(hash(1)).unwrap();

        assert!(!history.contains(hash(1), hash(9), 350).unwrap());
        assert!(history.contains(hash(1), hash(9), 200).unwrap());
    }

    #[test]
    fn reorg_reconciles_live_replay_map() {
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

        history.set_canonical_head(hash(2)).unwrap();
        assert!(history.contains(hash(2), hash(9), 200).unwrap());

        history.set_canonical_head(hash(3)).unwrap();
        assert!(!history.contains(hash(3), hash(9), 200).unwrap());
        assert!(history.contains(hash(2), hash(9), 200).unwrap());
    }

    #[test]
    fn reorg_to_earlier_timestamp_restores_live_entry() {
        let history = ExpiringNonceHistory::new(10);
        history.record_block(block(
            1,
            0,
            1,
            vec![ExpiringNonceEntry {
                replay_id: hash(9),
                valid_before: 10,
            }],
        ));
        history.record_block(block(2, 1, 10, Vec::new()));
        history.record_block(block(3, 1, 9, Vec::new()));

        history.set_canonical_head(hash(2)).unwrap();
        assert!(!history.contains(hash(2), hash(9), 10).unwrap());

        history.set_canonical_head(hash(3)).unwrap();
        assert!(history.contains(hash(3), hash(9), 9).unwrap());
    }
}
