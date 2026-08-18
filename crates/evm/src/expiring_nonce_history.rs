use alloy_consensus::transaction::SignerRecoverable;
use alloy_primitives::{B256, map::B256Map};
use smallvec::SmallVec;
use std::{
    collections::{HashMap, HashSet},
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
    blocks: B256Map<BlockRecord>,
    inclusions: B256Map<SmallVec<[Inclusion; 1]>>,
    anchors: B256Map<Anchor>,
    highest_timestamp: u64,
}

impl Default for HistoryInner {
    fn default() -> Self {
        let mut anchors = B256Map::default();
        anchors.insert(B256::ZERO, Anchor { complete_at: 0 });
        Self {
            blocks: B256Map::default(),
            inclusions: B256Map::default(),
            anchors,
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
        let blocks = blocks.into_iter().collect::<Vec<_>>();
        if let Some(first) = blocks.first() {
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
        let replay_ids = block
            .entries
            .iter()
            .map(|entry| entry.replay_id)
            .collect::<Vec<_>>();
        for entry in block.entries {
            inner
                .inclusions
                .entry(entry.replay_id)
                .or_default()
                .push(Inclusion {
                    block_hash: block.hash,
                    valid_before: entry.valid_before,
                });
        }
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
        inner.blocks.insert(
            block.hash,
            BlockRecord {
                parent_hash: block.parent_hash,
                timestamp: block.timestamp,
                replay_ids,
                complete_at,
            },
        );
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
            .inclusions
            .values()
            .map(SmallVec::len)
            .sum()
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

    fn is_ancestor_locked(
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

        let removed = inner
            .blocks
            .iter()
            .filter_map(|(hash, block)| {
                (block.timestamp < cutoff).then_some((*hash, block.clone()))
            })
            .collect::<HashMap<_, _>>();
        if removed.is_empty() {
            return (0, 0);
        }
        let removed_identifiers = removed.values().map(|block| block.replay_ids.len()).sum();
        let removed_blocks = removed.len();

        for (hash, block) in &removed {
            inner.blocks.remove(hash);
            for replay_id in &block.replay_ids {
                if let Some(inclusions) = inner.inclusions.get_mut(replay_id) {
                    inclusions.retain(|inclusion| inclusion.block_hash != *hash);
                    if inclusions.is_empty() {
                        inner.inclusions.remove(replay_id);
                    }
                }
            }
        }

        let boundary_parents = inner
            .blocks
            .values()
            .filter(|block| !inner.blocks.contains_key(&block.parent_hash))
            .map(|block| block.parent_hash)
            .collect::<HashSet<_>>();
        inner
            .anchors
            .retain(|hash, _| *hash == B256::ZERO || boundary_parents.contains(hash));
        for parent_hash in boundary_parents {
            if let Some(block) = removed.get(&parent_hash) {
                inner.anchors.insert(
                    parent_hash,
                    Anchor {
                        complete_at: block.timestamp.saturating_add(self.max_expiry_secs),
                    },
                );
            }
        }
        self.recompute_completeness_locked(inner);
        (removed_blocks, removed_identifiers)
    }

    fn recompute_completeness_locked(&self, inner: &mut HistoryInner) {
        for block in inner.blocks.values_mut() {
            block.complete_at = None;
        }

        loop {
            let updates = inner
                .blocks
                .iter()
                .filter_map(|(hash, block)| {
                    if block.complete_at.is_some() {
                        return None;
                    }
                    inner
                        .anchors
                        .get(&block.parent_hash)
                        .map(|anchor| anchor.complete_at)
                        .or_else(|| {
                            inner
                                .blocks
                                .get(&block.parent_hash)
                                .and_then(|parent| parent.complete_at)
                        })
                        .map(|complete_at| (*hash, complete_at))
                })
                .collect::<Vec<_>>();
            if updates.is_empty() {
                break;
            }
            for (hash, complete_at) in updates {
                inner
                    .blocks
                    .get_mut(&hash)
                    .expect("completeness update references a retained block")
                    .complete_at = Some(complete_at);
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
    }
}
