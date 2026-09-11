//! RocksDB-backed per-occurrence submission evidence and mirror frontier.

use crate::{
    state::{BlockCursor, FailureEvidence, OccurrenceId, ReplayIdentity, tx_index_key},
    store::Store,
};
use alloy::primitives::{Address, B256, U256};
use anyhow::{Context, Result, ensure};
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

const OCCURRENCES: &str = "occurrences";
const TX_INDEX: &str = "tx_index";
const COLUMNS: &[&str] = &[OCCURRENCES, TX_INDEX];
const SCHEMA: u32 = 2;
const SUMMARY_KEY: &[u8] = b"summary/submissions";
const PRUNE_CURSOR_KEY: &[u8] = b"retention/prune_cursor";

/// Durable mirror progress and aggregate submission outcomes.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MirrorState {
    pub accepted: u64,
    pub already_known: u64,
    pub rejected: u64,
    pub possibly_included: u64,
    pub ambiguous: u64,
    pub source_cursor: BlockCursor,
}

impl MirrorState {
    fn initial(identity: ReplayIdentity) -> Self {
        Self {
            source_cursor: identity.source_cursor(),
            ..Default::default()
        }
    }
}

/// Current durable submission state for one source occurrence.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionDisposition {
    Intent,
    Accepted,
    AlreadyKnown,
    Rejected,
    PossiblyIncluded,
    Ambiguous,
}

impl SubmissionDisposition {
    pub const fn terminal(self) -> bool {
        !matches!(self, Self::Intent)
    }
}

/// Bounded evidence from one authorized submission sequence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionEvidence {
    pub started_at_ms: u64,
    pub completed_at_ms: Option<u64>,
    pub attempts: u64,
    pub disposition: SubmissionDisposition,
    pub failure: Option<FailureEvidence>,
}

/// Binary source and dispatch evidence retained for inspection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MirrorOccurrence {
    pub source_block_hash: B256,
    pub transaction_hash: B256,
    pub transaction_type: u8,
    pub sender: Address,
    pub nonce: u64,
    pub nonce_key: U256,
    pub expiring: bool,
    pub encoded_length: u64,
    pub raw_on_failure: Option<Vec<u8>>,
    pub restart_ambiguities: u64,
    pub submission: SubmissionEvidence,
}

/// Final result collected by the async submitter and committed with the block frontier.
pub(super) struct CompletedSubmission {
    pub id: OccurrenceId,
    pub disposition: SubmissionDisposition,
    pub attempts: u32,
    pub completed_at_ms: u64,
    pub failure: Option<FailureEvidence>,
    pub raw_on_failure: Option<Vec<u8>>,
}

/// An ambiguous occurrence whose exact bytes are still available for bounded recovery.
pub(super) struct RecoverableSubmission {
    pub id: OccurrenceId,
    pub transaction_hash: B256,
    pub raw: Vec<u8>,
    pub started_at_ms: u64,
}

/// Single-writer mirror evidence database.
pub struct MirrorStore {
    store: Store,
    state: MirrorState,
}

impl MirrorStore {
    pub fn open(
        path: &Path,
        identity: ReplayIdentity,
        max_bytes: u64,
        min_free_bytes: u64,
    ) -> Result<Self> {
        let store = Store::open(path, COLUMNS, SCHEMA, identity, max_bytes, min_free_bytes)?;
        let saved_state = store.get_default(SUMMARY_KEY)?;
        let initialize = saved_state.is_none();
        let state = saved_state.unwrap_or_else(|| MirrorState::initial(identity));
        if initialize {
            let mut batch = WriteBatch::default();
            Store::put_default(&mut batch, SUMMARY_KEY, &state);
            store.commit(batch)?;
        }
        Ok(Self { store, state })
    }

    pub fn state(&self) -> &MirrorState {
        &self.state
    }

    pub(super) fn prepare_block(
        &self,
        records: Vec<(OccurrenceId, MirrorOccurrence)>,
    ) -> Result<BTreeSet<OccurrenceId>> {
        self.store.check_disk()?;
        let mut batch = WriteBatch::default();
        let mut restarted = BTreeSet::new();
        for (id, mut record) in records {
            ensure!(
                id.source_height == self.state.source_cursor.height.saturating_add(1),
                "mirror occurrence is not in the next source block"
            );
            if let Some(previous) = self.store.get::<MirrorOccurrence>(OCCURRENCES, &id.key())? {
                ensure!(
                    !previous.submission.disposition.terminal(),
                    "terminal occurrence exists beyond mirror cursor"
                );
                record.restart_ambiguities = previous.restart_ambiguities.saturating_add(1);
                restarted.insert(id);
            }
            self.store
                .put(&mut batch, OCCURRENCES, &id.key(), &record)?;
            self.store.put_raw(
                &mut batch,
                TX_INDEX,
                &tx_index_key(record.transaction_hash, id),
                &[],
            )?;
        }
        self.store.commit(batch)?;
        Ok(restarted)
    }

    pub(super) fn recoverable_ambiguous(
        &self,
        retain_blocks: u64,
    ) -> Result<Vec<RecoverableSubmission>> {
        if retain_blocks == 0 || self.state.source_cursor.height == 0 {
            return Ok(Vec::new());
        }
        let floor = self
            .state
            .source_cursor
            .height
            .saturating_sub(retain_blocks.saturating_sub(1));
        let start = OccurrenceId {
            source_height: floor,
            source_index: 0,
        }
        .key();
        let end = OccurrenceId {
            source_height: self.state.source_cursor.height,
            source_index: u32::MAX,
        }
        .key();
        let mut recoverable = Vec::new();
        for (key, value) in self
            .store
            .raw_range(OCCURRENCES, &start, &end, usize::MAX)?
        {
            let id = OccurrenceId::decode(&key).context("invalid mirror occurrence key")?;
            let occurrence: MirrorOccurrence = crate::store::decode(&value)?;
            if occurrence.submission.disposition != SubmissionDisposition::Ambiguous {
                continue;
            }
            recoverable.push(RecoverableSubmission {
                id,
                transaction_hash: occurrence.transaction_hash,
                raw: occurrence
                    .raw_on_failure
                    .context("ambiguous occurrence has no exact bytes")?,
                started_at_ms: occurrence.submission.started_at_ms,
            });
        }
        Ok(recoverable)
    }

    pub(super) fn complete_recovery(&mut self, completed: Vec<CompletedSubmission>) -> Result<()> {
        if completed.is_empty() {
            return Ok(());
        }
        let mut batch = WriteBatch::default();
        for result in completed {
            let mut occurrence = self
                .store
                .get::<MirrorOccurrence>(OCCURRENCES, &result.id.key())?
                .context("ambiguous mirror occurrence missing")?;
            ensure!(
                occurrence.submission.disposition == SubmissionDisposition::Ambiguous,
                "mirror recovery result is no longer ambiguous"
            );
            self.state.ambiguous = self.state.ambiguous.saturating_sub(1);
            occurrence.submission.completed_at_ms = Some(result.completed_at_ms);
            occurrence.submission.attempts = occurrence
                .submission
                .attempts
                .saturating_add(u64::from(result.attempts));
            occurrence.submission.disposition = result.disposition;
            occurrence.submission.failure = result.failure;
            occurrence.raw_on_failure = result.raw_on_failure;
            increment_outcome(&mut self.state, result.disposition)?;
            self.store
                .put(&mut batch, OCCURRENCES, &result.id.key(), &occurrence)?;
        }
        Store::put_default(&mut batch, SUMMARY_KEY, &self.state);
        self.store.commit(batch)
    }

    pub(super) fn complete_block(
        &mut self,
        cursor: BlockCursor,
        completed: Vec<CompletedSubmission>,
    ) -> Result<()> {
        ensure!(
            cursor.height == self.state.source_cursor.height.saturating_add(1)
                && cursor.hash != self.state.source_cursor.hash,
            "invalid mirror cursor advance"
        );
        let prefix = cursor.height.to_be_bytes();
        let prepared = self
            .store
            .raw_prefix(OCCURRENCES, &prefix)?
            .into_iter()
            .map(|(key, _)| OccurrenceId::decode(&key).context("invalid prepared occurrence key"))
            .collect::<Result<BTreeSet<_>>>()?;
        let completed_ids = completed
            .iter()
            .map(|result| result.id)
            .collect::<BTreeSet<_>>();
        ensure!(
            prepared == completed_ids && completed.len() == completed_ids.len(),
            "completed submissions do not exactly cover the prepared block"
        );
        let mut batch = WriteBatch::default();
        for result in completed {
            let mut occurrence = self
                .store
                .get::<MirrorOccurrence>(OCCURRENCES, &result.id.key())?
                .context("prepared mirror occurrence missing")?;
            ensure!(
                occurrence.submission.disposition == SubmissionDisposition::Intent,
                "mirror occurrence is not pending"
            );
            occurrence.submission.completed_at_ms = Some(result.completed_at_ms);
            occurrence.submission.attempts = u64::from(result.attempts);
            occurrence.submission.disposition = result.disposition;
            occurrence.submission.failure = result.failure;
            occurrence.raw_on_failure = result.raw_on_failure;
            increment_outcome(&mut self.state, result.disposition)?;
            self.store
                .put(&mut batch, OCCURRENCES, &result.id.key(), &occurrence)?;
        }
        self.state.source_cursor = cursor;
        Store::put_default(&mut batch, SUMMARY_KEY, &self.state);
        self.store.commit(batch)
    }

    pub(super) fn prune_completed(&self, retain_blocks: u64) -> Result<()> {
        if retain_blocks == 0 {
            return Ok(());
        }
        let floor = self
            .state
            .source_cursor
            .height
            .saturating_sub(retain_blocks);
        if floor == 0 {
            return Ok(());
        }
        let start = self
            .store
            .get_raw_default(PRUNE_CURSOR_KEY)?
            .unwrap_or_else(|| vec![0; 12]);
        let end = OccurrenceId {
            source_height: floor - 1,
            source_index: u32::MAX,
        }
        .key();
        let mut batch = WriteBatch::default();
        let mut pruned = 0u64;
        let mut last = None;
        for (key, value) in self.store.raw_range(OCCURRENCES, &start, &end, 10_001)? {
            if key == start {
                continue;
            }
            let id = OccurrenceId::decode(&key).context("invalid mirror occurrence key")?;
            last = Some(key.clone());
            let occurrence: MirrorOccurrence = crate::store::decode(&value)?;
            if !matches!(
                occurrence.submission.disposition,
                SubmissionDisposition::Accepted | SubmissionDisposition::AlreadyKnown
            ) {
                continue;
            }
            self.store.delete(&mut batch, OCCURRENCES, &key)?;
            self.store.delete(
                &mut batch,
                TX_INDEX,
                &tx_index_key(occurrence.transaction_hash, id),
            )?;
            pruned += 1;
        }
        if let Some(last) = last {
            batch.put(PRUNE_CURSOR_KEY, last);
            self.store.commit(batch)?;
            metrics::counter!("tempo_replay_rocksdb_pruned_records_total").increment(pruned);
        }
        Ok(())
    }

    pub(super) fn flush(&self) -> Result<()> {
        self.store.flush()
    }
}

fn increment_outcome(state: &mut MirrorState, disposition: SubmissionDisposition) -> Result<()> {
    match disposition {
        SubmissionDisposition::Accepted => state.accepted += 1,
        SubmissionDisposition::AlreadyKnown => state.already_known += 1,
        SubmissionDisposition::Rejected => state.rejected += 1,
        SubmissionDisposition::PossiblyIncluded => state.possibly_included += 1,
        SubmissionDisposition::Ambiguous => state.ambiguous += 1,
        SubmissionDisposition::Intent => anyhow::bail!("pending result cannot complete a block"),
    }
    Ok(())
}

/// Stable live-secondary view used by one inspection request.
pub struct MirrorReader {
    store: Store,
}

impl MirrorReader {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            store: Store::open_secondary(path, COLUMNS, SCHEMA)?,
        })
    }

    pub fn state(&self) -> Result<MirrorState> {
        self.store
            .get_default(SUMMARY_KEY)?
            .context("mirror summary missing")
    }

    pub fn by_hash(&self, hash: B256) -> Result<Vec<(OccurrenceId, MirrorOccurrence)>> {
        self.store
            .raw_prefix(TX_INDEX, hash.as_slice())?
            .into_iter()
            .map(|(key, _)| {
                let id =
                    OccurrenceId::decode(key.get(32..).context("invalid transaction index key")?)
                        .context("invalid occurrence index key")?;
                let occurrence = self
                    .store
                    .get(OCCURRENCES, &id.key())?
                    .context("indexed mirror occurrence missing")?;
                Ok((id, occurrence))
            })
            .collect()
    }

    pub fn occurrence(&self, id: OccurrenceId) -> Result<Option<MirrorOccurrence>> {
        self.store.get(OCCURRENCES, &id.key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ReplayIdentity {
        ReplayIdentity {
            chain_id: 4217,
            checkpoint_height: 10,
            source_hash: B256::repeat_byte(1),
            target_hash: B256::repeat_byte(2),
        }
    }

    fn occurrence(hash: B256) -> MirrorOccurrence {
        MirrorOccurrence {
            source_block_hash: B256::repeat_byte(3),
            transaction_hash: hash,
            transaction_type: 2,
            sender: Address::repeat_byte(4),
            nonce: 7,
            nonce_key: U256::ZERO,
            expiring: false,
            encoded_length: 100,
            raw_on_failure: None,
            restart_ambiguities: 0,
            submission: SubmissionEvidence {
                started_at_ms: 1,
                completed_at_ms: None,
                attempts: 0,
                disposition: SubmissionDisposition::Intent,
                failure: None,
            },
        }
    }

    #[test]
    fn binary_fixture() {
        assert_eq!(
            alloy::primitives::keccak256(
                crate::store::encode(&occurrence(B256::repeat_byte(5))).unwrap()
            ),
            alloy::primitives::b256!(
                "bcffd4620ff6f9db633b3ea519251488bd08804e8c22c0f822e3cc095750ccfe"
            )
        );
    }

    #[test]
    fn mirror_store_is_bound_to_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let store = MirrorStore::open(directory.path(), identity(), u64::MAX, 0).unwrap();
        assert_eq!(store.state().source_cursor.height, 10);
        let mut other = identity();
        other.target_hash = B256::repeat_byte(3);
        assert!(MirrorStore::open(directory.path(), other, u64::MAX, 0).is_err());
    }

    #[test]
    fn ambiguous_outcome_is_recovered_from_exact_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let id = OccurrenceId {
            source_height: 11,
            source_index: 0,
        };
        let hash = B256::repeat_byte(5);
        let mut store = MirrorStore::open(directory.path(), identity(), u64::MAX, 0).unwrap();
        store.prepare_block(vec![(id, occurrence(hash))]).unwrap();
        store
            .complete_block(
                BlockCursor {
                    height: 11,
                    hash: B256::repeat_byte(3),
                },
                vec![CompletedSubmission {
                    id,
                    disposition: SubmissionDisposition::Ambiguous,
                    attempts: 3,
                    completed_at_ms: 2,
                    failure: None,
                    raw_on_failure: Some(vec![1, 2, 3]),
                }],
            )
            .unwrap();
        let recoverable = store.recoverable_ambiguous(64).unwrap();
        assert_eq!(recoverable.len(), 1);
        assert_eq!(recoverable[0].raw, vec![1, 2, 3]);
        store
            .complete_recovery(vec![CompletedSubmission {
                id,
                disposition: SubmissionDisposition::AlreadyKnown,
                attempts: 1,
                completed_at_ms: 3,
                failure: None,
                raw_on_failure: None,
            }])
            .unwrap();
        assert_eq!(store.state().ambiguous, 0);
        assert_eq!(store.state().already_known, 1);
        let occurrence = store
            .store
            .get::<MirrorOccurrence>(OCCURRENCES, &id.key())
            .unwrap()
            .unwrap();
        assert_eq!(occurrence.submission.attempts, 4);
        assert!(occurrence.raw_on_failure.is_none());
    }

    #[test]
    fn intent_survives_restart_and_cursor_advances_with_outcome() {
        let directory = tempfile::tempdir().unwrap();
        let id = OccurrenceId {
            source_height: 11,
            source_index: 0,
        };
        let hash = B256::repeat_byte(5);
        let store = MirrorStore::open(directory.path(), identity(), u64::MAX, 0).unwrap();
        store.prepare_block(vec![(id, occurrence(hash))]).unwrap();
        drop(store);

        let mut reopened = MirrorStore::open(directory.path(), identity(), u64::MAX, 0).unwrap();
        assert_eq!(reopened.state().source_cursor.height, 10);
        reopened
            .prepare_block(vec![(id, occurrence(hash))])
            .unwrap();
        assert_eq!(
            reopened
                .store
                .get::<MirrorOccurrence>(OCCURRENCES, &id.key())
                .unwrap()
                .unwrap()
                .restart_ambiguities,
            1
        );
        assert!(
            reopened
                .complete_block(
                    BlockCursor {
                        height: 11,
                        hash: B256::repeat_byte(3),
                    },
                    Vec::new(),
                )
                .is_err()
        );
        assert_eq!(reopened.state().source_cursor.height, 10);
        reopened
            .complete_block(
                BlockCursor {
                    height: 11,
                    hash: B256::repeat_byte(3),
                },
                vec![CompletedSubmission {
                    id,
                    disposition: SubmissionDisposition::Accepted,
                    attempts: 1,
                    completed_at_ms: 2,
                    failure: None,
                    raw_on_failure: None,
                }],
            )
            .unwrap();
        assert_eq!(reopened.state().source_cursor.height, 11);
        assert_eq!(reopened.state().accepted, 1);
        assert_eq!(
            MirrorReader::open(directory.path())
                .unwrap()
                .by_hash(hash)
                .unwrap()
                .len(),
            1
        );
        for height in 12..=13 {
            reopened
                .complete_block(
                    BlockCursor {
                        height,
                        hash: B256::repeat_byte(height as u8),
                    },
                    Vec::new(),
                )
                .unwrap();
        }
        reopened.prune_completed(1).unwrap();
        assert!(
            MirrorReader::open(directory.path())
                .unwrap()
                .by_hash(hash)
                .unwrap()
                .is_empty()
        );
    }
}
