//! Binary RocksDB audit records, indexes, summaries, retention, and incidents.

use crate::{
    now_ms,
    state::{
        BlockCursor, EvidenceLevel, FailureEvidence, OccurrenceId, ReplayIdentity, tx_index_key,
    },
    store::{Store, decode},
};
use alloy::primitives::{Address, B256, U256};
use anyhow::{Context, Result, ensure};
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

const OCCURRENCES: &str = "occurrences";
const INDEXES: &str = "indexes";
const INCIDENTS: &str = "incidents";
const COLUMNS: &[&str] = &[OCCURRENCES, INDEXES, INCIDENTS];
const SCHEMA: u32 = 2;
const STATE_KEY: &[u8] = b"state/audit";
const TX_TAG: u8 = 0;
const PENDING_TAG: u8 = 1;
const INCLUDED_TAG: u8 = 2;
const TARGET_TAG: u8 = 3;

/// Durable audit cursors and aggregate outcomes.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSummary {
    pub source_cursor_height: u64,
    pub target_cursor_height: u64,
    pub included: u64,
    pub execution_drift: u64,
    pub missing_within_window: u64,
    pub missing_after_window: u64,
    pub archived_included: u64,
    pub consensus_incidents: u64,
    pub system_txs: u64,
    pub system_failures: u64,
    pub incident_records: u64,
}

/// Finalized receipt fields used for source/target comparison.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptSummary {
    pub status: bool,
    pub gas_used: u64,
    pub logs_hash: B256,
}

/// Exact transaction index within a finalized block.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxLocation {
    pub index: u32,
    pub block: BlockCursor,
}

/// Receipt fields that differ between finalized source and target execution.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptDrift {
    pub status: bool,
    pub gas: bool,
    pub logs: bool,
}

impl ReceiptDrift {
    pub const fn any(self) -> bool {
        self.status || self.gas || self.logs
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionDriftFinding {
    pub target: TxLocation,
    pub drift: ReceiptDrift,
}

/// Current finalized inclusion or missing-window result for a source occurrence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    Included(TxLocation),
    ExecutionDrift(ExecutionDriftFinding),
    MissingWithinWindow,
    MissingAfterWindow(FailureEvidence),
}

impl Finding {
    pub const fn included_location(&self) -> Option<TxLocation> {
        match self {
            Self::Included(location) => Some(*location),
            Self::ExecutionDrift(finding) => Some(finding.target),
            _ => None,
        }
    }
}

/// Replayable transaction expected from one finalized source location.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Expectation {
    pub source_block_hash: B256,
    pub source_timestamp_ms: u64,
    pub observed_at_ms: u64,
    pub target_height_when_observed: u64,
    pub transaction_hash: B256,
    pub transaction_type: u8,
    pub sender: Address,
    pub nonce_key: U256,
    pub expiring: bool,
    pub source_receipt: ReceiptSummary,
    pub finding: Finding,
}

/// Finalized target transaction and receipt used to resolve source expectations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetObservation {
    pub transaction_hash: B256,
    pub location: TxLocation,
    pub receipt: ReceiptSummary,
}

/// Persisted finality or naturally generated system-transaction observation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Incident {
    FinalityStall(FailureEvidence),
    FinalityResumed(BlockCursor),
    SourceFailure(FailureEvidence),
    TargetFailure(FailureEvidence),
    SystemFailure(FailureEvidence),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ObservationSide {
    Source,
    Target,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuditState {
    source_cursor: BlockCursor,
    target_cursor: BlockCursor,
    summary: AuditSummary,
    last_target_progress_ms: u64,
    stall_open: bool,
}

/// Single-writer audit evidence database.
pub struct AuditStore {
    store: Store,
    state: AuditState,
}

impl AuditStore {
    pub fn open(
        path: &Path,
        identity: ReplayIdentity,
        max_bytes: u64,
        min_free_bytes: u64,
    ) -> Result<Self> {
        let store = Store::open(path, COLUMNS, SCHEMA, identity, max_bytes, min_free_bytes)?;
        let state = match store.get_default(STATE_KEY)? {
            Some(state) => state,
            None => {
                let state = AuditState {
                    source_cursor: identity.source_cursor(),
                    target_cursor: identity.target_cursor(),
                    summary: AuditSummary {
                        source_cursor_height: identity.checkpoint_height,
                        target_cursor_height: identity.checkpoint_height,
                        ..Default::default()
                    },
                    last_target_progress_ms: now_ms(),
                    stall_open: false,
                };
                let mut batch = WriteBatch::default();
                Store::put_default(&mut batch, STATE_KEY, &state);
                store.commit(batch)?;
                state
            }
        };
        Ok(Self { store, state })
    }

    pub const fn source_cursor(&self) -> BlockCursor {
        self.state.source_cursor
    }

    pub const fn target_cursor(&self) -> BlockCursor {
        self.state.target_cursor
    }

    pub fn summary(&self) -> &AuditSummary {
        &self.state.summary
    }

    pub fn observe_source(
        &mut self,
        cursor: BlockCursor,
        expectations: Vec<(OccurrenceId, Expectation)>,
    ) -> Result<()> {
        ensure!(
            cursor.height == self.state.source_cursor.height.saturating_add(1),
            "invalid audit source cursor advance"
        );
        self.store.check_disk()?;
        let mut batch = WriteBatch::default();
        for (id, mut expectation) in expectations {
            ensure!(
                id.source_height == cursor.height,
                "expectation belongs to another block"
            );
            if let Some(observation) =
                self.first_target_observation(expectation.transaction_hash)?
            {
                apply_observation(&mut expectation, &observation);
            }
            self.transition(&mut batch, id, None, &expectation)?;
            self.store.put_raw(
                &mut batch,
                INDEXES,
                &tx_key(expectation.transaction_hash, id),
                &[],
            )?;
        }
        self.state.source_cursor = cursor;
        self.state.summary.source_cursor_height = cursor.height;
        Store::put_default(&mut batch, STATE_KEY, &self.state);
        self.store.commit(batch)
    }

    pub fn observe_target(
        &mut self,
        cursor: BlockCursor,
        observations: Vec<TargetObservation>,
        system_transactions: u64,
        system_failures: Vec<FailureEvidence>,
    ) -> Result<()> {
        ensure!(
            cursor.height == self.state.target_cursor.height.saturating_add(1),
            "invalid audit target cursor advance"
        );
        self.store.check_disk()?;
        let mut batch = WriteBatch::default();
        for observation in observations {
            let ids = self.occurrences_for_hash(observation.transaction_hash)?;
            if ids.is_empty() {
                self.store
                    .put(&mut batch, INDEXES, &target_key(&observation), &observation)?;
                continue;
            }
            for id in ids {
                let mut expectation = self
                    .store
                    .get::<Expectation>(OCCURRENCES, &id.key())?
                    .context("indexed audit occurrence missing")?;
                if expectation.finding.included_location().is_some() {
                    continue;
                }
                let previous = expectation.finding.clone();
                apply_observation(&mut expectation, &observation);
                self.transition(&mut batch, id, Some(&previous), &expectation)?;
            }
        }
        self.state.summary.system_txs += system_transactions;
        for failure in system_failures {
            self.state.summary.system_failures += 1;
            self.put_incident(&mut batch, Incident::SystemFailure(failure))?;
        }
        self.state.target_cursor = cursor;
        self.state.last_target_progress_ms = now_ms();
        self.state.summary.target_cursor_height = cursor.height;
        if self.state.stall_open {
            self.put_incident(&mut batch, Incident::FinalityResumed(cursor))?;
            self.state.stall_open = false;
        }
        Store::put_default(&mut batch, STATE_KEY, &self.state);
        self.store.commit(batch)
    }

    pub fn refresh_missing(
        &mut self,
        missing_after_blocks: u64,
        missing_after: Duration,
    ) -> Result<()> {
        let now = now_ms();
        let mut batch = WriteBatch::default();
        let mut changed = false;
        for (key, _) in self
            .store
            .raw_prefix_limit(INDEXES, &[PENDING_TAG], 100_000)?
        {
            let id = OccurrenceId::decode(key.get(1..).context("invalid pending index")?)
                .context("invalid pending occurrence")?;
            let mut expectation = self
                .store
                .get::<Expectation>(OCCURRENCES, &id.key())?
                .context("pending audit occurrence missing")?;
            let block_elapsed = missing_after_blocks > 0
                && self
                    .state
                    .target_cursor
                    .height
                    .saturating_sub(expectation.target_height_when_observed)
                    >= missing_after_blocks;
            let time_elapsed = !missing_after.is_zero()
                && now.saturating_sub(expectation.observed_at_ms)
                    >= missing_after.as_millis().min(u128::from(u64::MAX)) as u64;
            if !block_elapsed && !time_elapsed {
                continue;
            }
            let previous = expectation.finding.clone();
            expectation.finding = Finding::MissingAfterWindow(FailureEvidence {
                level: EvidenceLevel::Observed,
                rpc_code: None,
                message:
                    "transaction not observed in finalized target history within configured horizon"
                        .into(),
                first_observed_ms: expectation.observed_at_ms,
                last_observed_ms: now,
            });
            self.transition(&mut batch, id, Some(&previous), &expectation)?;
            changed = true;
        }
        if changed {
            Store::put_default(&mut batch, STATE_KEY, &self.state);
            self.store.commit(batch)?;
        }
        Ok(())
    }

    pub fn check_stall(&mut self, threshold: Duration) -> Result<()> {
        if threshold.is_zero()
            || self.state.stall_open
            || now_ms().saturating_sub(self.state.last_target_progress_ms)
                < threshold.as_millis().min(u128::from(u64::MAX)) as u64
        {
            return Ok(());
        }
        let now = now_ms();
        let evidence = FailureEvidence {
            level: EvidenceLevel::Observed,
            rpc_code: None,
            message: "target finality has not advanced within configured threshold".into(),
            first_observed_ms: self.state.last_target_progress_ms,
            last_observed_ms: now,
        };
        let mut batch = WriteBatch::default();
        self.put_incident(&mut batch, Incident::FinalityStall(evidence))?;
        self.state.summary.consensus_incidents += 1;
        self.state.stall_open = true;
        Store::put_default(&mut batch, STATE_KEY, &self.state);
        self.store.commit(batch)
    }

    pub(super) fn record_finality_failure(
        &mut self,
        side: ObservationSide,
        message: String,
    ) -> Result<()> {
        let now = now_ms();
        let evidence = FailureEvidence {
            level: EvidenceLevel::Observed,
            rpc_code: None,
            message,
            first_observed_ms: now,
            last_observed_ms: now,
        };
        let mut batch = WriteBatch::default();
        let incident = match side {
            ObservationSide::Source => Incident::SourceFailure(evidence),
            ObservationSide::Target => Incident::TargetFailure(evidence),
        };
        self.put_incident(&mut batch, incident)?;
        self.state.summary.consensus_incidents += 1;
        Store::put_default(&mut batch, STATE_KEY, &self.state);
        self.store.commit(batch)
    }

    pub fn prune_included(&mut self, retain_blocks: u64) -> Result<()> {
        if retain_blocks == 0 {
            return Ok(());
        }
        let floor = self
            .state
            .target_cursor
            .height
            .saturating_sub(retain_blocks);
        let mut batch = WriteBatch::default();
        let mut pruned = 0u64;
        for (key, _) in self
            .store
            .raw_prefix_limit(INDEXES, &[INCLUDED_TAG], 10_000)?
        {
            let (height, id) = decode_included_key(&key)?;
            if height >= floor || pruned >= 10_000 {
                break;
            }
            let expectation = self
                .store
                .get::<Expectation>(OCCURRENCES, &id.key())?
                .context("included audit occurrence missing")?;
            self.store.delete(&mut batch, OCCURRENCES, &id.key())?;
            self.store.delete(
                &mut batch,
                INDEXES,
                &tx_key(expectation.transaction_hash, id),
            )?;
            self.store.delete(&mut batch, INDEXES, &key)?;
            pruned += 1;
        }
        if pruned > 0 {
            self.state.summary.archived_included += pruned;
            Store::put_default(&mut batch, STATE_KEY, &self.state);
            self.store.commit(batch)?;
            metrics::counter!("tempo_replay_rocksdb_pruned_records_total").increment(pruned);
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.store.flush()
    }

    fn occurrences_for_hash(&self, hash: B256) -> Result<Vec<OccurrenceId>> {
        self.store
            .raw_prefix(INDEXES, &hash_prefix(TX_TAG, hash))?
            .into_iter()
            .map(|(key, _)| {
                OccurrenceId::decode(key.get(33..).context("invalid transaction index")?)
                    .context("invalid occurrence index")
            })
            .collect()
    }

    fn first_target_observation(&self, hash: B256) -> Result<Option<TargetObservation>> {
        self.store
            .raw_prefix(INDEXES, &hash_prefix(TARGET_TAG, hash))?
            .into_iter()
            .next()
            .map(|(_, value)| decode(&value))
            .transpose()
    }

    fn transition(
        &mut self,
        batch: &mut WriteBatch,
        id: OccurrenceId,
        previous: Option<&Finding>,
        expectation: &Expectation,
    ) -> Result<()> {
        if let Some(previous) = previous {
            match previous {
                Finding::MissingWithinWindow => {
                    self.state.summary.missing_within_window =
                        self.state.summary.missing_within_window.saturating_sub(1);
                    self.store.delete(batch, INDEXES, &pending_key(id))?;
                }
                Finding::MissingAfterWindow(_) => {
                    self.state.summary.missing_after_window =
                        self.state.summary.missing_after_window.saturating_sub(1);
                }
                Finding::Included(_) | Finding::ExecutionDrift(_) => {}
            }
        }
        match &expectation.finding {
            Finding::MissingWithinWindow => {
                self.state.summary.missing_within_window += 1;
                self.store.put_raw(batch, INDEXES, &pending_key(id), &[])?;
            }
            Finding::MissingAfterWindow(_) => self.state.summary.missing_after_window += 1,
            Finding::Included(location) => {
                self.state.summary.included += 1;
                self.store.put_raw(
                    batch,
                    INDEXES,
                    &included_key(location.block.height, id),
                    &[],
                )?;
            }
            Finding::ExecutionDrift(finding) => {
                self.state.summary.included += 1;
                self.state.summary.execution_drift += 1;
                self.store.put_raw(
                    batch,
                    INDEXES,
                    &included_key(finding.target.block.height, id),
                    &[],
                )?;
            }
        }
        self.store.put(batch, OCCURRENCES, &id.key(), expectation)
    }

    fn put_incident(&mut self, batch: &mut WriteBatch, incident: Incident) -> Result<()> {
        self.state.summary.incident_records += 1;
        self.store.put(
            batch,
            INCIDENTS,
            &incident_key(now_ms(), self.state.summary.incident_records),
            &incident,
        )
    }
}

/// Stable live-secondary view used by one inspection request.
pub struct AuditReader {
    store: Store,
}

impl AuditReader {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            store: Store::open_secondary(path, COLUMNS, SCHEMA)?,
        })
    }

    pub fn cursors(&self) -> Result<(BlockCursor, BlockCursor)> {
        let state: AuditState = self
            .store
            .get_default(STATE_KEY)?
            .context("audit state missing")?;
        Ok((state.source_cursor, state.target_cursor))
    }

    pub fn by_hash(&self, hash: B256) -> Result<Vec<(OccurrenceId, Expectation)>> {
        self.store
            .raw_prefix(INDEXES, &hash_prefix(TX_TAG, hash))?
            .into_iter()
            .map(|(key, _)| {
                let id =
                    OccurrenceId::decode(key.get(33..).context("invalid audit transaction index")?)
                        .context("invalid audit occurrence index")?;
                let expectation = self
                    .store
                    .get(OCCURRENCES, &id.key())?
                    .context("indexed audit occurrence missing")?;
                Ok((id, expectation))
            })
            .collect()
    }

    pub fn occurrence(&self, id: OccurrenceId) -> Result<Option<Expectation>> {
        self.store.get(OCCURRENCES, &id.key())
    }

    pub fn incidents(&self, from_ms: u64, to_ms: u64) -> Result<Vec<Incident>> {
        self.store
            .raw_range(
                INCIDENTS,
                &incident_key(from_ms, 0),
                &incident_key(to_ms, u64::MAX),
                100_000,
            )?
            .into_iter()
            .map(|(_, value)| decode(&value))
            .collect()
    }
}

pub(super) fn apply_observation(expectation: &mut Expectation, observation: &TargetObservation) {
    let source = &expectation.source_receipt;
    let target = &observation.receipt;
    let drift = ReceiptDrift {
        status: source.status != target.status,
        gas: source.gas_used != target.gas_used,
        logs: source.logs_hash != target.logs_hash,
    };
    expectation.finding = if drift.any() {
        Finding::ExecutionDrift(ExecutionDriftFinding {
            target: observation.location,
            drift,
        })
    } else {
        Finding::Included(observation.location)
    };
}

fn hash_prefix(tag: u8, hash: B256) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = tag;
    key[1..].copy_from_slice(hash.as_slice());
    key
}

fn tx_key(hash: B256, id: OccurrenceId) -> [u8; 45] {
    let indexed = tx_index_key(hash, id);
    let mut key = [0u8; 45];
    key[0] = TX_TAG;
    key[1..].copy_from_slice(&indexed);
    key
}

fn pending_key(id: OccurrenceId) -> [u8; 13] {
    let mut key = [0u8; 13];
    key[0] = PENDING_TAG;
    key[1..].copy_from_slice(&id.key());
    key
}

fn included_key(target_height: u64, id: OccurrenceId) -> [u8; 21] {
    let mut key = [0u8; 21];
    key[0] = INCLUDED_TAG;
    key[1..9].copy_from_slice(&target_height.to_be_bytes());
    key[9..].copy_from_slice(&id.key());
    key
}

fn decode_included_key(key: &[u8]) -> Result<(u64, OccurrenceId)> {
    ensure!(
        key.len() == 21 && key[0] == INCLUDED_TAG,
        "invalid included index key"
    );
    let height = u64::from_be_bytes(key[1..9].try_into()?);
    let id = OccurrenceId::decode(&key[9..]).context("invalid included occurrence")?;
    Ok((height, id))
}

fn target_key(observation: &TargetObservation) -> Vec<u8> {
    let mut key = Vec::with_capacity(45);
    key.extend_from_slice(&hash_prefix(TARGET_TAG, observation.transaction_hash));
    key.extend_from_slice(&observation.location.block.height.to_be_bytes());
    key.extend_from_slice(&observation.location.index.to_be_bytes());
    key
}

fn incident_key(timestamp: u64, sequence: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&timestamp.to_be_bytes());
    key[8..].copy_from_slice(&sequence.to_be_bytes());
    key
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

    fn expectation(hash: B256) -> Expectation {
        Expectation {
            source_block_hash: B256::repeat_byte(3),
            source_timestamp_ms: 1,
            observed_at_ms: 1,
            target_height_when_observed: 9,
            transaction_hash: hash,
            transaction_type: 2,
            sender: Address::repeat_byte(4),
            nonce_key: U256::ZERO,
            expiring: false,
            source_receipt: ReceiptSummary {
                status: true,
                gas_used: 21_000,
                logs_hash: B256::ZERO,
            },
            finding: Finding::MissingWithinWindow,
        }
    }

    #[test]
    fn binary_fixtures() {
        let expected = expectation(B256::repeat_byte(5));
        assert_eq!(
            alloy::primitives::keccak256(crate::store::encode(&expected).unwrap()),
            alloy::primitives::b256!(
                "b260e573be3fe25c693c24ffabd80730911e3d2c9d1ebb0d26180d5b719c160b"
            )
        );
        let incident = Incident::FinalityStall(FailureEvidence {
            level: EvidenceLevel::Observed,
            rpc_code: Some(-32000),
            message: "stalled".into(),
            first_observed_ms: 1,
            last_observed_ms: 2,
        });
        assert_eq!(
            alloy::primitives::keccak256(crate::store::encode(&incident).unwrap()),
            alloy::primitives::b256!(
                "fed4a0ae5582dd0d7c2682605510b62d93927eb6b2efcfd5d098cc3435e691a5"
            )
        );
    }

    #[test]
    fn audit_store_binds_identity_and_persists_cursors() {
        let directory = tempfile::tempdir().unwrap();
        let store = AuditStore::open(directory.path(), identity(), u64::MAX, 0).unwrap();
        assert_eq!(store.source_cursor().height, 10);
        drop(store);
        assert_eq!(
            AuditStore::open(directory.path(), identity(), u64::MAX, 0)
                .unwrap()
                .target_cursor()
                .height,
            10
        );
    }

    #[test]
    fn missing_occurrence_can_later_be_correlated_and_pruned() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = AuditStore::open(directory.path(), identity(), u64::MAX, 0).unwrap();
        let id = OccurrenceId {
            source_height: 11,
            source_index: 0,
        };
        let hash = B256::repeat_byte(5);
        store
            .observe_source(
                BlockCursor {
                    height: 11,
                    hash: B256::repeat_byte(3),
                },
                vec![(id, expectation(hash))],
            )
            .unwrap();
        store.refresh_missing(1, Duration::ZERO).unwrap();
        assert_eq!(store.summary().missing_after_window, 1);
        store
            .observe_target(
                BlockCursor {
                    height: 11,
                    hash: B256::repeat_byte(6),
                },
                vec![TargetObservation {
                    transaction_hash: hash,
                    location: TxLocation {
                        index: 0,
                        block: BlockCursor {
                            height: 11,
                            hash: B256::repeat_byte(6),
                        },
                    },
                    receipt: ReceiptSummary {
                        status: true,
                        gas_used: 21_000,
                        logs_hash: B256::ZERO,
                    },
                }],
                0,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(store.summary().missing_after_window, 0);
        assert_eq!(store.summary().included, 1);
        assert_eq!(
            AuditReader::open(directory.path())
                .unwrap()
                .by_hash(hash)
                .unwrap()
                .len(),
            1
        );
        store
            .observe_target(
                BlockCursor {
                    height: 12,
                    hash: B256::repeat_byte(7),
                },
                Vec::new(),
                0,
                Vec::new(),
            )
            .unwrap();
        store
            .observe_target(
                BlockCursor {
                    height: 13,
                    hash: B256::repeat_byte(8),
                },
                Vec::new(),
                0,
                Vec::new(),
            )
            .unwrap();
        store.prune_included(1).unwrap();
        assert!(
            store
                .store
                .get::<Expectation>(OCCURRENCES, &id.key())
                .unwrap()
                .is_none()
        );
        assert_eq!(store.summary().archived_included, 1);
    }

    #[test]
    fn finality_stall_is_recorded_once_and_resolved_by_progress() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = AuditStore::open(directory.path(), identity(), u64::MAX, 0).unwrap();
        store.state.last_target_progress_ms = 0;
        store.check_stall(Duration::from_millis(1)).unwrap();
        store.check_stall(Duration::from_millis(1)).unwrap();
        assert!(store.state.stall_open);
        assert_eq!(store.summary().consensus_incidents, 1);
        drop(store);
        let mut store = AuditStore::open(directory.path(), identity(), u64::MAX, 0).unwrap();
        assert!(store.state.stall_open);
        store
            .observe_target(
                BlockCursor {
                    height: 11,
                    hash: B256::repeat_byte(6),
                },
                Vec::new(),
                0,
                Vec::new(),
            )
            .unwrap();
        assert!(!store.state.stall_open);
    }

    #[test]
    fn target_observation_can_precede_source_expectation() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = AuditStore::open(directory.path(), identity(), u64::MAX, 0).unwrap();
        let id = OccurrenceId {
            source_height: 11,
            source_index: 0,
        };
        let hash = B256::repeat_byte(5);
        let target = BlockCursor {
            height: 11,
            hash: B256::repeat_byte(6),
        };
        store
            .observe_target(
                target,
                vec![TargetObservation {
                    transaction_hash: hash,
                    location: TxLocation {
                        index: 0,
                        block: target,
                    },
                    receipt: expectation(hash).source_receipt,
                }],
                0,
                Vec::new(),
            )
            .unwrap();
        store
            .observe_source(
                BlockCursor {
                    height: 11,
                    hash: B256::repeat_byte(3),
                },
                vec![(id, expectation(hash))],
            )
            .unwrap();
        assert!(matches!(
            store.store.get::<Expectation>(OCCURRENCES, &id.key()).unwrap().unwrap().finding,
            Finding::Included(location) if location.block == target
        ));
    }

    #[test]
    fn included_keys_sort_by_target_height() {
        let id = OccurrenceId {
            source_height: 4,
            source_index: 2,
        };
        assert!(included_key(10, id) < included_key(11, id));
        assert_eq!(
            decode_included_key(&included_key(10, id)).unwrap(),
            (10, id)
        );
    }
}
