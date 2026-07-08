//! In-memory implementation of the monitor store contract.
//!
//! This backend is intended for unit tests and processor integration tests. It
//! still enforces the store atomicity, continuity, and idempotency rules so
//! tests exercise the same proof-path contract as a durable backend.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};

use crate::{
    diagnostics::{
        coverage::{CheckResult, CoverageRecord},
        findings::FindingKey,
    },
    entity::DirtyEntity,
    input::facts::{BlockFacts, BlockNumHash, OrderedLog, ReceiptFacts, TxFacts},
    store::{
        AggregateUpdate, BlockCommit, BootstrapPolicy, DeliveryRecord, DeliveryStatus,
        FinalizedBlockRecord, FindingState, HistoryUpdate, KeysetUpdate, MonitorHealthUpdate,
        MonitorStore, OutboxRow, Result, SCHEMA_VERSION_V0, SchemaStatus, SchemaVersion,
        StateCacheUpdate, StoreError, schema_v0_tables, validation,
    },
};

/// Test backend for [`MonitorStore`](super::MonitorStore).
#[derive(Debug)]
pub struct InMemoryMonitorStore {
    bootstrap_policy: BootstrapPolicy,
    inner: Mutex<Inner>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Inner {
    pub head: Option<BlockNumHash>,
    pub finalized_blocks: BTreeMap<u64, FinalizedBlockRecord>,
    pub block_facts: HashMap<BlockNumHash, BlockFacts>,
    pub tx_facts: Vec<TxFacts>,
    pub receipt_facts: Vec<ReceiptFacts>,
    pub ordered_logs: Vec<OrderedLog>,
    pub dirty_entities: Vec<DirtyEntity>,
    pub state_cache_updates: Vec<StateCacheUpdate>,
    pub keyset_updates: Vec<KeysetUpdate>,
    pub aggregate_updates: Vec<AggregateUpdate>,
    pub history_updates: Vec<HistoryUpdate>,
    pub check_results: Vec<CheckResult>,
    pub coverage_records: Vec<CoverageRecord>,
    pub health_updates: Vec<MonitorHealthUpdate>,
    pub finding_state: HashMap<FindingKey, FindingState>,
    pub outbox: BTreeMap<u64, OutboxRow>,
    pub committed_blocks: HashMap<BlockNumHash, BlockCommit>,
    pub next_outbox_sequence: u64,
}

impl Default for InMemoryMonitorStore {
    fn default() -> Self {
        Self::with_bootstrap_policy(BootstrapPolicy::GenesisOnly)
    }
}

impl InMemoryMonitorStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_bootstrap_policy(bootstrap_policy: BootstrapPolicy) -> Self {
        Self {
            bootstrap_policy,
            inner: Mutex::new(Inner {
                next_outbox_sequence: 1,
                ..Default::default()
            }),
        }
    }

    #[cfg(test)]
    pub(super) fn snapshot(&self) -> Inner {
        self.inner.lock().expect("test store mutex").clone()
    }
}

impl MonitorStore for InMemoryMonitorStore {
    fn schema_status(&self) -> Result<SchemaStatus> {
        Ok(SchemaStatus::Ready {
            version: SchemaVersion(SCHEMA_VERSION_V0),
            tables: schema_v0_tables(),
        })
    }

    fn monitor_head(&self) -> Result<Option<BlockNumHash>> {
        Ok(self.inner.lock().map_err(|_| StoreError::Poisoned)?.head)
    }

    fn commit_block(&self, commit: BlockCommit) -> Result<()> {
        validation::validate_commit(&commit)?;
        let mut inner = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        if let Some(existing_commit) = inner.committed_blocks.get(&commit.new_monitor_head) {
            if existing_commit == &commit
                && inner
                    .head
                    .is_some_and(|h| h.number >= commit.new_monitor_head.number)
            {
                return Ok(());
            }
            return Err(StoreError::IdempotencyMismatch(
                "already committed block differs from reconstructed commit".into(),
            ));
        }
        if inner
            .finalized_blocks
            .contains_key(&commit.new_monitor_head.number)
        {
            return Err(StoreError::Continuity(
                "block number already committed with different hash".into(),
            ));
        }
        validation::validate_outbox_references(&commit, |key| {
            Ok(inner.finding_state.contains_key(key))
        })?;
        if let Some(prev) = inner.head {
            if commit.new_monitor_head.number != prev.number + 1 {
                return Err(StoreError::Continuity(
                    "commit is not contiguous with monitor_head".into(),
                ));
            }
            if commit.finalized_block.reference.parent != prev.hash {
                return Err(StoreError::Continuity(
                    "commit parent hash does not match monitor_head".into(),
                ));
            }
        } else {
            validation::validate_bootstrap(self.bootstrap_policy, &commit)?;
        }

        inner.finalized_blocks.insert(
            commit.new_monitor_head.number,
            commit.finalized_block.clone(),
        );
        inner
            .block_facts
            .insert(commit.new_monitor_head, commit.block_facts.clone());
        inner.tx_facts.extend(commit.tx_facts.clone());
        inner.receipt_facts.extend(commit.receipt_facts.clone());
        inner.ordered_logs.extend(commit.ordered_logs.clone());
        inner.dirty_entities.extend(commit.dirty_entities.clone());
        inner
            .state_cache_updates
            .extend(commit.state_cache_updates.clone());
        inner.keyset_updates.extend(commit.keyset_updates.clone());
        inner
            .aggregate_updates
            .extend(commit.aggregate_updates.clone());
        inner.history_updates.extend(commit.history_updates.clone());
        inner.check_results.extend(commit.check_results.clone());
        inner
            .coverage_records
            .extend(commit.coverage_records.clone());
        inner.health_updates.extend(commit.health_updates.clone());
        for transition in &commit.finding_updates {
            inner.finding_state.insert(
                transition.key.clone(),
                FindingState {
                    key: transition.key.clone(),
                    status: transition.to.clone(),
                    last_transition: transition.clone(),
                    last_seen: transition.at,
                },
            );
        }
        for event in &commit.outbox_events {
            let sequence = inner.next_outbox_sequence;
            inner.next_outbox_sequence += 1;
            inner.outbox.insert(
                sequence,
                OutboxRow {
                    sequence,
                    block: commit.new_monitor_head,
                    event: event.clone(),
                    delivery: DeliveryStatus::Pending,
                    attempts: 0,
                },
            );
        }
        inner
            .committed_blocks
            .insert(commit.new_monitor_head, commit.clone());
        inner.head = Some(commit.new_monitor_head);
        Ok(())
    }

    fn finalized_block(&self, number: u64) -> Result<Option<FinalizedBlockRecord>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| StoreError::Poisoned)?
            .finalized_blocks
            .get(&number)
            .cloned())
    }

    fn finding_state(&self, key: &FindingKey) -> Result<Option<FindingState>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| StoreError::Poisoned)?
            .finding_state
            .get(key)
            .cloned())
    }

    fn pending_outbox(&self, limit: usize) -> Result<Vec<OutboxRow>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| StoreError::Poisoned)?
            .outbox
            .values()
            .filter(|r| matches!(r.delivery, DeliveryStatus::Pending))
            .take(limit)
            .cloned()
            .collect())
    }

    fn mark_outbox_delivered(&self, sequence: u64, delivery: DeliveryRecord) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        let row = inner
            .outbox
            .get_mut(&sequence)
            .ok_or_else(|| StoreError::NotFound(format!("outbox sequence {sequence}")))?;
        row.delivery = DeliveryStatus::Delivered(delivery);
        Ok(())
    }
}
