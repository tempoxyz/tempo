//! In-memory implementation of the monitor store contract.
//!
//! This backend is intended for unit tests and processor integration tests. It
//! still enforces the store atomicity, continuity, and idempotency rules so
//! tests exercise the same proof-path contract as a durable backend.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Mutex,
};

use crate::{
    coverage::{CheckResult, CoverageRecord},
    entity::DirtyEntity,
    facts::{BlockFacts, BlockNumHash, OrderedLog, ReceiptFacts, TxFacts},
    findings::{FindingKey, MonitorHealthSignal},
    invariants::meta::initial_catalog,
};

use super::{
    AggregateUpdate, BlockCommit, BootstrapPolicy, DeliveryRecord, DeliveryStatus,
    FinalizedBlockRecord, FindingState, HistoryUpdate, KeysetUpdate, MonitorHealthUpdate,
    MonitorStore, OutboxRow, Result, SCHEMA_VERSION_V0, SchemaStatus, SchemaVersion,
    StateCacheUpdate, StoreError, schema_v0_tables,
};

/// Test backend for [`MonitorStore`](super::MonitorStore).
#[derive(Debug)]
pub struct InMemoryMonitorStore {
    bootstrap_policy: BootstrapPolicy,
    inner: Mutex<Inner>,
}

#[derive(Clone, Debug)]
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
                head: None,
                finalized_blocks: BTreeMap::new(),
                block_facts: HashMap::new(),
                tx_facts: Vec::new(),
                receipt_facts: Vec::new(),
                ordered_logs: Vec::new(),
                dirty_entities: Vec::new(),
                state_cache_updates: Vec::new(),
                keyset_updates: Vec::new(),
                aggregate_updates: Vec::new(),
                history_updates: Vec::new(),
                check_results: Vec::new(),
                coverage_records: Vec::new(),
                health_updates: Vec::new(),
                finding_state: HashMap::new(),
                outbox: BTreeMap::new(),
                committed_blocks: HashMap::new(),
                next_outbox_sequence: 1,
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
        validate_commit(&commit)?;
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
        validate_outbox_references(&inner, &commit)?;
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
            validate_bootstrap(self.bootstrap_policy, &commit)?;
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

fn validate_bootstrap(policy: BootstrapPolicy, commit: &BlockCommit) -> Result<()> {
    match policy {
        BootstrapPolicy::AnyFirstFinalizedBlock => Ok(()),
        BootstrapPolicy::GenesisOnly if commit.new_monitor_head.number == 0 => Ok(()),
        BootstrapPolicy::GenesisOnly => Err(StoreError::Continuity(
            "bootstrap policy requires first commit to be genesis".into(),
        )),
        BootstrapPolicy::StartAt(start) if commit.new_monitor_head == start => Ok(()),
        BootstrapPolicy::StartAt(start) => Err(StoreError::Continuity(format!(
            "bootstrap policy requires first commit to be {start:?}"
        ))),
    }
}

fn validate_commit(commit: &BlockCommit) -> Result<()> {
    let block = commit.new_monitor_head;
    if commit.finalized_block.reference != commit.block_facts.reference
        || commit.finalized_block.reference.block != block
    {
        return Err(StoreError::InvalidCommit(
            "finalized block, block facts, and new head disagree".into(),
        ));
    }
    for tx in &commit.tx_facts {
        if tx.block != block {
            return Err(StoreError::InvalidCommit(
                "tx fact references another block".into(),
            ));
        }
    }
    for receipt in &commit.receipt_facts {
        if receipt.block != block {
            return Err(StoreError::InvalidCommit(
                "receipt fact references another block".into(),
            ));
        }
    }
    for log in &commit.ordered_logs {
        if log.block != block {
            return Err(StoreError::InvalidCommit(
                "ordered log references another block".into(),
            ));
        }
    }
    let mut result_keys = HashSet::new();
    for result in &commit.check_results {
        if result.block != block || result.coverage.block != block {
            return Err(StoreError::InvalidCommit(
                "check result references another block".into(),
            ));
        }
        if result.coverage.invariant_id != result.invariant_id
            || result.coverage.entity != result.entity
        {
            return Err(StoreError::InvalidCommit(
                "check result coverage key disagrees with result key".into(),
            ));
        }
        if !result_keys.insert((
            result.block,
            result.invariant_id.clone(),
            result.entity.clone(),
        )) {
            return Err(StoreError::InvalidCommit(
                "duplicate check result for block/invariant/entity".into(),
            ));
        }
    }
    let mut coverage_keys = HashSet::new();
    for coverage in &commit.coverage_records {
        if coverage.block != block {
            return Err(StoreError::InvalidCommit(
                "coverage record references another block".into(),
            ));
        }
        if !coverage_keys.insert((
            coverage.block,
            coverage.invariant_id.clone(),
            coverage.entity.clone(),
        )) {
            return Err(StoreError::InvalidCommit(
                "duplicate coverage record for block/invariant/entity".into(),
            ));
        }
    }
    for transition in &commit.finding_updates {
        if transition.at != block {
            return Err(StoreError::InvalidCommit(
                "finding transition references another block".into(),
            ));
        }
    }
    for health in &commit.health_updates {
        if health.at != block {
            return Err(StoreError::InvalidCommit(
                "health update references another block".into(),
            ));
        }
    }

    let catalog = initial_catalog();
    for id in commit
        .check_results
        .iter()
        .map(|r| &r.invariant_id)
        .chain(commit.coverage_records.iter().map(|r| &r.invariant_id))
        .chain(commit.finding_updates.iter().map(|r| &r.key.invariant_id))
        .chain(
            commit
                .outbox_events
                .iter()
                .map(|r| &r.finding_key.invariant_id),
        )
        .chain(commit.health_updates.iter().filter_map(health_invariant_id))
    {
        if catalog.get(id).is_none() {
            return Err(StoreError::UnknownInvariant(id.clone()));
        }
    }
    Ok(())
}

fn validate_outbox_references(inner: &Inner, commit: &BlockCommit) -> Result<()> {
    let transition_keys = commit
        .finding_updates
        .iter()
        .map(|transition| &transition.key)
        .collect::<HashSet<_>>();

    for event in &commit.outbox_events {
        if !transition_keys.contains(&event.finding_key)
            && !inner.finding_state.contains_key(&event.finding_key)
        {
            return Err(StoreError::InvalidCommit(
                "outbox event references unknown finding".into(),
            ));
        }
    }
    Ok(())
}

fn health_invariant_id(
    update: &MonitorHealthUpdate,
) -> Option<&crate::invariants::meta::InvariantId> {
    match &update.signal {
        MonitorHealthSignal::CoverageDegraded { invariant_id, .. }
        | MonitorHealthSignal::CheckError { invariant_id, .. } => Some(invariant_id),
        MonitorHealthSignal::Healthy | MonitorHealthSignal::StoreLag { .. } => None,
    }
}
