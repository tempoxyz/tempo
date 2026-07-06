//! Atomic block commit model.
//!
//! A `BlockCommit` is the only object allowed to advance `monitor_head`. It
//! groups normalized facts, candidate selection, check output, coverage,
//! finding transitions, health updates, outbox events, and the new head into
//! one all-or-nothing store operation.

use serde::{Deserialize, Serialize};

use crate::{
    coverage::{CheckResult, CoverageRecord},
    entity::DirtyEntity,
    facts::{BlockFacts, BlockNumHash, OrderedLog, ReceiptFacts, TxFacts},
    findings::{FindingTransition, MonitorHealthSignal},
};

use super::{FinalizedBlockRecord, OutboxEvent};

/// Update to a feature state-cache table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateCacheUpdate {
    pub table: String,
    pub key: String,
    pub value: serde_json::Value,
}

/// Update to a feature keyset index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetUpdate {
    pub table: String,
    pub key: String,
}

/// Update to a feature aggregate table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateUpdate {
    pub table: String,
    pub key: String,
    pub value: serde_json::Value,
}

/// Update to a feature history table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryUpdate {
    pub table: String,
    pub key: String,
    pub value: serde_json::Value,
}

/// Durable monitor-health update emitted by block processing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorHealthUpdate {
    pub signal: MonitorHealthSignal,
    pub at: BlockNumHash,
}

/// All rows that must be committed atomically for one finalized block.
///
/// Every block-scoped row must reference `new_monitor_head`. On success the
/// store has durably finished the height; on failure no row or head update may
/// be partially visible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockCommit {
    pub finalized_block: FinalizedBlockRecord,
    pub block_facts: BlockFacts,
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
    pub finding_updates: Vec<FindingTransition>,
    pub health_updates: Vec<MonitorHealthUpdate>,
    pub outbox_events: Vec<OutboxEvent>,
    pub new_monitor_head: BlockNumHash,
}
