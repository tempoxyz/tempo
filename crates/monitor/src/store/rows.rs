//! Durable row types for the monitor store.
//!
//! Rows use monitor-owned domain types plus canonical Alloy/Tempo primitives.
//! They must not embed Reth provider, notification, or table types.

use crate::{
    facts::{BlockNumHash, BlockWithParent},
    findings::{FindingKey, FindingStatus, FindingTransition, OutboxEventKind},
};
use serde::{Deserialize, Serialize};

/// Singleton row recording the last fully committed finalized block.
///
/// This row is advanced only by an atomic block commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorHeadRecord {
    pub head: BlockNumHash,
}

/// Durable finalized block identity and metadata used for continuity checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedBlockRecord {
    pub reference: BlockWithParent,
    pub timestamp: u64,
    pub hardfork: tempo_hardfork::TempoHardfork,
}

/// Current durable lifecycle state for a finding key.
///
/// The row is updated in the same commit as the check result that caused the
/// transition, so report delivery can be retried without re-emitting findings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingState {
    pub key: FindingKey,
    pub status: FindingStatus,
    pub last_transition: FindingTransition,
    pub last_seen: BlockNumHash,
}

/// Delivery state for a report outbox row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Pending,
    Delivered(DeliveryRecord),
}

/// Durable acknowledgement from a report sink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub delivered_at_unix_ms: u64,
    pub sink: String,
    pub receipt: String,
}

/// Report event enqueued atomically with its finding transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEvent {
    pub finding_key: FindingKey,
    pub kind: OutboxEventKind,
    pub payload: serde_json::Value,
}

/// Durable report delivery queue row.
///
/// Delivery happens after `commit_block`; enqueueing this row, not successful
/// delivery, is the proof-path requirement for finishing a height.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxRow {
    pub sequence: u64,
    pub block: BlockNumHash,
    pub event: OutboxEvent,
    pub delivery: DeliveryStatus,
    pub attempts: u32,
}
