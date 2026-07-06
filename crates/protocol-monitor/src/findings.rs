//! Durable evidence and finding domain types.

use serde::{Deserialize, Serialize};

use crate::{
    coverage::CoverageRecord,
    entity::EntityKey,
    evidence::{EvidenceRef, EvidenceValue},
    facts::{BlockNumHash, BlockWithParent},
    invariants::meta::{InvariantId, Severity},
    state_view::StateReadKey,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedValue {
    pub label: String,
    pub value: EvidenceValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedValue {
    pub label: String,
    pub condition: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceItem {
    StateRead(StateReadKey),
    ChainRef(EvidenceRef),
    Note(String),
    Value(EvidenceValue),
    Json(serde_json::Value),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationEvidence {
    pub invariant_id: InvariantId,
    pub block: BlockWithParent,
    pub entity: Option<EntityKey>,
    pub expected: ExpectedValue,
    pub observed: Vec<ObservedValue>,
    pub items: Vec<EvidenceItem>,
    pub coverage: CoverageRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingKey {
    pub invariant_id: InvariantId,
    pub entity: Option<EntityKey>,
    pub first_seen: BlockNumHash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    Open,
    Acknowledged,
    Resolved,
    Suppressed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingTransition {
    pub key: FindingKey,
    pub from: Option<FindingStatus>,
    pub to: FindingStatus,
    pub at: BlockNumHash,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitorHealthSignal {
    Healthy,
    CoverageDegraded {
        invariant_id: InvariantId,
        detail: String,
    },
    StoreLag {
        finalized: u64,
        persisted: u64,
    },
    CheckError {
        invariant_id: InvariantId,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboxEventKind {
    FindingOpened { severity: Severity },
    FindingUpdated,
    FindingResolved,
    HealthSignal,
    CoverageGap,
}
