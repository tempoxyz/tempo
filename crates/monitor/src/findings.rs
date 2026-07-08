//! Durable finding lifecycle domain types.

use serde::{Deserialize, Serialize};

use crate::{
    entity::EntityKey,
    facts::BlockNumHash,
    invariants::meta::{InvariantId, Severity},
};

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
