//! Durable finding lifecycle domain types.

use serde::{Deserialize, Serialize};

use crate::{
    entity::EntityKey,
    input::facts::BlockNumHash,
    invariants::meta::{InvariantId, Severity},
};

/// Durable identity for a monitor finding.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingKey {
    pub invariant_id: InvariantId,
    pub entity: Option<EntityKey>,
    pub first_seen: BlockNumHash,
}

/// Durable lifecycle status for a finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    /// Finding is active and unresolved.
    Open,
    /// Operator acknowledged the finding.
    Acknowledged,
    /// Finding condition is no longer present.
    Resolved,
    /// Finding is intentionally hidden from normal reporting.
    Suppressed,
}

/// Durable lifecycle transition for a finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingTransition {
    pub key: FindingKey,
    pub from: Option<FindingStatus>,
    pub to: FindingStatus,
    pub at: BlockNumHash,
    pub reason: String,
}

/// Durable health signal emitted by monitor processing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitorHealthSignal {
    /// Monitor did not observe a degraded condition.
    Healthy,
    /// A check could not prove complete coverage.
    CoverageDegraded {
        /// Invariant affected by the coverage gap.
        invariant_id: InvariantId,
        /// Human-readable detail.
        detail: String,
    },
    /// Store progress is behind finalized chain progress.
    StoreLag {
        /// Finalized height observed by the adapter.
        finalized: u64,
        /// Height durably persisted by the monitor.
        persisted: u64,
    },
    /// A check failed internally.
    CheckError {
        /// Invariant whose check failed.
        invariant_id: InvariantId,
        /// Error message.
        message: String,
    },
}

/// Durable outbox event category.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboxEventKind {
    /// A finding was opened.
    FindingOpened {
        /// Severity of the opened finding.
        severity: Severity,
    },
    /// A finding was updated.
    FindingUpdated,
    /// A finding was resolved.
    FindingResolved,
    /// A monitor health signal should be reported.
    HealthSignal,
    /// A coverage gap should be reported.
    CoverageGap,
}
