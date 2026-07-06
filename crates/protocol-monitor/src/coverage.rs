//! Coverage and check outcome types.

use serde::{Deserialize, Serialize};

use crate::{
    entity::EntityKey,
    facts::BlockNumHash,
    findings::ViolationEvidence,
    invariants::meta::{InvariantId, Severity},
};

/// Overall coverage classification for an invariant result.
///
/// Only `Complete` coverage may produce a `CheckOutcome::Pass`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageStatus {
    Complete,
    Partial,
    Inconclusive,
    Degraded,
    NotNeeded,
}

impl CoverageStatus {
    pub const fn allows_pass(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageReason {
    CompleteInput,
    SelectedCandidatesOnly,
    MissingRequiredInput(String),
    TaintedTable(String),
    IncompleteKeyset(String),
    ReplayUnavailable,
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageGap {
    pub status: CoverageStatus,
    pub reason: CoverageReason,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRecord {
    pub invariant_id: InvariantId,
    pub block: BlockNumHash,
    pub entity: Option<EntityKey>,
    pub status: CoverageStatus,
    pub reasons: Vec<CoverageReason>,
}

/// A coverage-checked pass. Constructed only from complete coverage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteCoverage(pub CoverageRecord);

impl TryFrom<CoverageRecord> for CompleteCoverage {
    type Error = CoverageGap;

    fn try_from(record: CoverageRecord) -> Result<Self, Self::Error> {
        if record.status.allows_pass() {
            Ok(Self(record))
        } else {
            Err(CoverageGap {
                status: record.status,
                reason: record.reasons.into_iter().next().unwrap_or_else(|| {
                    CoverageReason::MissingRequiredInput("pass requires complete coverage".into())
                }),
                detail: "check pass requires complete coverage".into(),
            })
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckError {
    pub message: String,
    pub retryable: bool,
}

/// Coverage-aware check outcome.
///
/// Passing outcomes are only constructible from `CompleteCoverage`; degraded,
/// partial, inconclusive, or missing input must be represented explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckOutcome {
    Pass(CompleteCoverage),
    Violation(ViolationEvidence),
    Inconclusive(CoverageGap),
    Error(CheckError),
}

impl CheckOutcome {
    pub fn pass(coverage: CoverageRecord) -> Result<Self, CoverageGap> {
        CompleteCoverage::try_from(coverage).map(Self::Pass)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub invariant_id: InvariantId,
    pub block: BlockNumHash,
    pub entity: Option<EntityKey>,
    pub severity: Severity,
    pub coverage: CoverageRecord,
    pub outcome: CheckOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn degraded_coverage_cannot_construct_global_pass_helper() {
        let coverage = CoverageRecord {
            invariant_id: InvariantId::new("X"),
            block: BlockNumHash {
                number: 1,
                hash: B256::ZERO,
            },
            entity: None,
            status: CoverageStatus::Degraded,
            reasons: vec![CoverageReason::TaintedTable("tip20".into())],
        };
        assert!(CheckOutcome::pass(coverage).is_err());
    }

    #[test]
    fn not_needed_coverage_cannot_construct_pass() {
        let coverage = CoverageRecord {
            invariant_id: InvariantId::new("X"),
            block: BlockNumHash {
                number: 1,
                hash: B256::ZERO,
            },
            entity: None,
            status: CoverageStatus::NotNeeded,
            reasons: vec![CoverageReason::NotApplicable],
        };
        assert!(CheckOutcome::pass(coverage).is_err());
    }
}
