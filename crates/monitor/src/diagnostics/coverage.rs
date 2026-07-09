//! Coverage and check outcome types.

use serde::{Deserialize, Serialize};

use crate::{
    diagnostics::evidence::ViolationEvidence,
    entity::EntityKey,
    input::facts::BlockNumHash,
    invariants::meta::{InvariantId, Severity},
};

/// Overall coverage classification for an invariant result.
///
/// Only `Complete` coverage may produce a `CheckOutcome::Pass`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageStatus {
    /// All required inputs were available.
    Complete,
    /// Check ran over selected/incomplete inputs.
    Partial,
    /// Required inputs were missing, so no conclusion can be drawn.
    Inconclusive,
    /// Inputs or derived tables were degraded/tainted.
    Degraded,
    /// Check did not apply to this block/entity.
    NotNeeded,
}

impl CoverageStatus {
    /// Return true when this coverage status may produce a passing outcome.
    pub const fn allows_pass(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Reason for a coverage classification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageReason {
    /// All required inputs were complete.
    CompleteInput,
    /// Only selected candidates were evaluated.
    SelectedCandidatesOnly,
    /// A required input was missing.
    MissingRequiredInput(String),
    /// A derived table was marked tainted.
    TaintedTable(String),
    /// A keyset was incomplete.
    IncompleteKeyset(String),
    /// Replay data was unavailable.
    ReplayUnavailable,
    /// Check was not applicable.
    NotApplicable,
}

/// Explanation for a non-complete check coverage result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("coverage gap: {status:?}: {reason:?}: {detail}")]
pub struct CoverageGap {
    pub status: CoverageStatus,
    pub reason: CoverageReason,
    pub detail: String,
}

/// Durable coverage row for a check result.
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
pub struct CompleteCoverage(
    /// Coverage record proven complete.
    pub CoverageRecord,
);

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

/// Check execution error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckError {
    pub message: String,
    pub retryable: bool,
}

/// Coverage-aware check outcome.
///
/// Passing outcomes are only constructible from `CompleteCoverage`; degraded,
/// partial, inconclusive, or missing input must be represented explicitly.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckOutcome {
    /// Check passed with complete coverage.
    Pass(CompleteCoverage),
    /// Check found an invariant violation.
    Violation(ViolationEvidence),
    /// Check could not reach a conclusion due to coverage.
    Inconclusive(CoverageGap),
    /// Check failed internally.
    Error(CheckError),
}

impl CheckOutcome {
    /// Construct a passing outcome only if coverage is complete.
    pub fn pass(coverage: CoverageRecord) -> Result<Self, CoverageGap> {
        CompleteCoverage::try_from(coverage).map(Self::Pass)
    }
}

/// Durable result of evaluating one invariant for a block/entity.
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
    fn degraded_coverage_cannot_construct_global_pass_helper() -> eyre::Result<()> {
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
        Ok(())
    }

    #[test]
    fn not_needed_coverage_cannot_construct_pass() -> eyre::Result<()> {
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
        Ok(())
    }
}
