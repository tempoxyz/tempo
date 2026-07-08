//! Report payload schemas and report sinks.
//!
//! Store-backed reporting policy currently lives in [`crate::store`], where it
//! builds durable commit rows atomically with finalized block processing.

use crate::{
    diagnostics::{
        coverage::{CheckOutcome, CheckResult, CoverageGap, CoverageRecord},
        evidence::{EvidenceItem, ExpectedValue, ObservedValue},
        findings::{
            FindingKey, FindingStatus, FindingTransition, MonitorHealthSignal, OutboxEventKind,
        },
    },
    entity::EntityKey,
    invariants::meta::{InvariantId, Severity},
    processor::FinalizedBlockInput,
    store::{MonitorHealthUpdate, OutboxEvent},
};

pub const FINDING_REPORT_SCHEMA_V1: &str = "tempo.monitor.finding.v1";
pub const COVERAGE_GAP_REPORT_SCHEMA_V1: &str = "tempo.monitor.coverage_gap.v1";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReportBundle {
    pub finding_updates: Vec<FindingTransition>,
    pub health_updates: Vec<MonitorHealthUpdate>,
    pub outbox_events: Vec<OutboxEvent>,
}

#[derive(Clone, Debug, Default)]
pub struct ReportingPolicy;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    #[error("failed to serialize report payload: {0}")]
    Serialize(String),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FindingReportV1 {
    pub schema: String,
    pub summary: String,
    pub invariant_id: InvariantId,
    pub severity: Severity,
    pub finding_key: FindingKey,
    pub status: FindingStatus,
    pub transition: FindingTransition,
    pub block: crate::input::facts::BlockWithParent,
    pub entity: Option<EntityKey>,
    pub expected: ExpectedValue,
    pub observed: Vec<ObservedValue>,
    pub evidence: Vec<EvidenceItem>,
    pub coverage: CoverageRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoverageGapReportV1 {
    pub schema: String,
    pub summary: String,
    pub invariant_id: InvariantId,
    pub severity: Severity,
    pub block: crate::input::facts::BlockWithParent,
    pub entity: Option<EntityKey>,
    pub coverage: CoverageRecord,
    pub gap: CoverageGap,
}

impl ReportingPolicy {
    pub fn build_reports(
        &self,
        input: &FinalizedBlockInput,
        check_results: &[CheckResult],
    ) -> Result<ReportBundle, ReportError> {
        let mut bundle = ReportBundle::default();
        for result in check_results {
            match &result.outcome {
                CheckOutcome::Violation(evidence) => {
                    let key = FindingKey {
                        invariant_id: result.invariant_id.clone(),
                        entity: result.entity.clone(),
                        first_seen: result.block,
                    };
                    let transition = FindingTransition {
                        key: key.clone(),
                        from: None,
                        to: FindingStatus::Open,
                        at: result.block,
                        reason: violation_summary(&result.invariant_id, result.block.number),
                    };
                    let payload = FindingReportV1 {
                        schema: FINDING_REPORT_SCHEMA_V1.into(),
                        summary: transition.reason.clone(),
                        invariant_id: result.invariant_id.clone(),
                        severity: result.severity,
                        finding_key: key.clone(),
                        status: FindingStatus::Open,
                        transition: transition.clone(),
                        block: evidence.block,
                        entity: evidence.entity.clone(),
                        expected: evidence.expected.clone(),
                        observed: evidence.observed.clone(),
                        evidence: evidence.items.clone(),
                        coverage: evidence.coverage.clone(),
                    };
                    bundle.finding_updates.push(transition);
                    bundle.outbox_events.push(OutboxEvent {
                        finding_key: key,
                        kind: OutboxEventKind::FindingOpened {
                            severity: result.severity,
                        },
                        payload: to_payload(payload)?,
                    });
                }
                CheckOutcome::Inconclusive(gap) => {
                    let key = FindingKey {
                        invariant_id: result.invariant_id.clone(),
                        entity: result.entity.clone(),
                        first_seen: result.block,
                    };
                    let summary = coverage_gap_summary(
                        &result.invariant_id,
                        result.block.number,
                        gap.detail.as_str(),
                    );
                    bundle.health_updates.push(MonitorHealthUpdate {
                        signal: MonitorHealthSignal::CoverageDegraded {
                            invariant_id: result.invariant_id.clone(),
                            detail: gap.detail.clone(),
                        },
                        at: result.block,
                    });
                    bundle.outbox_events.push(OutboxEvent {
                        finding_key: key,
                        kind: OutboxEventKind::CoverageGap,
                        payload: to_payload(CoverageGapReportV1 {
                            schema: COVERAGE_GAP_REPORT_SCHEMA_V1.into(),
                            summary,
                            invariant_id: result.invariant_id.clone(),
                            severity: result.severity,
                            block: input.reference,
                            entity: result.entity.clone(),
                            coverage: result.coverage.clone(),
                            gap: gap.clone(),
                        })?,
                    });
                }
                CheckOutcome::Error(err) => {
                    bundle.health_updates.push(MonitorHealthUpdate {
                        signal: MonitorHealthSignal::CheckError {
                            invariant_id: result.invariant_id.clone(),
                            message: err.message.clone(),
                        },
                        at: result.block,
                    });
                }
                CheckOutcome::Pass(_) => {}
            }
        }
        Ok(bundle)
    }
}

fn to_payload<T: serde::Serialize>(payload: T) -> Result<serde_json::Value, ReportError> {
    serde_json::to_value(payload).map_err(|err| ReportError::Serialize(err.to_string()))
}

fn violation_summary(invariant_id: &InvariantId, block_number: u64) -> String {
    format!("{} violated at block {block_number}", invariant_id.as_str())
}

fn coverage_gap_summary(invariant_id: &InvariantId, block_number: u64, detail: &str) -> String {
    format!(
        "{} inconclusive at block {block_number}: {detail}",
        invariant_id.as_str()
    )
}
