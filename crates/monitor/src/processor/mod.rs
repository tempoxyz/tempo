//! Finalized block processor and atomic commit construction.
//!
//! The processor builds monitor-owned block views, runs checks, computes
//! coverage/finding/report rows, and hands a single block commit to the store.

mod checks;
use checks::{CheckSummary, check_outcome_label, run_block_checks};

use crate::{
    facts::{BlockFacts, BlockNumHash, BlockWithParent, OrderedLog, ReceiptFacts, TxFacts},
    reports::{ReportError, ReportingPolicy},
    store::{BlockCommit, FinalizedBlockRecord, MonitorStore, StoreError},
};
use serde::{Deserialize, Serialize};

/// Monitor-owned finalized block input produced by adapters before store writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedBlockInput {
    pub reference: BlockWithParent,
    pub block_facts: BlockFacts,
    pub tx_facts: Vec<TxFacts>,
    pub receipt_facts: Vec<ReceiptFacts>,
    pub ordered_logs: Vec<OrderedLog>,
}

impl FinalizedBlockInput {
    pub fn block(&self) -> BlockNumHash {
        self.reference.block
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProcessorError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("store error: {0}")]
    Store(String),
}

impl From<StoreError> for ProcessorError {
    fn from(value: StoreError) -> Self {
        Self::Store(format!("{value:?}"))
    }
}

impl From<ReportError> for ProcessorError {
    fn from(value: ReportError) -> Self {
        Self::Store(format!("{value:?}"))
    }
}

/// Builds complete block commits from normalized finalized block input.
#[derive(Clone, Debug, Default)]
pub struct FinalizedBlockProcessor;

impl FinalizedBlockProcessor {
    pub fn build_commit(
        &self,
        input: FinalizedBlockInput,
        _prior_head: Option<BlockNumHash>,
    ) -> Result<BlockCommit, ProcessorError> {
        validate_input(&input)?;
        let block = input.block();
        let check_results = run_block_checks(&input);
        let coverage_records = check_results
            .iter()
            .map(|result| result.coverage.clone())
            .collect();
        let reports = ReportingPolicy.build_reports(&input, &check_results)?;

        Ok(BlockCommit {
            finalized_block: FinalizedBlockRecord {
                reference: input.reference,
                timestamp: input.block_facts.header.timestamp,
                hardfork: input.block_facts.hardfork,
            },
            block_facts: input.block_facts,
            tx_facts: input.tx_facts,
            receipt_facts: input.receipt_facts,
            ordered_logs: input.ordered_logs,
            dirty_entities: Vec::new(),
            state_cache_updates: Vec::new(),
            keyset_updates: Vec::new(),
            aggregate_updates: Vec::new(),
            history_updates: Vec::new(),
            check_results,
            coverage_records,
            finding_updates: reports.finding_updates,
            health_updates: reports.health_updates,
            outbox_events: reports.outbox_events,
            new_monitor_head: block,
        })
    }

    pub fn process_and_commit<S: MonitorStore>(
        &self,
        store: &S,
        input: FinalizedBlockInput,
    ) -> Result<BlockNumHash, ProcessorError> {
        let prior_head = store.monitor_head()?;
        let block = input.block();
        let commit = self.build_commit(input, prior_head)?;
        let check_summary = CheckSummary::from_results(&commit.check_results);
        let check_logs = commit
            .check_results
            .iter()
            .map(|result| {
                (
                    result.invariant_id.as_str().to_owned(),
                    result.entity.clone(),
                    result.severity,
                    result.coverage.status.clone(),
                    check_outcome_label(&result.outcome),
                )
            })
            .collect::<Vec<_>>();
        store.commit_block(commit)?;
        for (invariant_id, entity, severity, coverage_status, outcome) in check_logs {
            tracing::info!(
                block_number = block.number,
                block_hash = ?block.hash,
                invariant_id,
                entity = ?entity,
                severity = ?severity,
                coverage_status = ?coverage_status,
                outcome,
                "monitor check result"
            );
        }
        tracing::info!(
            block_number = block.number,
            block_hash = ?block.hash,
            checks_total = check_summary.total,
            checks_passed = check_summary.passed,
            checks_violated = check_summary.violations,
            checks_inconclusive = check_summary.inconclusive,
            checks_errored = check_summary.errors,
            "monitor block committed"
        );
        Ok(block)
    }
}

pub fn validate_input(input: &FinalizedBlockInput) -> Result<(), ProcessorError> {
    let block = input.block();
    if input.block_facts.reference != input.reference {
        return Err(ProcessorError::InvalidInput(
            "block facts reference does not match input reference".into(),
        ));
    }
    for tx in &input.tx_facts {
        if tx.block != block {
            return Err(ProcessorError::InvalidInput(
                "transaction fact references another block".into(),
            ));
        }
    }
    for receipt in &input.receipt_facts {
        if receipt.block != block {
            return Err(ProcessorError::InvalidInput(
                "receipt fact references another block".into(),
            ));
        }
    }
    for log in &input.ordered_logs {
        if log.block != block {
            return Err(ProcessorError::InvalidInput(
                "ordered log references another block".into(),
            ));
        }
    }
    if input.receipt_facts.len() != input.tx_facts.len() {
        return Err(ProcessorError::InvalidInput(
            "receipt count does not match transaction count".into(),
        ));
    }
    Ok(())
}

#[cfg(all(test, feature = "store"))]
mod tests {
    use super::*;
    use crate::{
        facts::{
            BlockFacts, BlockWithParent, FactValue, HeaderFacts, ReceiptFacts, TxEnvelopeFacts,
            TxFacts,
        },
        findings::{FindingStatus, OutboxEventKind},
        invariants::meta::{Severity, ids},
        reports::{COVERAGE_GAP_REPORT_SCHEMA_V1, FINDING_REPORT_SCHEMA_V1},
        store::{
            BootstrapPolicy, InMemoryMonitorStore, JsonlOutboxSink, MonitorStore, OutboxWorker,
            OutboxWorkerConfig,
        },
    };
    use alloy_primitives::{Address, B256, TxKind, U256};
    use std::num::NonZeroU64;
    use tempo_hardfork::TempoHardfork;
    use tempo_primitives::TempoTxType;

    fn b(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    fn input(
        header_gas_used: u64,
        gas_limit: u64,
        receipt_cumulative_gas: u64,
        missing_receipt_gas: bool,
    ) -> FinalizedBlockInput {
        let block = BlockNumHash {
            number: 1,
            hash: b(1),
        };
        let reference = BlockWithParent::new(b(0), block);
        let tx_hash = b(0x10);
        FinalizedBlockInput {
            reference,
            block_facts: BlockFacts {
                reference,
                hardfork: TempoHardfork::Genesis,
                header: HeaderFacts {
                    timestamp: 1,
                    timestamp_millis: 1000,
                    gas_used: header_gas_used,
                    gas_limit,
                    general_gas_limit: gas_limit,
                    shared_gas_limit: 0,
                    base_fee_per_gas: None,
                    beneficiary: Address::ZERO,
                    consensus_context: None,
                },
            },
            tx_facts: vec![TxFacts {
                block,
                tx_index: 0,
                tx_hash,
                is_system: false,
                envelope: TxEnvelopeFacts {
                    tx_type: TempoTxType::AA,
                    action: TxKind::Call(Address::ZERO),
                    gas_limit: 30_000,
                    nonce: 0,
                    value: U256::ZERO,
                    nonce_key: None,
                    valid_before: NonZeroU64::new(100),
                    valid_after: None,
                    fee_token: None,
                },
                sender: FactValue::Available(Address::ZERO),
                fee_payer: FactValue::Available(Address::ZERO),
                unique_intent: FactValue::Available(b(0x20)),
            }],
            receipt_facts: vec![ReceiptFacts {
                block,
                tx_hash,
                tx_index: 0,
                success: true,
                gas_used: if missing_receipt_gas {
                    FactValue::Missing {
                        reason: "test missing gas".into(),
                    }
                } else {
                    FactValue::Available(receipt_cumulative_gas)
                },
                cumulative_gas_used: receipt_cumulative_gas,
            }],
            ordered_logs: Vec::new(),
        }
    }

    #[test]
    fn violating_check_creates_typed_finding_report() -> eyre::Result<()> {
        let commit =
            FinalizedBlockProcessor.build_commit(input(20_999, 30_000, 21_000, false), None)?;
        assert_eq!(commit.finding_updates.len(), 1);
        assert_eq!(commit.outbox_events.len(), 1);
        let transition = &commit.finding_updates[0];
        assert_eq!(transition.to, FindingStatus::Open);
        assert_eq!(transition.key.first_seen, commit.new_monitor_head);
        let event = &commit.outbox_events[0];
        assert_eq!(event.finding_key, transition.key);
        assert!(matches!(
            event.kind,
            OutboxEventKind::FindingOpened {
                severity: Severity::Critical
            }
        ));
        assert_eq!(event.payload["schema"], FINDING_REPORT_SCHEMA_V1);
        assert_eq!(event.payload["invariant_id"], ids::BLOCK_TOTAL_GAS);
        assert_eq!(event.payload["severity"], "Critical");
        assert_eq!(
            event.payload["finding_key"],
            serde_json::to_value(&transition.key)?
        );
        assert_eq!(
            event.payload["block"],
            serde_json::to_value(commit.finalized_block.reference)?
        );
        assert_eq!(event.payload["expected"]["label"], "block total gas");
        assert_eq!(
            event.payload["observed"]
                .as_array()
                .expect("observed")
                .len(),
            3
        );
        assert_eq!(
            event.payload["evidence"]
                .as_array()
                .expect("evidence")
                .len(),
            2
        );
        assert_eq!(
            event.payload["coverage"],
            serde_json::to_value(&commit.coverage_records[0])?
        );
        assert_eq!(
            event.payload["summary"],
            "TEMPO-BLOCK-TOTAL-GAS violated at block 1"
        );
        Ok(())
    }

    #[test]
    fn inconclusive_check_creates_coverage_gap_report_and_health_update() -> eyre::Result<()> {
        let commit =
            FinalizedBlockProcessor.build_commit(input(21_000, 30_000, 21_000, true), None)?;
        assert!(commit.finding_updates.is_empty());
        assert_eq!(commit.health_updates.len(), 1);
        assert_eq!(commit.outbox_events.len(), 1);
        let event = &commit.outbox_events[0];
        assert!(matches!(event.kind, OutboxEventKind::CoverageGap));
        assert_eq!(event.payload["schema"], COVERAGE_GAP_REPORT_SCHEMA_V1);
        assert_eq!(event.payload["invariant_id"], ids::BLOCK_TOTAL_GAS);
        assert!(
            event.payload["gap"]["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("test missing gas"))
        );
        assert!(
            event.payload["summary"]
                .as_str()
                .is_some_and(|summary| summary.contains("inconclusive at block 1"))
        );
        Ok(())
    }

    #[test]
    fn passing_check_does_not_emit_reports() -> eyre::Result<()> {
        let commit =
            FinalizedBlockProcessor.build_commit(input(21_000, 30_000, 21_000, false), None)?;
        assert!(commit.finding_updates.is_empty());
        assert!(commit.health_updates.is_empty());
        assert!(commit.outbox_events.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn typed_finding_reports_commit_idempotently_enqueue_and_deliver_jsonl()
    -> eyre::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = std::sync::Arc::new(InMemoryMonitorStore::with_bootstrap_policy(
            BootstrapPolicy::AnyFirstFinalizedBlock,
        ));
        let commit =
            FinalizedBlockProcessor.build_commit(input(20_999, 30_000, 21_000, false), None)?;
        let key = commit.finding_updates[0].key.clone();
        store.commit_block(commit.clone())?;
        store.commit_block(commit)?;
        assert_eq!(store.monitor_head()?.expect("head").number, 1);
        assert_eq!(
            store.finding_state(&key)?.expect("finding state").status,
            FindingStatus::Open
        );
        let pending = store.pending_outbox(10)?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event.payload["schema"], FINDING_REPORT_SCHEMA_V1);

        let path = dir.path().join("outbox.jsonl");
        let worker = OutboxWorker::new(
            store.clone(),
            JsonlOutboxSink::open(&path)?,
            OutboxWorkerConfig::default(),
        );
        assert_eq!(worker.tick().await?, 1);
        let contents = std::fs::read_to_string(path)?;
        let line: serde_json::Value = serde_json::from_str(contents.trim_end())?;
        assert_eq!(line["event"]["payload"]["schema"], FINDING_REPORT_SCHEMA_V1);
        assert_eq!(
            line["event"]["payload"]["finding_key"],
            serde_json::to_value(key)?
        );
        Ok(())
    }
}
