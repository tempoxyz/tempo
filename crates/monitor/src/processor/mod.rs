//! Finalized block processor and atomic commit construction.
//!
//! The processor builds monitor-owned block views, runs checks, computes
//! coverage/finding/report rows, and hands a single block commit to the store.

#[cfg(feature = "store")]
mod checks;
#[cfg(feature = "store")]
use checks::{CheckSummary, check_outcome_label, run_block_checks};

use crate::facts::{BlockFacts, BlockNumHash, BlockWithParent, OrderedLog, ReceiptFacts, TxFacts};
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

#[cfg(feature = "store")]
impl From<crate::store::StoreError> for ProcessorError {
    fn from(value: crate::store::StoreError) -> Self {
        Self::Store(format!("{value:?}"))
    }
}

/// Builds complete block commits from normalized finalized block input.
#[cfg(feature = "store")]
#[derive(Clone, Debug, Default)]
pub struct FinalizedBlockProcessor;

#[cfg(feature = "store")]
impl FinalizedBlockProcessor {
    pub fn build_commit(
        &self,
        input: FinalizedBlockInput,
        _prior_head: Option<BlockNumHash>,
    ) -> Result<crate::store::BlockCommit, ProcessorError> {
        validate_input(&input)?;
        let block = input.block();
        let check_results = run_block_checks(&input);
        let coverage_records = check_results
            .iter()
            .map(|result| result.coverage.clone())
            .collect();
        // Finding and outbox rows for violations are deferred until the reporting policy is wired;
        // this PoC persists the durable check result and coverage record.

        Ok(crate::store::BlockCommit {
            finalized_block: crate::store::FinalizedBlockRecord {
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
            finding_updates: Vec::new(),
            health_updates: Vec::new(),
            outbox_events: Vec::new(),
            new_monitor_head: block,
        })
    }

    pub fn process_and_commit<S: crate::store::MonitorStore>(
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
