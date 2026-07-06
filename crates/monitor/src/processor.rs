//! Finalized block processor and atomic commit construction.
//!
//! The processor builds monitor-owned block views, runs checks, computes
//! coverage/finding/report rows, and hands a single block commit to the store.

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessorError {
    InvalidInput(String),
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
            check_results: Vec::new(),
            coverage_records: Vec::new(),
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
        store.commit_block(commit)?;
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
