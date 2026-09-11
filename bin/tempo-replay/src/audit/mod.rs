//! Independent finalized inclusion, receipt, liveness, and system-behavior auditing.

mod state;

pub use state::{
    AuditReader, AuditStore, AuditSummary, ExecutionDriftFinding, Expectation, Finding, Incident,
    ReceiptDrift, ReceiptSummary, TargetObservation, TxLocation,
};

use self::state::ObservationSide;
#[cfg(test)]
use self::state::apply_observation;
use crate::{
    now_ms,
    source::{FinalizedBlock, TempoProvider, TxMetadata, fetch_finalized_block, replayable},
    state::{EvidenceLevel, FailureEvidence, OccurrenceId},
    store::bounded_error,
};
use alloy::{
    consensus::{BlockHeader, Transaction, transaction::TxHashRef},
    network::ReceiptResponse,
    primitives::keccak256,
    providers::Provider,
};
use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use metrics::gauge;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tempo_chainspec::{
    TempoHardforks,
    spec::{SYSTEM_TX_ADDRESSES, SYSTEM_TX_COUNT, chainspec_from_chain_id},
};
use tempo_consensus::finalized_header_stream::{
    Error as FinalizedStreamError, FinalizedHeaderStream,
};
use tempo_primitives::TempoTxEnvelope;
use tokio_util::sync::CancellationToken;

/// Independent source/target finality observer and receipt comparator.
pub struct Auditor {
    pub source: TempoProvider,
    pub target: TempoProvider,
    pub source_finalized: FinalizedHeaderStream,
    pub target_finalized: FinalizedHeaderStream,
    pub store: Arc<Mutex<AuditStore>>,
    pub source_to_block: Option<u64>,
    pub missing_after_blocks: u64,
    pub missing_after: Duration,
    pub retain_included_blocks: u64,
    pub finality_stall: Duration,
    pub chain_id: u64,
}

impl Auditor {
    pub async fn run(mut self, stop: CancellationToken) -> Result<AuditSummary> {
        ensure!(
            self.missing_after_blocks > 0 || !self.missing_after.is_zero(),
            "audit missing horizon must be positive"
        );
        let (mut source_cursor, mut target_cursor, _) =
            blocking_snapshot(self.store.clone()).await?;
        loop {
            if self
                .source_to_block
                .is_some_and(|end| source_cursor.height >= end)
            {
                let (_, _, summary) = blocking_snapshot(self.store.clone()).await?;
                if summary.missing_within_window == 0 {
                    break;
                }
            }
            tokio::select! {
                biased;
                _ = stop.cancelled() => break,
                source = self.source_finalized.next(), if self.source_to_block.is_none_or(|end| source_cursor.height < end) => {
                    let header = match source {
                        Some(Ok(header)) => header,
                        Some(Err(error)) => return self.stream_error(ObservationSide::Source, error, "source finalized history failed").await,
                        None => return self.history_message(ObservationSide::Source, "source finalized stream ended", false).await,
                    };
                    if header.number() != source_cursor.height.saturating_add(1)
                        || header.parent_hash() != source_cursor.hash
                    {
                        return self.history_message(ObservationSide::Source, "source audit history is not contiguous", true).await;
                    }
                    source_cursor = match self.observe_source(header).await {
                        Ok(cursor) => cursor,
                        Err(error) => return self.history_error(ObservationSide::Source, error, "source audit observation failed", false).await,
                    };
                }
                target = self.target_finalized.next() => {
                    let header = match target {
                        Some(Ok(header)) => header,
                        Some(Err(error)) => return self.stream_error(ObservationSide::Target, error, "target finalized history failed").await,
                        None => return self.history_message(ObservationSide::Target, "target finalized stream ended", false).await,
                    };
                    if header.number() != target_cursor.height.saturating_add(1)
                        || header.parent_hash() != target_cursor.hash
                    {
                        return self.history_message(ObservationSide::Target, "target audit history is not contiguous", true).await;
                    }
                    target_cursor = match self.observe_target(header).await {
                        Ok(cursor) => cursor,
                        Err(error) => return self.history_error(ObservationSide::Target, error, "target audit observation failed", false).await,
                    };
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    let store = self.store.clone();
                    let missing_blocks = self.missing_after_blocks;
                    let missing_time = self.missing_after;
                    let stall = self.finality_stall;
                    tokio::task::spawn_blocking(move || {
                        let mut store = lock(&store)?;
                        store.refresh_missing(missing_blocks, missing_time)?;
                        store.check_stall(stall)
                    }).await??;
                }
            }
        }
        let store = self.store.clone();
        let summary = tokio::task::spawn_blocking(move || {
            let store = lock(&store)?;
            store.flush()?;
            Ok::<_, anyhow::Error>(store.summary().clone())
        })
        .await??;
        Ok(summary)
    }

    async fn observe_source(
        &self,
        header: reth_primitives_traits::SealedHeader<tempo_primitives::TempoHeader>,
    ) -> Result<crate::state::BlockCursor> {
        let block = fetch_finalized_block(&self.source, &header).await?;
        let receipts =
            fetch_receipt_summaries(&self.source, &block, "fetch source block receipts").await?;
        let target_height = blocking_snapshot(self.store.clone()).await?.1.height;
        let mut expectations = Vec::new();
        for (index, (txs, receipt)) in block.transactions.into_iter().zip(receipts).enumerate() {
            let TxMetadata::Replayable(metadata) = TxMetadata::from_envelope(&txs)? else {
                continue;
            };
            expectations.push((
                OccurrenceId {
                    source_height: block.cursor.height,
                    source_index: u32::try_from(index)
                        .context("source transaction index exceeds u32")?,
                },
                Expectation {
                    source_block_hash: block.cursor.hash,
                    source_timestamp_ms: block.timestamp_ms,
                    observed_at_ms: now_ms(),
                    target_height_when_observed: target_height,
                    transaction_hash: metadata.hash,
                    transaction_type: metadata.transaction_type,
                    sender: metadata.sender,
                    nonce_key: metadata.nonce_key,
                    expiring: metadata.expiring,
                    source_receipt: receipt,
                    finding: Finding::MissingWithinWindow,
                },
            ));
        }
        let cursor = block.cursor;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || lock(&store)?.observe_source(cursor, expectations))
            .await??;
        gauge!("tempo_replay_audit_source_height").set(cursor.height as f64);
        Ok(cursor)
    }

    async fn observe_target(
        &self,
        header: reth_primitives_traits::SealedHeader<tempo_primitives::TempoHeader>,
    ) -> Result<crate::state::BlockCursor> {
        let block = fetch_finalized_block(&self.target, &header).await?;
        let receipts =
            fetch_receipt_summaries(&self.target, &block, "fetch target block receipts").await?;
        let mut system_failures = system_invariant_failures(
            &block.transactions,
            block.timestamp_ms / 1_000,
            self.chain_id,
        )?;
        let mut observations = Vec::new();
        let mut system_txs = 0;
        for (index, (tx, receipt)) in block.transactions.into_iter().zip(receipts).enumerate() {
            let hash = *tx.tx_hash();
            let location = TxLocation {
                block: block.cursor,
                index: u32::try_from(index).context("target transaction index exceeds u32")?,
            };
            if replayable(&tx) {
                observations.push(TargetObservation {
                    transaction_hash: hash,
                    location,
                    receipt,
                });
            } else {
                system_txs += 1;
                if !receipt.status {
                    system_failures.push(system_failure(
                        now_ms(),
                        format!(
                            "target system/subblock transaction {hash} reverted at {}:{}",
                            location.block.height, location.index
                        ),
                    ));
                }
            }
        }
        let cursor = block.cursor;
        let retain = self.retain_included_blocks;
        let missing_blocks = self.missing_after_blocks;
        let missing_time = self.missing_after;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let mut store = lock(&store)?;
            store.observe_target(cursor, observations, system_txs, system_failures)?;
            store.refresh_missing(missing_blocks, missing_time)?;
            store.prune_included(retain)
        })
        .await??;
        gauge!("tempo_replay_audit_target_height").set(cursor.height as f64);
        Ok(cursor)
    }

    async fn stream_error(
        &self,
        side: ObservationSide,
        error: FinalizedStreamError,
        context: &str,
    ) -> Result<AuditSummary> {
        let message = format!("{context}: {error}");
        let consensus = !matches!(
            error,
            FinalizedStreamError::Rpc(_)
                | FinalizedStreamError::MissingHeader(_)
                | FinalizedStreamError::MissingTransitionCertificate { .. }
        );
        self.history_message(side, &message, consensus).await
    }

    async fn history_error<E: std::fmt::Display>(
        &self,
        side: ObservationSide,
        error: E,
        context: &str,
        consensus: bool,
    ) -> Result<AuditSummary> {
        self.history_message(side, &format!("{context}: {error}"), consensus)
            .await
    }

    async fn history_message(
        &self,
        side: ObservationSide,
        message: &str,
        consensus: bool,
    ) -> Result<AuditSummary> {
        let message = bounded_error(message);
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            lock(&store)?.record_history_failure(side, message, consensus)
        })
        .await??;
        if consensus {
            anyhow::bail!("authenticated finalized history is not contiguous")
        }
        anyhow::bail!("finalized history observation failed; restart under a supervisor")
    }
}

fn system_invariant_failures(
    transactions: &[TempoTxEnvelope],
    timestamp: u64,
    chain_id: u64,
) -> Result<Vec<FailureEvidence>> {
    let chainspec = chainspec_from_chain_id(chain_id)
        .with_context(|| format!("unsupported Tempo chain id {chain_id}"))?;
    let expected = if chainspec.is_t4_active_at_timestamp(timestamp) {
        0
    } else {
        SYSTEM_TX_COUNT
    };
    let now = now_ms();
    let mut failures = transactions
        .iter()
        .filter(|transaction| {
            transaction.is_system_tx() && !transaction.is_valid_system_tx(chain_id)
        })
        .map(|transaction| {
            system_failure(
                now,
                format!("invalid system transaction {}", transaction.tx_hash()),
            )
        })
        .collect::<Vec<_>>();
    let tail = transactions
        .get(transactions.len().saturating_sub(expected)..)
        .unwrap_or_default();
    let system_tail = tail.iter().filter(|transaction| transaction.is_system_tx());
    let observed = system_tail.clone().count();
    if observed != expected {
        failures.push(system_failure(
            now,
            format!("expected {expected} end-of-block system transactions, observed {observed}"),
        ));
    }
    for (transaction, expected_to) in system_tail.zip(SYSTEM_TX_ADDRESSES) {
        if transaction.to() != Some(expected_to) {
            failures.push(system_failure(
                now,
                format!(
                    "end-of-block system transaction has target {:?}, expected {expected_to}",
                    transaction.to()
                ),
            ));
        }
    }
    Ok(failures)
}

fn system_failure(now: u64, message: String) -> FailureEvidence {
    FailureEvidence {
        level: EvidenceLevel::Observed,
        rpc_code: None,
        message: bounded_error(message),
        first_observed_ms: now,
        last_observed_ms: now,
    }
}

async fn fetch_receipt_summaries(
    provider: &TempoProvider,
    block: &FinalizedBlock,
    context: &'static str,
) -> Result<Vec<ReceiptSummary>> {
    let receipts = provider
        .get_block_receipts(block.cursor.height.into())
        .await
        .context(context)?
        .with_context(|| format!("finalized block {} has no receipts", block.cursor.height))?;
    ensure!(
        receipts.len() == block.transactions.len(),
        "finalized block {} returned {} receipts for {} transactions",
        block.cursor.height,
        receipts.len(),
        block.transactions.len()
    );
    Ok(receipts.iter().map(receipt_summary).collect())
}

fn receipt_summary(receipt: &tempo_alloy::rpc::TempoTransactionReceipt) -> ReceiptSummary {
    ReceiptSummary {
        status: receipt.status(),
        gas_used: receipt.gas_used(),
        logs_hash: consensus_logs_hash(receipt.logs()),
    }
}

fn consensus_logs_hash(logs: &[alloy::rpc::types::Log]) -> alloy::primitives::B256 {
    let mut encoded = Vec::new();
    alloy::rlp::encode_iter::<_, _, alloy::primitives::Log>(
        logs.iter().map(|log| &log.inner),
        &mut encoded,
    );
    keccak256(encoded)
}

fn lock(store: &Mutex<AuditStore>) -> Result<std::sync::MutexGuard<'_, AuditStore>> {
    store
        .lock()
        .map_err(|_| anyhow::anyhow!("audit store writer panicked"))
}

async fn blocking_snapshot(
    store: Arc<Mutex<AuditStore>>,
) -> Result<(
    crate::state::BlockCursor,
    crate::state::BlockCursor,
    AuditSummary,
)> {
    tokio::task::spawn_blocking(move || {
        let store = lock(&store)?;
        Ok((
            store.source_cursor(),
            store.target_cursor(),
            store.summary().clone(),
        ))
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BlockCursor;
    use alloy::primitives::B256;

    fn location(height: u64, hash: B256) -> TxLocation {
        TxLocation {
            block: BlockCursor { height, hash },
            index: 0,
        }
    }

    #[test]
    fn system_invariants_follow_the_hardfork_schedule() {
        assert!(!system_invariant_failures(&[], 0, 4217).unwrap().is_empty());
        assert!(
            system_invariant_failures(&[], u64::MAX, 4217)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn receipt_drift_is_diagnostic() {
        let mut expectation = Expectation {
            source_block_hash: B256::ZERO,
            source_timestamp_ms: 1,
            observed_at_ms: 1_000,
            target_height_when_observed: 10,
            transaction_hash: B256::repeat_byte(1),
            transaction_type: 2,
            sender: alloy::primitives::Address::ZERO,
            nonce_key: alloy::primitives::U256::ZERO,
            expiring: false,
            source_receipt: ReceiptSummary {
                status: true,
                gas_used: 21_000,
                logs_hash: B256::ZERO,
            },
            finding: Finding::MissingWithinWindow,
        };
        let transaction_hash = expectation.transaction_hash;
        apply_observation(
            &mut expectation,
            &TargetObservation {
                transaction_hash,
                location: location(3, B256::repeat_byte(2)),
                receipt: ReceiptSummary {
                    status: false,
                    gas_used: 30_000,
                    logs_hash: B256::ZERO,
                },
            },
        );
        assert!(matches!(expectation.finding, Finding::ExecutionDrift(_)));
    }

    #[test]
    fn receipt_log_hash_ignores_rpc_location_metadata() {
        let receipt = |block_byte: u8, block_number: u64| {
            let block_hash = B256::repeat_byte(block_byte);
            serde_json::from_value::<tempo_alloy::rpc::TempoTransactionReceipt>(serde_json::json!({
                "type": "0x2",
                "status": "0x1",
                "cumulativeGasUsed": "0x5208",
                "logsBloom": format!("0x{}", "00".repeat(256)),
                "logs": [{
                    "address": "0x1111111111111111111111111111111111111111",
                    "topics": [format!("{:#x}", B256::repeat_byte(0x22))],
                    "data": "0x010203",
                    "blockHash": format!("{block_hash:#x}"),
                    "blockNumber": format!("0x{block_number:x}"),
                    "blockTimestamp": "0x1234",
                    "transactionHash": format!("{:#x}", B256::repeat_byte(0x33)),
                    "transactionIndex": "0x1",
                    "logIndex": "0x2",
                    "removed": false
                }],
                "transactionHash": format!("{:#x}", B256::repeat_byte(0x33)),
                "transactionIndex": "0x1",
                "blockHash": format!("{block_hash:#x}"),
                "blockNumber": format!("0x{block_number:x}"),
                "gasUsed": "0x5208",
                "effectiveGasPrice": "0x1",
                "from": "0x4444444444444444444444444444444444444444",
                "to": "0x5555555555555555555555555555555555555555",
                "contractAddress": null,
                "feePayer": "0x4444444444444444444444444444444444444444"
            }))
            .unwrap()
        };

        let source = receipt(0xaa, 10);
        let target = receipt(0xbb, 11);
        assert_ne!(
            serde_json::to_vec(source.logs()).unwrap(),
            serde_json::to_vec(target.logs()).unwrap()
        );
        assert_eq!(receipt_summary(&source), receipt_summary(&target));
    }
}
