//! Bounded exact-byte transaction mirroring with durable per-occurrence evidence.

mod state;

pub use state::{
    MirrorOccurrence, MirrorReader, MirrorState, MirrorStore, SubmissionDisposition,
    SubmissionEvidence,
};

use self::state::CompletedSubmission;
use crate::{
    now_ms,
    source::{TempoProvider, TxMetadata, fetch_finalized_block},
    state::{EvidenceLevel, FailureEvidence, OccurrenceId},
    store::bounded_error,
};
use alloy::{
    consensus::BlockHeader, eips::eip2718::Encodable2718, primitives::B256, providers::Provider,
    transports::TransportError,
};
use anyhow::{Context, Result, ensure};
use futures_util::{StreamExt, stream};
use metrics::{counter, gauge};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tempo_consensus::finalized_header_stream::FinalizedHeaderStream;
use tokio_util::sync::CancellationToken;

/// Stateful runner that mirrors one authenticated source block at a time.
pub struct Mirror {
    pub source: TempoProvider,
    pub target: TempoProvider,
    pub finalized: FinalizedHeaderStream,
    pub store: Arc<Mutex<MirrorStore>>,
    pub concurrency: usize,
    pub retries: u32,
    pub retry_delay: Duration,
    pub retain_completed_blocks: u64,
    pub to_block: Option<u64>,
}

impl Mirror {
    pub async fn run(mut self, stop: CancellationToken) -> Result<MirrorState> {
        ensure!(
            self.concurrency > 0,
            "submission concurrency must be positive"
        );
        let mut cursor = blocking_state(self.store.clone()).await?.source_cursor;
        gauge!("tempo_replay_processed_height").set(cursor.height as f64);

        loop {
            let header = tokio::select! {
                _ = stop.cancelled() => break,
                header = self.finalized.next() => match header {
                    Some(header) => header?,
                    None => break,
                },
            };
            if self.to_block.is_some_and(|end| header.number() > end) {
                break;
            }
            ensure!(
                header.number() == cursor.height.saturating_add(1),
                "authenticated source stream skipped a block"
            );
            ensure!(
                header.parent_hash() == cursor.hash,
                "authenticated source history no longer extends durable mirror state"
            );

            let block = fetch_finalized_block(&self.source, &header).await?;
            gauge!("tempo_replay_source_finalized_height").set(block.cursor.height as f64);
            gauge!("tempo_replay_lag_ms").set(now_ms().saturating_sub(block.timestamp_ms) as f64);

            let mut queued = Vec::new();
            let mut records = Vec::new();
            for (index, tx) in block.transactions.into_iter().enumerate() {
                let TxMetadata::Replayable(metadata) = TxMetadata::from_envelope(&tx)? else {
                    continue;
                };
                let id = OccurrenceId {
                    source_height: block.cursor.height,
                    source_index: u32::try_from(index).context("transaction index exceeds u32")?,
                };
                let raw = tx.encoded_2718();
                let started_at_ms = now_ms();
                records.push((
                    id,
                    MirrorOccurrence {
                        source_block_hash: block.cursor.hash,
                        transaction_hash: metadata.hash,
                        transaction_type: metadata.transaction_type,
                        sender: metadata.sender,
                        nonce: metadata.nonce,
                        nonce_key: metadata.nonce_key,
                        expiring: metadata.expiring,
                        encoded_length: metadata.encoded_length,
                        raw_on_failure: None,
                        restart_ambiguities: 0,
                        submission: SubmissionEvidence {
                            started_at_ms,
                            completed_at_ms: None,
                            attempts: 0,
                            disposition: SubmissionDisposition::Intent,
                            failure: None,
                        },
                    },
                ));
                queued.push(Queued {
                    id,
                    expected: metadata.hash,
                    raw,
                    started_at_ms,
                });
            }

            let store = self.store.clone();
            tokio::task::spawn_blocking(move || lock(&store)?.prepare_block(records)).await??;
            gauge!("tempo_replay_queue_depth").set(queued.len() as f64);

            let target = self.target.clone();
            let retries = self.retries;
            let delay = self.retry_delay;
            let mut submissions = stream::iter(queued.into_iter().map(|queued| {
                let target = target.clone();
                async move { submit(&target, queued, retries, delay).await }
            }))
            .buffered(self.concurrency);
            let mut completed = Vec::new();
            while let Some(result) = submissions.next().await {
                completed.push(result);
                gauge!("tempo_replay_queue_depth").decrement(1.0);
            }

            let store = self.store.clone();
            let next = block.cursor;
            let retain = self.retain_completed_blocks;
            tokio::task::spawn_blocking(move || {
                let mut store = lock(&store)?;
                store.complete_block(next, completed)?;
                store.prune_completed(retain)
            })
            .await??;
            cursor = block.cursor;
            gauge!("tempo_replay_processed_height").set(cursor.height as f64);
            gauge!("tempo_replay_queue_depth").set(0.0);
            if stop.is_cancelled() || self.to_block == Some(cursor.height) {
                break;
            }
        }

        let state = blocking_state(self.store.clone()).await?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || lock(&store)?.flush()).await??;
        Ok(state)
    }
}

struct Queued {
    id: OccurrenceId,
    expected: B256,
    raw: Vec<u8>,
    started_at_ms: u64,
}

const MAX_RETRY_BACKOFF_SHIFT: u32 = 8;

async fn submit(
    target: &TempoProvider,
    queued: Queued,
    retries: u32,
    retry_delay: Duration,
) -> CompletedSubmission {
    let expected = queued.expected;
    let mut last_error = None;
    for attempt in 0..=retries {
        match target.send_raw_transaction(queued.raw.as_slice()).await {
            Ok(pending) if *pending.tx_hash() == expected => {
                counter!("tempo_replay_submissions_total", "outcome" => "accepted").increment(1);
                return completed(queued, SubmissionDisposition::Accepted, attempt + 1, None);
            }
            Ok(pending) => {
                let evidence = FailureEvidence {
                    level: EvidenceLevel::Observed,
                    rpc_code: None,
                    message: bounded_error(format!(
                        "target returned unexpected hash {}",
                        pending.tx_hash()
                    )),
                    first_observed_ms: queued.started_at_ms,
                    last_observed_ms: now_ms(),
                };
                return completed(
                    queued,
                    SubmissionDisposition::Ambiguous,
                    attempt + 1,
                    Some(evidence),
                );
            }
            Err(error) => {
                let message = rpc_message(&error);
                if is_already_known(&message) {
                    counter!("tempo_replay_submissions_total", "outcome" => "already_known")
                        .increment(1);
                    return completed(
                        queued,
                        SubmissionDisposition::AlreadyKnown,
                        attempt + 1,
                        None,
                    );
                }
                let evidence = rpc_evidence(&error, &message, queued.started_at_ms);
                if is_deterministic_rejection(&message) {
                    counter!("tempo_replay_submissions_total", "outcome" => "rejected")
                        .increment(1);
                    tracing::warn!(%expected, error = %message, "shadow rejected source transaction");
                    return completed(
                        queued,
                        SubmissionDisposition::Rejected,
                        attempt + 1,
                        Some(evidence),
                    );
                }
                last_error = Some(evidence);
                if attempt < retries {
                    counter!("tempo_replay_retries_total").increment(1);
                    tokio::time::sleep(
                        retry_delay.saturating_mul(1 << attempt.min(MAX_RETRY_BACKOFF_SHIFT)),
                    )
                    .await;
                }
            }
        }
    }

    counter!("tempo_replay_submissions_total", "outcome" => "ambiguous").increment(1);
    tracing::warn!(%expected, "submission outcome remains ambiguous after bounded retries");
    completed(
        queued,
        SubmissionDisposition::Ambiguous,
        retries.saturating_add(1),
        last_error,
    )
}

fn completed(
    queued: Queued,
    disposition: SubmissionDisposition,
    attempts: u32,
    failure: Option<FailureEvidence>,
) -> CompletedSubmission {
    let retain_raw = matches!(
        disposition,
        SubmissionDisposition::Rejected | SubmissionDisposition::Ambiguous
    );
    CompletedSubmission {
        id: queued.id,
        disposition,
        attempts,
        completed_at_ms: now_ms(),
        failure,
        raw_on_failure: retain_raw.then_some(queued.raw),
    }
}

fn rpc_message(error: &TransportError) -> String {
    error
        .as_error_resp()
        .map_or_else(|| error.to_string(), |payload| payload.message.to_string())
}

fn rpc_evidence(error: &TransportError, message: &str, first_observed_ms: u64) -> FailureEvidence {
    let response = error.as_error_resp();
    FailureEvidence {
        level: if is_deterministic_rejection(message) {
            EvidenceLevel::Inferred
        } else if response.is_some() {
            EvidenceLevel::RpcReported
        } else {
            EvidenceLevel::Observed
        },
        rpc_code: response.map(|payload| payload.code),
        message: bounded_error(message),
        first_observed_ms,
        last_observed_ms: now_ms(),
    }
}

fn is_already_known(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("already known")
        || message.contains("already imported")
        || message.contains("known transaction")
}

fn is_deterministic_rejection(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "invalid transaction",
        "invalid signature",
        "nonce too low",
        "expired",
        "insufficient funds",
        "unsupported transaction",
        "chain id",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

fn lock(store: &Mutex<MirrorStore>) -> Result<std::sync::MutexGuard<'_, MirrorStore>> {
    store
        .lock()
        .map_err(|_| anyhow::anyhow!("mirror store writer panicked"))
}

async fn blocking_state(store: Arc<Mutex<MirrorStore>>) -> Result<MirrorState> {
    tokio::task::spawn_blocking(move || Ok(lock(&store)?.state().clone())).await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_error_categories_are_small_and_explicit() {
        assert!(is_already_known("transaction already known"));
        assert!(is_deterministic_rejection("nonce too low"));
        assert!(!is_deterministic_rejection("connection reset"));
    }
}
