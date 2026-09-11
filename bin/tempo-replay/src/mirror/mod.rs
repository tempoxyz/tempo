//! Bounded exact-byte transaction mirroring with durable per-occurrence evidence.

mod state;

pub use state::{
    MirrorOccurrence, MirrorReader, MirrorState, MirrorStore, SubmissionDisposition,
    SubmissionEvidence,
};

use self::state::{CompletedSubmission, RecoverableSubmission};
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
        self.recover_ambiguous().await?;

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
                    restarted: false,
                });
            }

            let store = self.store.clone();
            let restarted =
                tokio::task::spawn_blocking(move || lock(&store)?.prepare_block(records)).await??;
            for queued in &mut queued {
                queued.restarted = restarted.contains(&queued.id);
            }
            gauge!("tempo_replay_queue_depth").set(queued.len() as f64);

            let completed = submit_all(
                self.target.clone(),
                queued,
                self.concurrency,
                self.retries,
                self.retry_delay,
            )
            .await;

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
            self.recover_ambiguous().await?;
            if stop.is_cancelled() || self.to_block == Some(cursor.height) {
                break;
            }
        }

        let state = blocking_state(self.store.clone()).await?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || lock(&store)?.flush()).await??;
        Ok(state)
    }

    async fn recover_ambiguous(&self) -> Result<()> {
        let store = self.store.clone();
        let retain = AMBIGUOUS_RESUBMIT_BLOCKS;
        let recoverable =
            tokio::task::spawn_blocking(move || lock(&store)?.recoverable_ambiguous(retain))
                .await??;
        if recoverable.is_empty() {
            return Ok(());
        }
        tracing::info!(
            count = recoverable.len(),
            retain_blocks = retain,
            "re-submitting ambiguous transactions"
        );
        let queued: Vec<_> = recoverable.into_iter().map(Queued::from).collect();
        gauge!("tempo_replay_queue_depth").set(queued.len() as f64);
        let completed = submit_all(
            self.target.clone(),
            queued,
            self.concurrency,
            self.retries,
            self.retry_delay,
        )
        .await;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || lock(&store)?.complete_recovery(completed)).await??;
        gauge!("tempo_replay_queue_depth").set(0.0);
        Ok(())
    }
}

struct Queued {
    id: OccurrenceId,
    expected: B256,
    raw: Vec<u8>,
    started_at_ms: u64,
    restarted: bool,
}

impl From<RecoverableSubmission> for Queued {
    fn from(recoverable: RecoverableSubmission) -> Self {
        Self {
            id: recoverable.id,
            expected: recoverable.transaction_hash,
            raw: recoverable.raw,
            started_at_ms: recoverable.started_at_ms,
            restarted: true,
        }
    }
}

async fn submit_all(
    target: TempoProvider,
    queued: Vec<Queued>,
    concurrency: usize,
    retries: u32,
    retry_delay: Duration,
) -> Vec<CompletedSubmission> {
    let mut submissions = stream::iter(queued.into_iter().map(|queued| {
        let target = target.clone();
        async move { submit(&target, queued, retries, retry_delay).await }
    }))
    .buffered(concurrency);
    let mut completed = Vec::new();
    while let Some(result) = submissions.next().await {
        completed.push(result);
        gauge!("tempo_replay_queue_depth").decrement(1.0);
    }
    completed
}

const AMBIGUOUS_RESUBMIT_BLOCKS: u64 = 64;
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
                if error.as_error_resp().is_some() && is_already_known(&message) {
                    counter!("tempo_replay_submissions_total", "outcome" => "already_known")
                        .increment(1);
                    return completed(
                        queued,
                        SubmissionDisposition::AlreadyKnown,
                        attempt + 1,
                        None,
                    );
                }
                if error.as_error_resp().is_some() {
                    let restarted_nonce = queued.restarted && is_nonce_too_low(&message);
                    let disposition = if restarted_nonce {
                        SubmissionDisposition::PossiblyIncluded
                    } else {
                        SubmissionDisposition::Rejected
                    };
                    let evidence =
                        rpc_evidence(&error, &message, queued.started_at_ms, restarted_nonce);
                    let outcome = if restarted_nonce {
                        "possibly_included"
                    } else {
                        "rejected"
                    };
                    counter!("tempo_replay_submissions_total", "outcome" => outcome).increment(1);
                    tracing::warn!(%expected, error = %message, %outcome, "shadow rejected source transaction");
                    return completed(queued, disposition, attempt + 1, Some(evidence));
                }
                last_error = Some(rpc_evidence(&error, &message, queued.started_at_ms, false));
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
        SubmissionDisposition::Rejected
            | SubmissionDisposition::PossiblyIncluded
            | SubmissionDisposition::Ambiguous
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

fn rpc_evidence(
    error: &TransportError,
    message: &str,
    first_observed_ms: u64,
    inferred: bool,
) -> FailureEvidence {
    let response = error.as_error_resp();
    FailureEvidence {
        level: if inferred {
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

fn is_nonce_too_low(message: &str) -> bool {
    message.to_ascii_lowercase().contains("nonce too low")
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

    fn queued(restarted: bool) -> Queued {
        Queued {
            id: OccurrenceId {
                source_height: 11,
                source_index: 0,
            },
            expected: B256::repeat_byte(1),
            raw: vec![0x02, 0x01],
            started_at_ms: 1,
            restarted,
        }
    }

    #[tokio::test]
    async fn structured_pool_rejections_are_not_retried_as_transport_errors() {
        let responses = alloy::transports::mock::Asserter::new();
        responses.push_failure_msg("transaction underpriced");
        let provider = alloy::providers::builder::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(responses);
        let completed = submit(&provider, queued(false), 2, Duration::ZERO).await;
        assert_eq!(completed.disposition, SubmissionDisposition::Rejected);
        assert_eq!(completed.attempts, 1);
        assert_eq!(completed.failure.unwrap().level, EvidenceLevel::RpcReported);
    }

    #[tokio::test]
    async fn restarted_nonce_too_low_is_possibly_included() {
        let responses = alloy::transports::mock::Asserter::new();
        responses.push_failure_msg("nonce too low");
        let provider = alloy::providers::builder::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(responses);
        let completed = submit(&provider, queued(true), 2, Duration::ZERO).await;
        assert_eq!(
            completed.disposition,
            SubmissionDisposition::PossiblyIncluded
        );
        assert_eq!(completed.attempts, 1);
        assert_eq!(completed.failure.unwrap().level, EvidenceLevel::Inferred);
    }
}
