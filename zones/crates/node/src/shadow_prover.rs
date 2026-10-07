//! Finalized L1 batch observation for RPC-only shadow provers.

use std::time::Duration;

use alloy_consensus::{BlockHeader as _, Sealable as _, proofs::calculate_transaction_root};
use alloy_primitives::{Address, TxKind};
use alloy_provider::{DynProvider, Provider as _};
use alloy_sol_types::SolCall as _;
use alloy_transport::{RpcError, TransportError, TransportErrorKind};
use eyre::{OptionExt as _, Result, WrapErr as _, ensure};
use tempo_alloy::TempoNetwork;
use tempo_primitives::TempoTxEnvelope;
use tempo_zone_contracts::{
    BatchSubmitted, TokenEnablementTransition, legacySubmitBatchCall, submitBatchCall,
};
use tokio::sync::mpsc::Receiver;
use tracing::{error, info, warn};
use zone_l1::FinalizedBatchSubmission;
use zone_sequencer::{BatchData, ShadowProofAnchor, ShadowProver, ZoneSequencerProvider};

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CONNECTION_ATTEMPTS: u32 = 5;

/// Feeds finalized RPC-follower submissions and their exact settlement inputs to the detached
/// shadow prover.
#[derive(Clone)]
pub(crate) struct RpcFollowerShadowProver<P> {
    portal_address: Address,
    zone_provider: P,
    l1_provider: DynProvider<TempoNetwork>,
    prover: ShadowProver,
}

impl<P: ZoneSequencerProvider> RpcFollowerShadowProver<P> {
    pub(crate) fn new(
        portal_address: Address,
        zone_provider: P,
        l1_provider: DynProvider<TempoNetwork>,
        prover: ShadowProver,
    ) -> Self {
        Self {
            portal_address,
            zone_provider,
            l1_provider,
            prover,
        }
    }

    /// Observe finalized `submitBatch` calls. The Portal has already verified the included quorum
    /// certificate before emitting the event; decoding the call binds each proof job to that
    /// accepted certificate.
    pub(crate) async fn run(self, mut submissions: Receiver<FinalizedBatchSubmission>) {
        while let Some(submission) = submissions.recv().await {
            self.process_submission_with_retry(&submission).await;
        }
    }

    async fn process_submission_with_retry(&self, submission: &FinalizedBatchSubmission) {
        for attempt in 1..=MAX_CONNECTION_ATTEMPTS {
            match self.process_submission(submission).await {
                Ok(()) => return,
                Err(err) if is_retryable_connection_error(&err) => {
                    if attempt == MAX_CONNECTION_ATTEMPTS {
                        error!(
                            target: "zone::node::shadow_prover",
                            l1_block_hash = %submission.block.hash,
                            transaction_index = submission.transaction_index,
                            log_index = submission.log_index,
                            error = ?err,
                            attempts = attempt,
                            "Failed to process finalized batch submission; retry budget exhausted"
                        );
                        return;
                    }
                    let retry_delay = POLL_INTERVAL * 2_u32.pow(attempt - 1);
                    warn!(
                        target: "zone::node::shadow_prover",
                        l1_block_hash = %submission.block.hash,
                        transaction_index = submission.transaction_index,
                        log_index = submission.log_index,
                        error = ?err,
                        attempt,
                        max_attempts = MAX_CONNECTION_ATTEMPTS,
                        retry_delay_secs = retry_delay.as_secs(),
                        "Connection error processing finalized batch submission; retrying"
                    );
                    tokio::time::sleep(retry_delay).await;
                }
                Err(err) => {
                    error!(
                        target: "zone::node::shadow_prover",
                        l1_block_hash = %submission.block.hash,
                        transaction_index = submission.transaction_index,
                        log_index = submission.log_index,
                        error = ?err,
                        "Rejected finalized batch submission"
                    );
                    return;
                }
            }
        }
    }

    async fn process_submission(&self, submission: &FinalizedBatchSubmission) -> Result<()> {
        let call = self
            .fetch_submit_batch_calls(submission)
            .await?
            .into_iter()
            .find(|call| call_matches_event(call, &submission.event))
            .ok_or_eyre(format!(
                "L1 block {} transaction {} contains no submitBatch call matching log {}",
                submission.block.hash, submission.transaction_index, submission.log_index
            ))?;
        let (to, batch, anchor) = self
            .submission_target(&call, &submission.event, submission.block.number)
            .await
            .wrap_err_with(|| {
                format!(
                    "validate finalized submitBatch in L1 block {} transaction {}",
                    submission.block.hash, submission.transaction_index
                )
            })?;

        self.wait_and_enqueue(to, batch, anchor).await
    }

    async fn fetch_submit_batch_calls(
        &self,
        submission: &FinalizedBatchSubmission,
    ) -> Result<Vec<submitBatchCall>> {
        let block = self
            .l1_provider
            .get_block_by_hash(submission.block.hash)
            .full()
            .await?
            .ok_or_eyre(format!("L1 block {} was not found", submission.block.hash))?;
        ensure!(
            block.header.number() == submission.block.number,
            "L1 block {} has number {}, expected {}",
            submission.block.hash,
            block.header.number(),
            submission.block.number
        );
        ensure!(
            block.header.as_ref().hash_slow() == submission.block.hash,
            "L1 block response does not match authenticated hash {}",
            submission.block.hash
        );
        let expected_transactions_root = block.header.transactions_root();
        let transactions = block
            .try_into_transactions()
            .map_err(|_| {
                eyre::eyre!(
                    "L1 block {} did not return full transactions",
                    submission.block.hash
                )
            })?
            .into_iter()
            .map(|transaction| transaction.into_inner())
            .collect::<Vec<_>>();
        verify_transactions_root(
            &transactions,
            expected_transactions_root,
            submission.block.hash,
        )?;
        let transaction_index = usize::try_from(submission.transaction_index)
            .wrap_err("L1 transaction index overflows usize")?;
        let tx = transactions.get(transaction_index).ok_or_eyre(format!(
            "L1 block {} has no transaction at authenticated receipt index {}",
            submission.block.hash, submission.transaction_index
        ))?;

        let calls = tx
            .calls()
            .filter_map(|(kind, input)| {
                if kind != TxKind::Call(self.portal_address) {
                    return None;
                }
                if submission.is_legacy {
                    legacySubmitBatchCall::abi_decode(input)
                        .ok()
                        .map(|call| submitBatchCall {
                            tempoBlockNumber: call.tempoBlockNumber,
                            recentTempoBlockNumber: call.recentTempoBlockNumber,
                            blockTransition: call.blockTransition,
                            depositQueueTransition: call.depositQueueTransition,
                            tokenEnablementTransition: TokenEnablementTransition {
                                prevProcessedTokenCount: 0,
                                nextProcessedTokenCount: 0,
                            },
                            withdrawalQueueHash: call.withdrawalQueueHash,
                            verifierConfig: call.verifierConfig,
                            proof: call.proof,
                            nextZoneHeight: call.nextZoneHeight,
                            signatures: call.signatures,
                        })
                } else {
                    submitBatchCall::abi_decode(input).ok()
                }
            })
            .collect::<Vec<_>>();

        ensure!(
            !calls.is_empty(),
            "L1 block {} transaction {} contains no submitBatch call to Portal {}",
            submission.block.hash,
            submission.transaction_index,
            self.portal_address
        );
        Ok(calls)
    }

    async fn submission_target(
        &self,
        call: &submitBatchCall,
        event: &BatchSubmitted,
        submission_block_number: u64,
    ) -> Result<(u64, BatchData, ShadowProofAnchor)> {
        ensure!(
            !call.signatures.is_empty(),
            "accepted submitBatch call has an empty quorum certificate"
        );
        let to =
            u64::try_from(call.nextZoneHeight).wrap_err("submitted Zone height overflows u64")?;
        let anchor_number =
            submitted_anchor_number(call.tempoBlockNumber, call.recentTempoBlockNumber)?;
        ensure!(
            anchor_number <= submission_block_number,
            "submitted anchor {anchor_number} is above submission block {submission_block_number}"
        );
        let anchor_hash = self
            .l1_provider
            .get_header_by_number(anchor_number.into())
            .await?
            .ok_or_eyre(format!(
                "submitted Tempo anchor {anchor_number} is unavailable"
            ))?
            .hash_slow();

        Ok((
            to,
            BatchData {
                zone_height: to,
                tempo_block_number: call.tempoBlockNumber,
                prev_block_hash: call.blockTransition.prevBlockHash,
                next_block_hash: call.blockTransition.nextBlockHash,
                prev_processed_deposit_hash: call.depositQueueTransition.prevProcessedHash,
                next_processed_deposit_hash: call.depositQueueTransition.nextProcessedHash,
                prev_deposit_number: call.depositQueueTransition.prevDepositNumber,
                next_deposit_number: call.depositQueueTransition.nextDepositNumber,
                prev_processed_token_count: call.tokenEnablementTransition.prevProcessedTokenCount,
                next_processed_token_count: call.tokenEnablementTransition.nextProcessedTokenCount,
                withdrawal_queue_hash: call.withdrawalQueueHash,
                withdrawal_batch_index: event.withdrawalBatchIndex,
            },
            ShadowProofAnchor {
                number: anchor_number,
                hash: anchor_hash,
            },
        ))
    }

    async fn wait_and_enqueue(
        &self,
        to: u64,
        batch: BatchData,
        anchor: ShadowProofAnchor,
    ) -> Result<()> {
        let from = self.wait_for_local_range(to, &batch).await?;

        info!(
            target: "zone::node::shadow_prover",
            zone_from = from,
            zone_to = to,
            anchor_number = anchor.number,
            anchor_hash = %anchor.hash,
            "Queueing finalized quorum-certified batch for shadow proving"
        );
        self.prover
            .enqueue_with_anchor(from, to, batch, anchor)
            .await
    }

    async fn wait_for_local_range(&self, to: u64, batch: &BatchData) -> Result<u64> {
        let from = loop {
            if batch.prev_block_hash.is_zero() {
                break 1;
            }
            if let Some(previous) = self.zone_provider.block_number(batch.prev_block_hash)? {
                break previous.saturating_add(1);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        };
        ensure!(from <= to, "submitted Zone range {from}..={to} is invalid");

        loop {
            let local_head = self.zone_provider.last_block_number()?;
            if local_head >= to {
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }

        ensure!(
            self.zone_provider.block_hash(to)? == Some(batch.next_block_hash),
            "local canonical Zone block {to} does not match finalized submission {}",
            batch.next_block_hash
        );
        if from > 1 {
            ensure!(
                self.zone_provider.block_hash(from - 1)? == Some(batch.prev_block_hash),
                "local parent of Zone range {from}..={to} does not match finalized submission {}",
                batch.prev_block_hash
            );
        }

        Ok(from)
    }
}

fn is_retryable_connection_error(error: &eyre::Report) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<TransportError>()
            .is_some_and(is_retryable_rpc_error)
    })
}

fn is_retryable_rpc_error(error: &TransportError) -> bool {
    match error {
        RpcError::ErrorResp(error) => error.is_retry_err(),
        RpcError::UnsupportedFeature(_)
        | RpcError::LocalUsageError(_)
        | RpcError::SerError(_)
        | RpcError::DeserError { .. }
        | RpcError::Transport(TransportErrorKind::NonRetryable(_)) => false,
        _ => true,
    }
}

fn verify_transactions_root(
    transactions: &[TempoTxEnvelope],
    expected: alloy_primitives::B256,
    block_hash: alloy_primitives::B256,
) -> Result<()> {
    let computed = calculate_transaction_root(transactions);
    ensure!(
        computed == expected,
        "transaction root mismatch for L1 block {block_hash}: expected {expected}, got {computed}"
    );
    Ok(())
}

fn call_matches_event(call: &submitBatchCall, event: &BatchSubmitted) -> bool {
    event.nextBlockHash == call.blockTransition.nextBlockHash
        && event.nextProcessedDepositQueueHash == call.depositQueueTransition.nextProcessedHash
        && event.lastProcessedDepositNumber == call.depositQueueTransition.nextDepositNumber
        && event.withdrawalQueueHash == call.withdrawalQueueHash
        && event.lastProcessedEnabledTokenCount
            == call.tokenEnablementTransition.nextProcessedTokenCount
}

fn submitted_anchor_number(tempo_block_number: u64, recent_tempo_block_number: u64) -> Result<u64> {
    if recent_tempo_block_number == 0 {
        return Ok(tempo_block_number);
    }
    ensure!(
        recent_tempo_block_number > tempo_block_number,
        "submitted ancestry anchor does not follow its Tempo checkpoint"
    );
    Ok(recent_tempo_block_number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_match_binds_t13_token_cursor() {
        use alloy_primitives::{B256, U256};
        use tempo_zone_contracts::{BlockTransition, DepositQueueTransition};

        let call = submitBatchCall {
            tempoBlockNumber: 10,
            recentTempoBlockNumber: 0,
            blockTransition: BlockTransition {
                prevBlockHash: B256::ZERO,
                nextBlockHash: B256::repeat_byte(1),
            },
            depositQueueTransition: DepositQueueTransition {
                prevProcessedHash: B256::ZERO,
                nextProcessedHash: B256::repeat_byte(2),
                prevDepositNumber: 0,
                nextDepositNumber: 3,
            },
            tokenEnablementTransition: TokenEnablementTransition {
                prevProcessedTokenCount: 2,
                nextProcessedTokenCount: 4,
            },
            withdrawalQueueHash: B256::repeat_byte(3),
            verifierConfig: Default::default(),
            proof: Default::default(),
            nextZoneHeight: U256::ONE,
            signatures: Vec::new(),
        };
        let mut event = BatchSubmitted {
            withdrawalBatchIndex: 1,
            withdrawalQueueIndex: U256::ZERO,
            nextProcessedDepositQueueHash: call.depositQueueTransition.nextProcessedHash,
            nextBlockHash: call.blockTransition.nextBlockHash,
            withdrawalQueueHash: call.withdrawalQueueHash,
            lastProcessedDepositNumber: call.depositQueueTransition.nextDepositNumber,
            lastProcessedEnabledTokenCount: 4,
        };
        assert!(call_matches_event(&call, &event));
        event.lastProcessedEnabledTokenCount = 3;
        assert!(!call_matches_event(&call, &event));
    }

    #[test]
    fn direct_submission_anchors_to_checkpoint() {
        assert_eq!(submitted_anchor_number(42, 0).unwrap(), 42);
    }

    #[test]
    fn ancestry_submission_uses_committed_recent_block() {
        assert_eq!(submitted_anchor_number(42, 100).unwrap(), 100);
    }

    #[test]
    fn ancestry_submission_must_follow_checkpoint() {
        assert!(submitted_anchor_number(42, 42).is_err());
        assert!(submitted_anchor_number(42, 41).is_err());
    }

    #[test]
    fn transaction_root_authentication_rejects_mismatch() {
        let transactions = Vec::<TempoTxEnvelope>::new();
        let expected = calculate_transaction_root(&transactions);

        verify_transactions_root(&transactions, expected, alloy_primitives::B256::ZERO).unwrap();
        assert!(
            verify_transactions_root(
                &transactions,
                alloy_primitives::B256::repeat_byte(0x42),
                alloy_primitives::B256::ZERO,
            )
            .is_err()
        );
    }

    #[test]
    fn retries_only_retryable_transport_errors() {
        let retryable = Err::<(), _>(TransportErrorKind::backend_gone())
            .wrap_err("fetch finalized block")
            .unwrap_err();
        assert!(is_retryable_connection_error(&retryable));

        let terminal = eyre::Report::new(TransportErrorKind::non_retryable_str("invalid request"));
        assert!(!is_retryable_connection_error(&terminal));
        assert!(!is_retryable_connection_error(&eyre::eyre!(
            "invalid settlement"
        )));
    }
}
