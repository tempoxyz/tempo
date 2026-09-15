//! Counterfactual replay of canonical blocks under candidate Tempo hardfork rules.
//!
//! The node continues to follow and persist the canonical chain normally. For each newly canonical
//! block, a worker replays its exact transactions using a cloned chainspec in which every Tempo
//! fork through the configured candidate is active:
//!
//! ```text
//! candidate[N] = CandidateRules(CanonicalState[N - 1], CanonicalBlock[N])
//! ```
//!
//! Replay starts from the canonical parent state and keeps all writes in a private in-memory
//! overlay. The overlay is discarded after collecting transaction status, gas, logs, and output
//! hashes; it is never persisted, submitted to forkchoice, or reused by later blocks.
//!
//! Candidate status, gas, and logs are first compared with canonical receipts. On a mismatch, the
//! block is replayed under canonical rules as a control, which must reproduce those receipts before
//! a candidate divergence is reported. The control also provides output hashes, so output-only
//! differences are detectable between the two replay runs, but not directly from receipts. If a
//! candidate transaction is invalid, the remaining block suffix is inconclusive because it no
//! longer has a valid candidate state prefix.

use alloy::consensus::BlockHeader as _;
use alloy_evm::block::{BlockExecutor as _, TxResult as _};
use alloy_primitives::{B256, Log, keccak256};
use alloy_rlp::{encode_list, list_length};
use reth_chainspec::ForkCondition;
use reth_ethereum::tasks::TaskExecutor;
use reth_evm::ConfigureEvm as _;
use reth_primitives_traits::{RecoveredBlock, transaction::TxHashRef as _};
use reth_provider::{CanonStateSubscriptions, ChainSpecProvider, StateProviderFactory};
use reth_revm::{database::StateProviderDatabase, db::State};
use reth_tracing::tracing::{debug, error, info, info_span, warn};
use std::{sync::Arc, time::Instant};
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{TempoChainSpec, TempoHardforks as _},
};
use tempo_evm::{TempoEvmConfig, TempoTxResult};
use tempo_primitives::{Block, TempoPrimitives, TempoReceipt};
use tokio::sync::broadcast::error::RecvError;

/// Replays canonical blocks under candidate rules without changing canonical state.
#[derive(Debug)]
pub struct ShadowReplayer<P> {
    provider: P,
    control_config: TempoEvmConfig,
    candidate_config: TempoEvmConfig,
    candidate_hardfork: TempoHardfork,
}

impl<P> ShadowReplayer<P>
where
    P: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + Send
        + Sync
        + 'static,
{
    pub fn new(provider: P, candidate_hardfork: TempoHardfork) -> Self {
        let canonical_spec = provider.chain_spec();
        let candidate_spec = Arc::new(candidate_chain_spec(&canonical_spec, candidate_hardfork));
        Self {
            control_config: TempoEvmConfig::new(canonical_spec),
            candidate_config: TempoEvmConfig::new(candidate_spec),
            provider,
            candidate_hardfork,
        }
    }

    /// Spawns the replay task. Lagged notifications are reported rather than backfilled.
    pub fn spawn(self, executor: TaskExecutor) {
        let mut notifications = self.provider.subscribe_to_canonical_state();
        let hardfork = self.candidate_hardfork;
        let replayer = Arc::new(self);
        let worker = executor.clone();
        executor.spawn_task(async move {
            info!(target: "shadow_replay", %hardfork, "Started counterfactual shadow replay");
            loop {
                let notification = match notifications.recv().await {
                    Ok(notification) => notification,
                    Err(RecvError::Lagged(skipped)) => {
                        metrics::counter!("tempo_shadow_replay_notifications_lagged_total")
                            .increment(skipped);
                        error!(target: "shadow_replay", skipped, "Shadow replay missed canonical blocks");
                        continue;
                    }
                    Err(RecvError::Closed) => return,
                };

                if let Some(reverted) = notification.reverted() {
                    warn!(
                        target: "shadow_replay",
                        from = reverted.first().number(),
                        to = reverted.tip().number(),
                        "Shadow replay findings for reverted blocks are stale"
                    );
                }

                let committed = notification.committed();
                for block in committed.blocks().values() {
                    let span = info_span!(
                        target: "shadow_replay",
                        "shadow_replay",
                        block_number = block.number(),
                        block_hash = ?block.hash(),
                        %hardfork,
                    );

                    if replayer
                        .control_config
                        .chain_spec()
                        .tempo_hardfork_at(block.timestamp())
                        >= hardfork
                    {
                        span.in_scope(|| {
                            debug!(target: "shadow_replay", "Candidate already active on canonical chain")
                        });
                        continue;
                    }

                    let block_number = block.number();
                    let chain = Arc::clone(&committed);
                    let replayer = Arc::clone(&replayer);
                    let started_at = Instant::now();
                    let result = worker
                        .spawn_blocking(move || {
                            let block = &chain.blocks()[&block_number];
                            let receipts = chain.execution_outcome().receipts_by_block(block_number);
                            replayer.replay(block, receipts)
                        })
                        .await;
                    metrics::histogram!("shadow_replay_execution_duration_seconds")
                        .record(started_at.elapsed().as_secs_f64());

                    // Entered only after the await so the span never leaks across a yield point.
                    let _guard = span.enter();
                    match result {
                        Ok(Ok(finding)) => finding.report(),
                        Ok(Err(err)) => {
                            metrics::counter!("tempo_shadow_replay_blocks_total", "result" => "error")
                                .increment(1);
                            error!(target: "shadow_replay", %err, "Shadow replay failed");
                            continue;
                        }
                        Err(err) => {
                            metrics::counter!("tempo_shadow_replay_blocks_total", "result" => "panic")
                                .increment(1);
                            error!(target: "shadow_replay", %err, "Shadow replay worker panicked");
                            continue;
                        }
                    };
                    metrics::counter!("tempo_shadow_replay_blocks_total", "result" => "success")
                        .increment(1);
                    metrics::gauge!("shadow_replay_latest_completed_block")
                        .set(block.number() as f64);
                }
            }
        });
    }
}

impl<P: StateProviderFactory> ShadowReplayer<P> {
    fn replay(
        &self,
        block: &RecoveredBlock<Block>,
        canonical_receipts: &[TempoReceipt],
    ) -> Result<Finding, String> {
        let canonical = observe_receipts(canonical_receipts);
        let candidate = self.execute(&self.candidate_config, block)?;
        if candidate.reproduces(&canonical) {
            return Ok(Finding::Match);
        }

        // Something differs: confirm the replay setup by reproducing canonical receipts under
        // canonical rules, then report the first difference against that control run.
        let control = self.execute(&self.control_config, block)?;
        if let Some(failure) = &control.failure {
            return Err(format!("control execution failed: {}", failure.error));
        }
        if !control.reproduces(&canonical) {
            return Err("control execution does not reproduce canonical receipts".into());
        }

        if let Some((index, diff)) = first_divergence(&control.txs, &candidate.txs) {
            return Ok(Finding::Divergence {
                tx: TxCursor::new(block, index),
                diff,
            });
        }

        candidate.failure.map(Finding::Inconclusive).ok_or_else(|| {
            "candidate replay did not reproduce canonical receipts but has no control \
                 divergence or execution failure"
                .to_string()
        })
    }

    /// Executes `block` on top of its parent state in a private overlay that is dropped on return.
    fn execute(
        &self,
        evm_config: &TempoEvmConfig,
        block: &RecoveredBlock<Block>,
    ) -> Result<Evidence, String> {
        let state_provider = self
            .provider
            .state_by_block_hash(block.parent_hash())
            .map_err(|err| format!("failed to open parent state {}: {err}", block.parent_hash()))?;
        let mut db = State::builder()
            .with_database(StateProviderDatabase::new(&state_provider))
            .build();
        let mut executor = evm_config
            .executor_for_block(&mut db, block.sealed_block())
            .map_err(|err| format!("failed to configure block executor: {err}"))?;

        let mut evidence = Evidence::default();
        if let Err(err) = executor.apply_pre_execution_changes() {
            return Ok(evidence.fail(None, format!("pre-execution changes failed: {err}")));
        }

        for (index, tx) in block.transactions_recovered().enumerate() {
            match executor.execute_transaction_without_commit(tx) {
                Ok(result) => {
                    evidence.txs.push((&result).into());
                    executor.commit_transaction(result);
                }
                Err(err) => return Ok(evidence.fail(Some(TxCursor::new(block, index)), err)),
            }
        }

        match executor.finish() {
            Ok(_) => Ok(evidence),
            Err(err) => Ok(evidence.fail(None, format!("post-execution changes failed: {err}"))),
        }
    }
}

/// Canonical location of a transaction within a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TxCursor {
    block_number: u64,
    tx_index: usize,
    tx_hash: B256,
}

impl TxCursor {
    fn new(block: &RecoveredBlock<Block>, index: usize) -> Self {
        Self {
            block_number: block.number(),
            tx_index: index,
            tx_hash: *block.body().transactions[index].tx_hash(),
        }
    }
}

/// The first terminal interpretation of a candidate replay.
#[derive(Debug, PartialEq, Eq)]
enum Finding {
    Match,
    Divergence { tx: TxCursor, diff: TxDiff },
    Inconclusive(Failure),
}

impl Finding {
    fn report(self) {
        match self {
            Self::Match => debug!(target: "shadow_replay", "Candidate replay match"),
            Self::Divergence { tx, diff } => {
                metrics::counter!("tempo_shadow_replay_findings_total", "kind" => "divergence")
                    .increment(1);
                warn!(
                    target: "shadow_replay",
                    ?tx,
                    ?diff,
                    "Candidate replay divergence"
                );
            }
            Self::Inconclusive(failure) => {
                metrics::counter!("tempo_shadow_replay_findings_total", "kind" => "inconclusive")
                    .increment(1);
                warn!(
                    target: "shadow_replay",
                    tx = ?failure.tx,
                    error = %failure.error,
                    "Candidate replay is inconclusive"
                );
            }
        }
    }
}

/// Execution failure after which the remaining block suffix is inconclusive.
#[derive(Debug, PartialEq, Eq)]
struct Failure {
    /// Failing transaction, or `None` for pre/post-execution failures.
    tx: Option<TxCursor>,
    error: String,
}

/// Per-transaction observations of one block execution, up to the first failure.
#[derive(Debug, Default)]
struct Evidence {
    txs: Vec<ObservedTx>,
    failure: Option<Failure>,
}

impl Evidence {
    fn fail(mut self, tx: Option<TxCursor>, error: impl ToString) -> Self {
        self.failure = Some(Failure {
            tx,
            error: error.to_string(),
        });
        self
    }

    /// Whether this execution completed and reproduced every canonical receipt.
    fn reproduces(&self, canonical: &[ObservedTx]) -> bool {
        self.failure.is_none()
            && self.txs.len() == canonical.len()
            && first_divergence(canonical, &self.txs).is_none()
    }
}

/// Compact, comparable outcome of one transaction.
#[derive(Debug, PartialEq, Eq)]
struct ObservedTx {
    success: bool,
    gas_used: u64,
    logs_hash: B256,
    /// Hash of the output or revert data; `None` when unobservable (canonical receipts).
    output_hash: Option<B256>,
}

impl From<&TempoTxResult> for ObservedTx {
    fn from(result: &TempoTxResult) -> Self {
        let result = &result.result().result;
        Self {
            success: result.is_success(),
            gas_used: result.tx_gas_used(),
            logs_hash: hash_logs(result.logs()),
            output_hash: Some(keccak256(result.output().map_or(&[][..], |out| out))),
        }
    }
}

/// Which observed fields of a transaction changed between two executions.
#[derive(Debug, PartialEq, Eq)]
struct TxDiff {
    status: bool,
    gas: bool,
    logs: bool,
    output: bool,
}

impl TxDiff {
    /// Returns which observed fields differ, or `None` if the transactions are equivalent.
    fn between(some: &ObservedTx, other: &ObservedTx) -> Option<Self> {
        let diff = Self {
            status: some.success != other.success,
            gas: some.gas_used != other.gas_used,
            logs: some.logs_hash != other.logs_hash,
            output: some
                .output_hash
                .zip(other.output_hash)
                .is_some_and(|(a, b)| a != b),
        };
        (diff.status || diff.gas || diff.logs || diff.output).then_some(diff)
    }
}

fn observe_receipts(receipts: &[TempoReceipt]) -> Vec<ObservedTx> {
    let mut previous_cumulative_gas = 0;
    receipts
        .iter()
        .map(|receipt| {
            let gas_used = receipt.cumulative_gas_used - previous_cumulative_gas;
            previous_cumulative_gas = receipt.cumulative_gas_used;
            ObservedTx {
                success: receipt.success,
                gas_used,
                logs_hash: hash_logs(&receipt.logs),
                output_hash: None,
            }
        })
        .collect()
}

/// Clones `canonical` and activates all Tempo forks from `Genesis` until (including) `hardfork`.
fn candidate_chain_spec(canonical: &TempoChainSpec, hardfork: TempoHardfork) -> TempoChainSpec {
    let mut candidate = canonical.clone();
    for &fork in TempoHardfork::VARIANTS
        .iter()
        .take_while(|&&fork| fork <= hardfork)
    {
        candidate
            .inner
            .hardforks
            .insert(fork, ForkCondition::Timestamp(0));
    }
    candidate
}

fn first_divergence(reference: &[ObservedTx], candidate: &[ObservedTx]) -> Option<(usize, TxDiff)> {
    reference
        .iter()
        .zip(candidate)
        .enumerate()
        .find_map(|(index, (reference, candidate))| {
            TxDiff::between(reference, candidate).map(|diff| (index, diff))
        })
}

fn hash_logs(logs: &[Log]) -> B256 {
    let mut encoded = Vec::with_capacity(list_length(logs));
    encode_list(logs, &mut encoded);
    keccak256(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(gas_used: u64, output_hash: Option<B256>) -> ObservedTx {
        ObservedTx {
            success: true,
            gas_used,
            logs_hash: B256::ZERO,
            output_hash,
        }
    }

    #[test]
    fn reports_first_divergence_and_ignores_unobservable_output() {
        let reference = [observed(10, None), observed(20, None)];
        let candidate = [
            observed(10, Some(B256::repeat_byte(1))),
            observed(21, Some(B256::repeat_byte(2))),
        ];
        let (index, diff) = first_divergence(&reference, &candidate).unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            diff,
            TxDiff {
                status: false,
                gas: true,
                logs: false,
                output: false
            }
        );

        let control = [observed(10, Some(B256::repeat_byte(1)))];
        let candidate = [observed(10, Some(B256::repeat_byte(3)))];
        let (index, diff) = first_divergence(&control, &candidate).unwrap();
        assert_eq!(index, 0);
        assert!(diff.output && !diff.gas);
    }

    #[test]
    fn candidate_schedule_activates_prefix_without_mutating_canonical() {
        let canonical = TempoChainSpec::mainnet();
        let canonical_activation = canonical.tempo_fork_activation(TempoHardfork::T13);
        let candidate = candidate_chain_spec(&canonical, TempoHardfork::T12);

        assert_eq!(candidate.tempo_hardfork_at(0), TempoHardfork::T12);
        assert_eq!(
            candidate.tempo_fork_activation(TempoHardfork::T13),
            canonical_activation
        );
        assert_eq!(
            canonical.tempo_fork_activation(TempoHardfork::T13),
            canonical_activation
        );
    }
}
