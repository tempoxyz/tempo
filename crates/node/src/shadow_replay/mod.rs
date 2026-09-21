//! Counterfactual replay of canonical blocks under shadow (candidate) Tempo hardfork rules.
//!
//! The node follows and persists the canonical chain. For each newly canonical block, executes
//! its exact transactions independently under real (control) and shadow (candidate) rules:
//!
//! ```text
//! real[N]   = CanonicalHardforkRules(CanonicalState[N - 1], CanonicalBlock[N])
//! shadow[N] = CandidateHardforkRules(CanonicalState[N - 1], CanonicalBlock[N])
//! ```
//!
//! Each execution opens its own parent-state provider and keeps writes in a private in-memory
//! overlay. Overlays are discarded after collecting receipt observations, outputs, fee provenance,
//! and net state transitions. They are never persisted, submitted to forkchoice, shared between
//! executions, or reused by later blocks.
//!
//! Control re-execution must reproduce canonical receipts. Failure or divergence indicates a
//! non-canonical STF and terminates live replay. Shadow findings never stop replay.
//!
//! Analysis compares completed pre-block, transaction, and post-block boundaries in order.
//! It compares net committed effects at each boundary—not complete state equality, write history,
//! or effects under identical evolving prefixes. Expectations classify individual differences;
//! a state/context difference ends analysis after its boundary unless the first accepting rule
//! establishes comparability. Expected differences and incomplete coverage are reported separately.

mod analysis;
mod fees;

use alloy::consensus::BlockHeader as _;
use alloy_evm::{
    Evm as _,
    block::{BlockExecutor as _, TxResult as _},
};
use alloy_primitives::{B256, keccak256};
use alloy_rlp::{encode_list, list_length};
use analysis::Report;
use fees::{FeeWrites, RecordingFeeManager};
use reth_chainspec::ForkCondition;
use reth_ethereum::tasks::TaskExecutor;
use reth_evm::ConfigureEvm as _;
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{CanonStateSubscriptions, ChainSpecProvider, StateProviderFactory};
use reth_revm::{
    database::StateProviderDatabase,
    db::{State, TransitionState},
};
use reth_tracing::tracing::{debug, error, info, info_span, warn};
use std::{cell::RefCell, collections::HashSet, rc::Rc, sync::Arc, time::Instant};
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{TempoChainSpec, TempoHardforks as _},
};
use tempo_evm::{TempoEvmConfig, TempoTxResult};
use tempo_primitives::{Block, TempoPrimitives, TempoReceipt};
use tokio::sync::broadcast::error::RecvError;

/// Result of replaying one canonical block under candidate hardfork rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// All boundaries matched without differences.
    Match,
    /// Every difference was accepted and all boundaries were compared.
    Expected,
    /// No unexplained finding, but subsequent comparisons could not be trusted.
    Inconclusive,
    /// At least one difference or execution failure remains unexplained.
    Findings,
}

/// Replays canonical blocks under candidate rules without changing canonical state.
#[derive(Debug)]
pub struct ShadowReplayer<P> {
    provider: P,
    real_config: TempoEvmConfig,
    shadow_config: TempoEvmConfig,
    shadow_hardfork: TempoHardfork,
}

impl<P: ChainSpecProvider<ChainSpec = TempoChainSpec>> ShadowReplayer<P> {
    pub fn new(provider: P, shadow_hardfork: TempoHardfork) -> Self {
        let canonical_spec = provider.chain_spec();
        let shadow_spec = Arc::new(shadow_spec(&canonical_spec, shadow_hardfork));
        Self {
            real_config: TempoEvmConfig::new(canonical_spec),
            shadow_config: TempoEvmConfig::new(shadow_spec),
            provider,
            shadow_hardfork,
        }
    }
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
    /// Spawns the replay task. Lagged notifications are reported rather than backfilled.
    ///
    /// Runs as a critical task: a control-arm failure panics the task, which shuts the node down.
    pub fn spawn(self, executor: TaskExecutor) {
        let mut notifs = self.provider.subscribe_to_canonical_state();
        let hardfork = self.shadow_hardfork;
        let replayer = Arc::new(self);
        let worker = executor.clone();
        executor.spawn_critical_task("shadow replay", async move {
            info!(target: "shadow_replay", %hardfork, "Started counterfactual shadow replay");
            loop {
                let notif = match notifs.recv().await {
                    Ok(notif) => notif,
                    Err(RecvError::Lagged(skipped)) => {
                        metrics::counter!("tempo_shadow_replay_notifications_lagged_total")
                            .increment(skipped);
                        error!(target: "shadow_replay", skipped, "Shadow replay missed canonical blocks");
                        continue;
                    }
                    Err(RecvError::Closed) => return,
                };

                if let Some(reverted) = notif.reverted() {
                    warn!(
                        target: "shadow_replay",
                        from = reverted.first().number(),
                        to = reverted.tip().number(),
                        "Shadow replay findings for reverted blocks are stale"
                    );
                }

                let committed = notif.committed();
                for block in committed.blocks().values() {
                    let span = info_span!(
                        target: "shadow_replay",
                        "shadow_replay",
                        block_number = block.number(),
                        block_hash = ?block.hash(),
                        %hardfork,
                    );
                    if replayer
                        .real_config
                        .chain_spec()
                        .tempo_hardfork_at(block.timestamp())
                        >= hardfork
                    {
                        span.in_scope(|| {
                            debug!(target: "shadow_replay", "Candidate already active on canonical chain")
                        });
                        continue;
                    }

                    let number = block.number();
                    let chain = Arc::clone(&committed);
                    let replay = Arc::clone(&replayer);
                    let started_at = Instant::now();
                    let result = worker
                        .spawn_blocking(move || {
                            let block = &chain.blocks()[&number];
                            replay.replay(
                                block,
                                chain.execution_outcome().receipts_by_block(number),
                            )
                        })
                        .await;
                    metrics::histogram!("tempo_shadow_replay_execution_duration_seconds")
                        .record(started_at.elapsed().as_secs_f64());

                    // Entered only after the await so the span never leaks across a yield point.
                    let _guard = span.enter();
                    let err = match result {
                        Ok(Ok(_)) => {
                            metrics::gauge!("tempo_shadow_replay_latest_completed_block").set(number as f64);
                            metrics::counter!("tempo_shadow_replay_blocks_total").increment(1);
                            continue;
                        }
                        Ok(Err(err)) => err,
                        Err(err) => format!("shadow replay worker panicked: {err}"),
                    };
                    error!(target: "shadow_replay", %err, "Control re-execution diverged from canonical chain");
                    panic!("shadow replay control failure at block {number}: {err}");
                }
            }
        });
    }
}

impl<P: StateProviderFactory + Sync> ShadowReplayer<P> {
    /// Replays a canonical block under both rule sets.
    /// IMPORTANT: An error means the control arm can't be trusted. Callers must treat it as fatal.
    pub fn replay(
        &self,
        block: &RecoveredBlock<Block>,
        receipts: &[TempoReceipt],
    ) -> Result<ReplayOutcome, String> {
        let (real, shadow) = std::thread::scope(|scope| {
            let shadow = scope.spawn(|| self.execute(&self.shadow_config, block));
            let real = self.execute(&self.real_config, block);
            (real, shadow.join())
        });
        let real = real?;
        let shadow = shadow.map_err(|_| "shadow execution panicked".to_string())??;
        if let Some(f) = &real.failure {
            return Err(format!(
                "re-execution failed at {:?}: {}",
                f.boundary, f.error
            ));
        }
        if !matches_receipts(&real.txs, receipts) {
            return Err("re-execution does not reproduce canonical receipts".into());
        }

        let canonical = self
            .real_config
            .chain_spec()
            .tempo_hardfork_at(block.timestamp());
        let rules = analysis::between(canonical, self.shadow_hardfork);
        let report = Report::analyze(&real, &shadow, &rules);
        let outcome = report.outcome(&shadow);
        metrics::counter!("tempo_shadow_replay_boundaries_total", "result" => "compared")
            .increment(report.boundaries_evaluated as u64);
        metrics::counter!("tempo_shadow_replay_boundaries_total", "result" => "inconclusive")
            .increment(report.boundaries_not_evaluated as u64);
        for (&rule, &count) in &report.expected {
            metrics::counter!("tempo_shadow_replay_expected_differences_total", "rule" => rule)
                .increment(count as u64);
        }
        metrics::counter!("tempo_shadow_replay_unexplained_differences_total")
            .increment(report.unexplained as u64);
        if matches!(outcome, ReplayOutcome::Match | ReplayOutcome::Expected) {
            debug!(target: "shadow_replay", ?outcome, ?report, "Shadow replay compared all boundaries");
            return Ok(outcome);
        }

        let kind = if outcome == ReplayOutcome::Inconclusive {
            "inconclusive"
        } else {
            "unexplained"
        };
        metrics::counter!("tempo_shadow_replay_findings_total", "kind" => kind).increment(1);
        let failure = shadow.failure.as_ref();
        let after_cutoff = failure
            .zip(report.cutoff)
            .is_some_and(|(failure, cutoff)| failure.boundary > cutoff);
        warn!(
            target: "shadow_replay",
            block_number = block.number(),
            block_hash = ?block.hash(),
            findings = ?report,
            shadow_failure_boundary = ?failure.map(|f| f.boundary),
            shadow_failure = failure.map(|f| f.error.as_str()).unwrap_or(""),
            failure_after_cutoff = after_cutoff,
            ?outcome,
            real_completed_txs = real.txs.len(),
            shadow_completed_txs = shadow.txs.len(),
            "Shadow replay needs review; differences are not confirmed regressions"
        );
        Ok(outcome)
    }

    /// Executes `block` on top of its canonical parent in an isolated, disposable overlay.
    ///
    /// Completed boundary transitions are drained immediately. A failed boundary is recorded but
    /// never exposed as a completed state effect, and execution never resumes after a rejected
    /// transaction.
    fn execute(
        &self,
        config: &TempoEvmConfig,
        block: &RecoveredBlock<Block>,
    ) -> Result<Evidence, String> {
        let drain = |db: &mut State<_>| {
            db.transition_state
                .as_mut()
                .expect("bundle updates enabled")
                .take()
        };

        let provider = self
            .provider
            .state_by_block_hash(block.parent_hash())
            .map_err(|e| format!("failed to open parent state {}: {e}", block.parent_hash()))?;
        let mut db = State::builder()
            .with_database(StateProviderDatabase::new(&provider))
            .with_bundle_update()
            .build();
        let writes = Rc::new(RefCell::new(FeeWrites::default()));
        let evm = config
            .evm_for_block(&mut db, block.header())
            .map_err(|e| format!("failed to configure EVM: {e}"))?
            .with_fee_manager(RecordingFeeManager(Rc::clone(&writes)));
        let context = config
            .context_for_block(block.sealed_block())
            .map_err(|e| format!("failed to configure executor: {e}"))?;
        let mut executor = config.create_executor(evm, context);
        let mut evidence = Evidence::default();
        if let Err(e) = executor.apply_pre_execution_changes() {
            return Ok(evidence.fail(Boundary::PreBlock, e.to_string()));
        }
        evidence.pre_block = Some(drain(executor.evm_mut().db_mut()));
        for (index, tx) in block.transactions_recovered().enumerate() {
            let result = match executor.execute_transaction_without_commit(tx) {
                Ok(r) => r,
                Err(e) => return Ok(evidence.fail(Boundary::Transaction(index), e.to_string())),
            };
            let scratch = std::mem::take(&mut *writes.borrow_mut());
            let observed = ObservedTx::from_result(&result, scratch);
            executor.commit_transaction(result);
            evidence.txs.push(ObservedTx {
                state: drain(executor.evm_mut().db_mut()),
                ..observed
            });
        }
        match executor.finish() {
            Ok((mut evm, _)) => evidence.post_block = Some(drain(evm.db_mut())),
            Err(e) => return Ok(evidence.fail(Boundary::PostBlock, e.to_string())),
        }
        Ok(evidence)
    }
}

/// Receipt-derivable transaction fields used for canonical validation and replay comparison.
#[derive(Debug, PartialEq, Eq)]
struct ReceiptObservation {
    success: bool,
    gas_used: u64,
    logs_hash: B256,
}

/// Execution evidence retained for one successfully committed transaction.
///
/// Section/block gas consumption is tracked separately because it can diverge even when
/// receipt gas is unchanged.
#[derive(Debug)]
struct ObservedTx {
    receipt: ReceiptObservation,
    block_gas_used: u64,
    output_hash: B256,
    logs_hash: B256,
    fee_logs_hash: B256,
    fee_slots: HashSet<(alloy_primitives::Address, alloy_primitives::U256)>,
    state: TransitionState,
}

impl ObservedTx {
    fn from_result(result: &TempoTxResult, writes: FeeWrites) -> Self {
        let execution = &result.result().result;
        let logs = execution.logs();
        let (mut app, mut fee) = (Vec::new(), Vec::new());
        for (index, log) in logs.iter().enumerate() {
            if writes.log_ranges.iter().any(|range| range.contains(&index)) {
                fee.push(log);
            } else {
                app.push(log);
            }
        }
        Self {
            block_gas_used: result.block_gas_used(),
            receipt: ReceiptObservation {
                success: execution.is_success(),
                gas_used: execution.tx_gas_used(),
                logs_hash: hash_logs(logs),
            },
            output_hash: keccak256(execution.output().map_or(&[][..], |x| x)),
            logs_hash: hash_logs(&app),
            fee_logs_hash: hash_logs(&fee),
            fee_slots: writes.slots,
            state: TransitionState::default(),
        }
    }
}

/// A logical execution boundary whose committed effects can be compared independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Boundary {
    PreBlock,
    Transaction(usize),
    PostBlock,
}

/// Execution failure located at the first boundary that did not complete.
#[derive(Debug)]
struct Failure {
    boundary: Boundary,
    error: String,
}

/// Completed boundary evidence and, when present, the first execution failure.
///
/// `None` for pre/post-block state means that boundary did not complete. `Some(empty)` means it
/// completed without a net recorded effect.
#[derive(Debug, Default)]
struct Evidence {
    pre_block: Option<TransitionState>,
    txs: Vec<ObservedTx>,
    post_block: Option<TransitionState>,
    failure: Option<Failure>,
}

impl Evidence {
    fn fail(mut self, boundary: Boundary, error: String) -> Self {
        self.failure = Some(Failure { boundary, error });
        self
    }
}

fn matches_receipts(txs: &[ObservedTx], receipts: &[TempoReceipt]) -> bool {
    if txs.len() != receipts.len() {
        return false;
    }

    let mut previous_gas = 0;
    txs.iter().zip(receipts).all(|(tx, receipt)| {
        let gas_used = receipt.cumulative_gas_used - previous_gas;
        previous_gas = receipt.cumulative_gas_used;
        tx.receipt
            == ReceiptObservation {
                success: receipt.success,
                gas_used,
                logs_hash: hash_logs(&receipt.logs),
            }
    })
}

fn hash_logs<T: alloy_rlp::Encodable>(logs: &[T]) -> B256 {
    let mut encoded = Vec::with_capacity(list_length(logs));
    encode_list(logs, &mut encoded);
    keccak256(encoded)
}

fn shadow_spec(canonical: &TempoChainSpec, hardfork: TempoHardfork) -> TempoChainSpec {
    let mut c = canonical.clone();
    for &fork in TempoHardfork::VARIANTS
        .iter()
        .take_while(|&&f| f <= hardfork)
    {
        c.inner.hardforks.insert(fork, ForkCondition::Timestamp(0));
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shadow_schedule_activates_prefix_without_mutating_canonical() {
        let canonical = TempoChainSpec::mainnet();
        let activation = canonical.tempo_fork_activation(TempoHardfork::T13);
        let shadow = shadow_spec(&canonical, TempoHardfork::T12);
        assert_eq!(shadow.tempo_hardfork_at(0), TempoHardfork::T12);
        assert_eq!(
            canonical.tempo_fork_activation(TempoHardfork::T13),
            activation
        );
    }
}
