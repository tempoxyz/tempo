//! Counterfactual replay of canonical blocks under shadow (candidate) Tempo hardfork rules.
//!
//! The node follows and persists the canonical chain. For each newly canonical block, it executes
//! every transaction under both the canonical (control) and candidate rules from the same canonical
//! prefix. The candidate result is observed, then discarded; the control result advances both
//! executors before the next transaction. This isolates differences to the transaction that caused
//! them instead of cascading candidate state through the rest of the block.
//!
//! Execution uses private in-memory overlays. Candidate writes are never persisted, submitted to
//! forkchoice, or used as prestate for another transaction or block.
//!
//! Control re-execution must reproduce canonical receipts. Failure or divergence indicates a
//! non-canonical STF and terminates live replay. Shadow findings never stop replay.
//!
//! Analysis compares completed pre-block, transaction, and post-block boundaries in order. It
//! compares net effects at each boundary—not complete state equality or write history. Expectations
//! classify individual differences, and incomplete coverage is reported separately.

mod analysis;
mod fees;

use alloy::{consensus::BlockHeader as _, sol_types::SolEvent as _};
use alloy_evm::{
    Evm as _,
    block::{BlockExecutor as _, TxResult as _},
};
use alloy_primitives::{B256, U256, keccak256};
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
    database_interface::bal::BalState,
    db::{CacheState, State, TransitionState},
    state::EvmState,
};
use reth_tracing::tracing::{debug, error, info, info_span, warn};
use std::{cell::RefCell, collections::HashSet, rc::Rc, sync::Arc, time::Instant};
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{TempoChainSpec, TempoHardforks as _},
};
use tempo_contracts::precompiles::{ITIP20, TIP_FEE_MANAGER_ADDRESS};
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
        let (real, shadow) = self.execute(block)?;
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
        let report = Report::analyze(&real, &shadow, &rules, block);
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
        warn!(
            target: "shadow_replay",
            block_number = block.number(),
            block_hash = ?block.hash(),
            findings = ?report,
            shadow_failure_boundary = ?failure.map(|f| f.boundary),
            shadow_failure = failure.map(|f| f.error.as_str()).unwrap_or(""),
            ?outcome,
            real_processed_txs = real.txs.len(),
            shadow_processed_txs = shadow.txs.len(),
            "Shadow replay needs review; differences are not confirmed regressions"
        );
        Ok(outcome)
    }

    /// Executes each transaction under both rule sets from the same canonical prefix.
    ///
    /// The candidate result is observed but never committed. Committing the control result into
    /// both executors gives the next candidate transaction the exact same prestate and block
    /// execution context as the control, so one difference cannot cascade through the block.
    fn execute(&self, block: &RecoveredBlock<Block>) -> Result<(Evidence, Evidence), String> {
        let provider = self
            .provider
            .state_by_block_hash(block.parent_hash())
            .map_err(|e| format!("failed to open parent state {}: {e}", block.parent_hash()))?;
        let mut db = State::builder()
            .with_database(StateProviderDatabase::new(&provider))
            .with_bundle_update()
            .build();
        let writes = Rc::new(RefCell::new(FeeWrites::default()));
        let evm = self
            .real_config
            .evm_for_block(&mut db, block.header())
            .map_err(|e| format!("failed to configure control EVM: {e}"))?
            .with_fee_manager(RecordingFeeManager(Rc::clone(&writes)));
        let context = self
            .real_config
            .context_for_block(block.sealed_block())
            .map_err(|e| format!("failed to configure control executor: {e}"))?;
        let mut executor = self.real_config.create_executor(evm, context);
        let mut real = Evidence::default();
        if let Err(e) = executor.apply_pre_execution_changes() {
            return Ok((
                real.fail(Boundary::PreBlock, e.to_string()),
                Evidence::default(),
            ));
        }
        real.pre_block = Some(drain(executor.evm_mut().db_mut()));

        // A one-entry queue pipelines the two arms without retaining an unbounded number of cloned
        // control results when one arm runs ahead.
        let (results, canonical_results) = std::sync::mpsc::sync_channel(1);
        let canonical_cache = executor.evm().db().cache.clone();
        let canonical_bal = executor.evm().db().bal_state.clone();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                self.execute_shadow(block, canonical_cache, canonical_bal, canonical_results)
            });
            let mut results = Some(results);
            for (index, tx) in block.transactions_recovered().enumerate() {
                let result = match executor.execute_transaction_without_commit(tx) {
                    Ok(result) => result,
                    Err(e) => {
                        real = real.fail(Boundary::Transaction(index), e.to_string());
                        break;
                    }
                };
                let observed =
                    ObservedTx::from_result(&result, std::mem::take(&mut *writes.borrow_mut()));
                if results
                    .as_ref()
                    .is_some_and(|sender| sender.send(result.clone()).is_err())
                {
                    results = None;
                }
                executor.commit_transaction(result);
                real.txs
                    .push(Ok(observed.with_state(drain(executor.evm_mut().db_mut()))));
            }
            drop(results);
            if real.failure.is_none() {
                match executor.finish() {
                    Ok((mut evm, _)) => real.post_block = Some(drain(evm.db_mut())),
                    Err(e) => real = real.fail(Boundary::PostBlock, e.to_string()),
                }
            }
            let shadow = worker
                .join()
                .map_err(|_| "shadow execution panicked".to_string())??;
            Ok((real, shadow))
        })
    }

    fn execute_shadow(
        &self,
        block: &RecoveredBlock<Block>,
        canonical_cache: CacheState,
        canonical_bal: BalState,
        canonical_results: std::sync::mpsc::Receiver<TempoTxResult>,
    ) -> Result<Evidence, String> {
        let provider = self
            .provider
            .state_by_block_hash(block.parent_hash())
            .map_err(|e| {
                format!(
                    "failed to open shadow parent state {}: {e}",
                    block.parent_hash()
                )
            })?;
        let mut db = State::builder()
            .with_database(StateProviderDatabase::new(&provider))
            .with_bundle_update()
            .build();
        let writes = Rc::new(RefCell::new(FeeWrites::default()));
        let evm = self
            .shadow_config
            .evm_for_block(&mut db, block.header())
            .map_err(|e| format!("failed to configure shadow EVM: {e}"))?
            .with_fee_manager(RecordingFeeManager(Rc::clone(&writes)));
        let context = self
            .shadow_config
            .context_for_block(block.sealed_block())
            .map_err(|e| format!("failed to configure shadow executor: {e}"))?;
        let mut executor = self.shadow_config.create_executor(evm, context);
        let mut shadow = Evidence::default();
        if let Err(e) = executor.apply_pre_execution_changes() {
            return Ok(shadow.fail(Boundary::PreBlock, e.to_string()));
        }
        shadow.pre_block = Some(drain(executor.evm_mut().db_mut()));

        // Candidate pre-block changes are evidence, not input to shadow transactions.
        executor.evm_mut().db_mut().cache = canonical_cache;
        executor.evm_mut().db_mut().bal_state = canonical_bal;

        for tx in block.transactions_recovered() {
            match executor.execute_transaction_without_commit(tx) {
                Ok(result) => {
                    let observed =
                        ObservedTx::from_result(&result, std::mem::take(&mut *writes.borrow_mut()));
                    shadow.txs.push(Ok(
                        observed.with_state(transition(result.into_result().state))
                    ));
                }
                Err(e) => {
                    let _ = std::mem::take(&mut *writes.borrow_mut());
                    shadow.txs.push(Err(e.to_string()));
                }
            }
            let Ok(canonical) = canonical_results.recv() else {
                return Ok(shadow);
            };
            executor.commit_transaction(canonical);
            // The canonical commit is prestate for the next transaction, not shadow evidence.
            let _ = drain(executor.evm_mut().db_mut());
        }

        match executor.finish() {
            Ok((mut evm, _)) => shadow.post_block = Some(drain(evm.db_mut())),
            Err(e) => shadow = shadow.fail(Boundary::PostBlock, e.to_string()),
        }
        Ok(shadow)
    }
}

fn drain<DB>(db: &mut State<DB>) -> TransitionState {
    db.transition_state
        .as_mut()
        .expect("bundle updates enabled")
        .take()
}

fn transition(state: EvmState) -> TransitionState {
    let mut cache = CacheState::new();
    for (&address, account) in &state {
        if account.is_loaded_as_not_existing() {
            cache.insert_not_existing(address);
        } else {
            cache.insert_account_with_storage(
                address,
                account.original_info(),
                account
                    .storage
                    .iter()
                    .map(|(&slot, value)| (slot, value.original_value))
                    .collect(),
            );
        }
    }
    let transitions = cache.apply_evm_state(state, |_, _| {});
    let mut evidence = TransitionState::default();
    evidence.add_transitions(transitions);
    evidence
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum TxOutcome {
    #[default]
    Success,
    Revert,
    Halt,
}

/// Execution evidence retained for one successfully committed transaction.
///
/// Section/block gas consumption is tracked separately because it can diverge even when
/// receipt gas is unchanged.
#[derive(Debug, Default)]
struct ObservedTx {
    /// Whether execution succeeded, reverted, or halted.
    outcome: TxOutcome,
    /// Gas consumed by the transaction for its receipt and fee charge.
    gas_used: u64,
    /// Hash of the unmodified ordered logs, used to validate canonical receipts.
    receipt_logs_hash: B256,
    /// Gas charged against the block, which can differ from receipt gas.
    block_gas_used: u64,
    /// Hash of the transaction's output bytes (empty when there is no output).
    output_hash: B256,
    /// Positions of logs emitted by protocol fee hooks.
    fee_log_ranges: Vec<std::ops::Range<usize>>,
    /// Validated post-fee amount and full receipt hash with only that amount zeroed.
    fee_normalized: Option<(U256, B256)>,
    /// Storage slots touched by fee hooks, which may also have application writes.
    fee_slots: HashSet<(alloy_primitives::Address, alloy_primitives::U256)>,
    /// Net account and storage transitions observed at this transaction boundary.
    state: TransitionState,
}

impl ObservedTx {
    fn from_result(result: &TempoTxResult, writes: FeeWrites) -> Self {
        let execution = &result.result().result;
        let logs = execution.logs();
        let fee_normalized = normalized_fee_transfer(logs, &writes);
        Self {
            block_gas_used: result.block_gas_used(),
            outcome: match execution {
                reth_revm::context::result::ExecutionResult::Success { .. } => TxOutcome::Success,
                reth_revm::context::result::ExecutionResult::Revert { .. } => TxOutcome::Revert,
                reth_revm::context::result::ExecutionResult::Halt { .. } => TxOutcome::Halt,
            },
            gas_used: execution.tx_gas_used(),
            receipt_logs_hash: hash_logs(logs),
            output_hash: keccak256(execution.output().map_or(&[][..], |x| x)),
            fee_log_ranges: writes.log_ranges,
            fee_normalized,
            fee_slots: writes.slots,
            state: TransitionState::default(),
        }
    }

    fn with_state(mut self, state: TransitionState) -> Self {
        self.state = state;
        self
    }
}

type TxEvidence = Result<ObservedTx, String>;

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
    txs: Vec<TxEvidence>,
    post_block: Option<TransitionState>,
    failure: Option<Failure>,
}

impl Evidence {
    fn fail(mut self, boundary: Boundary, error: String) -> Self {
        self.failure = Some(Failure { boundary, error });
        self
    }
}

fn matches_receipts(txs: &[TxEvidence], receipts: &[TempoReceipt]) -> bool {
    if txs.len() != receipts.len() {
        return false;
    }

    let mut previous_gas = 0;
    txs.iter().zip(receipts).all(|(tx, receipt)| {
        let Ok(tx) = tx else {
            return false;
        };
        let gas_used = receipt.cumulative_gas_used - previous_gas;
        previous_gas = receipt.cumulative_gas_used;
        (tx.outcome == TxOutcome::Success) == receipt.success
            && tx.gas_used == gas_used
            && tx.receipt_logs_hash == hash_logs(&receipt.logs)
    })
}

/// Only the post-fee hook's expected TIP-20 transfer amount can be normalized. Every other
/// byte and the log positions remain committed by the returned full-receipt hash.
fn normalized_fee_transfer(
    logs: &[alloy_primitives::Log],
    writes: &FeeWrites,
) -> Option<(U256, B256)> {
    let (index, token, payer, amount) = writes.post_tx_transfer?;
    let log = logs.get(index)?;
    if log.address != token || !writes.log_ranges.iter().any(|range| range.contains(&index)) {
        return None;
    }
    let mut transfer = ITIP20::Transfer::decode_log_validate(log).ok()?;
    if transfer.data.from != payer
        || transfer.data.to != TIP_FEE_MANAGER_ADDRESS
        || transfer.data.amount != amount
        || transfer.data.encode_log_data() != log.data
    {
        return None;
    }
    transfer.data.amount = U256::ZERO;
    let mut normalized = logs.to_vec();
    normalized[index] = ITIP20::Transfer::encode_log(&transfer);
    Some((amount, hash_logs(&normalized)))
}

fn hash_logs<T: alloy_rlp::Encodable>(logs: &[T]) -> B256 {
    let mut encoded = Vec::with_capacity(list_length(logs));
    encode_list(logs, &mut encoded);
    keccak256(encoded)
}

fn shadow_spec(canonical: &TempoChainSpec, hardfork: TempoHardfork) -> TempoChainSpec {
    let mut spec = canonical.clone();
    spec.inner
        .hardforks
        .insert(hardfork, ForkCondition::Timestamp(0));
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use reth_revm::{
        DatabaseCommit,
        state::{Account, AccountInfo, EvmStorageSlot, TransactionId},
    };

    #[test]
    fn fee_log_normalization_preserves_order_and_non_amount_fields() {
        let token = Address::repeat_byte(1);
        let payer = Address::repeat_byte(2);
        let logs = |amount| {
            vec![
                alloy_primitives::Log::empty(),
                alloy_primitives::Log {
                    address: token,
                    data: ITIP20::Transfer {
                        from: payer,
                        to: TIP_FEE_MANAGER_ADDRESS,
                        amount,
                    }
                    .encode_log_data(),
                },
            ]
        };
        let writes = |amount| FeeWrites {
            log_ranges: std::iter::once(1..2).collect(),
            post_tx_transfer: Some((1, token, payer, amount)),
            ..Default::default()
        };
        let (canonical, candidate) = (logs(U256::from(85)), logs(U256::from(79)));
        let candidate_writes = writes(U256::from(79));
        let (_, expected) = normalized_fee_transfer(&canonical, &writes(U256::from(85))).unwrap();
        let (_, actual) = normalized_fee_transfer(&candidate, &candidate_writes).unwrap();
        assert_eq!(actual, expected);
        assert_ne!(hash_logs(&canonical), hash_logs(&candidate));

        let mut changed = candidate.clone();
        changed[0] = changed[1].clone();
        let (_, changed_fees) = normalized_fee_transfer(&changed, &candidate_writes).unwrap();
        assert_ne!(changed_fees, expected);
        let mut swapped = candidate;
        swapped.swap(0, 1);
        assert!(normalized_fee_transfer(&swapped, &candidate_writes).is_none());
    }

    #[test]
    fn shadow_schedule_only_overrides_candidate() {
        let canonical = TempoChainSpec::mainnet();
        let t11 = canonical.tempo_fork_activation(TempoHardfork::T11);
        let t13 = canonical.tempo_fork_activation(TempoHardfork::T13);
        let shadow = shadow_spec(&canonical, TempoHardfork::T12);
        assert_eq!(shadow.tempo_hardfork_at(0), TempoHardfork::T12);
        assert_eq!(shadow.tempo_fork_activation(TempoHardfork::T11), t11);
        assert_eq!(canonical.tempo_fork_activation(TempoHardfork::T13), t13);
    }

    #[test]
    fn transaction_transition_does_not_require_the_accumulated_cache() {
        let address = Address::ZERO;
        let created_address = Address::repeat_byte(1);
        let destroyed_address = Address::repeat_byte(2);
        let slot = U256::from(1);
        let original = AccountInfo {
            balance: U256::from(10),
            ..Default::default()
        };
        let mut account = Account::from(original.clone());
        account.info.balance = U256::from(9);
        account.storage.insert(
            slot,
            EvmStorageSlot::new_changed(U256::from(2), U256::from(3), TransactionId::ZERO),
        );
        account.mark_touch();
        let mut created = Account::new_not_existing(TransactionId::ZERO);
        created.info.balance = U256::from(1);
        created.mark_touch();
        created.mark_created();
        let mut destroyed = Account::from(original.clone());
        destroyed.mark_touch();
        destroyed.mark_selfdestruct();
        let state = EvmState::from_iter([
            (address, account),
            (created_address, created),
            (destroyed_address, destroyed),
        ]);

        let mut db = State::builder().with_bundle_update().build();
        db.insert_account_with_storage(
            address,
            original.clone(),
            [(slot, U256::from(2))].into_iter().collect(),
        );
        db.insert_not_existing(created_address);
        db.insert_account(destroyed_address, original);
        db.commit(state.clone());

        assert_eq!(transition(state), drain(&mut db));
    }
}
