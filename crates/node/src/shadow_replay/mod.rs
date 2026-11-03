//! Counterfactual replay of canonical blocks under shadow (candidate) Tempo hardfork rules.
//!
//! The node follows and persists the canonical chain. For each newly canonical block, it executes
//! every transaction under both the canonical (control) and candidate rules from the same canonical
//! prefix, with candidate pre-block setup retained in the shadow arm. The candidate transaction
//! result is observed, then discarded; the control result advances both executors before the next
//! transaction. This isolates differences to the transaction that caused
//! them instead of cascading candidate state through the rest of the block.
//!
//! Execution uses private in-memory overlays. Candidate pre-block changes remain in the prestate
//! of every shadow transaction; candidate transaction writes are never persisted, submitted to
//! forkchoice, or used as prestate for another transaction or block.
//!
//! Control re-execution must reproduce canonical receipts. Failure or divergence indicates a
//! non-canonical STF and terminates live replay. Shadow findings never stop replay.
//!
//! Analysis compares completed pre-block, transaction, and post-block boundaries in order. It
//! compares net effects at each boundary—not complete state equality or write history. Gas-only
//! changes are not findings; fork expectations classify known effects, and incomplete coverage
//! is reported separately.

mod analysis;
mod expectations;
mod fees;

use alloy::{consensus::BlockHeader as _, sol_types::SolEvent as _};
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rlp::{encode_list, list_length};
use analysis::Report;
use evm2::evm::{Cache, PendingState, TxResultExt};
use fees::{FeeWrites, RecordingFeeManager};
use metrics::{Counter, Gauge, Histogram};
use parking_lot::Mutex;
use reth_chainspec::ForkCondition;
use reth_ethereum::tasks::TaskExecutor;
use reth_evm::{
    BlockExecutor as _, BlockExecutorFactory as _, ConfigureEvm as _,
    database::StateProviderDatabase,
};
use reth_execution_types::{BlockState, StateUpdate};
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{
    CanonStateSubscriptions, ChainSpecProvider, StateProvider, StateProviderFactory,
};
use reth_tracing::tracing::{debug, error, info, info_span, warn};
use reth_trie_common::bundle_state::{AccountStatus, TransitionAccount, TransitionState};
use std::{collections::hash_map::Entry, sync::Arc, time::Instant};
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

/// Keeps replay metrics and their existing names/labels in one place.
#[derive(Debug)]
struct ShadowReplayMetrics {
    notifications_lagged: Counter,
    blocks: Counter,
    execution_duration: Histogram,
    latest_completed_block: Gauge,
    boundaries_compared: Counter,
    boundaries_inconclusive: Counter,
    unexplained_differences: Counter,
    findings_unexplained: Counter,
    findings_inconclusive: Counter,
}

impl Default for ShadowReplayMetrics {
    fn default() -> Self {
        Self {
            notifications_lagged: metrics::counter!(
                "tempo_shadow_replay_notifications_lagged_total"
            ),
            blocks: metrics::counter!("tempo_shadow_replay_blocks_total"),
            execution_duration: metrics::histogram!(
                "tempo_shadow_replay_execution_duration_seconds"
            ),
            latest_completed_block: metrics::gauge!("tempo_shadow_replay_latest_completed_block"),
            boundaries_compared: metrics::counter!("tempo_shadow_replay_boundaries_total", "result" => "compared"),
            boundaries_inconclusive: metrics::counter!("tempo_shadow_replay_boundaries_total", "result" => "inconclusive"),
            unexplained_differences: metrics::counter!(
                "tempo_shadow_replay_unexplained_differences_total"
            ),
            findings_unexplained: metrics::counter!("tempo_shadow_replay_findings_total", "kind" => "unexplained"),
            findings_inconclusive: metrics::counter!("tempo_shadow_replay_findings_total", "kind" => "inconclusive"),
        }
    }
}

impl ShadowReplayMetrics {
    fn record_report(&self, report: &Report, outcome: ReplayOutcome) {
        self.boundaries_compared
            .increment(report.boundaries_evaluated as u64);
        self.boundaries_inconclusive
            .increment(report.boundaries_not_evaluated as u64);
        for (&rule, &count) in &report.expected {
            metrics::counter!("tempo_shadow_replay_expected_differences_total", "rule" => rule)
                .increment(count as u64);
        }
        self.unexplained_differences
            .increment(report.unexplained as u64);
        match outcome {
            ReplayOutcome::Findings => self.findings_unexplained.increment(1),
            ReplayOutcome::Inconclusive => self.findings_inconclusive.increment(1),
            _ => {}
        }
    }
}

/// Replays canonical blocks under candidate rules without changing canonical state.
#[derive(Debug)]
pub struct ShadowReplayer<P> {
    provider: P,
    real_config: TempoEvmConfig,
    shadow_config: TempoEvmConfig,
    shadow_hardfork: TempoHardfork,
    metrics: ShadowReplayMetrics,
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
            metrics: ShadowReplayMetrics::default(),
        }
    }
}

impl<P> ShadowReplayer<P>
where
    P: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    /// Spawns the replay task. Lagged notifications are reported rather than backfilled.
    ///
    /// Runs as a critical task: a control-arm failure panics the task, which shuts the node down.
    pub fn spawn(self, executor: TaskExecutor) {
        let mut notifs = self.provider.subscribe_to_canonical_state();
        let hardfork = self.shadow_hardfork;
        let replayer = self;
        executor.spawn_critical_blocking_task("shadow replay", async move {
            info!(target: "shadow_replay", %hardfork, "Started counterfactual shadow replay");
            loop {
                let notif = match notifs.recv().await {
                    Ok(notif) => notif,
                    Err(RecvError::Lagged(skipped)) => {
                        replayer.metrics.notifications_lagged.increment(skipped);
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
                    let started_at = Instant::now();
                    let result = replayer.replay(
                        block,
                        committed.execution_outcome().receipts_by_block(number),
                    );
                    replayer.metrics.execution_duration.record(started_at.elapsed().as_secs_f64());

                    // Dropped before the next notification await.
                    let _guard = span.enter();
                    let err = match result {
                        Ok(_) => {
                            replayer.metrics.latest_completed_block.set(number as f64);
                            replayer.metrics.blocks.increment(1);
                            continue;
                        }
                        Err(err) => err,
                    };
                    error!(target: "shadow_replay", %err, "Control re-execution diverged from canonical chain");
                    panic!("shadow replay control failure at block {number}: {err}");
                }
            }
        });
    }
}

impl<P: StateProviderFactory> ShadowReplayer<P> {
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
        let rules = expectations::between(canonical, self.shadow_hardfork);
        let report = Report::analyze(&real, &shadow, &rules, block);
        let outcome = report.outcome(&shadow);
        self.metrics.record_report(&report, outcome);
        if matches!(outcome, ReplayOutcome::Match | ReplayOutcome::Expected) {
            debug!(target: "shadow_replay", ?outcome, ?report, "Shadow replay compared all boundaries");
            return Ok(outcome);
        }

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
    /// both executors advances the canonical prefix without cascading candidate transaction
    /// effects; candidate pre-block changes are preserved across control commits.
    fn execute(&self, block: &RecoveredBlock<Block>) -> Result<(Evidence, Evidence), String> {
        let provider = self
            .provider
            .state_by_block_hash(block.parent_hash())
            .map_err(|e| format!("failed to open parent state {}: {e}", block.parent_hash()))?;
        let mut db = StateProviderDatabase::new(provider.into_evm_state_provider());
        let writes = Arc::new(Mutex::new(FeeWrites::default()));
        let mut evm = self
            .real_config
            .evm_for_block(&mut db, block.header())
            .map_err(|e| format!("failed to configure control EVM: {e}"))?;
        evm.ext_mut().fee_manager = Arc::new(RecordingFeeManager(Arc::clone(&writes)));
        let context = self
            .real_config
            .context_for_block(block.sealed_block())
            .map_err(|e| format!("failed to configure control executor: {e}"))?;
        let mut executor = self.real_config.create_executor(evm, context);
        let updates = Arc::new(Mutex::new(Vec::new()));
        executor.set_state_hook({
            let updates = Arc::clone(&updates);
            move |state| updates.lock().push(state)
        });
        let mut real = Evidence::default();
        if let Err(e) = executor.apply_pre_execution_changes() {
            return Ok((
                real.fail(Boundary::PreBlock, e.to_string()),
                Evidence::default(),
            ));
        }
        real.pre_block = Some(take_updates(&updates));

        // A one-entry queue pipelines the two arms without retaining an unbounded number of cloned
        // control results when one arm runs ahead.
        let (results, canonical_results) = std::sync::mpsc::sync_channel(1);
        let canonical_bal = executor.evm().overlay_db().bal_context.clone();
        std::thread::scope(|scope| {
            let worker =
                scope.spawn(|| self.execute_shadow(block, canonical_bal, canonical_results));
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
                    ObservedTx::from_result(&result, std::mem::take(&mut *writes.lock()));
                if results
                    .as_ref()
                    .is_some_and(|sender| sender.send(result.clone()).is_err())
                {
                    results = None;
                }
                executor
                    .commit_transaction(result)
                    .map_err(|e| format!("failed to commit control transaction: {e}"))?;
                real.txs
                    .push(Ok(observed.with_state(take_updates(&updates))));
            }
            drop(results);
            if real.failure.is_none() {
                match executor.finish() {
                    Ok(_) => real.post_block = Some(take_updates(&updates)),
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
        canonical_bal: evm2::evm::BalContext,
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
        let mut db = StateProviderDatabase::new(provider.into_evm_state_provider());
        let writes = Arc::new(Mutex::new(FeeWrites::default()));
        let mut evm = self
            .shadow_config
            .evm_for_block(&mut db, block.header())
            .map_err(|e| format!("failed to configure shadow EVM: {e}"))?;
        evm.ext_mut().fee_manager = Arc::new(RecordingFeeManager(Arc::clone(&writes)));
        let context = self
            .shadow_config
            .context_for_block(block.sealed_block())
            .map_err(|e| format!("failed to configure shadow executor: {e}"))?;
        let mut executor = self.shadow_config.create_executor(evm, context);
        let updates = Arc::new(Mutex::new(Vec::new()));
        executor.set_state_hook({
            let updates = Arc::clone(&updates);
            move |state| updates.lock().push(state)
        });
        let mut shadow = Evidence::default();
        if let Err(e) = executor.apply_pre_execution_changes() {
            return Ok(shadow.fail(Boundary::PreBlock, e.to_string()));
        }
        shadow.pre_block = Some(take_updates(&updates));
        // Keep candidate pre-block changes in the cache; only transaction results are discarded.
        executor.evm_mut().overlay_db_mut().bal_context = canonical_bal;

        for tx in block.transactions_recovered() {
            match executor.execute_transaction_without_commit(tx) {
                Ok(result) => {
                    let observed =
                        ObservedTx::from_result(&result, std::mem::take(&mut *writes.lock()));
                    shadow.txs.push(Ok(
                        observed.with_state(transition_pending(result.pending_state()))
                    ));
                }
                Err(e) => {
                    let _ = std::mem::take(&mut *writes.lock());
                    shadow.txs.push(Err(e.to_string()));
                }
            }
            let Ok(canonical) = canonical_results.recv() else {
                return Ok(shadow);
            };
            // The commit merges changed storage slots, but replaces the entire AccountInfo.
            // Preserve candidate setup for fields the control transaction did not change.
            let canonical_state = pending_update(canonical.pending_state());
            let saved = save_pre_block_info(
                &executor.evm().overlay_db().cache,
                shadow.pre_block.as_ref().unwrap(),
                &canonical_state,
            );
            executor
                .commit_transaction(canonical)
                .map_err(|e| format!("failed to commit canonical shadow prefix: {e}"))?;
            let db = executor.evm_mut().overlay_db_mut();
            restore_pre_block_info(&mut db.cache, saved);
            // The control commit advances the prefix, not shadow transaction evidence.
            let _ = take_updates(&updates);
        }

        match executor.finish() {
            Ok(_) => shadow.post_block = Some(take_updates(&updates)),
            Err(e) => shadow = shadow.fail(Boundary::PostBlock, e.to_string()),
        }
        Ok(shadow)
    }
}

struct SavedPreBlockInfo {
    address: Address,
    candidate: evm2::evm::AccountInfo,
    control_before: evm2::evm::AccountInfo,
    control_after: evm2::evm::AccountInfo,
}

/// Before a control commit, snapshot candidate pre-block accounts it touches.
fn save_pre_block_info(
    cache: &Cache,
    pre_block: &TransitionState,
    update: &StateUpdate,
) -> Vec<SavedPreBlockInfo> {
    update
        .accounts
        .iter()
        .filter(|account| {
            !account.created
                && account.current.is_some()
                && pre_block.transitions.contains_key(&account.address)
        })
        .filter_map(|account| {
            cache
                .accounts
                .get(&account.address)
                .and_then(Option::as_ref)
                .map(|candidate| SavedPreBlockInfo {
                    address: account.address,
                    candidate: candidate.clone(),
                    control_before: account.original.clone().unwrap_or_default(),
                    control_after: account.current.clone().unwrap_or_default(),
                })
        })
        .collect()
}

/// After the control commit, retain candidate account-info fields the control left unchanged.
/// Control changes take precedence. Restore the saved account if revm cleared it as empty.
fn restore_pre_block_info(cache: &mut Cache, saved: Vec<SavedPreBlockInfo>) {
    for SavedPreBlockInfo {
        address,
        mut candidate,
        control_before,
        control_after,
    } in saved
    {
        let current = cache.accounts.get(&address).and_then(Option::as_ref);
        if control_before.balance != control_after.balance {
            candidate.balance = current.map_or(control_after.balance, |info| info.balance);
        }
        if control_before.nonce != control_after.nonce {
            candidate.nonce = current.map_or(control_after.nonce, |info| info.nonce);
        }
        if control_before.code_hash != control_after.code_hash {
            candidate.code_hash = current.map_or(control_after.code_hash, |info| info.code_hash);
            candidate.code = current.and_then(|info| info.code.clone());
        }
        cache.accounts.insert(address, Some(candidate));
    }
}

fn take_updates(updates: &Mutex<Vec<StateUpdate>>) -> TransitionState {
    transition_of(std::mem::take(&mut *updates.lock()))
}

fn transition_of(updates: impl IntoIterator<Item = StateUpdate>) -> TransitionState {
    let mut merged = TransitionState::default();
    for state in updates {
        for account in state.accounts {
            let previous_status = match &account.original {
                None => AccountStatus::LoadedNotExisting,
                Some(info) if info.is_empty() => AccountStatus::LoadedEmptyEIP161,
                Some(_) => AccountStatus::Loaded,
            };
            let status = if account.current.is_none() {
                previous_status.on_selfdestructed()
            } else if account.wiped && !account.created {
                AccountStatus::DestroyedChanged
            } else if account.created {
                previous_status.on_created()
            } else {
                previous_status.on_changed(
                    account
                        .original
                        .as_ref()
                        .is_none_or(|info| info.nonce == 0 && info.is_empty_code_hash()),
                )
            };
            let transition = TransitionAccount {
                info: account.current,
                status,
                previous_info: account.original,
                previous_status,
                storage: account.storage.into_iter().collect(),
                storage_was_destroyed: account.wiped,
            };
            match merged.transitions.entry(account.address) {
                Entry::Vacant(entry) => {
                    entry.insert(transition);
                }
                Entry::Occupied(mut entry) => merge_transition(entry.get_mut(), transition),
            }
        }
    }
    merged
}

/// Applies a later transition of the same account on top of `account`.
fn merge_transition(account: &mut TransitionAccount, other: TransitionAccount) {
    account.info = other.info;
    account.status = other.status;
    // A deletion starts a new storage lifetime.
    if matches!(
        other.status,
        AccountStatus::Destroyed | AccountStatus::DestroyedAgain
    ) {
        account.storage = other.storage;
        account.storage_was_destroyed = true;
        return;
    }
    for (key, slot) in other.storage {
        match account.storage.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(slot);
            }
            Entry::Occupied(mut entry) => {
                if entry.get().original_value() == slot.present_value() {
                    entry.remove();
                } else {
                    entry.get_mut().present_value = slot.present_value();
                }
            }
        }
    }
}

/// Collects the accounts a transaction's pending state would commit.
fn pending_update(state: &PendingState) -> StateUpdate {
    let mut update = StateUpdate::default();
    let mut block = BlockState::new();
    for changes in state.account_changes() {
        block.commit_account_changes(changes, Some(&mut update));
    }
    update
}

fn transition_pending(state: &PendingState) -> TransitionState {
    transition_of([pending_update(state)])
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum TxOutcome {
    #[default]
    Success,
    Revert,
    Halt,
}

/// Execution evidence retained for one successfully committed transaction.
#[derive(Debug, Default)]
struct ObservedTx {
    /// Whether execution succeeded, reverted, or halted.
    outcome: TxOutcome,
    /// Execution gas accounting for receipt validation, fee charges, and headroom checks.
    gas: TxResultExt,
    /// Hash of the unmodified ordered logs, used to validate canonical receipts.
    receipt_logs_hash: B256,
    /// Hash of the transaction's output bytes (empty when there is no output).
    output_hash: B256,
    /// Full receipt hash with only the validated post-fee amount zeroed.
    fee_normalized: Option<B256>,
    /// Fee-hook log, storage, and charge provenance for this transaction.
    fee: FeeWrites,
    /// Net account and storage transitions observed at this transaction boundary.
    state: TransitionState,
}

impl ObservedTx {
    fn from_result(result: &TempoTxResult, writes: FeeWrites) -> Self {
        let execution = result.result();
        let logs = &execution.logs;
        let fee_normalized = normalized_fee_transfer(logs, &writes);
        Self {
            outcome: if execution.status {
                TxOutcome::Success
            } else if execution.stop.is_revert() {
                TxOutcome::Revert
            } else {
                TxOutcome::Halt
            },
            gas: TxResultExt {
                total_gas_spent: execution.total_gas_spent,
                state_gas_spent: execution.state_gas_spent,
                refunded: execution.refunded,
                floor_gas: execution.floor_gas,
                ..Default::default()
            },
            receipt_logs_hash: hash_logs(logs),
            output_hash: keccak256(&execution.output),
            fee_normalized,
            fee: writes,
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
            && tx.gas.tx_gas_used() == gas_used
            && tx.receipt_logs_hash == hash_logs(&receipt.logs)
    })
}

/// Only the post-fee hook's expected TIP-20 transfer amount can be normalized. Every other
/// byte and the log positions remain committed by the returned full-receipt hash.
fn normalized_fee_transfer(logs: &[alloy_primitives::Log], writes: &FeeWrites) -> Option<B256> {
    let (index, token, payer, amount, _) = writes.post_tx_transfer?;
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
    Some(hash_logs(&normalized))
}

fn hash_logs<T: alloy_rlp::Encodable>(logs: &[T]) -> B256 {
    let mut encoded = Vec::with_capacity(list_length(logs));
    encode_list(logs, &mut encoded);
    keccak256(encoded)
}

fn shadow_spec(canonical: &TempoChainSpec, hardfork: TempoHardfork) -> TempoChainSpec {
    // Production replay starts after T10; mainnet genesis is at timestamp 0.
    // Activate candidate rules at timestamp 1 so candidate fork is not mistaken for a genesis.
    let mut spec = canonical.clone();
    for &fork in TempoHardfork::VARIANTS
        .iter()
        .filter(|&&fork| fork != TempoHardfork::Genesis && fork <= hardfork)
    {
        spec.inner
            .hardforks
            .insert(fork, ForkCondition::Timestamp(1));
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use evm2::{
        bytecode::Bytecode,
        evm::{AccountInfo, InMemoryDB},
    };
    use reth_execution_types::AccountUpdate;
    use reth_trie_common::bundle_state::StorageSlot;
    use tempo_contracts::{
        precompiles::{
            ZONE_FACTORY_ADDRESS, ZONE_PORTAL_IMPL_ADDRESS,
            zone_factory::{INITIAL_FACTORY_OWNER, initial_zone_factory_config},
        },
        zones::{T13_ZONE_PORTAL_RUNTIME, ZONE_PORTAL_RUNTIME},
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
            post_tx_transfer: Some((1, token, payer, amount, U256::ZERO)),
            ..Default::default()
        };
        let (canonical, candidate) = (logs(U256::from(85)), logs(U256::from(79)));
        let candidate_writes = writes(U256::from(79));
        let expected = normalized_fee_transfer(&canonical, &writes(U256::from(85))).unwrap();
        let actual = normalized_fee_transfer(&candidate, &candidate_writes).unwrap();
        assert_eq!(actual, expected);
        assert_ne!(hash_logs(&canonical), hash_logs(&candidate));
        assert!(normalized_fee_transfer(&candidate, &writes(U256::from(85))).is_none());

        let mut changed = candidate.clone();
        changed[0] = changed[1].clone();
        let changed_fees = normalized_fee_transfer(&changed, &candidate_writes).unwrap();
        assert_ne!(changed_fees, expected);
        let mut swapped = candidate;
        swapped.swap(0, 1);
        assert!(normalized_fee_transfer(&swapped, &candidate_writes).is_none());
    }

    #[test]
    fn candidate_pre_block_setup_is_transaction_prestate() {
        let canonical = TempoChainSpec::mainnet();
        let candidate = Arc::new(shadow_spec(&canonical, TempoHardfork::T13));
        let mut block = Block::default();
        let ForkCondition::Timestamp(timestamp) =
            canonical.tempo_fork_activation(TempoHardfork::T4)
        else {
            panic!("T4 must activate at a timestamp");
        };
        block.header.inner.timestamp = timestamp;
        block.header.inner.parent_beacon_block_root = Some(B256::ZERO);
        block.header.inner.base_fee_per_gas = Some(0);
        let block = RecoveredBlock::new_unhashed(block, vec![]);
        let config = TempoEvmConfig::new(candidate);
        let evm = config
            .evm_for_block(InMemoryDB::default(), block.header())
            .unwrap();
        let context = config.context_for_block(block.sealed_block()).unwrap();
        let mut executor = config.create_executor(evm, context);
        let updates = Arc::new(Mutex::new(Vec::new()));
        executor.set_state_hook({
            let updates = Arc::clone(&updates);
            move |state| updates.lock().push(state)
        });
        executor.apply_pre_execution_changes().unwrap();
        let pre_block = take_updates(&updates);
        // Commit a control result that touches the Zone account but carries canonical (old)
        // code. Only its changed storage slot should replace the candidate pre-block setup.
        let control_original = AccountInfo {
            code_hash: keccak256(ZONE_PORTAL_RUNTIME),
            ..Default::default()
        };
        let state = StateUpdate {
            accounts: vec![AccountUpdate {
                address: ZONE_PORTAL_IMPL_ADDRESS,
                current: Some(AccountInfo {
                    balance: U256::from(9),
                    ..control_original.clone()
                }),
                original: Some(control_original),
                created: false,
                wiped: false,
                storage: vec![(
                    U256::ZERO,
                    StorageSlot::new_changed(U256::ZERO, U256::from(42)),
                )],
            }],
        };
        let db = executor.evm_mut().overlay_db_mut();
        let saved = save_pre_block_info(&db.cache, &pre_block, &state);
        let old_code = Bytecode::new_raw(ZONE_PORTAL_RUNTIME);
        let original = evm2::evm::AccountInfo::default().with_code(old_code);
        let current = evm2::evm::AccountInfo {
            balance: U256::from(9),
            ..original.clone()
        };
        let mut pending = PendingState::default();
        pending.insert_account(ZONE_PORTAL_IMPL_ADDRESS, Some(original), Some(current));
        pending.insert_storage(
            ZONE_PORTAL_IMPL_ADDRESS,
            U256::ZERO,
            U256::ZERO,
            U256::from(42),
        );
        db.commit_pending(&pending);
        restore_pre_block_info(&mut db.cache, saved);
        let portal = db.cache.accounts[&ZONE_PORTAL_IMPL_ADDRESS]
            .as_ref()
            .unwrap();
        assert_eq!(
            db.cache.contracts[&portal.code_hash].original_bytes(),
            T13_ZONE_PORTAL_RUNTIME
        );
        assert_eq!(portal.balance, U256::from(9));
        assert_eq!(
            db.cache.storage[&ZONE_PORTAL_IMPL_ADDRESS].slots[&U256::ZERO],
            U256::from(42)
        );
        assert_eq!(
            db.cache.storage[&ZONE_FACTORY_ADDRESS].slots[&U256::ZERO],
            initial_zone_factory_config(INITIAL_FACTORY_OWNER)
        );
    }

    #[test]
    fn transaction_transition_does_not_require_the_accumulated_cache() {
        let address = Address::ZERO;
        let created_address = Address::repeat_byte(1);
        let destroyed_address = Address::repeat_byte(2);
        let slot = U256::ONE;
        let original = AccountInfo {
            balance: U256::from(10),
            nonce: 1,
            ..Default::default()
        };
        let mut pending = PendingState::default();
        pending.insert_account(
            address,
            Some(original.clone()),
            Some(AccountInfo {
                balance: U256::from(9),
                ..original.clone()
            }),
        );
        pending.insert_storage(address, slot, U256::from(2), U256::from(3));
        pending.insert_account(
            created_address,
            None,
            Some(AccountInfo {
                balance: U256::ONE,
                ..Default::default()
            }),
        );
        pending.insert_account(destroyed_address, Some(original.clone()), None);

        let transitions = transition_pending(&pending).transitions;
        let changed = &transitions[&address];
        assert_eq!(changed.status, AccountStatus::Changed);
        assert_eq!(changed.previous_info.as_ref(), Some(&original));
        assert_eq!(changed.info.as_ref().unwrap().balance, U256::from(9));
        assert_eq!(
            changed.storage[&slot],
            StorageSlot::new_changed(U256::from(2), U256::from(3))
        );
        let created = &transitions[&created_address];
        assert_eq!(created.status, AccountStatus::InMemoryChange);
        assert_eq!(created.previous_info, None);
        assert_eq!(created.info.as_ref().unwrap().balance, U256::ONE);
        let destroyed = &transitions[&destroyed_address];
        assert_eq!(destroyed.status, AccountStatus::Destroyed);
        assert_eq!(destroyed.previous_info.as_ref(), Some(&original));
        assert_eq!(destroyed.info, None);
    }
}
