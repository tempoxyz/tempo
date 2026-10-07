use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory, IntoTxEnv,
    precompiles::PrecompilesMap,
    revm::{
        Context, ExecuteEvm, InspectEvm, Inspector, SystemCallEvm,
        context::{
            ContextTr, DBErrorMarker, JournalTr,
            result::{EVMError, ResultAndState, ResultGas},
        },
        inspector::NoOpInspector,
    },
};
use alloy_primitives::{Address, Bytes, TxKind, map::HashMap};
use reth_revm::{
    InspectSystemCallEvm, MainContext, State,
    context::{
        CfgEnv,
        result::{ExecutionResult, HaltReason},
    },
};
use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
    rc::Rc,
    time::{Duration, Instant},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{storage::StorageAction, storage_credits::NonCreditableSlots};
use tempo_revm::{
    ProtocolFeeManager, TempoInvalidTransaction, TempoTxEnv, ValidationContext, evm::TempoContext,
    handler::TempoEvmHandler,
};

use crate::{
    TempoBlockEnv, TempoPoolValidationEvm, TempoPoolValidationResult,
    parallel::{
        CaptureEvent, EnginePrewarmingCache, EnginePrewarmingSession, ExecutionStats,
        PreexecutedTransaction, PrewarmingExecutor, PrewarmingState, SpeculativeBatch,
        SpeculativeExecutor, SpeculativeResult,
    },
};

type CandidateValidator<DB> = fn(
    &mut SpeculativeResult<<DB as reth_revm::Database>::Error>,
    &mut DB,
) -> Result<bool, <DB as reth_revm::Database>::Error>;

// Install this only in the marked factory. A function pointer also keeps the
// recording EVM from recursively instantiating another ReadRecorder<DB>.
type EngineCapture<DB> = fn(
    &mut DB,
    EvmEnv<TempoHardfork, TempoBlockEnv>,
    PrewarmingState,
    TempoTxEnv,
    Option<usize>,
) -> Result<
    PreexecutedTransaction,
    EVMError<<DB as reth_revm::Database>::Error, TempoInvalidTransaction>,
>;

/// Ordered Engine diagnostics, separate from deterministic execution counters.
#[derive(Debug, Default)]
struct EngineWaitTimings {
    takes: u64,
    take_wait: Duration,
    take_hold: Duration,
    prefix_writes: u64,
    prefix_write_wait: Duration,
    prefix_write_hold: Duration,
}

/// Wall times of completed calls on this EVM, separate from deterministic counters.
/// System/inspected execution and commits bypassing this wrapper are not timed.
#[derive(Debug, Default)]
struct ExecutionStageTimings {
    validation_calls: u64,
    validation_conflicts: u64,
    validation_errors: u64,
    validation: Duration,
    ordinary_calls: u64,
    ordinary_errors: u64,
    ordinary: Duration,
    ordinary_by_reason: [OrdinaryStageTiming; 4],
    commit_calls: u64,
    commit: Duration,
    prewarmed_reuse_disposal_calls: u64,
    prewarmed_reuse_disposal: Duration,
    prewarmed_fallback_disposal_calls: u64,
    prewarmed_fallback_disposal: Duration,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct OrdinaryStageTiming {
    calls: u64,
    elapsed: Duration,
}

/// Why this invocation reached ordered execution. A missing candidate includes
/// unavailable results and reuse guards; it does not imply a worker was scheduled.
#[derive(Clone, Copy)]
enum OrdinaryReason {
    NoCandidate,
    Conflict,
    SpeculativeError,
    ValidationError,
}

/// Opt-in disposal timing at the existing partial-move boundary. A local
/// candidate must be declared after this guard so Rust drops its remaining
/// fields in their normal order before the guard takes the end timestamp.
struct ConsumedCandidateDropTimer<'a> {
    elapsed: &'a mut Duration,
    started: Option<Instant>,
}

impl<'a> ConsumedCandidateDropTimer<'a> {
    fn new(elapsed: &'a mut Duration) -> Self {
        Self {
            elapsed,
            started: None,
        }
    }

    fn start(&mut self) {
        self.started = Some(Instant::now());
    }
}

impl Drop for ConsumedCandidateDropTimer<'_> {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            *self.elapsed = started.elapsed();
        }
    }
}

/// Factory for creating Tempo EVM instances.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct TempoEvmFactory {
    pub(crate) engine_prewarming: Option<EnginePrewarmingCache>,
}

impl EvmFactory for TempoEvmFactory {
    type Evm<DB: Database, I: Inspector<Self::Context<DB>>> = TempoEvm<DB, I>;
    type Context<DB: Database> = TempoContext<DB>;
    type Tx = TempoTxEnv;
    type Error<DBError: DBErrorMarker> = EVMError<DBError, TempoInvalidTransaction>;
    type HaltReason = HaltReason;
    type Spec = TempoHardfork;
    type BlockEnv = TempoBlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let Some(cache) = &self.engine_prewarming else {
            return TempoEvm::new(db, input);
        };
        let mut canonical = input.clone();
        // These flags identify payload prewarming only within the private
        // Engine configuration. Txpool prewarming also disables the base fee.
        let capture = canonical.cfg_env.disable_nonce_check
            && canonical.cfg_env.disable_balance_check
            && !canonical.cfg_env.disable_base_fee;
        if capture {
            canonical.cfg_env.disable_nonce_check = false;
            canonical.cfg_env.disable_balance_check = false;
        }
        let session = cache.session(&canonical);
        let mut evm = TempoEvm::new(db, input);
        if session.is_some() && capture {
            evm.engine_capture = Some(|db, env, prefix, tx, offset| {
                PrewarmingExecutor::new(db, env)
                    .with_state(prefix)
                    .execute(tx, offset)
            });
        }
        evm.engine_session = session;
        evm
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        TempoEvm::new(db, input).with_inspector(inspector)
    }
}

/// Tempo EVM implementation.
///
/// This is a wrapper type around the `revm` ethereum evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// `RevmEvm` type.
#[expect(missing_debug_implementations)]
pub struct TempoEvm<DB: Database, I = NoOpInspector> {
    inner: tempo_revm::TempoEvm<DB, I>,
    inspect: bool,
    speculative: Option<SpeculativeExecutor>,
    prepared: Option<SpeculativeBatch<DB::Error>>,
    preexecuted: Option<PreexecutedTransaction>,
    candidate_validator: Option<CandidateValidator<DB>>,
    state_committer: Option<fn(&mut DB, reth_revm::state::EvmState)>,
    engine_session: Option<std::sync::Arc<EnginePrewarmingSession>>,
    engine_capture: Option<EngineCapture<DB>>,
    engine_wait_timings: EngineWaitTimings,
    execution_stage_timings: Option<Box<ExecutionStageTimings>>,
    execution_stats: ExecutionStats,
    last_sample: ExecutionStats,
    backoff_remaining: usize,
    worker_cfg: reth_revm::context::CfgEnv<TempoHardfork>,
    standard_configuration: bool,
    journal_exposed: bool,
}

impl<DB: Database> TempoEvm<DB> {
    /// Create a new [`TempoEvm`] instance.
    pub fn new(db: DB, input: EvmEnv<TempoHardfork, TempoBlockEnv>) -> Self {
        // TIP-1016 (EIP-8037 state gas split) is gated by `cfg_env.enable_amsterdam_eip8037`
        // and is independent of the T4 hardfork. The caller is responsible for setting the
        // flag on the input `EvmEnv`; here we pass it through unchanged.
        let worker_cfg = input.cfg_env.clone();
        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(input.block_env)
            .with_cfg(input.cfg_env)
            .with_tx(Default::default());

        Self {
            inner: tempo_revm::TempoEvm::new(ctx, NoOpInspector {}),
            inspect: false,
            speculative: None,
            prepared: None,
            preexecuted: None,
            candidate_validator: None,
            state_committer: None,
            engine_session: None,
            engine_capture: None,
            engine_wait_timings: EngineWaitTimings::default(),
            execution_stage_timings: None,
            execution_stats: ExecutionStats::default(),
            last_sample: ExecutionStats::default(),
            backoff_remaining: 0,
            worker_cfg,
            standard_configuration: true,
            journal_exposed: false,
        }
    }
}

impl<P: Database, I> TempoEvm<&mut State<P>, I> {
    /// Uses the current authoritative State cache for exact speculative read
    /// validation. Cold reads and BAL-backed state retain Database validation.
    pub fn enable_state_cache_validation(&mut self) {
        self.candidate_validator = Some(|candidate, db| candidate.validate_state(*db));
    }

    pub(crate) fn enable_state_cache_commit(&mut self) {
        self.state_committer = Some(|db, changes| crate::state_commit::commit(*db, changes));
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// A block executor can consume strict candidates, but must never return
    /// hint-only prewarming results even if given a relaxed EVM by a caller.
    pub(crate) fn disarm_engine_capture(&mut self) {
        if self.engine_capture.take().is_some() {
            self.engine_session = None;
        }
    }

    pub(crate) fn has_engine_prewarming(&self) -> bool {
        self.engine_session.is_some() && self.engine_capture.is_none()
    }

    /// Publishes accepted block state as advisory hints for Engine workers.
    /// This is deliberately separate from transact_raw: executing or discarding
    /// a candidate must never advance the prefix seen by other workers.
    pub(crate) fn record_engine_commit(
        &mut self,
        state: &reth_revm::state::EvmState,
        is_expiring_nonce: bool,
    ) {
        let Some(session) = &self.engine_session else {
            return;
        };
        if self.engine_capture.is_some()
            || self.speculative_batch_size() == 0
            || self.inner.ctx.cfg != self.worker_cfg
            || self.inner.ctx.cfg != session.env().cfg_env
            || self.inner.ctx.block != session.env().block_env
            || self.inner.ctx.cfg.disable_fee_charge
            || self.inner.actions().is_enabled()
            || self.inner.skip_valid_after_check
            || self.inner.skip_liquidity_check
            || !self.inner.ctx.journaled_state.state.is_empty()
            || !self.inner.ctx.journaled_state.transient_storage.is_empty()
            || !self.inner.ctx.journaled_state.logs.is_empty()
        {
            return;
        }
        let (waited, held) =
            session.record_commit(state, is_expiring_nonce && self.inner.ctx.cfg.spec.is_t1());
        // The prefix guard has been dropped before touching EVM-local totals.
        self.engine_wait_timings.prefix_writes += 1;
        self.engine_wait_timings.prefix_write_wait += waited;
        self.engine_wait_timings.prefix_write_hold += held;
    }

    /// One summary at block-loop completion; worker capture does not update these.
    pub(crate) fn log_engine_wait_timings(&self) {
        if self.engine_capture.is_none()
            && let Some(session) = &self.engine_session
        {
            session.log_loop_finish_snapshot();
        }
        let timings = &self.engine_wait_timings;
        if timings.takes == 0 && timings.prefix_writes == 0 {
            return;
        }
        tracing::debug!(
            target: "tempo::execution",
            block_number = %self.inner.ctx.block.number,
            takes = timings.takes,
            take_wait_seconds = timings.take_wait.as_secs_f64(),
            take_hold_seconds = timings.take_hold.as_secs_f64(),
            prefix_writes = timings.prefix_writes,
            prefix_write_wait_seconds = timings.prefix_write_wait.as_secs_f64(),
            prefix_write_hold_seconds = timings.prefix_write_hold.as_secs_f64(),
            "Engine prewarming lock timings"
        );
    }

    /// Enables bounded speculative execution using the standard Tempo EVM configuration.
    pub fn set_speculative_executor(&mut self, executor: Option<SpeculativeExecutor>) {
        self.prepared = None;
        self.preexecuted = None;
        // Each installation starts a fresh diagnostic interval. Disabling the
        // executor drops its timers; disabled paths never read the clock.
        self.execution_stage_timings = executor
            .as_ref()
            .is_some_and(SpeculativeExecutor::stage_diagnostics)
            .then(Box::default);
        self.speculative = executor;
        self.last_sample = self.execution_stats;
        self.backoff_remaining = 0;
    }

    /// Supplies a worker-owned prewarming result for the next transaction. This
    /// does not bypass environment, transaction, configuration or read checks.
    pub fn set_preexecuted_transaction(&mut self, candidate: PreexecutedTransaction) {
        if self.speculative_batch_size() > 0 && self.inner.ctx.cfg == self.worker_cfg {
            self.execution_stats.speculated += 1;
            self.preexecuted = Some(candidate);
        }
    }

    /// Maximum lookahead, or zero when speculative execution is disabled.
    pub fn speculative_batch_size(&self) -> usize {
        if self.inspect || !self.standard_configuration {
            return 0;
        }
        self.speculative
            .as_ref()
            .map_or(0, SpeculativeExecutor::batch_size)
    }

    /// Returns execution counters for this EVM instance.
    pub const fn execution_stats(&self) -> ExecutionStats {
        self.execution_stats
    }

    pub(crate) fn has_prepared_transactions(&self) -> bool {
        self.prepared
            .as_ref()
            .is_some_and(|batch| !batch.is_empty())
            || self.backoff_remaining > 0
    }

    /// Speculates on a bounded set of transactions with their respective fee recipients.
    /// No writes are committed. Candidates are checked against the actual transaction,
    /// configuration, block environment and database reads before reuse.
    pub fn prepare_transactions(
        &mut self,
        transactions: impl IntoIterator<Item = (TempoTxEnv, Address)>,
    ) {
        self.prepare_transactions_with(transactions, |tx| &tx.0, std::convert::identity);
    }

    /// Borrows candidate environments to check nonce hints before converting them
    /// into owned worker inputs. Backoff advances the source without borrowing or
    /// converting its transactions. Neither path changes authoritative execution.
    pub fn prepare_transactions_with<T>(
        &mut self,
        transactions: impl IntoIterator<Item = T>,
        mut view: impl FnMut(&T) -> &TempoTxEnv,
        mut convert: impl FnMut(T) -> (TempoTxEnv, Address),
    ) {
        self.prepared = None;
        if self.inspect
            || !self.standard_configuration
            // Instructions and precompiles were constructed with this configuration.
            // Mutating ctx.cfg alone does not reconstruct those components.
            || self.inner.ctx.cfg != self.worker_cfg
            || self.inner.ctx.cfg.disable_fee_charge
            || self.inner.actions().is_enabled()
            || self.inner.skip_valid_after_check
            || self.inner.skip_liquidity_check
            || !self.inner.ctx.journaled_state.state.is_empty()
            || !self.inner.ctx.journaled_state.transient_storage.is_empty()
            || !self.inner.ctx.journaled_state.logs.is_empty()
        {
            return;
        }
        let Some(executor) = &self.speculative else {
            return;
        };
        let sampled = self.execution_stats.speculated - self.last_sample.speculated;
        let reused = self.execution_stats.reused - self.last_sample.reused
            + self.execution_stats.bodies_reused
            - self.last_sample.bodies_reused;
        if executor.adaptive_backoff() && sampled >= 32 && reused * 2 < sampled {
            // This is only a scheduling choice. No result bypasses read validation.
            // Reusing a few cheap results is insufficient to offset scheduling and
            // replay of the rest, even when shared fee arithmetic can be rebased.
            // Retry periodically so a later independent workload can use the pool.
            self.backoff_remaining = executor.batch_size().saturating_mul(8);
        }
        self.last_sample = self.execution_stats;
        if self.backoff_remaining > 0 {
            // Advance a payload builder's preview iterator by the same window even
            // when workers are idle, preserving its lookahead alignment.
            transactions
                .into_iter()
                .take(executor.batch_size())
                .for_each(drop);
            return;
        }
        // Limit speculative gas as well as transaction count. A malformed block
        // or a pool of high-limit transactions must not multiply a whole block's
        // maximum execution work by the lookahead window.
        let mut remaining_gas = self.inner.ctx.block.gas_limit;
        let spec = self.inner.ctx.cfg.spec;
        let timestamp = self.inner.ctx.block.timestamp.saturating_to();
        let disable_nonce_check = self.inner.ctx.cfg.disable_nonce_check;
        let mut prefetched = HashMap::default();
        let inputs = transactions
            .into_iter()
            .take(executor.batch_size())
            .filter_map(|candidate| {
                let borrowed = view(&candidate);
                let hint = tempo_revm::replay::nonce_hint(borrowed, spec, timestamp);
                if crate::parallel::nonce_is_stale(
                    &mut self.inner.ctx.journaled_state.database,
                    &mut prefetched,
                    hint,
                    disable_nonce_check,
                ) {
                    self.execution_stats.nonce_filtered += 1;
                    return None;
                }
                let (mut tx, beneficiary) = convert(candidate);
                if tx.is_system_tx {
                    return None;
                }
                // Bound actual worker inputs even if a caller's conversion
                // changes fields from the borrowed view used for the hint.
                remaining_gas = remaining_gas.checked_sub(tx.inner.gas_limit)?;
                if let Some(aa) = tx.tempo_tx_env.as_mut() {
                    aa.expiring_nonce_idx = None;
                }
                let mut block_env = self.inner.ctx.block.clone();
                block_env.beneficiary = beneficiary;
                Some((
                    tx,
                    EvmEnv {
                        block_env,
                        cfg_env: self.inner.ctx.cfg.clone(),
                    },
                ))
            })
            .collect::<Vec<_>>();
        self.execution_stats.speculated += inputs.len() as u64;
        self.prepared = Some(executor.speculate(
            &mut self.inner.ctx.journaled_state.database,
            inputs,
            prefetched,
        ));
    }

    pub(crate) fn commit_state(&mut self, changes: reth_revm::state::EvmState)
    where
        DB: reth_revm::DatabaseCommit,
    {
        let started = self
            .execution_stage_timings
            .as_ref()
            .map(|_| Instant::now());
        let db = &mut self.inner.ctx.journaled_state.database;
        if let Some(commit) = self.state_committer {
            commit(db, changes);
        } else {
            db.commit(changes);
        }
        if let Some(started) = started {
            let elapsed = started.elapsed();
            let timings = self.execution_stage_timings.as_mut().unwrap();
            timings.commit_calls += 1;
            timings.commit += elapsed;
        }
    }

    /// Snapshot before block finalization. These stages do not include receipt
    /// construction, dispatch, prefix publication, system calls or finalization.
    pub(crate) fn log_execution_stage_timings(&self) {
        let Some(timings) = &self.execution_stage_timings else {
            return;
        };
        tracing::debug!(target: "tempo::execution",
            phase = "before_block_finalization",
            validation_calls = timings.validation_calls,
            validation_conflicts = timings.validation_conflicts,
            validation_errors = timings.validation_errors,
            validation_seconds = timings.validation.as_secs_f64(),
            ordinary_calls = timings.ordinary_calls,
            ordinary_errors = timings.ordinary_errors,
            ordinary_seconds = timings.ordinary.as_secs_f64(),
            ordinary_no_candidate_calls = timings.ordinary_by_reason[OrdinaryReason::NoCandidate as usize].calls,
            ordinary_no_candidate_seconds = timings.ordinary_by_reason[OrdinaryReason::NoCandidate as usize].elapsed.as_secs_f64(),
            ordinary_conflict_calls = timings.ordinary_by_reason[OrdinaryReason::Conflict as usize].calls,
            ordinary_conflict_seconds = timings.ordinary_by_reason[OrdinaryReason::Conflict as usize].elapsed.as_secs_f64(),
            ordinary_speculative_error_calls = timings.ordinary_by_reason[OrdinaryReason::SpeculativeError as usize].calls,
            ordinary_speculative_error_seconds = timings.ordinary_by_reason[OrdinaryReason::SpeculativeError as usize].elapsed.as_secs_f64(),
            ordinary_validation_error_calls = timings.ordinary_by_reason[OrdinaryReason::ValidationError as usize].calls,
            ordinary_validation_error_seconds = timings.ordinary_by_reason[OrdinaryReason::ValidationError as usize].elapsed.as_secs_f64(),
            commit_calls = timings.commit_calls,
            commit_seconds = timings.commit.as_secs_f64(),
            prewarmed_reuse_disposal_calls = timings.prewarmed_reuse_disposal_calls,
            prewarmed_reuse_disposal_seconds = timings.prewarmed_reuse_disposal.as_secs_f64(),
            prewarmed_fallback_disposal_calls = timings.prewarmed_fallback_disposal_calls,
            prewarmed_fallback_disposal_seconds = timings.prewarmed_fallback_disposal.as_secs_f64(),
            "Ordered execution stage timings"
        );
    }

    /// Consumes this EVM wrapper and returns the inner [`tempo_revm::TempoEvm`].
    pub fn into_inner(self) -> tempo_revm::TempoEvm<DB, I> {
        self.inner
    }

    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &TempoContext<DB> {
        &self.inner.inner.ctx
    }

    /// Consumes this EVM wrapper and returns the EVM context.
    pub fn into_ctx(self) -> TempoContext<DB> {
        self.inner.inner.ctx
    }

    /// Returns the [`EvmEnv`] for the current block.
    pub fn evm_env(&self) -> EvmEnv<TempoHardfork, TempoBlockEnv> {
        EvmEnv {
            cfg_env: self.ctx().cfg.clone(),
            block_env: self.ctx().block.clone(),
        }
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut TempoContext<DB> {
        self.journal_exposed = true;
        &mut self.inner.inner.ctx
    }

    /// Recheck caller-controlled journal warming only after mutable context exposure.
    /// Ordinary execution preserves the standard precompile set and clears the
    /// transaction-local warming on finalize/discard. Database reads remain
    /// independently validated for every candidate.
    fn standard_journal_for_reuse(&mut self) -> bool {
        if !self.journal_exposed {
            return true;
        }
        let journal = &self.inner.ctx.journaled_state;
        let warm = &journal.warm_addresses;
        if !journal.state.is_empty()
            || !journal.transient_storage.is_empty()
            || !journal.logs.is_empty()
            || journal.depth != 0
            || !journal.journal.is_empty()
            || !journal.selfdestructed_addresses.is_empty()
            || warm.coinbase().is_some()
            || !warm.access_list().is_empty()
        {
            return false;
        }
        let precompiles = warm.precompiles();
        if !precompiles.is_empty()
            && precompiles
                != <PrecompilesMap as alloy_evm::revm::handler::PrecompileProvider<
                    TempoContext<DB>,
                >>::warm_addresses(&self.inner.inner.precompiles)
        {
            return false;
        }
        self.journal_exposed = false;
        true
    }

    /// Provides a mutable reference to the inner [`tempo_revm::TempoEvm`].
    pub fn inner_mut(&mut self) -> &mut tempo_revm::TempoEvm<DB, I> {
        // Custom instructions or precompiles must execute on this EVM.
        self.set_speculative_executor(None);
        self.standard_configuration = false;
        &mut self.inner
    }

    /// Returns the validator-credited fee amount (post-feeAMM haircut) recorded by the most
    /// recent `collectFeePostTx`. Reset per-tx in the handler's `validate_env`.
    pub fn validator_fee(&self) -> alloy_primitives::U256 {
        self.inner.validator_fee
    }

    /// Returns the transaction-local protocol slots whose clears must not mint storage credits.
    pub fn non_creditable_slots(&self) -> Rc<RefCell<NonCreditableSlots>> {
        self.inner.non_creditable_slots()
    }

    /// Sets the inspector for the EVM.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        TempoEvm {
            inner: self.inner.with_inspector(inspector),
            inspect: true,
            speculative: self.speculative,
            prepared: None,
            preexecuted: None,
            candidate_validator: self.candidate_validator,
            state_committer: self.state_committer,
            engine_session: None,
            engine_capture: None,
            engine_wait_timings: self.engine_wait_timings,
            execution_stage_timings: self.execution_stage_timings,
            execution_stats: self.execution_stats,
            last_sample: self.last_sample,
            backoff_remaining: self.backoff_remaining,
            worker_cfg: self.worker_cfg,
            standard_configuration: self.standard_configuration,
            journal_exposed: self.journal_exposed,
        }
    }

    /// Updates the protocol fee manager used by the EVM.
    pub fn with_fee_manager<F>(mut self, fee_manager: F) -> Self
    where
        F: ProtocolFeeManager<DB> + 'static,
    {
        self.set_speculative_executor(None);
        self.standard_configuration = false;
        self.inner = self.inner.with_fee_manager(fee_manager);
        self
    }

    /// Runs the full transaction validation pipeline without executing the transaction.
    ///
    /// Returns a [`ValidationContext`] with context relevant for the transaction pool.
    pub fn validate_transaction(
        &mut self,
        tx: impl IntoTxEnv<TempoTxEnv>,
    ) -> Result<ValidationContext, EVMError<DB::Error, TempoInvalidTransaction>> {
        self.inner.inner.ctx.tx = tx.into_tx_env();
        let mut handler = TempoEvmHandler::<DB, I>::new();
        handler.validate_transaction(&mut self.inner)
    }

    /// Enables recording of storage actions.
    pub fn with_actions(mut self) -> Self {
        let mut actions = self.inner.actions().clone();
        actions.enable();
        self.inner = self.inner.with_actions(actions);
        self
    }

    /// Replaces the recorded storage actions with an empty buffer, returning the previous actions.
    pub fn take_actions(&mut self) -> Option<Vec<StorageAction>> {
        self.inner.actions().take()
    }

    /// Clears the recorded storage actions without releasing the backing allocation.
    pub fn clear_actions(&mut self) {
        self.inner.actions().clear();
    }

    /// Replaces the recorded storage actions with the given ones, returning the previous actions.
    pub fn replace_actions(&mut self, actions: Vec<StorageAction>) -> Option<Vec<StorageAction>> {
        self.inner.actions().replace(actions)
    }
}

impl<DB, I> TempoPoolValidationEvm for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    fn configure_for_pool(&mut self) {
        // The pool admits future-time and future-nonce transactions and performs its own cached
        // AMM liquidity check after EVM validation.
        self.inner.skip_valid_after_check = true;
        self.inner.skip_liquidity_check = true;
        self.ctx_mut().cfg.disable_nonce_check = true;
        // Pool admission enforces the T7 fee floor. The dynamic block base fee
        // is checked during block selection/execution, once queued transactions can pay it.
        self.ctx_mut().cfg.disable_base_fee = true;
    }

    fn validate_pool_transaction(
        &mut self,
        tx: TempoTxEnv,
    ) -> (TempoPoolValidationResult<DB::Error>, TempoTxEnv) {
        let result = self.validate_transaction(tx);
        let tx = core::mem::take(&mut self.ctx_mut().tx);
        // Discard this transaction's journaled writes (nonce bumps, fee deduction,
        // key authorisation) while keeping loaded accounts and storage warm for the
        // rest of the batch.
        self.ctx_mut().journal_mut().discard_tx();
        self.inner.clear();
        (result, tx)
    }
}

impl<DB: Database, I> Deref for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type Target = TempoContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I> DerefMut for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I> Evm for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type DB = DB;
    type Tx = TempoTxEnv;
    type Error = EVMError<DB::Error, TempoInvalidTransaction>;
    type HaltReason = HaltReason;
    type Spec = TempoHardfork;
    type BlockEnv = TempoBlockEnv;
    type Precompiles = PrecompilesMap;
    type Inspector = I;

    fn block(&self) -> &Self::BlockEnv {
        &self.block
    }

    fn cfg_env(&self) -> &CfgEnv<Self::Spec> {
        &self.cfg
    }

    fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.set_body_replay(None);
        let mut ordinary_reason = OrdinaryReason::NoCandidate;
        if let Some(session) = self.engine_session.as_ref() {
            if let Some(capture) = self.engine_capture {
                // Capture mutably inspects the EVM while holding its worker guard.
                // Ordered consumption only needs to borrow the session.
                let session = std::sync::Arc::clone(session);
                let _capture_worker = session.worker_entry();
                let guard_admitted = !self.inspect
                    && self.standard_configuration
                    && self.inner.ctx.cfg == self.worker_cfg
                    && self.inner.ctx.block == session.env().block_env
                    && !self.inner.ctx.cfg.disable_fee_charge
                    && !self.inner.actions().is_enabled()
                    && !self.inner.skip_valid_after_check
                    && !self.inner.skip_liquidity_check
                    && self.inner.ctx.journaled_state.state.is_empty()
                    && self.inner.ctx.journaled_state.transient_storage.is_empty()
                    && self.inner.ctx.journaled_state.logs.is_empty();
                if guard_admitted && session.can_capture(&tx) && {
                    let standard = self.standard_journal_for_reuse();
                    if !standard {
                        session.capture_event(CaptureEvent::JournalRejected);
                    }
                    standard
                } {
                    session.capture_event(CaptureEvent::StrictAttempts);
                    let mut strict_tx = tx.clone();
                    // Reth's index is a parent-relative ring prediction. The
                    // recorder applies it once, then records a canonical tx.
                    let offset = strict_tx
                        .tempo_tx_env
                        .as_mut()
                        .and_then(|aa| aa.expiring_nonce_idx.take());
                    if let Ok(candidate) = capture(
                        &mut self.inner.ctx.journaled_state.database,
                        session.env().clone(),
                        session.prefix(),
                        strict_tx,
                        offset,
                    ) {
                        session.capture_event(CaptureEvent::StrictSucceeded);
                        // In pinned Reth this return value supplies proof
                        // prefetch targets only. It is never committed. Keep
                        // the strict result separate from the shared read cache.
                        let hint = candidate.prewarming_result();
                        session.publish(candidate);
                        return Ok(hint);
                    }
                    session.capture_event(CaptureEvent::StrictFailed);
                    // A strict failure must retain the legacy relaxed prewarm,
                    // including its original transaction and AA offset.
                } else if !guard_admitted {
                    session.capture_event(CaptureEvent::GuardRejected);
                }
            } else {
                let (candidate, timings) = session.take_timed(&tx);
                if let Some((waited, held)) = timings {
                    // The retained-map guard has already been dropped.
                    self.engine_wait_timings.takes += 1;
                    self.engine_wait_timings.take_wait += waited;
                    self.engine_wait_timings.take_hold += held;
                }
                if let Some(candidate) = candidate {
                    self.set_preexecuted_transaction(candidate);
                }
            }
        }
        if self.backoff_remaining > 0 && !tx.is_system_tx {
            self.backoff_remaining -= 1;
            self.execution_stats.backoff += 1;
        }
        if !self.inspect
            && self.standard_configuration
            // Changing the context does not rebuild instructions or precompiles.
            // Provider-owned candidates must honor the same construction guard
            // as candidates scheduled through prepare_transactions_with.
            && self.inner.ctx.cfg == self.worker_cfg
            && !self.inner.actions().is_enabled()
            && !self.inner.skip_valid_after_check
            && !self.inner.skip_liquidity_check
            && self.inner.ctx.journaled_state.state.is_empty()
            && self.inner.ctx.journaled_state.transient_storage.is_empty()
            && self.inner.ctx.journaled_state.logs.is_empty()
            && let Some((mut candidate, prewarmed)) = self
                .preexecuted
                .take()
                .and_then(|candidate| candidate.into_candidate(&tx))
                .map(|candidate| (candidate, true))
                .or_else(|| {
                    self.prepared
                        .as_mut()
                        .and_then(|batch| {
                            batch.take(&tx, &mut self.inner.ctx.journaled_state.database)
                        })
                        .map(|candidate| (candidate, false))
                })
            && self.standard_journal_for_reuse()
            && candidate.env.cfg_env == self.inner.ctx.cfg
            && candidate.env.block_env == self.inner.ctx.block
        {
            if candidate.result.is_err() {
                self.execution_stats.retries += 1;
                ordinary_reason = OrdinaryReason::SpeculativeError;
            } else {
                let started = self
                    .execution_stage_timings
                    .as_ref()
                    .map(|_| Instant::now());
                let valid = match self.candidate_validator {
                    Some(validate) => {
                        validate(&mut candidate, &mut self.inner.ctx.journaled_state.database)
                    }
                    None => candidate.validate(&mut self.inner.ctx.journaled_state.database),
                };
                if let Some(started) = started {
                    let elapsed = started.elapsed();
                    let timings = self.execution_stage_timings.as_mut().unwrap();
                    timings.validation_calls += 1;
                    timings.validation_conflicts += u64::from(matches!(valid, Ok(false)));
                    timings.validation_errors += u64::from(valid.is_err());
                    timings.validation += elapsed;
                }
                let validation_error = valid.is_err();
                if valid.unwrap_or(false) {
                    self.execution_stats.reused += 1;
                    if prewarmed && let Some(executor) = &self.speculative {
                        executor.record_prewarmed_reuse();
                    }
                    self.execution_stats.fees_rebased += u64::from(candidate.fees_rebased);
                    self.execution_stats.native_rebased += u64::from(candidate.native_rebased);
                    self.inner.ctx.tx = tx;
                    self.inner.validator_fee = candidate.validator_fee;
                    if prewarmed && self.execution_stage_timings.is_some() {
                        let mut elapsed = Duration::ZERO;
                        let result = {
                            let mut timer = ConsumedCandidateDropTimer::new(&mut elapsed);
                            let candidate = candidate;
                            timer.start();
                            candidate.result
                        };
                        let timings = self.execution_stage_timings.as_mut().unwrap();
                        timings.prewarmed_reuse_disposal_calls += 1;
                        timings.prewarmed_reuse_disposal += elapsed;
                        return result;
                    }
                    return candidate.result;
                } else {
                    ordinary_reason = if validation_error {
                        OrdinaryReason::ValidationError
                    } else {
                        OrdinaryReason::Conflict
                    };
                    self.execution_stats.conflicts += 1;
                    use crate::parallel::ConflictKind;
                    match candidate.conflict {
                        Some(ConflictKind::Metadata) => {
                            self.execution_stats.metadata_conflicts += 1
                        }
                        Some(ConflictKind::NoncePointer) => {
                            self.execution_stats.nonce_pointer_conflicts += 1
                        }
                        Some(ConflictKind::Nonce) => self.execution_stats.nonce_conflicts += 1,
                        Some(ConflictKind::Storage) => self.execution_stats.storage_conflicts += 1,
                        Some(ConflictKind::Fee) => self.execution_stats.fee_conflicts += 1,
                        // Provider errors retain the ordinary ordered fallback.
                        None => self.execution_stats.validation_errors += 1,
                    }
                    tracing::trace!(target: "tempo::execution::conflicts", caller = ?tx.inner.caller, payer = ?tx.fee_payer().ok(), "Conflicting candidate");
                    if prewarmed && self.execution_stage_timings.is_some() {
                        let mut elapsed = Duration::ZERO;
                        {
                            let mut timer = ConsumedCandidateDropTimer::new(&mut elapsed);
                            let candidate = candidate;
                            self.inner.set_body_replay(candidate.body);
                            timer.start();
                        }
                        let timings = self.execution_stage_timings.as_mut().unwrap();
                        timings.prewarmed_fallback_disposal_calls += 1;
                        timings.prewarmed_fallback_disposal += elapsed;
                    } else {
                        self.inner.set_body_replay(candidate.body);
                    }
                }
            }
        }
        if tx.is_system_tx {
            let TxKind::Call(to) = tx.inner.kind else {
                return Err(TempoInvalidTransaction::SystemTransactionMustBeCall.into());
            };

            let mut result = if self.inspect {
                self.inner
                    .inspect_system_call_with_caller(tx.inner.caller, to, tx.inner.data)?
            } else {
                self.inner
                    .system_call_with_caller(tx.inner.caller, to, tx.inner.data)?
            };

            // system transactions should not consume any gas
            let ExecutionResult::Success { gas, .. } = &mut result.result else {
                return Err(
                    TempoInvalidTransaction::SystemTransactionFailed(result.result.into()).into(),
                );
            };

            *gas = ResultGas::default();

            Ok(result)
        } else if self.inspect {
            self.inner.inspect_tx(tx)
        } else {
            let started = self
                .execution_stage_timings
                .as_ref()
                .map(|_| Instant::now());
            let result = self.inner.transact(tx);
            if let Some(started) = started {
                let elapsed = started.elapsed();
                let timings = self.execution_stage_timings.as_mut().unwrap();
                timings.ordinary_calls += 1;
                timings.ordinary_errors += u64::from(result.is_err());
                timings.ordinary += elapsed;
                // Partition the existing interval exactly, without another
                // clock read or any timing work when diagnostics are disabled.
                let reason = &mut timings.ordinary_by_reason[ordinary_reason as usize];
                reason.calls += 1;
                reason.elapsed += elapsed;
            }
            if self.inner.body_was_reused() {
                self.execution_stats.bodies_reused += 1;
            }
            result
        }
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.system_call_with_caller(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec, Self::BlockEnv>) {
        let Context {
            block: block_env,
            cfg: cfg_env,
            journaled_state,
            ..
        } = self.inner.inner.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
        if enabled {
            self.prepared = None;
        } else {
            // Inspectors receive mutable contexts directly, bypassing ctx_mut.
            self.journal_exposed = true;
        }
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        (
            &self.inner.inner.ctx.journaled_state.database,
            &self.inner.inner.inspector,
            &self.inner.inner.precompiles,
        )
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        // Access to the instruction/precompile or inspector configuration invalidates
        // the assumption that workers run the same standard Tempo EVM.
        self.set_speculative_executor(None);
        self.standard_configuration = false;
        (
            &mut self.inner.inner.ctx.journaled_state.database,
            &mut self.inner.inner.inspector,
            &mut self.inner.inner.precompiles,
        )
    }

    fn db_mut(&mut self) -> &mut Self::DB {
        // Database mutations are covered by read validation and do not require
        // disabling the pool (this is also the ordinary ordered commit path).
        &mut self.inner.inner.ctx.journaled_state.database
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{test_evm, test_evm_with_basefee};
    use alloy_primitives::{B256, U256, keccak256};
    use alloy_sol_types::{SolCall, SolError, SolValue};
    use indexmap::IndexMap;
    use revm::{
        DatabaseCommit, DatabaseRef,
        bytecode::opcode,
        context::{BlockEnv, CfgEnv, JournalTr, TxEnv, result::HaltReason},
        database::{EmptyDB, InMemoryDB},
        state::{AccountInfo, Bytecode, EvmState},
    };
    use std::{assert_matches, collections::BTreeMap};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::{
        precompiles::{
            IZoneFactory, ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS, ZONE_PORTAL_IMPL_ADDRESS,
        },
        zones::{ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME},
    };
    use tempo_precompiles::{
        NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS,
        TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageAction, StorageActions, StorageCtx, StorageKey},
        storage_credits::StorageCredits,
        test_util::TIP20Setup,
        tip_fee_manager::{
            IFeeManager, TipFeeManager,
            amm::{Pool, PoolKey, compute_amount_out},
            slots as fee_manager_slots,
        },
        tip20::{
            ITIP20, rewards::__packing_user_reward_info as user_reward_info_slots,
            slots as tip20_slots,
        },
        tip403_registry::slots as tip403_registry_slots,
        zone_factory::{ZONE_CREATION_GAS, ZoneFactory, portal_address},
    };
    use tempo_primitives::{TempoAddressExt, transaction::Call};
    use tempo_revm::{TempoBatchCallEnv, gas_params::tempo_gas_params_with_amsterdam};

    use super::*;

    alloy_sol_types::sol! {
        enum TestZonePortalRole {
            None,
            Sequencer,
            Account,
            CallbackGateway,
            PauseGuardian
        }

        enum TestZonePortalCapability {
            PausePortal,
            AccessPolicy
        }

        struct TestBlockTransition {
            bytes32 prevBlockHash;
            bytes32 nextBlockHash;
        }

        struct TestDepositQueueTransition {
            bytes32 prevProcessedHash;
            bytes32 nextProcessedHash;
            uint64 prevDepositNumber;
            uint64 nextDepositNumber;
        }

        interface TestZonePortal {
            error InvalidProof();

            function enableToken(address token) external;
            function tokenEnablementHash() external view returns (bytes32);
            function hasRole(address account, TestZonePortalRole role) external view returns (bool);
            function isSequencer(address account) external view returns (bool);
            function setAllowedAccount(address account, bool allowed) external;
            function paused() external view returns (bool);
            function pauseExpiry() external view returns (uint64);
            function abdicationEffectiveAt(TestZonePortalCapability capability)
                external
                view
                returns (uint64);
            function pause() external;
            function resume() external;
            function submitBatch(
                uint64 tempoBlockNumber,
                uint64 recentTempoBlockNumber,
                TestBlockTransition calldata blockTransition,
                TestDepositQueueTransition calldata depositQueueTransition,
                bytes32 withdrawalQueueHash,
                bytes calldata verifierConfig,
                bytes calldata proof,
                uint256 nextZoneHeight,
                bytes[] calldata signatures
            ) external;
        }

        interface TestZoneMessenger {
            function relayMessage(
                uint32 zoneId,
                address token,
                bytes32 senderTag,
                address target,
                uint128 amount,
                uint64 gasLimit,
                bytes calldata data
            ) external;
        }

        interface TestWithdrawalReceiver {
            function onWithdrawalReceived(
                uint32 zoneId,
                address portal,
                bytes32 senderTag,
                address token,
                uint128 amount,
                bytes calldata data
            ) external returns (bytes4);
        }
    }

    fn runtime_returning_selector(selector: [u8; 4]) -> Bytecode {
        const SELECTOR_SHIFT_BITS: u8 = 224;
        const ABI_WORD_BYTES: u8 = 32;

        let mut code = vec![opcode::PUSH4];
        code.extend_from_slice(&selector);
        code.extend_from_slice(&[
            opcode::PUSH1,
            SELECTOR_SHIFT_BITS,
            opcode::SHL,
            opcode::PUSH0,
            opcode::MSTORE,
            opcode::PUSH1,
            ABI_WORD_BYTES,
            opcode::PUSH0,
            opcode::RETURN,
        ]);
        Bytecode::new_legacy(code.into())
    }

    fn initialize_zone_factory(db: &mut InMemoryDB, owner: Address) {
        let code = Bytecode::new_legacy([0xef].into());
        db.insert_account_info(
            ZONE_FACTORY_ADDRESS,
            AccountInfo {
                code_hash: code.hash_slow(),
                code: Some(code),
                ..Default::default()
            },
        );
        let factory_config = U256::ONE | (U256::from_be_slice(owner.as_slice()) << u32::BITS);
        db.insert_account_storage(ZONE_FACTORY_ADDRESS, U256::ZERO, factory_config)
            .unwrap();
    }

    #[test]
    fn can_execute_system_tx() {
        let mut evm = test_evm(EmptyDB::default());
        let result = evm
            .transact(TempoTxEnv {
                inner: TxEnv {
                    caller: Address::ZERO,
                    gas_price: 0,
                    gas_limit: 21000,
                    ..Default::default()
                },
                is_system_tx: true,
                ..Default::default()
            })
            .unwrap();

        assert!(result.result.is_success());
    }

    #[test]
    fn consumed_candidate_disposal_scope_preserves_partial_move_drop_order() {
        use std::cell::RefCell;

        struct Probe<'a> {
            name: &'static str,
            events: &'a RefCell<Vec<(&'static str, Instant)>>,
        }
        impl Drop for Probe<'_> {
            fn drop(&mut self) {
                self.events.borrow_mut().push((self.name, Instant::now()));
            }
        }
        struct Candidate<'a> {
            before: Probe<'a>,
            result: Probe<'a>,
            body: Probe<'a>,
            after: Probe<'a>,
        }
        let events = RefCell::new(Vec::new());
        let candidate = || Candidate {
            before: Probe {
                name: "before",
                events: &events,
            },
            result: Probe {
                name: "result",
                events: &events,
            },
            body: Probe {
                name: "body",
                events: &events,
            },
            after: Probe {
                name: "after",
                events: &events,
            },
        };
        let names = || {
            events
                .borrow()
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
        };

        let mut elapsed = Duration::ZERO;
        let started;
        let result = {
            let mut timer = ConsumedCandidateDropTimer::new(&mut elapsed);
            let candidate = candidate();
            // Read the fields used only for their destructors, retaining their
            // declaration positions and avoiding dead-field lint suppression.
            assert_eq!(candidate.before.name, "before");
            assert_eq!(candidate.after.name, "after");
            timer.start();
            started = timer.started.unwrap();
            candidate.result
        };
        assert_eq!(names(), ["before", "body", "after"]);
        let finished = started + elapsed;
        assert!(
            events
                .borrow()
                .iter()
                .all(|(_, at)| started <= *at && *at <= finished)
        );
        drop(result);
        assert_eq!(names(), ["before", "body", "after", "result"]);
        events.borrow_mut().clear();

        let mut elapsed = Duration::ZERO;
        let started;
        let mut transferred_body = None;
        {
            let mut timer = ConsumedCandidateDropTimer::new(&mut elapsed);
            let candidate = candidate();
            let mut transfer_body = |body| {
                assert!(events.borrow().is_empty());
                assert!(transferred_body.is_none());
                transferred_body = Some(body);
            };
            transfer_body(candidate.body);
            timer.start();
            started = timer.started.unwrap();
        }
        assert_eq!(names(), ["before", "result", "after"]);
        let finished = started + elapsed;
        assert!(
            events
                .borrow()
                .iter()
                .all(|(_, at)| started <= *at && *at <= finished)
        );
        drop(transferred_body);
        assert_eq!(names(), ["before", "result", "after", "body"]);
        events.borrow_mut().clear();

        let mut elapsed = Duration::ZERO;
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut timer = ConsumedCandidateDropTimer::new(&mut elapsed);
            let candidate = candidate();
            let transfer_body: fn(Probe<'_>) = |_body| panic!("body transfer failure");
            transfer_body(candidate.body);
            timer.start();
        }));
        assert!(unwound.is_err());
        assert_eq!(
            elapsed,
            Duration::ZERO,
            "transfer failure must not start timing"
        );
        assert_eq!(names(), ["body", "before", "result", "after"]);
    }

    /// Empty-scope clock floor only, never a destructor or executor benchmark.
    /// Run on the measurement host before and after an execution diagnostic.
    #[test]
    #[ignore = "bounded disposal clock calibration"]
    fn consumed_candidate_disposal_clock_calibration() {
        const SAMPLES: usize = 16_384;
        let mut reuse = Vec::with_capacity(SAMPLES);
        let mut fallback = Vec::with_capacity(SAMPLES);
        for _ in 0..SAMPLES {
            let mut elapsed = Duration::ZERO;
            let result = {
                let mut timer = ConsumedCandidateDropTimer::new(&mut elapsed);
                let candidate = std::hint::black_box((0_u8, 0_u8));
                timer.start();
                candidate.0
            };
            std::hint::black_box(result);
            reuse.push(elapsed.as_nanos());

            let mut elapsed = Duration::ZERO;
            {
                let mut timer = ConsumedCandidateDropTimer::new(&mut elapsed);
                let candidate = std::hint::black_box((0_u8, 0_u8));
                std::hint::black_box(candidate.1);
                timer.start();
            }
            fallback.push(elapsed.as_nanos());
        }
        for (kind, mut samples) in [("reuse", reuse), ("fallback", fallback)] {
            samples.sort_unstable();
            eprintln!(
                "consumed_candidate_disposal_clock kind={kind} samples={SAMPLES} p50_ns={} p99_ns={} max_ns={}",
                samples[SAMPLES / 2],
                samples[SAMPLES * 99 / 100],
                samples[SAMPLES - 1],
            );
        }
    }

    #[test]
    fn execution_stage_diagnostics_preserve_reuse_fallback_and_reset() {
        use revm::{database::CacheDB, database_interface::EmptyDBTyped};
        #[derive(Debug, thiserror::Error)]
        #[error("validation provider error")]
        struct ProviderError;
        impl DBErrorMarker for ProviderError {}

        let parent = CacheDB::new(EmptyDBTyped::<ProviderError>::new());
        let env = test_evm_with_basefee(EmptyDB::default(), 0).finish().1;
        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::with_last_byte(201),
                kind: TxKind::Call(Address::with_last_byte(202)),
                gas_limit: 1_000_000,
                ..Default::default()
            },
            ..Default::default()
        };
        for enabled in [false, true] {
            for case in ["reuse", "conflict", "provider_error", "retry", "missing"] {
                let mut tx = tx.clone();
                if case == "retry" {
                    tx.inner.nonce = 1;
                }
                let mut expected = TempoEvm::new(parent.clone(), env.clone());
                let mut actual = TempoEvm::new(parent.clone(), env.clone());
                actual.set_speculative_executor(Some(
                    SpeculativeExecutor::new(1, 1)
                        .unwrap()
                        .with_streaming(false)
                        .with_stage_diagnostics(enabled),
                ));
                if case == "retry" {
                    // Complete an invalid future-nonce candidate before the
                    // ordered prefix changes. Its error must be retried.
                    actual.prepare_transactions([(tx.clone(), env.block_env.beneficiary)]);
                } else if case != "missing" {
                    let candidate = PrewarmingExecutor::new(parent.clone(), env.clone())
                        .execute(tx.clone(), None)
                        .unwrap();
                    actual.set_preexecuted_transaction(candidate);
                }
                if matches!(case, "conflict" | "retry") {
                    for evm in [&mut actual, &mut expected] {
                        evm.db_mut().insert_account_info(
                            tx.inner.caller,
                            AccountInfo {
                                balance: U256::ONE,
                                nonce: u64::from(case == "retry"),
                                ..Default::default()
                            },
                        );
                    }
                } else if case == "provider_error" {
                    actual.candidate_validator = Some(|_, _| Err(ProviderError));
                }
                let reference = expected.transact_raw(tx.clone()).unwrap();
                let result = actual.transact_raw(tx.clone()).unwrap();
                assert_eq!(result, reference);
                expected.commit_state(reference.state);
                actual.commit_state(result.state);
                assert_eq!(
                    actual.db().cache.accounts.len(),
                    expected.db().cache.accounts.len()
                );
                for (address, account) in &actual.db().cache.accounts {
                    let expected_account = &expected.db().cache.accounts[address];
                    assert!(tempo_revm::replay::account_info_matches(
                        &account.info,
                        &expected_account.info
                    ));
                    assert_eq!(account.storage, expected_account.storage);
                    assert_eq!(account.account_state, expected_account.account_state);
                }
                let error = actual.transact_raw(tx.clone()).unwrap_err();
                assert_eq!(
                    error.to_string(),
                    expected.transact_raw(tx.clone()).unwrap_err().to_string()
                );
                if enabled {
                    let timings = actual.execution_stage_timings.as_ref().unwrap();
                    let validation_calls = u64::from(!matches!(case, "retry" | "missing"));
                    assert_eq!(timings.validation_calls, validation_calls);
                    assert_eq!(timings.validation_conflicts, u64::from(case == "conflict"));
                    assert_eq!(
                        timings.validation_errors,
                        u64::from(case == "provider_error")
                    );
                    assert_eq!(timings.ordinary_calls, if case == "reuse" { 1 } else { 2 });
                    assert_eq!(timings.ordinary_errors, 1);
                    assert_eq!(
                        timings
                            .ordinary_by_reason
                            .each_ref()
                            .map(|stage| stage.calls),
                        [
                            1 + u64::from(case == "missing"),
                            u64::from(case == "conflict"),
                            u64::from(case == "retry"),
                            u64::from(case == "provider_error"),
                        ]
                    );
                    assert_eq!(
                        timings
                            .ordinary_by_reason
                            .iter()
                            .map(|stage| stage.calls)
                            .sum::<u64>(),
                        timings.ordinary_calls
                    );
                    assert_eq!(
                        timings
                            .ordinary_by_reason
                            .iter()
                            .map(|stage| stage.elapsed)
                            .sum::<Duration>(),
                        timings.ordinary
                    );
                    assert_eq!(timings.commit_calls, 1);
                    assert_eq!(
                        timings.prewarmed_reuse_disposal_calls,
                        u64::from(case == "reuse")
                    );
                    assert_eq!(
                        timings.prewarmed_fallback_disposal_calls,
                        u64::from(matches!(case, "conflict" | "provider_error"))
                    );
                    let inspected = actual.with_inspector(NoOpInspector {});
                    assert_eq!(
                        inspected
                            .execution_stage_timings
                            .as_ref()
                            .unwrap()
                            .validation_calls,
                        validation_calls
                    );
                    actual = inspected;
                } else {
                    assert!(actual.execution_stage_timings.is_none());
                }
                actual.set_speculative_executor(Some(
                    SpeculativeExecutor::new(1, 1)
                        .unwrap()
                        .with_stage_diagnostics(true),
                ));
                let timings = actual.execution_stage_timings.as_ref().unwrap();
                assert_eq!(timings.validation_calls, 0);
                assert_eq!(timings.ordinary_calls, 0);
                for stage in &timings.ordinary_by_reason {
                    assert_eq!(stage, &OrdinaryStageTiming::default());
                }
                assert_eq!(timings.commit_calls, 0);
                assert_eq!(timings.prewarmed_reuse_disposal_calls, 0);
                assert_eq!(timings.prewarmed_reuse_disposal, Duration::ZERO);
                assert_eq!(timings.prewarmed_fallback_disposal_calls, 0);
                assert_eq!(timings.prewarmed_fallback_disposal, Duration::ZERO);
                actual.set_speculative_executor(None);
                assert!(actual.execution_stage_timings.is_none());
            }
        }
    }

    #[test]
    fn test_transact_raw() {
        let mut evm = test_evm_with_basefee(EmptyDB::default(), 0);

        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::repeat_byte(0x01),
                gas_price: 0,
                gas_limit: 21000,
                kind: TxKind::Call(Address::repeat_byte(0x02)),
                ..Default::default()
            },
            is_system_tx: false,
            fee_token: None,
            ..Default::default()
        };

        let result = evm.transact_raw(tx);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.result.is_success());
        assert_eq!(result.result.tx_gas_used(), 21000);
    }

    #[test]
    fn test_transact_raw_system_tx() {
        let mut evm = test_evm(EmptyDB::default());

        // System transaction
        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::ZERO,
                gas_price: 0,
                gas_limit: 21000,
                kind: TxKind::Call(Address::repeat_byte(0x01)),
                ..Default::default()
            },
            is_system_tx: true,
            ..Default::default()
        };

        let result = evm.transact_raw(tx);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.result.is_success());
        // System transactions should not consume gas
        assert_eq!(result.result.tx_gas_used(), 0);
    }

    #[test]
    fn test_transact_raw_system_tx_must_be_call() {
        let mut evm = test_evm(EmptyDB::default());

        // System transaction with Create kind
        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::ZERO,
                gas_price: 0,
                gas_limit: 21000,
                kind: TxKind::Create,
                ..Default::default()
            },
            is_system_tx: true,
            ..Default::default()
        };

        let result = evm.transact_raw(tx);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            EVMError::Transaction(TempoInvalidTransaction::SystemTransactionMustBeCall)
        ));
    }

    #[test]
    fn test_transact_raw_system_tx_failed() {
        let mut cache_db = InMemoryDB::default();
        // Deploy a contract that always reverts: PUSH1 0x00 PUSH1 0x00 REVERT (0x60006000fd)
        let revert_code = Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xfd]);
        let contract_addr = Address::repeat_byte(0xaa);

        cache_db.insert_account_info(
            contract_addr,
            revm::state::AccountInfo {
                code_hash: alloy_primitives::keccak256(&revert_code),
                code: Some(revm::bytecode::Bytecode::new_raw(revert_code)),
                ..Default::default()
            },
        );

        let mut evm = test_evm(cache_db);

        // System transaction that will fail with call to contract that reverts
        let tx = TempoTxEnv {
            inner: TxEnv {
                caller: Address::ZERO,
                gas_price: 0,
                gas_limit: 1_000_000,
                kind: TxKind::Call(contract_addr),
                ..Default::default()
            },
            is_system_tx: true,
            ..Default::default()
        };

        let result = evm.transact_raw(tx);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            EVMError::Transaction(TempoInvalidTransaction::SystemTransactionFailed(_))
        ));
    }

    #[test]
    fn test_transact_system_call() {
        let mut evm = test_evm(EmptyDB::default());

        let caller = Address::repeat_byte(0x01);
        let contract = Address::repeat_byte(0x02);
        let data = Bytes::from_static(&[0x01, 0x02, 0x03]);

        let result = evm.transact_system_call(caller, contract, data);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.result.is_success());
    }

    #[test]
    fn zone_factory_created_portal_executes_deployed_runtime() {
        let owner = Address::repeat_byte(0x11);
        let admin = Address::repeat_byte(0x22);
        let sequencer = Address::repeat_byte(0x33);
        // Returns 42 for every call. The portal proxy should delegate to this deployed runtime.
        let logic_runtime = Bytecode::new_legacy(Bytes::from_static(&[
            0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ]));
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            ZONE_PORTAL_IMPL_ADDRESS,
            AccountInfo {
                code_hash: logic_runtime.hash_slow(),
                code: Some(logic_runtime),
                ..Default::default()
            },
        );
        initialize_zone_factory(&mut db, owner);
        let mut evm = TempoEvm::new(db, evm_env_with_spec(TempoHardfork::T10));

        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            TIP20Setup::path_usd(admin).apply()
        })
        .unwrap();
        let setup_state = evm.ctx_mut().journaled_state.finalize();
        evm.db_mut().commit(setup_state);

        let result = evm
            .transact_system_call(
                owner,
                ZONE_FACTORY_ADDRESS,
                IZoneFactory::createZoneCall {
                    params: IZoneFactory::CreateZoneParams {
                        initialToken: PATH_USD_ADDRESS,
                        accessMode: true,
                        gatewayMode: true,
                        allowedAccounts: vec![admin],
                        zoneGateways: vec![Address::repeat_byte(0x44)],
                        admin,
                        sequencers: vec![sequencer],
                        threshold: 1,
                        rpcUrl: "https://zone.example".to_string(),
                    },
                }
                .abi_encode()
                .into(),
            )
            .unwrap();
        assert!(
            result.result.is_success(),
            "createZone failed: {:?}",
            result.result
        );
        assert!(result.result.tx_gas_used() >= ZONE_CREATION_GAS);
        assert!(result.result.gas().block_regular_gas_used() >= ZONE_CREATION_GAS);
        let create_output = match &result.result {
            ExecutionResult::Success {
                output: revm::context::result::Output::Call(output),
                ..
            } => output.clone(),
            result => panic!("unexpected createZone result: {result:?}"),
        };
        let created = IZoneFactory::createZoneCall::abi_decode_returns(&create_output).unwrap();
        evm.db_mut().commit(result.state);

        let result = evm
            .transact_system_call(Address::ZERO, created.portal, Bytes::new())
            .unwrap();
        let output = match result.result {
            ExecutionResult::Success {
                output: revm::context::result::Output::Call(output),
                ..
            } => output,
            result => panic!("portal call failed: {result:?}"),
        };
        assert_eq!(U256::from_be_slice(&output), U256::from(42));
    }

    #[test]
    fn zone_portal_runtime_commits_subsequent_token_enablements() {
        let owner = Address::repeat_byte(0x11);
        let admin = Address::repeat_byte(0x22);
        let sequencer = Address::repeat_byte(0x33);
        let portal_runtime = Bytecode::new_legacy(tempo_contracts::zones::ZONE_PORTAL_RUNTIME);
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            ZONE_PORTAL_IMPL_ADDRESS,
            AccountInfo {
                code_hash: portal_runtime.hash_slow(),
                code: Some(portal_runtime),
                ..Default::default()
            },
        );
        initialize_zone_factory(&mut db, owner);
        let mut evm = TempoEvm::new(db, evm_env_with_spec(TempoHardfork::T10));

        let second_token = StorageCtx::enter_ctx(
            evm.ctx_mut(),
            StorageActions::disabled(),
            || -> Result<_, TempoPrecompileError> {
                TIP20Setup::path_usd(admin).apply()?;
                Ok(TIP20Setup::create("Second Token", "SECOND", admin)
                    .apply()?
                    .address())
            },
        )
        .unwrap();
        let setup_state = evm.ctx_mut().journaled_state.finalize();
        evm.db_mut().commit(setup_state);

        let create = evm
            .transact_system_call(
                owner,
                ZONE_FACTORY_ADDRESS,
                IZoneFactory::createZoneCall {
                    params: IZoneFactory::CreateZoneParams {
                        initialToken: PATH_USD_ADDRESS,
                        accessMode: true,
                        gatewayMode: true,
                        allowedAccounts: vec![],
                        zoneGateways: vec![],
                        admin,
                        sequencers: vec![sequencer],
                        threshold: 1,
                        rpcUrl: "https://zone.example".to_string(),
                    },
                }
                .abi_encode()
                .into(),
            )
            .unwrap();
        let output = match &create.result {
            ExecutionResult::Success {
                output: revm::context::result::Output::Call(output),
                ..
            } => output,
            result => panic!("createZone failed: {result:?}"),
        };
        let created = IZoneFactory::createZoneCall::abi_decode_returns(output).unwrap();
        evm.db_mut().commit(create.state);

        let sequencer_status = evm
            .transact_system_call(
                Address::ZERO,
                created.portal,
                TestZonePortal::isSequencerCall { account: sequencer }
                    .abi_encode()
                    .into(),
            )
            .unwrap();
        let output = match sequencer_status.result {
            ExecutionResult::Success {
                output: revm::context::result::Output::Call(output),
                ..
            } => output,
            result => panic!("isSequencer failed: {result:?}"),
        };
        assert!(TestZonePortal::isSequencerCall::abi_decode_returns(&output).unwrap());

        let account = Address::repeat_byte(0x55);
        let set_account = evm
            .transact_system_call(
                admin,
                created.portal,
                TestZonePortal::setAllowedAccountCall {
                    account,
                    allowed: true,
                }
                .abi_encode()
                .into(),
            )
            .unwrap();
        assert!(
            set_account.result.is_success(),
            "setAllowedAccount failed: {:?}",
            set_account.result
        );
        evm.db_mut().commit(set_account.state);

        let account_role = evm
            .transact_system_call(
                Address::ZERO,
                created.portal,
                TestZonePortal::hasRoleCall {
                    account,
                    role: TestZonePortalRole::Account,
                }
                .abi_encode()
                .into(),
            )
            .unwrap();
        let output = match account_role.result {
            ExecutionResult::Success {
                output: revm::context::result::Output::Call(output),
                ..
            } => output,
            result => panic!("hasRole failed: {result:?}"),
        };
        assert!(TestZonePortal::hasRoleCall::abi_decode_returns(&output).unwrap());

        for call in [
            TestZonePortal::pausedCall {}.abi_encode(),
            TestZonePortal::pauseExpiryCall {}.abi_encode(),
            TestZonePortal::abdicationEffectiveAtCall {
                capability: TestZonePortalCapability::PausePortal,
            }
            .abi_encode(),
        ] {
            let result = evm
                .transact_system_call(Address::ZERO, created.portal, call.into())
                .unwrap();
            let output = match result.result {
                ExecutionResult::Success {
                    output: revm::context::result::Output::Call(output),
                    ..
                } => output,
                result => panic!("pause ABI call failed: {result:?}"),
            };
            assert_eq!(U256::from_be_slice(&output), U256::ZERO);
        }

        let pause = evm
            .transact_system_call(
                sequencer,
                created.portal,
                TestZonePortal::pauseCall {}.abi_encode().into(),
            )
            .unwrap();
        assert!(
            pause.result.is_success(),
            "pause failed: {:?}",
            pause.result
        );
        evm.db_mut().commit(pause.state);

        let submit = evm
            .transact_system_call(
                sequencer,
                created.portal,
                TestZonePortal::submitBatchCall {
                    tempoBlockNumber: 0,
                    recentTempoBlockNumber: 0,
                    blockTransition: TestBlockTransition {
                        prevBlockHash: B256::repeat_byte(1),
                        nextBlockHash: B256::ZERO,
                    },
                    depositQueueTransition: TestDepositQueueTransition {
                        prevProcessedHash: B256::ZERO,
                        nextProcessedHash: B256::ZERO,
                        prevDepositNumber: 0,
                        nextDepositNumber: 0,
                    },
                    withdrawalQueueHash: B256::ZERO,
                    verifierConfig: Bytes::new(),
                    proof: Bytes::new(),
                    nextZoneHeight: U256::ZERO,
                    signatures: Vec::new(),
                }
                .abi_encode()
                .into(),
            )
            .unwrap();
        match submit.result {
            ExecutionResult::Revert { output, .. } => {
                assert_eq!(output.as_ref(), TestZonePortal::InvalidProof::SELECTOR)
            }
            result => panic!("paused submitBatch should reach proof validation: {result:?}"),
        }

        let resume = evm
            .transact_system_call(
                admin,
                created.portal,
                TestZonePortal::resumeCall {}.abi_encode().into(),
            )
            .unwrap();
        assert!(
            resume.result.is_success(),
            "resume failed: {:?}",
            resume.result
        );
        evm.db_mut().commit(resume.state);

        let paused = evm
            .transact_system_call(
                Address::ZERO,
                created.portal,
                TestZonePortal::pausedCall {}.abi_encode().into(),
            )
            .unwrap();
        let output = match paused.result {
            ExecutionResult::Success {
                output: revm::context::result::Output::Call(output),
                ..
            } => output,
            result => panic!("paused failed after resume: {result:?}"),
        };
        assert_eq!(U256::from_be_slice(&output), U256::ZERO);

        let enable = evm
            .transact_system_call(
                admin,
                created.portal,
                TestZonePortal::enableTokenCall {
                    token: second_token,
                }
                .abi_encode()
                .into(),
            )
            .unwrap();
        assert!(
            enable.result.is_success(),
            "enableToken failed: {:?}",
            enable.result
        );
        evm.db_mut().commit(enable.state);

        let commitment = evm
            .transact_system_call(
                Address::ZERO,
                created.portal,
                TestZonePortal::tokenEnablementHashCall {}
                    .abi_encode()
                    .into(),
            )
            .unwrap();
        let output = match commitment.result {
            ExecutionResult::Success {
                output: revm::context::result::Output::Call(output),
                ..
            } => output,
            result => panic!("tokenEnablementHash failed: {result:?}"),
        };
        let actual = TestZonePortal::tokenEnablementHashCall::abi_decode_returns(&output).unwrap();
        let initial = keccak256(
            (B256::ZERO, PATH_USD_ADDRESS, "pathUSD", "pathUSD", "USD").abi_encode_params(),
        );
        let expected =
            keccak256((initial, second_token, "Second Token", "SECOND", "USD").abi_encode_params());
        assert_eq!(actual, expected);
    }

    #[test]
    fn zone_messenger_runtime_authorizes_registered_callback_gateway() {
        let owner = Address::repeat_byte(0x11);
        let admin = Address::repeat_byte(0x22);
        let sequencer = Address::repeat_byte(0x33);
        let gateway = Address::repeat_byte(0x44);
        let mut db = InMemoryDB::default();
        for (address, runtime) in [
            (ZONE_PORTAL_IMPL_ADDRESS, ZONE_PORTAL_RUNTIME),
            (ZONE_MESSENGER_ADDRESS, ZONE_MESSENGER_RUNTIME),
        ] {
            let code = Bytecode::new_legacy(runtime);
            db.insert_account_info(
                address,
                AccountInfo {
                    code_hash: code.hash_slow(),
                    code: Some(code),
                    ..Default::default()
                },
            );
        }
        let callback_runtime =
            runtime_returning_selector(TestWithdrawalReceiver::onWithdrawalReceivedCall::SELECTOR);
        db.insert_account_info(
            gateway,
            AccountInfo {
                code_hash: callback_runtime.hash_slow(),
                code: Some(callback_runtime),
                ..Default::default()
            },
        );
        initialize_zone_factory(&mut db, owner);
        let mut evm = TempoEvm::new(db, evm_env_with_spec(TempoHardfork::T10));

        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(ZONE_MESSENGER_ADDRESS, U256::from(100))
                .apply()
        })
        .unwrap();
        let setup_state = evm.ctx_mut().journaled_state.finalize();
        evm.db_mut().commit(setup_state);

        let create = evm
            .transact_system_call(
                owner,
                ZONE_FACTORY_ADDRESS,
                IZoneFactory::createZoneCall {
                    params: IZoneFactory::CreateZoneParams {
                        initialToken: PATH_USD_ADDRESS,
                        accessMode: false,
                        gatewayMode: true,
                        allowedAccounts: vec![],
                        zoneGateways: vec![gateway],
                        admin,
                        sequencers: vec![sequencer],
                        threshold: 1,
                        rpcUrl: "https://zone.example".to_string(),
                    },
                }
                .abi_encode()
                .into(),
            )
            .unwrap();
        let output = match &create.result {
            ExecutionResult::Success {
                output: revm::context::result::Output::Call(output),
                ..
            } => output,
            result => panic!("createZone failed: {result:?}"),
        };
        let created = IZoneFactory::createZoneCall::abi_decode_returns(output).unwrap();
        evm.db_mut().commit(create.state);

        let relay = evm
            .transact_system_call(
                created.portal,
                ZONE_MESSENGER_ADDRESS,
                TestZoneMessenger::relayMessageCall {
                    zoneId: created.zoneId,
                    token: PATH_USD_ADDRESS,
                    senderTag: B256::ZERO,
                    target: gateway,
                    amount: 1,
                    gasLimit: 100_000,
                    data: Bytes::new(),
                }
                .abi_encode()
                .into(),
            )
            .unwrap();
        assert!(
            relay.result.is_success(),
            "registered gateway callback failed: {:?}",
            relay.result
        );
    }

    #[test]
    fn zone_factory_creation_oog_below_minimum_reverts_state() {
        let owner = Address::repeat_byte(0x11);
        let admin = Address::repeat_byte(0x22);
        let sequencer = Address::repeat_byte(0x33);
        let mut env = evm_env_with_spec(TempoHardfork::T10);
        env.block_env.basefee = 0;
        let mut db = InMemoryDB::default();
        initialize_zone_factory(&mut db, owner);
        let mut evm = TempoEvm::new(db, env);

        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            TIP20Setup::path_usd(admin).apply()
        })
        .unwrap();
        let setup_state = evm.ctx_mut().journaled_state.finalize();
        evm.db_mut().commit(setup_state);

        let input = IZoneFactory::createZoneCall {
            params: IZoneFactory::CreateZoneParams {
                initialToken: PATH_USD_ADDRESS,
                accessMode: true,
                gatewayMode: true,
                allowedAccounts: vec![admin],
                zoneGateways: vec![Address::repeat_byte(0x44)],
                admin,
                sequencers: vec![sequencer],
                threshold: 1,
                rpcUrl: "https://zone.example".to_string(),
            },
        }
        .abi_encode();

        let result = evm
            .transact_raw(TempoTxEnv {
                inner: TxEnv {
                    caller: owner,
                    gas_price: 0,
                    gas_limit: ZONE_CREATION_GAS - 1,
                    kind: TxKind::Call(ZONE_FACTORY_ADDRESS),
                    data: input.into(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        assert_matches!(
            result.result,
            ExecutionResult::Halt {
                reason: HaltReason::OutOfGas(_),
                ..
            }
        );
        evm.db_mut().commit(result.state);

        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            let factory = ZoneFactory::new();
            assert_eq!(factory.next_zone_id()?, 1);
            assert!(!factory.is_zone_portal(portal_address(1))?);
            Ok::<_, TempoPrecompileError>(())
        })
        .unwrap();
    }

    #[derive(Default)]
    struct StorageState {
        reconstructed: BTreeMap<(Address, U256), U256>,
        first_loads: BTreeMap<(Address, U256), U256>,
    }

    impl StorageState {
        fn apply_sload_value(
            &mut self,
            key: (Address, U256),
            value: U256,
            action: &str,
            hardfork: TempoHardfork,
        ) -> U256 {
            match self.reconstructed.get(&key) {
                Some(current) => {
                    let (address, slot) = key;
                    assert_eq!(
                        *current, value,
                        "{action} SLOAD value must match reconstructed current value for {address:?}:{slot:?} on {hardfork:?}",
                    );
                    *current
                }
                None => {
                    self.first_loads.insert(key, value);
                    self.reconstructed.insert(key, value);
                    value
                }
            }
        }
    }

    fn assert_storage_actions_reconstruct_evm_state(
        actions: &[StorageAction],
        state: &EvmState,
        hardfork: TempoHardfork,
    ) {
        let mut storage_state = StorageState::default();

        for action in actions {
            match *action {
                StorageAction::Sload(address, slot, value) => {
                    let key = (address, slot);
                    storage_state.apply_sload_value(key, value, "SLOAD", hardfork);
                }
                StorageAction::Sstore(address, slot, sload_value, value) => {
                    let key = (address, slot);
                    storage_state.apply_sload_value(key, sload_value, "SSTORE", hardfork);
                    storage_state.reconstructed.insert(key, value);
                }
                StorageAction::Sinc(address, slot, sload_value, delta) => {
                    let key = (address, slot);
                    let current =
                        storage_state.apply_sload_value(key, sload_value, "SINC", hardfork);
                    let value = current.checked_add(delta).unwrap_or_else(|| {
                        panic!("SINC overflow for {address:?}:{slot:?} on {hardfork:?}")
                    });
                    storage_state.reconstructed.insert(key, value);
                }
                StorageAction::Sdec(address, slot, sload_value, delta) => {
                    let key = (address, slot);
                    let current =
                        storage_state.apply_sload_value(key, sload_value, "SDEC", hardfork);
                    let value = current.checked_sub(delta).unwrap_or_else(|| {
                        panic!("SDEC underflow for {address:?}:{slot:?} on {hardfork:?}")
                    });
                    storage_state.reconstructed.insert(key, value);
                }
                StorageAction::FeeAmmSwap(slot, sload_value, amount_in) => {
                    let key = (action.address(), slot);
                    let current =
                        storage_state.apply_sload_value(key, sload_value, "FeeAmmSwap", hardfork);
                    let mut pool = Pool::decode_from_slot(current);
                    pool.apply_swap(
                        amount_in,
                        compute_amount_out(amount_in).expect("compute_amount_out should not fail"),
                    )
                    .unwrap_or_else(|err| {
                        panic!(
                            "FeeAmmSwap invalid for {:?}:{slot:?} on {hardfork:?}: {err}",
                            action.address()
                        )
                    });
                    storage_state
                        .reconstructed
                        .insert(key, pool.encode_to_slot().unwrap());
                }
                StorageAction::FeeAmmLiquidityCheck(
                    slot,
                    sload_value,
                    amount_out,
                    has_enough_liquidity,
                ) => {
                    let key = (action.address(), slot);
                    let current = storage_state.apply_sload_value(
                        key,
                        sload_value,
                        "FeeAmmLiquidityCheck",
                        hardfork,
                    );
                    let pool = Pool::decode_from_slot(current);
                    assert_eq!(
                        pool.has_enough_reserve_validator_token(amount_out),
                        has_enough_liquidity,
                        "FeeAmmLiquidityCheck mismatch for {:?}:{slot:?} on {hardfork:?}",
                        action.address(),
                    );
                }
            }
        }

        for (address, account) in state {
            for (slot, storage_slot) in &account.storage {
                let key = (*address, *slot);
                let original_value = storage_state.first_loads.get(&key).unwrap_or_else(|| {
                    panic!(
                        "EVM output storage cell {address:?}:{slot:?} was not loaded in StorageActions on {hardfork:?}",
                    )
                });
                assert_eq!(
                    *original_value,
                    storage_slot.original_value(),
                    "reconstructed original value mismatch for {address:?}:{slot:?} on {hardfork:?}",
                );

                let reconstructed_value = storage_state.reconstructed.get(&key).unwrap_or_else(|| {
                    panic!(
                        "EVM output storage cell {address:?}:{slot:?} was not reconstructed from StorageActions on {hardfork:?}",
                    )
                });
                assert_eq!(
                    *reconstructed_value,
                    storage_slot.present_value(),
                    "reconstructed present value mismatch for {address:?}:{slot:?} on {hardfork:?}",
                );
            }
        }
    }

    struct StorageActionSnapshotLabels {
        addresses: BTreeMap<Address, &'static str>,
        slots: BTreeMap<(Address, U256), &'static str>,
        tip20_slots: BTreeMap<U256, &'static str>,
    }

    fn snapshot_storage_actions(
        actions: &[StorageAction],
        labels: &StorageActionSnapshotLabels,
    ) -> Vec<String> {
        actions
            .iter()
            .map(|action| match *action {
                StorageAction::Sload(address, slot, value) => {
                    format!(
                        "Sload({}, {}, {value})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::Sstore(address, slot, sload_value, value) => {
                    format!(
                        "Sstore({}, {}, {sload_value}, {value})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::Sinc(address, slot, sload_value, delta) => {
                    format!(
                        "Sinc({}, {}, {sload_value}, {delta})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::Sdec(address, slot, sload_value, delta) => {
                    format!(
                        "Sdec({}, {}, {sload_value}, {delta})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::FeeAmmSwap(slot, sload_value, amount_in) => {
                    format!(
                        "FeeAmmSwap({}, {}, {sload_value}, {amount_in})",
                        labels.address(action.address()),
                        labels.slot(action.address(), slot),
                    )
                }
                StorageAction::FeeAmmLiquidityCheck(
                    slot,
                    slot_value,
                    amount_out,
                    has_enough_liquidity,
                ) => {
                    format!(
                        "FeeAmmLiquidityCheck({}, {}, {slot_value}, {amount_out}, {has_enough_liquidity})",
                        labels.address(action.address()),
                        labels.slot(action.address(), slot),
                    )
                }
            })
            .collect()
    }

    impl StorageActionSnapshotLabels {
        fn address(&self, address: Address) -> String {
            self.addresses
                .get(&address)
                .copied()
                .map(str::to_string)
                .unwrap_or_else(|| format!("{address:?}"))
        }

        fn slot(&self, address: Address, slot: U256) -> String {
            if address.is_tip20() {
                self.tip20_slots.get(&slot)
            } else {
                self.slots.get(&(address, slot))
            }
            .copied()
            .map(str::to_string)
            .unwrap_or_else(|| slot.to_string())
        }
    }

    #[test]
    fn test_tip20_full_evm_storage_actions() {
        for hardfork in TempoHardfork::VARIANTS {
            // skip pre-T5 hardforks to avoid clutter
            if !hardfork.is_t5() {
                continue;
            }

            let sender = Address::repeat_byte(0x01);
            let recipient = Address::repeat_byte(0x02);
            let beneficiary = Address::repeat_byte(0x03);
            let starting_balance = U256::from(1_000_000);
            let transfer_amount = U256::from(100);
            let gas_limit = 1_000_000;
            let gas_price = 1_000_000_000u64;
            let amm_liquidity_reserve = 500_000u128;
            let amm_liquidity = U256::from(amm_liquidity_reserve);

            let mut evm = TempoEvm::new(
                InMemoryDB::default(),
                EvmEnv {
                    block_env: TempoBlockEnv {
                        inner: BlockEnv {
                            beneficiary,
                            basefee: gas_price,
                            gas_limit: 30_000_000,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    ..evm_env_with_spec(*hardfork)
                },
            );

            let (fee_token, two_hop_fee_token) =
                StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
                    TIP20Setup::path_usd(sender)
                        .with_issuer(sender)
                        .with_mint(sender, starting_balance)
                        .apply()?;
                    let fee_token = TIP20Setup::create("FeeToken", "FEE", sender)
                        .with_salt(B256::ZERO)
                        .with_issuer(sender)
                        .with_mint(sender, starting_balance)
                        .with_mint(recipient, starting_balance)
                        .apply()?;
                    let two_hop_fee_token = TIP20Setup::create("TwoHopFeeToken", "2HOP", sender)
                        .with_salt(B256::repeat_byte(0x01))
                        .quote_token(fee_token.address())
                        .with_issuer(sender)
                        .with_mint(sender, starting_balance)
                        .apply()?;

                    let mut fee_manager = TipFeeManager::new();
                    fee_manager.set_user_token(
                        sender,
                        IFeeManager::setUserTokenCall {
                            token: fee_token.address(),
                        },
                    )?;
                    fee_manager.mint(
                        sender,
                        fee_token.address(),
                        PATH_USD_ADDRESS,
                        amm_liquidity,
                        sender,
                    )?;
                    let two_hop_first_pool_id =
                        PoolKey::new(two_hop_fee_token.address(), fee_token.address()).get_id();
                    let two_hop_first_pool_slot =
                        U256::from_be_bytes::<32>(two_hop_first_pool_id.into())
                            .mapping_slot(fee_manager_slots::POOLS);
                    StorageCtx.sstore(
                        TIP_FEE_MANAGER_ADDRESS,
                        two_hop_first_pool_slot,
                        Pool {
                            reserve_user_token: 0,
                            reserve_validator_token: amm_liquidity_reserve,
                        }
                        .encode_to_slot()?,
                    )?;

                    Ok::<(Address, Address), tempo_precompiles::error::TempoPrecompileError>((
                        fee_token.address(),
                        two_hop_fee_token.address(),
                    ))
                })
                .expect("TIP20 setup should succeed");
            let setup_state = evm.ctx_mut().journaled_state.finalize();
            evm.db_mut().commit(setup_state);

            let mut evm = evm.with_actions();
            assert_eq!(evm.take_actions(), Some(vec![]));

            let sender_balance_slot = sender.mapping_slot(tip20_slots::BALANCES);
            let fee_manager_balance_slot =
                TIP_FEE_MANAGER_ADDRESS.mapping_slot(tip20_slots::BALANCES);
            let recipient_balance_slot = recipient.mapping_slot(tip20_slots::BALANCES);
            let sender_reward_info_slot = sender.mapping_slot(tip20_slots::USER_REWARD_INFO);
            let recipient_reward_info_slot = recipient.mapping_slot(tip20_slots::USER_REWARD_INFO);
            let validator_token_slot =
                beneficiary.mapping_slot(fee_manager_slots::VALIDATOR_TOKENS);
            let user_token_slot = sender.mapping_slot(fee_manager_slots::USER_TOKENS);
            let collected_fees_slot = PATH_USD_ADDRESS
                .mapping_slot(beneficiary.mapping_slot(fee_manager_slots::COLLECTED_FEES));
            let pool_id = PoolKey::new(fee_token, PATH_USD_ADDRESS).get_id();
            let pool_slot =
                U256::from_be_bytes::<32>(pool_id.into()).mapping_slot(fee_manager_slots::POOLS);
            let pending_pool_reservation_slot = U256::from_be_bytes::<32>(pool_id.into())
                .mapping_slot(fee_manager_slots::PENDING_FEE_SWAP_RESERVATION);
            let two_hop_direct_pool_id = PoolKey::new(two_hop_fee_token, PATH_USD_ADDRESS).get_id();
            let two_hop_direct_pool_slot = U256::from_be_bytes::<32>(two_hop_direct_pool_id.into())
                .mapping_slot(fee_manager_slots::POOLS);
            let two_hop_first_pool_id = PoolKey::new(two_hop_fee_token, fee_token).get_id();
            let two_hop_first_pool_slot = U256::from_be_bytes::<32>(two_hop_first_pool_id.into())
                .mapping_slot(fee_manager_slots::POOLS);
            let two_hop_first_pending_pool_reservation_slot =
                U256::from_be_bytes::<32>(two_hop_first_pool_id.into())
                    .mapping_slot(fee_manager_slots::PENDING_FEE_SWAP_RESERVATION);
            let receive_policy_config_slot =
                recipient.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES);
            let nonce_key = U256::from(42);
            let sender_nonce_key_slot = nonce_key
                .mapping_slot(sender.mapping_slot(tempo_precompiles::nonce::slots::NONCES));

            #[rustfmt::skip]
            let labels = StorageActionSnapshotLabels {
                addresses: BTreeMap::from([
                    (PATH_USD_ADDRESS, "PATH_USD"),
                    (fee_token, "FEE_TOKEN"),
                    (two_hop_fee_token, "TWO_HOP_FEE_TOKEN"),
                    (TIP_FEE_MANAGER_ADDRESS, "TIP_FEE_MANAGER"),
                    (TIP403_REGISTRY_ADDRESS, "TIP403_REGISTRY"),
                    (STORAGE_CREDITS_ADDRESS, "STORAGE_CREDITS"),
                    (NONCE_PRECOMPILE_ADDRESS, "NONCE_MANAGER"),
                ]),
                slots: BTreeMap::from([
                    ((TIP_FEE_MANAGER_ADDRESS, validator_token_slot), "validatorTokens[beneficiary]"),
                    ((TIP_FEE_MANAGER_ADDRESS, user_token_slot), "userTokens[sender]"),
                    ((TIP_FEE_MANAGER_ADDRESS, collected_fees_slot), "collectedFees[beneficiary][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, pool_slot), "pools[FEE_TOKEN][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, pending_pool_reservation_slot), "pendingFeeSwapReservation[FEE_TOKEN][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, two_hop_direct_pool_slot), "pools[TWO_HOP_FEE_TOKEN][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, two_hop_first_pool_slot), "pools[TWO_HOP_FEE_TOKEN][FEE_TOKEN]"),
                    ((TIP_FEE_MANAGER_ADDRESS, two_hop_first_pending_pool_reservation_slot), "pendingFeeSwapReservation[TWO_HOP_FEE_TOKEN][FEE_TOKEN]"),
                    ((TIP403_REGISTRY_ADDRESS, receive_policy_config_slot), "receivePolicies[recipient]"),
                    ((STORAGE_CREDITS_ADDRESS, StorageCredits::slot(PATH_USD_ADDRESS)), "storageCredits[PATH_USD]"),
                    ((STORAGE_CREDITS_ADDRESS, StorageCredits::slot(fee_token)), "storageCredits[FEE_TOKEN]"),
                    ((STORAGE_CREDITS_ADDRESS, StorageCredits::slot(two_hop_fee_token)), "storageCredits[TWO_HOP_FEE_TOKEN]"),
                    ((NONCE_PRECOMPILE_ADDRESS, sender_nonce_key_slot), "nonces[sender][42]"),
                ]),
                tip20_slots: BTreeMap::from([
                    (tip20_slots::CURRENCY, "currency"),
                    (tip20_slots::QUOTE_TOKEN, "quoteToken"),
                    (tip20_slots::TRANSFER_POLICY_ID, "transferPolicyId"),
                    (tip20_slots::PAUSED, "paused"),
                    (tip20_slots::GLOBAL_REWARD_PER_TOKEN, "globalRewardPerToken"),
                    (sender_balance_slot, "balances[sender]"),
                    (fee_manager_balance_slot, "balances[FeeManager]"),
                    (recipient_balance_slot, "balances[recipient]"),
                    (sender_reward_info_slot + user_reward_info_slots::REWARD_RECIPIENT, "userRewardInfo[sender].rewardRecipient"),
                    (sender_reward_info_slot + user_reward_info_slots::REWARD_PER_TOKEN, "userRewardInfo[sender].rewardPerToken"),
                    (sender_reward_info_slot + user_reward_info_slots::REWARD_BALANCE, "userRewardInfo[sender].rewardBalance"),
                    (recipient_reward_info_slot + user_reward_info_slots::REWARD_RECIPIENT, "userRewardInfo[recipient].rewardRecipient"),
                    (recipient_reward_info_slot + user_reward_info_slots::REWARD_PER_TOKEN, "userRewardInfo[recipient].rewardPerToken"),
                    (recipient_reward_info_slot + user_reward_info_slots::REWARD_BALANCE, "userRewardInfo[recipient].rewardBalance"),
                ]),
            };

            let run_transfer = |evm: &mut TempoEvm<InMemoryDB>,
                                caller: Address,
                                to: Address,
                                amount: U256,
                                nonce: u64,
                                nonce_key: U256,
                                fee_token: Address|
             -> eyre::Result<Vec<String>> {
                let calldata: Bytes = ITIP20::transferCall { to, amount }.abi_encode().into();
                let tx = TempoTxEnv {
                    inner: TxEnv {
                        caller,
                        gas_price: u128::from(gas_price),
                        gas_limit,
                        kind: TxKind::Call(PATH_USD_ADDRESS),
                        data: calldata.clone(),
                        nonce,
                        ..Default::default()
                    },
                    fee_token: Some(fee_token),
                    tempo_tx_env: (!nonce_key.is_zero()).then(|| {
                        Box::new(TempoBatchCallEnv {
                            aa_calls: vec![Call {
                                to: TxKind::Call(PATH_USD_ADDRESS),
                                value: U256::ZERO,
                                input: calldata.clone(),
                            }],
                            nonce_key,
                            ..Default::default()
                        })
                    }),
                    ..Default::default()
                };
                let result = evm.transact_raw(tx)?;
                assert_matches!(
                    result.result,
                    ExecutionResult::Success { .. },
                    "hardfork: {hardfork:?}"
                );
                let actions = evm
                    .take_actions()
                    .expect("storage action recording should be enabled");
                assert_storage_actions_reconstruct_evm_state(&actions, &result.state, *hardfork);
                evm.db_mut().commit(result.state);
                Ok(snapshot_storage_actions(&actions, &labels))
            };

            let snapshot = IndexMap::from([
                // TIP-20 transfer with sequential protocol nonce and a fee token that requires going through feeAMM to pay fees.
                (
                    "direct_first_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        0,
                        U256::ZERO,
                        fee_token,
                    )
                    .unwrap(),
                ),
                // Same as first transfer. Now we expect a lot of storage actions to change from SLOAD+SSTORE into SINC/SDEC, because recipient
                // and fee balances are no longer zero.
                (
                    "direct_second_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        1,
                        U256::ZERO,
                        fee_token,
                    )
                    .unwrap(),
                ),
                // Same as second transfer, but different fee token that requires a two-hop path.
                (
                    "twohop_first_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        2,
                        U256::ZERO,
                        two_hop_fee_token,
                    )
                    .unwrap(),
                ),
                // Same as third transfer.
                (
                    "twohop_second_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        3,
                        U256::ZERO,
                        two_hop_fee_token,
                    )
                    .unwrap(),
                ),
                // TIP-20 transfer with a 2D nonce.
                (
                    "2d_nonce_first_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        0,
                        nonce_key,
                        fee_token,
                    )
                    .unwrap(),
                ),
                (
                    "2d_nonce_second_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        1,
                        nonce_key,
                        fee_token,
                    )
                    .unwrap(),
                ),
                // Clear sender balance, minting a storage credit for PATH_USD.
                ("clear_balance_transfer", {
                    let sender_balance = evm
                        .db()
                        .storage_ref(PATH_USD_ADDRESS, sender_balance_slot)
                        .expect("sender balance slot should be available");
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        sender_balance,
                        4,
                        U256::ZERO,
                        fee_token,
                    )
                    .unwrap()
                }),
                // Recreate sender balance, consuming the PATH_USD storage credit through an SSTORE.
                (
                    "recreate_balance_transfer",
                    run_transfer(
                        &mut evm,
                        recipient,
                        sender,
                        transfer_amount,
                        0,
                        U256::ZERO,
                        fee_token,
                    )
                    .unwrap(),
                ),
            ]);
            insta::assert_yaml_snapshot!(
                format!("tip20_full_evm_storage_actions_{}", hardfork.name()),
                snapshot
            );
        }
    }

    // ==================== TIP-1000 EVM Configuration Tests ====================

    /// Helper to create EvmEnv with a specific hardfork spec.
    fn evm_env_with_spec(
        spec: tempo_chainspec::hardfork::TempoHardfork,
    ) -> EvmEnv<tempo_chainspec::hardfork::TempoHardfork, TempoBlockEnv> {
        EvmEnv::<tempo_chainspec::hardfork::TempoHardfork, TempoBlockEnv>::new(
            CfgEnv::new_with_spec_and_gas_params(
                spec,
                tempo_gas_params_with_amsterdam(spec, false),
            ),
            TempoBlockEnv::default(),
        )
    }

    /// Test that TempoEvm applies custom gas params via `tempo_gas_params()`.
    /// This verifies the [TIP-1000] gas parameter override mechanism.
    ///
    /// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
    #[test]
    fn test_tempo_evm_applies_gas_params() {
        // Create EVM with T1 hardfork to get TIP-1000 gas params
        let evm = TempoEvm::new(EmptyDB::default(), evm_env_with_spec(TempoHardfork::T1));

        // Verify gas params were applied (check a known T1 override)
        // T1 has tx_eip7702_per_empty_account_cost = 12,500
        let gas_params = &evm.ctx().cfg.gas_params;
        assert_eq!(
            gas_params.tx_eip7702_per_empty_account_cost(),
            12_500,
            "T1 should have EIP-7702 per empty account cost of 12,500"
        );
    }

    /// Test that TempoEvm respects the gas limit cap passed in via EvmEnv.
    /// Note: The 30M [TIP-1000] gas cap is set in ConfigureEvm::evm_env(), not here.
    /// This test verifies that TempoEvm::new() preserves the cap from the input.
    ///
    /// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
    #[test]
    fn test_tempo_evm_respects_gas_cap() {
        let mut env = evm_env_with_spec(TempoHardfork::T1);
        env.cfg_env.tx_gas_limit_cap = TempoHardfork::T1.tx_gas_limit_cap();

        let evm = TempoEvm::new(EmptyDB::default(), env);

        // Verify gas limit cap is preserved
        assert_eq!(
            evm.ctx().cfg.tx_gas_limit_cap,
            TempoHardfork::T1.tx_gas_limit_cap(),
            "TempoEvm should preserve the gas limit cap from input"
        );
    }

    /// Test that gas params differ between T0 and T1 hardforks.
    #[test]
    fn test_tempo_evm_gas_params_differ_t0_vs_t1() {
        // Create T0 and T1 EVMs
        let t0_evm = TempoEvm::new(EmptyDB::default(), evm_env_with_spec(TempoHardfork::T0));
        let t1_evm = TempoEvm::new(EmptyDB::default(), evm_env_with_spec(TempoHardfork::T1));

        // T0 should have default EIP-7702 cost (25,000)
        // T1 should have reduced cost (12,500)
        let t0_eip7702_cost = t0_evm
            .ctx()
            .cfg
            .gas_params
            .tx_eip7702_per_empty_account_cost();
        let t1_eip7702_cost = t1_evm
            .ctx()
            .cfg
            .gas_params
            .tx_eip7702_per_empty_account_cost();

        assert_eq!(t0_eip7702_cost, 25_000, "T0 should have default 25,000");
        assert_eq!(t1_eip7702_cost, 12_500, "T1 should have reduced 12,500");
        assert_ne!(
            t0_eip7702_cost, t1_eip7702_cost,
            "Gas params should differ between T0 and T1"
        );
    }

    /// Test that T1 has significantly higher state creation costs.
    #[test]
    fn test_tempo_evm_t1_state_creation_costs() {
        use revm::context_interface::cfg::GasId;

        let evm = TempoEvm::new(EmptyDB::default(), evm_env_with_spec(TempoHardfork::T1));
        let gas_params = &evm.ctx().cfg.gas_params;

        // Verify TIP-1000 state creation cost increases
        assert_eq!(
            gas_params.get(GasId::sstore_set_without_load_cost()),
            250_000,
            "T1 SSTORE set cost should be 250,000"
        );
        assert_eq!(
            gas_params.get(GasId::tx_create_cost()),
            500_000,
            "T1 TX create cost should be 500,000"
        );
        assert_eq!(
            gas_params.get(GasId::create()),
            500_000,
            "T1 CREATE opcode cost should be 500,000"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_cost()),
            250_000,
            "T1 new account cost should be 250,000"
        );
        assert_eq!(
            gas_params.get(GasId::code_deposit_cost()),
            1_000,
            "T1 code deposit cost should be 1,000 per byte"
        );
    }
}
