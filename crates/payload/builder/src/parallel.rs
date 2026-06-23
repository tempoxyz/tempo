use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc::{self, Receiver, Sender},
};

use reth_evm::Evm;
use reth_storage_api::StateProviderFactory;
use reth_tasks::{TaskExecutor, WorkerPool};
use reth_transaction_pool::{BestTransactions, error::InvalidPoolTransactionError};
use tempo_evm::{ExpiringNonceReplay, StorageActionReplay, TempoTxResult, evm::TempoEvm};
use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, storage::StorageAction};
use tempo_transaction_pool::{
    StateAwareBestTransactions,
    best::{BestTransaction, StateAwareBestTransactionsUpdate},
    transaction::StorageActionReplaySource,
};
use tracing::trace;

use crate::prewarming::{PrewarmEvmState, PrewarmingExecutionContext};

#[derive(Debug)]
pub(crate) struct PlannedTransaction {
    pub(crate) tx: BestTransaction,
    pub(crate) replay: Option<Box<StorageActionReplay>>,
    pub(crate) replay_source: Option<StorageActionReplaySource>,
    pub(crate) action_buffer: Option<Vec<StorageAction>>,
}

impl PlannedTransaction {
    pub(crate) fn without_replay(tx: BestTransaction) -> Self {
        Self {
            tx,
            replay: None,
            replay_source: None,
            action_buffer: None,
        }
    }
}

/// Streams speculative action collection on the prewarming worker pool.
pub(crate) struct PrewarmingPlanner<Provider> {
    commands_tx: Sender<PlannerCommand>,
    results_rx: Receiver<PlannerMessage>,
    stop: Arc<AtomicBool>,
    prewarm: PrewarmingExecutionContext<Provider>,
    in_flight: Arc<AtomicUsize>,
    state_updates_rx: Receiver<StateAwareBestTransactionsUpdate>,
    state_update_pool: Vec<StateAwareBestTransactionsUpdate>,
    completed: usize,
    source_exhausted: bool,
}

impl<Provider> PrewarmingPlanner<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    pub(crate) fn new<Txs>(
        prewarm: PrewarmingExecutionContext<Provider>,
        best_txs: StateAwareBestTransactions<Txs>,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
    {
        let (results_tx, results_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let (state_updates_tx, state_updates_rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let in_flight = Arc::new(AtomicUsize::new(0));

        let executor = prewarm.executor();
        let planner_ctx = PlannerContext {
            best_txs,
            results_tx,
            commands_tx: commands_tx.clone(),
            commands_rx,
            state_updates_tx,
            stop: stop.clone(),
            prewarm: prewarm.clone(),
            in_flight: in_flight.clone(),
            action_buffers: Vec::new(),
            next_expiring_nonce_offset: 0,
            source_exhausted: false,
        };
        prewarm
            .executor()
            .spawn_blocking_named("builder-planner", move || {
                Self::start_planner(executor, planner_ctx);
            });

        Self {
            commands_tx,
            results_rx,
            stop,
            prewarm,
            in_flight,
            state_updates_rx,
            state_update_pool: Vec::new(),
            completed: 0,
            source_exhausted: false,
        }
    }

    fn start_planner<Txs>(
        executor: TaskExecutor,
        mut ctx: PlannerContext<StateAwareBestTransactions<Txs>, Provider>,
    ) where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
    {
        let pool = executor.prewarming_pool();

        pool.in_place_scope(|scope| {
            let prewarm = ctx.prewarm.clone();
            scope.spawn(move |_| {
                pool.init::<PrewarmEvmState>(|_| prewarm.evm_for_ctx().map(TempoEvm::with_actions));
            });

            let advance = |planner: &mut PlannerContext<
                StateAwareBestTransactions<Txs>,
                Provider,
            >| {
                if planner.source_exhausted || planner.stop.load(Ordering::Relaxed) {
                    return;
                }

                let Some(tx) = planner.best_txs.next() else {
                    planner.source_exhausted = true;
                    let _ = planner.results_tx.send(PlannerMessage::SourceExhausted);
                    return;
                };

                planner.in_flight.fetch_add(1, Ordering::Relaxed);
                let expiring_nonce_offset = if tx.transaction.is_expiring_nonce() {
                    let offset = planner.next_expiring_nonce_offset;
                    planner.next_expiring_nonce_offset += 1;
                    Some(offset)
                } else {
                    None
                };

                let prewarm = planner.prewarm.clone();
                let results_tx = planner.results_tx.clone();
                let commands_tx = planner.commands_tx.clone();
                let action_buffer = planner.action_buffers.pop();
                scope.spawn(move |_| {
                    let planned =
                        plan_transaction_replay(prewarm, tx, action_buffer, expiring_nonce_offset);
                    let _ = results_tx.send(PlannerMessage::Planned { planned });
                    let _ = commands_tx.send(PlannerCommand::Advance);
                });
            };

            for _ in 0..pool.current_num_threads() * 2 {
                advance(&mut ctx);
            }

            while let Ok(command) = ctx.commands_rx.recv() {
                match command {
                    PlannerCommand::Advance => {
                        advance(&mut ctx);
                    }
                    PlannerCommand::Invalid { tx, kind } => {
                        ctx.best_txs.mark_invalid(&tx, kind);
                    }
                    PlannerCommand::StateUpdate(mut update) => {
                        ctx.best_txs.apply_update(&update);
                        update.clear();
                        let _ = ctx.state_updates_tx.send(update);
                    }
                    PlannerCommand::RecycleActions(mut actions) => {
                        actions.clear();
                        ctx.action_buffers.push(actions);
                    }
                    PlannerCommand::Stop {
                        drain_rx: _drain_rx,
                    } => {
                        ctx.stop.store(true, Ordering::Relaxed);
                        ctx.prewarm.stop();
                        return;
                    }
                }
            }
        });

        pool.clear();
    }

    pub(crate) fn next(&mut self) -> Option<PlannedTransaction> {
        loop {
            if self.source_exhausted && self.completed == self.in_flight.load(Ordering::Relaxed) {
                return None;
            }

            let Ok(message) = self.results_rx.recv() else {
                return None;
            };

            match message {
                PlannerMessage::Planned { planned } => {
                    self.completed += 1;
                    return Some(planned);
                }
                PlannerMessage::SourceExhausted => {
                    self.source_exhausted = true;
                }
            }
        }
    }

    pub(crate) fn mark_invalid(&self, tx: &BestTransaction, kind: InvalidPoolTransactionError) {
        let _ = self.commands_tx.send(PlannerCommand::Invalid {
            tx: tx.clone(),
            kind,
        });
    }

    pub(crate) fn recycle_actions(&self, mut actions: Vec<StorageAction>) {
        actions.clear();
        let _ = self
            .commands_tx
            .send(PlannerCommand::RecycleActions(actions));
    }

    pub(crate) fn on_state_update(&mut self, result: &TempoTxResult) {
        self.recycle_state_updates();

        let mut update = self.state_update_pool.pop().unwrap_or_default();
        update.update_from_result(result);
        if update.is_empty() {
            self.state_update_pool.push(update);
            return;
        }

        if let Err(mpsc::SendError(PlannerCommand::StateUpdate(update))) =
            self.commands_tx.send(PlannerCommand::StateUpdate(update))
        {
            self.state_update_pool.push(update);
        }
    }

    fn recycle_state_updates(&mut self) {
        while let Ok(update) = self.state_updates_rx.try_recv() {
            self.state_update_pool.push(update);
        }
    }
}

impl<Provider> Drop for PrewarmingPlanner<Provider> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.prewarm.stop();

        let (_drain_tx, replacement_rx) = mpsc::channel();
        let drain_rx = core::mem::replace(&mut self.results_rx, replacement_rx);
        let _ = self.commands_tx.send(PlannerCommand::Stop { drain_rx });
    }
}

struct PlannerContext<Txs, Provider> {
    best_txs: Txs,
    results_tx: Sender<PlannerMessage>,
    commands_tx: Sender<PlannerCommand>,
    commands_rx: Receiver<PlannerCommand>,
    state_updates_tx: Sender<StateAwareBestTransactionsUpdate>,
    stop: Arc<AtomicBool>,
    prewarm: PrewarmingExecutionContext<Provider>,
    in_flight: Arc<AtomicUsize>,
    action_buffers: Vec<Vec<StorageAction>>,
    next_expiring_nonce_offset: usize,
    source_exhausted: bool,
}

enum PlannerCommand {
    Advance,
    Invalid {
        tx: BestTransaction,
        kind: InvalidPoolTransactionError,
    },
    StateUpdate(StateAwareBestTransactionsUpdate),
    RecycleActions(Vec<StorageAction>),
    Stop {
        drain_rx: Receiver<PlannerMessage>,
    },
}

#[derive(Debug)]
enum PlannerMessage {
    Planned { planned: PlannedTransaction },
    SourceExhausted,
}

fn plan_transaction_replay<Provider>(
    prewarm: PrewarmingExecutionContext<Provider>,
    tx: BestTransaction,
    mut action_buffer: Option<Vec<StorageAction>>,
    expiring_nonce_offset: Option<usize>,
) -> PlannedTransaction
where
    Provider: StateProviderFactory + Clone + 'static,
{
    if prewarm.is_stopped() {
        return PlannedTransaction {
            tx,
            replay: None,
            replay_source: None,
            action_buffer,
        };
    }

    let parent_hash = prewarm.parent_hash();
    if let Some((replay, replay_source)) = tx
        .transaction
        .cached_storage_action_replay_with_source(parent_hash)
    {
        return PlannedTransaction {
            tx,
            replay: Some(Box::new(replay)),
            replay_source: Some(replay_source),
            action_buffer,
        };
    }

    let replay = WorkerPool::with_worker_mut(|worker| {
        let Some(evm) = worker
            .get_or_init::<PrewarmEvmState>(|| prewarm.evm_for_ctx().map(TempoEvm::with_actions))
        else {
            return None;
        };

        let tx_hash = *tx.hash();

        if prewarm.is_stopped() {
            return None;
        }

        if !tx.transaction.is_storage_action_replay_candidate() {
            evm.clear_actions();
            return None;
        }

        let expiring_nonce = expiring_nonce_replay(&tx);
        let mut tx_env = tx.transaction.clone_tx_env();
        if let Some(tempo_tx_env) = tx_env.tempo_tx_env.as_mut() {
            tempo_tx_env.expiring_nonce_idx = expiring_nonce_offset;
        }

        let mut result = match evm.transact_raw(tx_env) {
            Ok(result) => result,
            Err(err) => {
                evm.clear_actions();
                trace!(
                    target: "payload_builder",
                    %err,
                    ?tx_hash,
                    "Failed to collect prewarm storage actions"
                );
                return None;
            }
        };

        if !result.result.is_success() {
            evm.clear_actions();
            trace!(
                target: "payload_builder",
                ?tx_hash,
                result = ?result.result,
                "Prewarm action collection produced non-success result"
            );
            return None;
        }

        let mut actions = evm.replace_actions(action_buffer.take().unwrap_or_default())?;
        if expiring_nonce.is_some() {
            actions.retain(|action| !is_nonce_manager_action(action));
        }
        if actions.is_empty() && expiring_nonce.is_none() {
            action_buffer = Some(actions);
            return None;
        }

        result.state.clear();
        Some(Box::new(StorageActionReplay {
            result: result.result,
            actions,
            validator_fee: evm.validator_fee(),
            state: result.state,
            expiring_nonce,
        }))
    });

    if let Some(replay) = replay.as_ref() {
        tx.transaction.cache_storage_action_replay(
            parent_hash,
            (**replay).clone(),
            StorageActionReplaySource::PayloadBuilder,
        );
    }
    let replay_source = replay
        .as_ref()
        .map(|_| StorageActionReplaySource::PayloadBuilder);

    PlannedTransaction {
        tx,
        replay,
        replay_source,
        action_buffer,
    }
}

fn expiring_nonce_replay(tx: &BestTransaction) -> Option<ExpiringNonceReplay> {
    if !tx.transaction.is_expiring_nonce() {
        return None;
    }

    let valid_before = tx
        .transaction
        .tx_env()
        .tempo_tx_env
        .as_ref()?
        .valid_before?;
    Some(ExpiringNonceReplay {
        hash: tx.transaction.expiring_nonce_hash()?,
        valid_before,
    })
}

fn is_nonce_manager_action(action: &StorageAction) -> bool {
    let address = match *action {
        StorageAction::Sload(address, ..)
        | StorageAction::Sstore(address, ..)
        | StorageAction::Sinc(address, ..)
        | StorageAction::Sdec(address, ..) => address,
    };
    address == NONCE_PRECOMPILE_ADDRESS
}
