use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
};

use reth_evm::Evm;
use reth_storage_api::StateProviderFactory;
use reth_tasks::{TaskExecutor, WorkerPool};
use reth_transaction_pool::BestTransactions;
use tempo_evm::evm::TempoEvm;
use tempo_precompiles::storage::StorageAction;
use tempo_transaction_pool::best::BestTransaction;
use tracing::trace;

use crate::prewarming::{PrewarmEvmState, PrewarmingExecutionContext};

/// Starts speculative action collection on the prewarming worker pool.
///
/// The payload builder does not consume these actions yet. This is a staging
/// point for wiring action replay without changing block construction behavior.
pub(crate) struct PrewarmingPlanner<Provider> {
    commands_tx: Sender<PlannerCommand>,
    stop: Arc<AtomicBool>,
    prewarm: PrewarmingExecutionContext<Provider>,
}

impl<Provider> PrewarmingPlanner<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    pub(crate) fn new<Txs>(
        executor: TaskExecutor,
        prewarm: PrewarmingExecutionContext<Provider>,
        best_txs: Txs,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
    {
        let (commands_tx, commands_rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));

        let coordinator_executor = executor.clone();
        let coordinator_commands_tx = commands_tx.clone();
        let coordinator_stop = stop.clone();
        let coordinator_prewarm = prewarm.clone();
        executor.spawn_blocking_named("builder-prewarm-planner", move || {
            Self::start_planner(
                coordinator_executor,
                PlannerContext {
                    best_txs,
                    commands_tx: coordinator_commands_tx,
                    commands_rx,
                    stop: coordinator_stop,
                    prewarm: coordinator_prewarm,
                    next_expiring_nonce_offset: 0,
                    source_exhausted: false,
                    in_flight: 0,
                },
            );
        });

        Self {
            commands_tx,
            stop,
            prewarm,
        }
    }

    fn start_planner<Txs>(executor: TaskExecutor, mut ctx: PlannerContext<Txs, Provider>)
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
    {
        let pool = executor.prewarming_pool();

        pool.in_place_scope(|scope| {
            let prewarm = ctx.prewarm.clone();
            scope.spawn(move |_| {
                pool.init::<PrewarmEvmState>(|_| prewarm.evm_for_ctx().map(TempoEvm::with_actions));
            });

            let advance = |planner: &mut PlannerContext<Txs, Provider>| {
                if planner.source_exhausted || planner.stop.load(Ordering::Relaxed) {
                    return;
                }

                let Some(tx) = planner.best_txs.next() else {
                    planner.source_exhausted = true;
                    return;
                };

                let expiring_nonce_offset = if tx.transaction.is_expiring_nonce() {
                    let offset = planner.next_expiring_nonce_offset;
                    planner.next_expiring_nonce_offset += 1;
                    Some(offset)
                } else {
                    None
                };

                planner.in_flight += 1;
                let prewarm = planner.prewarm.clone();
                let commands_tx = planner.commands_tx.clone();
                scope.spawn(move |_| {
                    let collected = prewarm_transaction_actions(prewarm, tx, expiring_nonce_offset);
                    let _ = commands_tx.send(PlannerCommand::TaskDone { collected });
                });
            };

            for _ in 0..pool.current_num_threads() * 2 {
                advance(&mut ctx);
            }

            while ctx.in_flight != 0 || !ctx.source_exhausted {
                let Ok(command) = ctx.commands_rx.recv() else {
                    break;
                };

                match command {
                    PlannerCommand::TaskDone { collected } => {
                        ctx.in_flight = ctx.in_flight.saturating_sub(1);
                        if let Some(collected) = collected {
                            trace!(
                                target: "payload_builder",
                                tx_hash = ?collected.tx.hash(),
                                action_count = collected.actions.len(),
                                "Collected prewarm storage actions"
                            );
                        }
                        advance(&mut ctx);
                    }
                    PlannerCommand::Stop => {
                        ctx.stop.store(true, Ordering::Relaxed);
                        ctx.prewarm.stop();
                        return;
                    }
                }
            }
        });

        pool.clear();
    }
}

impl<Provider> Drop for PrewarmingPlanner<Provider> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.prewarm.stop();
        let _ = self.commands_tx.send(PlannerCommand::Stop);
    }
}

struct PlannerContext<Txs, Provider> {
    best_txs: Txs,
    commands_tx: Sender<PlannerCommand>,
    commands_rx: Receiver<PlannerCommand>,
    stop: Arc<AtomicBool>,
    prewarm: PrewarmingExecutionContext<Provider>,
    next_expiring_nonce_offset: usize,
    source_exhausted: bool,
    in_flight: usize,
}

#[derive(Debug)]
enum PlannerCommand {
    TaskDone { collected: Option<CollectedActions> },
    Stop,
}

#[derive(Debug)]
struct CollectedActions {
    tx: BestTransaction,
    actions: Vec<StorageAction>,
}

fn prewarm_transaction_actions<Provider>(
    prewarm: PrewarmingExecutionContext<Provider>,
    tx: BestTransaction,
    expiring_nonce_offset: Option<usize>,
) -> Option<CollectedActions>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    if prewarm.is_stopped() {
        return None;
    }

    WorkerPool::with_worker_mut(|worker| {
        let Some(evm) = worker
            .get_or_init::<PrewarmEvmState>(|| prewarm.evm_for_ctx().map(TempoEvm::with_actions))
        else {
            return None;
        };

        let tx_hash = *tx.hash();

        if prewarm.is_stopped() {
            return None;
        }

        let mut tx_env = tx.transaction.clone_tx_env();
        if let Some(tempo_tx_env) = tx_env.tempo_tx_env.as_mut() {
            tempo_tx_env.expiring_nonce_idx = expiring_nonce_offset;
        }

        let result = match evm.transact_raw(tx_env) {
            Ok(result) => result,
            Err(err) => {
                let _ = evm.replace_actions(Vec::new());
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
            let _ = evm.replace_actions(Vec::new());
            trace!(
                target: "payload_builder",
                ?tx_hash,
                result = ?result.result,
                "Prewarm action collection produced non-success result"
            );
            return None;
        }

        let actions = evm.take_actions()?;
        if actions.is_empty() {
            return None;
        }

        Some(CollectedActions { tx, actions })
    })
}
