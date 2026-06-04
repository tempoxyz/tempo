use alloy_primitives::Address;
use reth_evm::{Database, Evm};
use reth_storage_api::StateProviderFactory;
use reth_tasks::{TaskExecutor, WorkerPool};
use reth_transaction_pool::{BestTransactions, error::InvalidPoolTransactionError};
use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    },
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{
    Tip20TransferBlockstmFallback, Tip20TransferBlockstmPlan, Tip20TransferBlockstmTx,
    build_tip20_transfer_blockstm_plan, prewarm_tip20_transfer_blockstm_plan,
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::TipFeeManager,
};
use tempo_transaction_pool::{
    StateAwareBestTransactions,
    best::{BestTransaction, StateAwareBestTransactionsUpdate},
};
use tracing::trace;

use crate::prewarming::{PrewarmEvmState, PrewarmingExecutionContext};

#[derive(Debug)]
pub(crate) enum PayloadBuildError {
    Unsupported(&'static str),
    Planning(Tip20TransferBlockstmFallback),
    Execution(Tip20TransferBlockstmFallback),
}

impl fmt::Display for PayloadBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(reason) => {
                write!(f, "BlockSTM TIP-20 payload build unsupported: {reason}")
            }
            Self::Planning(reason) => write!(
                f,
                "BlockSTM TIP-20 plan creation failed: {}",
                reason.as_str()
            ),
            Self::Execution(reason) => {
                write!(f, "BlockSTM TIP-20 execution failed: {}", reason.as_str())
            }
        }
    }
}

impl Error for PayloadBuildError {}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PlanningContext {
    pub(crate) validator_token: Address,
    pub(crate) beneficiary: Address,
    pub(crate) basefee: u128,
    pub(crate) blob_gasprice: u128,
    pub(crate) spec: TempoHardfork,
}

#[derive(Debug)]
pub(crate) struct PlannedTransfer {
    pub(crate) tx: BestTransaction,
    pub(crate) plan: Tip20TransferBlockstmPlan,
}

/// TIP-20 BlockSTM planner backed by the payload prewarming worker pool.
pub(crate) struct Planner<Provider> {
    commands_tx: Sender<PlannerCommand>,
    results_rx: Receiver<PlannerMessage>,
    stop: Arc<AtomicBool>,
    prewarm: Option<PrewarmingExecutionContext<Provider>>,
    scheduled_count: Arc<AtomicUsize>,
    completed_count: usize,
    source_exhausted: bool,
}

pub(crate) enum PlannerNext {
    Planned(Result<PlannedTransfer, Tip20TransferBlockstmFallback>),
    Empty,
}

impl<Provider> Planner<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    pub(crate) fn new<Txs>(
        executor: TaskExecutor,
        ctx: PlanningContext,
        prewarm: Option<PrewarmingExecutionContext<Provider>>,
        best_txs: StateAwareBestTransactions<Txs>,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + 'static,
    {
        let (results_tx, results_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let scheduled_count = Arc::new(AtomicUsize::new(0));
        let coordinator_stop = stop.clone();

        let coordinator_executor = executor.clone();
        let coordinator_commands_tx = commands_tx.clone();
        let coordinator_prewarm = prewarm.clone();
        let coordinator_scheduled_count = scheduled_count.clone();
        executor.spawn_blocking_named("builder-blockstm-planner", move || {
            Self::start_planning(
                coordinator_executor,
                PlannerContext {
                    best_txs,
                    results_tx,
                    commands_rx,
                    commands_tx: coordinator_commands_tx,
                    stop: coordinator_stop,
                    prewarm: coordinator_prewarm,
                    ctx,
                    scheduled_count: coordinator_scheduled_count,
                    next_sequence: 0,
                    source_exhausted: false,
                },
            );
        });

        Self {
            commands_tx,
            results_rx,
            stop,
            prewarm,
            scheduled_count,
            completed_count: 0,
            source_exhausted: false,
        }
    }

    fn start_planning<Txs>(
        executor: TaskExecutor,
        mut planner: PlannerContext<StateAwareBestTransactions<Txs>, Provider>,
    ) where
        Txs: BestTransactions<Item = BestTransaction> + 'static,
    {
        let pool = executor.prewarming_pool();

        pool.in_place_scope(|scope| {
            if let Some(prewarm) = planner.prewarm.clone() {
                scope.spawn(move |_| {
                    pool.init::<PrewarmEvmState>(|_| prewarm.evm_for_ctx());
                });
            }

            let advance =
                |planner: &mut PlannerContext<StateAwareBestTransactions<Txs>, Provider>| {
                    if planner.source_exhausted || planner.stop.load(Ordering::Relaxed) {
                        return;
                    }

                    let Some(tx) = planner.best_txs.next() else {
                        planner.source_exhausted = true;
                        let _ = planner.results_tx.send(PlannerMessage::SourceExhausted);
                        return;
                    };

                    let sequence = planner.next_sequence;
                    planner.next_sequence += 1;
                    planner
                        .scheduled_count
                        .store(planner.next_sequence, Ordering::Relaxed);

                    let results_tx = planner.results_tx.clone();
                    let commands_tx = planner.commands_tx.clone();
                    let prewarm = planner.prewarm.clone();
                    let ctx = planner.ctx;
                    scope.spawn(move |_| {
                        let item = build_tip20_transfer_blockstm_plan(
                            &candidate(&tx),
                            ctx.validator_token,
                            ctx.beneficiary,
                            ctx.basefee,
                            ctx.blob_gasprice,
                            ctx.spec,
                        )
                        .map(|plan| {
                            if let Some(prewarm) = prewarm {
                                prewarm_tip20_transfer_plan(&prewarm, &plan, sequence);
                            }
                            PlannedTransfer { tx, plan }
                        });
                        let _ = results_tx.send(PlannerMessage::Planned(item));
                        let _ = commands_tx.send(PlannerCommand::Advance);
                    });
                };

            for _ in 0..pool.current_num_threads() * 2 {
                advance(&mut planner);
            }

            while let Ok(command) = planner.commands_rx.recv() {
                match command {
                    PlannerCommand::Advance => {
                        advance(&mut planner);
                    }
                    PlannerCommand::Invalid { tx, kind } => {
                        planner.best_txs.mark_invalid(&tx, kind);
                    }
                    PlannerCommand::StateUpdate(update) => {
                        planner.best_txs.apply_update(update);
                    }
                    PlannerCommand::Stop => {
                        planner.stop.store(true, Ordering::Relaxed);
                        if let Some(prewarm) = &planner.prewarm {
                            prewarm.stop();
                        }
                        return;
                    }
                }
            }
        });

        if planner.prewarm.is_some() {
            pool.clear();
        }
    }

    pub(crate) fn mark_invalid(&self, tx: &BestTransaction, kind: InvalidPoolTransactionError) {
        let _ = self.commands_tx.send(PlannerCommand::Invalid {
            tx: tx.clone(),
            kind,
        });
    }

    pub(crate) fn on_state_update(&self, update: StateAwareBestTransactionsUpdate) {
        let _ = self.commands_tx.send(PlannerCommand::StateUpdate(update));
    }

    pub(crate) fn scheduled_count(&self) -> usize {
        self.scheduled_count.load(Ordering::Relaxed)
    }

    pub(crate) fn next(&mut self) -> PlannerNext {
        loop {
            if self.source_exhausted
                && self.completed_count == self.scheduled_count.load(Ordering::Relaxed)
            {
                return PlannerNext::Empty;
            }

            let Ok(message) = self.results_rx.recv() else {
                return PlannerNext::Empty;
            };
            if let Some(item) = self.record_message(message) {
                return PlannerNext::Planned(item);
            }
        }
    }

    fn record_message(
        &mut self,
        message: PlannerMessage,
    ) -> Option<Result<PlannedTransfer, Tip20TransferBlockstmFallback>> {
        match message {
            PlannerMessage::SourceExhausted => {
                self.source_exhausted = true;
                None
            }
            PlannerMessage::Planned(item) => {
                self.completed_count += 1;
                Some(item)
            }
        }
    }
}

impl<Provider> Drop for Planner<Provider> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(prewarm) = &self.prewarm {
            prewarm.stop();
        }
        let _ = self.commands_tx.send(PlannerCommand::Stop);
    }
}

struct PlannerContext<Txs, Provider> {
    best_txs: Txs,
    results_tx: Sender<PlannerMessage>,
    commands_rx: Receiver<PlannerCommand>,
    commands_tx: Sender<PlannerCommand>,
    stop: Arc<AtomicBool>,
    prewarm: Option<PrewarmingExecutionContext<Provider>>,
    ctx: PlanningContext,
    scheduled_count: Arc<AtomicUsize>,
    next_sequence: usize,
    source_exhausted: bool,
}

#[derive(Debug)]
enum PlannerMessage {
    Planned(Result<PlannedTransfer, Tip20TransferBlockstmFallback>),
    SourceExhausted,
}

#[derive(Debug)]
enum PlannerCommand {
    Advance,
    Invalid {
        tx: BestTransaction,
        kind: InvalidPoolTransactionError,
    },
    StateUpdate(StateAwareBestTransactionsUpdate),
    Stop,
}

fn prewarm_tip20_transfer_plan<Provider>(
    prewarm: &PrewarmingExecutionContext<Provider>,
    plan: &Tip20TransferBlockstmPlan,
    sequence: usize,
) where
    Provider: StateProviderFactory + Clone + 'static,
{
    if prewarm.is_stopped() {
        return;
    }

    WorkerPool::with_worker_mut(|worker| {
        let Some(evm) = worker.get_or_init::<PrewarmEvmState>(|| prewarm.evm_for_ctx()) else {
            return;
        };

        if let Err(err) = prewarm_tip20_transfer_blockstm_plan(evm.db_mut(), plan) {
            trace!(
                target: "payload_builder",
                ?err,
                sequence,
                "Failed to prewarm BlockSTM TIP-20 plan storage"
            );
        }
    });
}

/// Builds an executor-owned BlockSTM candidate from a pooled transaction.
pub(crate) fn candidate(tx: &BestTransaction) -> Tip20TransferBlockstmTx<'_> {
    Tip20TransferBlockstmTx {
        tx_env: tx.transaction.clone_tx_env(),
        recovered: tx.transaction.inner(),
        fee_token: tx.transaction.effective_fee_token(),
    }
}

/// Reads the validator's preferred fee token from FeeManager storage.
pub(crate) fn validator_token<DB: Database>(
    db: &mut DB,
    beneficiary: Address,
) -> Result<Address, DB::Error> {
    let slot = TipFeeManager::new().validator_tokens[beneficiary].slot();
    let token = db.storage(TIP_FEE_MANAGER_ADDRESS, slot)?;
    if token.is_zero() {
        Ok(DEFAULT_FEE_TOKEN)
    } else {
        Ok(Address::from_word(token.into()))
    }
}
