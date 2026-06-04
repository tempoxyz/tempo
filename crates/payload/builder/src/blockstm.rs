use alloy_primitives::Address;
use reth_evm::{Database, Evm};
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_revm::context::result::{EVMError, InvalidTransaction};
use reth_storage_api::StateProviderFactory;
use reth_tasks::{TaskExecutor, WorkerPool};
use reth_transaction_pool::{BestTransactions, error::InvalidPoolTransactionError};
use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender, SyncSender},
    },
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{
    TempoInvalidTransaction, Tip20TransferActionReplay, Tip20TransferBlockstmFallback,
    Tip20TransferBlockstmTx, validate_tip20_transfer_blockstm_tx,
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::TipFeeManager,
};
use tempo_transaction_pool::{
    StateAwareBestTransactions,
    best::{BestTransaction, StateAwareBestTransactionsUpdate},
    transaction::TempoPoolTransactionError,
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
            Self::Planning(reason) => {
                write!(f, "BlockSTM TIP-20 planning failed: {}", reason.as_str())
            }
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
    pub(crate) spec: TempoHardfork,
}

#[derive(Debug)]
pub(crate) enum PlannedTransfer {
    Valid {
        tx: BestTransaction,
        replay: Tip20TransferActionReplay,
    },
    Invalid {
        tx: BestTransaction,
        kind: InvalidPoolTransactionError,
    },
}

/// TIP-20 BlockSTM planner backed by the payload prewarming worker pool.
pub(crate) struct Planner<Provider> {
    commands_tx: Sender<PlannerCommand>,
    results_rx: Receiver<PlannerMessage>,
    stop: Arc<AtomicBool>,
    prewarm: PrewarmingExecutionContext<Provider>,
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
        prewarm: PrewarmingExecutionContext<Provider>,
        best_txs: StateAwareBestTransactions<Txs>,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + 'static,
    {
        let (results_tx, results_rx) = mpsc::sync_channel(1);
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
            let prewarm = planner.prewarm.clone();
            scope.spawn(move |_| {
                pool.init::<PrewarmEvmState>(|_| prewarm.evm_for_ctx());
            });

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
                        let item = (|| {
                            let candidate = candidate(&tx);
                            validate_tip20_transfer_blockstm_tx(
                                &candidate,
                                ctx.validator_token,
                                ctx.spec,
                            )?;
                            match prewarm_tip20_transfer_actions(&prewarm, candidate, sequence)? {
                                Ok(replay) => Ok(PlannedTransfer::Valid { tx, replay }),
                                Err(kind) => Ok(PlannedTransfer::Invalid { tx, kind }),
                            }
                        })();
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
                        planner.prewarm.stop();
                        return;
                    }
                }
            }
        });

        pool.clear();
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
        self.prewarm.stop();
        let _ = self.commands_tx.send(PlannerCommand::Stop);
    }
}

struct PlannerContext<Txs, Provider> {
    best_txs: Txs,
    results_tx: SyncSender<PlannerMessage>,
    commands_rx: Receiver<PlannerCommand>,
    commands_tx: Sender<PlannerCommand>,
    stop: Arc<AtomicBool>,
    prewarm: PrewarmingExecutionContext<Provider>,
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

fn prewarm_tip20_transfer_actions<Provider>(
    prewarm: &PrewarmingExecutionContext<Provider>,
    candidate: Tip20TransferBlockstmTx<'_>,
    sequence: usize,
) -> Result<
    Result<Tip20TransferActionReplay, InvalidPoolTransactionError>,
    Tip20TransferBlockstmFallback,
>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    if prewarm.is_stopped() {
        return Err(Tip20TransferBlockstmFallback::ActionExecutionFailed);
    }

    WorkerPool::with_worker_mut(|worker| {
        let Some(evm) = worker.get_or_init::<PrewarmEvmState>(|| prewarm.evm_for_ctx()) else {
            return Err(Tip20TransferBlockstmFallback::ActionExecutionFailed);
        };

        let _ = evm.take_actions();
        let result = match evm.transact_raw(candidate.tx_env) {
            Ok(result) => result,
            Err(err) => {
                trace!(
                target: "payload_builder",
                ?err,
                sequence,
                "Failed to prewarm BlockSTM TIP-20 transfer actions"
                );
                return invalid_pool_error_from_evm_error(err).map(Err);
            }
        };
        if !result.result.is_success() {
            trace!(
                target: "payload_builder",
                sequence,
                result = ?result.result,
                "BlockSTM TIP-20 action prewarm produced non-success result"
            );
            return Err(Tip20TransferBlockstmFallback::ActionExecutionFailed);
        }

        let actions = evm
            .take_actions()
            .filter(|actions| !actions.is_empty())
            .ok_or(Tip20TransferBlockstmFallback::MissingActions)?;

        Ok(Ok(Tip20TransferActionReplay {
            result: result.result,
            actions,
            validator_fee: evm.validator_fee(),
        }))
    })
}

fn invalid_pool_error_from_evm_error<DBError>(
    error: EVMError<DBError, TempoInvalidTransaction>,
) -> Result<InvalidPoolTransactionError, Tip20TransferBlockstmFallback> {
    match error {
        EVMError::Transaction(error) => Ok(invalid_pool_error_from_transaction_error(error)),
        _ => Err(Tip20TransferBlockstmFallback::ActionExecutionFailed),
    }
}

fn invalid_pool_error_from_transaction_error(
    error: TempoInvalidTransaction,
) -> InvalidPoolTransactionError {
    match error {
        TempoInvalidTransaction::EthInvalidTransaction(
            InvalidTransaction::LackOfFundForMaxFee { fee, balance },
        ) => InvalidPoolTransactionError::Consensus(InvalidTransactionError::InsufficientFunds(
            (*balance, *fee).into(),
        )),
        error => InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(error)),
    }
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
