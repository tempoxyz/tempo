use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc::{self, Receiver, Sender},
};

use alloy_primitives::{Address, TxKind};
use alloy_sol_types::SolInterface;
use reth_evm::{Evm, RecoveredTx};
use reth_revm::context::Transaction as _;
use reth_storage_api::StateProviderFactory;
use reth_tasks::{TaskExecutor, WorkerPool};
use reth_transaction_pool::{BestTransactions, error::InvalidPoolTransactionError};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::{StorageActionReplay, evm::TempoEvm};
use tempo_primitives::{TempoAddressExt, transaction::TEMPO_EXPIRING_NONCE_KEY};
use tempo_revm::TempoTxEnv;
use tempo_transaction_pool::{
    StateAwareBestTransactions,
    best::{BestTransaction, StateAwareBestTransactionsUpdate},
};
use tracing::trace;

use crate::prewarming::{PrewarmEvmState, PrewarmingExecutionContext};

#[derive(Debug)]
pub(crate) struct PlannedTransaction {
    pub(crate) tx: BestTransaction,
    pub(crate) replay: Option<StorageActionReplay>,
}

impl PlannedTransaction {
    pub(crate) fn without_replay(tx: BestTransaction) -> Self {
        Self { tx, replay: None }
    }
}

/// Streams speculative action collection on the prewarming worker pool.
pub(crate) struct PrewarmingPlanner<Provider> {
    commands_tx: Sender<PlannerCommand>,
    results_rx: Receiver<PlannerMessage>,
    stop: Arc<AtomicBool>,
    prewarm: PrewarmingExecutionContext<Provider>,
    scheduled_count: Arc<AtomicUsize>,
    completed_count: usize,
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
        let stop = Arc::new(AtomicBool::new(false));
        let scheduled_count = Arc::new(AtomicUsize::new(0));

        let coordinator_executor = prewarm.executor();
        let coordinator_commands_tx = commands_tx.clone();
        let coordinator_stop = stop.clone();
        let coordinator_prewarm = prewarm.clone();
        let coordinator_scheduled_count = scheduled_count.clone();
        prewarm
            .executor()
            .spawn_blocking_named("builder-prewarm-planner", move || {
                Self::start_planner(
                    coordinator_executor,
                    PlannerContext {
                        best_txs,
                        results_tx,
                        commands_tx: coordinator_commands_tx,
                        commands_rx,
                        stop: coordinator_stop,
                        prewarm: coordinator_prewarm,
                        scheduled_count: coordinator_scheduled_count,
                        next_expiring_nonce_offset: 0,
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

                    planner.scheduled_count.fetch_add(1, Ordering::Relaxed);

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
                    scope.spawn(move |_| {
                        let planned = plan_transaction_replay(prewarm, tx, expiring_nonce_offset);
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
                    PlannerCommand::StateUpdate(update) => {
                        ctx.best_txs.apply_update(update);
                    }
                    PlannerCommand::Stop { drain_rx } => {
                        ctx.stop.store(true, Ordering::Relaxed);
                        ctx.prewarm.stop();
                        drop(drain_rx);
                        return;
                    }
                }
            }
        });

        pool.clear();
    }

    pub(crate) fn next(&mut self) -> Option<PlannedTransaction> {
        loop {
            if self.source_exhausted
                && self.completed_count == self.scheduled_count.load(Ordering::Relaxed)
            {
                return None;
            }

            let Ok(message) = self.results_rx.recv() else {
                return None;
            };
            if let Some(planned) = self.record_message(message) {
                return Some(planned);
            }
        }
    }

    fn record_message(&mut self, message: PlannerMessage) -> Option<PlannedTransaction> {
        match message {
            PlannerMessage::SourceExhausted => {
                self.source_exhausted = true;
                None
            }
            PlannerMessage::Planned { planned } => {
                self.completed_count += 1;
                if let Some(replay) = planned.replay.as_ref() {
                    trace!(
                        target: "payload_builder",
                        tx_hash = ?planned.tx.hash(),
                        action_count = replay.actions.len(),
                        "Collected prewarm storage action replay"
                    );
                }
                Some(planned)
            }
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
    stop: Arc<AtomicBool>,
    prewarm: PrewarmingExecutionContext<Provider>,
    scheduled_count: Arc<AtomicUsize>,
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
    expiring_nonce_offset: Option<usize>,
) -> PlannedTransaction
where
    Provider: StateProviderFactory + Clone + 'static,
{
    if prewarm.is_stopped() {
        return PlannedTransaction::without_replay(tx);
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

        let mut tx_env = tx.transaction.clone_tx_env();
        if let Some(tempo_tx_env) = tx_env.tempo_tx_env.as_mut() {
            tempo_tx_env.expiring_nonce_idx = expiring_nonce_offset;
        }
        if !is_storage_action_replay_candidate(&tx, &tx_env, evm.cfg.spec) {
            let _ = evm.replace_actions(Vec::new());
            return None;
        }

        let mut result = match evm.transact_raw(tx_env) {
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

        result.state.clear();
        Some(StorageActionReplay {
            result: result.result,
            actions,
            validator_fee: evm.validator_fee(),
            state: result.state,
        })
    });

    PlannedTransaction { tx, replay }
}

fn is_storage_action_replay_candidate(
    tx: &BestTransaction,
    tx_env: &TempoTxEnv,
    spec: TempoHardfork,
) -> bool {
    if tx.transaction.inner().tx().subblock_proposer().is_some() {
        return false;
    }
    if !tx_env.value().is_zero() {
        return false;
    }
    if tx_env
        .access_list()
        .is_some_and(|mut access_list| access_list.next().is_some())
    {
        return false;
    }
    if tx_env.authorization_list_len() != 0 {
        return false;
    }

    let Some(aa_env) = tx_env.tempo_tx_env.as_ref() else {
        return false;
    };
    if !aa_env.tempo_authorization_list.is_empty() {
        return false;
    }
    if aa_env.key_authorization.is_some() {
        return false;
    }
    if aa_env.nonce_key == TEMPO_EXPIRING_NONCE_KEY || tx_env.nonce() != 0 {
        return false;
    }
    if aa_env.valid_before.is_none() {
        return false;
    }
    if tx
        .transaction
        .inner()
        .tx()
        .as_aa()
        .is_some_and(|aa| aa.signature().as_keychain().is_some())
    {
        return false;
    }
    if tx_env.fee_payer().is_err() {
        return false;
    }

    let mut calls = tx_env.calls();
    let Some((kind, input)) = calls.next() else {
        return false;
    };
    if !is_valid_tip20_transfer_call(*kind, input) {
        return false;
    }
    calls.next().is_none()
}

fn is_valid_tip20_transfer_call(kind: TxKind, input: &[u8]) -> bool {
    let TxKind::Call(token) = kind else {
        return false;
    };
    if !token.is_tip20() {
        return false;
    }

    match ITIP20::ITIP20Calls::abi_decode(input) {
        Ok(ITIP20::ITIP20Calls::transfer(call)) => is_valid_direct_recipient(call.to),
        Ok(ITIP20::ITIP20Calls::transferWithMemo(call)) => is_valid_direct_recipient(call.to),
        Ok(ITIP20::ITIP20Calls::transferFrom(_))
        | Ok(ITIP20::ITIP20Calls::transferFromWithMemo(_))
        | Ok(_) => false,
        Err(_) => false,
    }
}

fn is_valid_direct_recipient(to: Address) -> bool {
    !to.is_zero() && !to.is_tip20() && !to.is_virtual()
}
