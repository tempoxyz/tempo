use alloy_primitives::Address;
use reth_evm::{Database, Evm};
use reth_storage_api::StateProviderFactory;
use reth_tasks::{TaskExecutor, WorkerPool};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    sync::mpsc::{self, Receiver, Sender},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{
    Tip20TransferActionReplay, Tip20TransferBlockstmFallback, Tip20TransferBlockstmPlan,
    Tip20TransferBlockstmTx, build_tip20_transfer_blockstm_plan,
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::TipFeeManager,
};
use tempo_transaction_pool::best::BestTransaction;
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
    pub(crate) replay: Tip20TransferActionReplay,
}

#[derive(Debug)]
struct PlanningResult {
    sequence: usize,
    item: Result<PlannedTransfer, Tip20TransferBlockstmFallback>,
}

/// Ordered TIP-20 BlockSTM planner backed by the payload prewarming worker pool.
pub(crate) struct Planner<'a, Provider> {
    pool: &'a WorkerPool,
    ctx: PlanningContext,
    prewarm: Option<PrewarmingExecutionContext<Provider>>,
    tx: Sender<PlanningResult>,
    rx: Receiver<PlanningResult>,
    next_sequence: usize,
    next_emit: usize,
    pending_jobs: usize,
    max_pending_jobs: usize,
    buffered: BTreeMap<usize, Result<PlannedTransfer, Tip20TransferBlockstmFallback>>,
}

pub(crate) enum PlannerNext {
    Planned(Result<PlannedTransfer, Tip20TransferBlockstmFallback>),
    ScheduleMore,
    Empty,
}

impl<'a, Provider> Planner<'a, Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    pub(crate) fn new(
        executor: &'a TaskExecutor,
        ctx: PlanningContext,
        prewarm: Option<PrewarmingExecutionContext<Provider>>,
    ) -> Self {
        let pool = executor.prewarming_pool();
        let (tx, rx) = mpsc::channel();
        Self {
            pool,
            ctx,
            prewarm,
            tx,
            rx,
            next_sequence: 0,
            next_emit: 0,
            pending_jobs: 0,
            max_pending_jobs: (pool.current_num_threads() * 2).max(1),
            buffered: BTreeMap::new(),
        }
    }

    pub(crate) fn can_schedule(&mut self) -> bool {
        self.drain_completed();
        self.pending_jobs < self.max_pending_jobs
    }

    pub(crate) fn schedule(&mut self, tx: BestTransaction) {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.pending_jobs += 1;

        let result_tx = self.tx.clone();
        let ctx = self.ctx;
        let prewarm = self.prewarm.clone();
        self.pool.spawn(move || {
            let item = (|| {
                let candidate = candidate_with_expiring_nonce_offset(&tx, Some(sequence));
                let plan = build_tip20_transfer_blockstm_plan(
                    &candidate,
                    ctx.validator_token,
                    ctx.beneficiary,
                    ctx.basefee,
                    ctx.blob_gasprice,
                    ctx.spec,
                )?;
                let Some(prewarm) = prewarm else {
                    return Err(Tip20TransferBlockstmFallback::MissingActions);
                };
                let replay = prewarm_tip20_transfer_actions(&prewarm, candidate, sequence)?;
                Ok((plan, replay))
            })()
            .map(|(plan, replay)| PlannedTransfer { tx, plan, replay });
            let _ = result_tx.send(PlanningResult { sequence, item });
        });
    }

    pub(crate) fn next(&mut self, can_schedule_more: bool) -> PlannerNext {
        loop {
            if let Some(item) = self.buffered.remove(&self.next_emit) {
                self.next_emit += 1;
                return PlannerNext::Planned(item);
            }
            if self.next_emit == self.next_sequence {
                return PlannerNext::Empty;
            }

            self.drain_completed();
            if let Some(item) = self.buffered.remove(&self.next_emit) {
                self.next_emit += 1;
                return PlannerNext::Planned(item);
            }
            if self.next_emit == self.next_sequence {
                return PlannerNext::Empty;
            }
            if can_schedule_more && self.pending_jobs < self.max_pending_jobs {
                return PlannerNext::ScheduleMore;
            }

            let Ok(result) = self.rx.recv() else {
                return PlannerNext::Empty;
            };
            self.record_completed(result);
        }
    }

    fn drain_completed(&mut self) {
        while let Ok(result) = self.rx.try_recv() {
            self.record_completed(result);
        }
    }

    fn record_completed(&mut self, result: PlanningResult) {
        self.pending_jobs = self
            .pending_jobs
            .checked_sub(1)
            .expect("completed planning job without pending job");
        self.buffered.insert(result.sequence, result.item);
    }
}

fn prewarm_tip20_transfer_actions<Provider>(
    prewarm: &PrewarmingExecutionContext<Provider>,
    candidate: Tip20TransferBlockstmTx<'_>,
    sequence: usize,
) -> Result<Tip20TransferActionReplay, Tip20TransferBlockstmFallback>
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
        let result = evm.transact_raw(candidate.tx_env).map_err(|err| {
            trace!(
                target: "payload_builder",
                ?err,
                sequence,
                "Failed to prewarm BlockSTM TIP-20 transfer actions"
            );
            Tip20TransferBlockstmFallback::ActionExecutionFailed
        })?;
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

        Ok(Tip20TransferActionReplay {
            result: result.result,
            actions,
            validator_fee: evm.validator_fee(),
        })
    })
}

/// Builds an executor-owned BlockSTM candidate from a pooled transaction.
pub(crate) fn candidate(tx: &BestTransaction) -> Tip20TransferBlockstmTx<'_> {
    candidate_with_expiring_nonce_offset(tx, None)
}

fn candidate_with_expiring_nonce_offset(
    tx: &BestTransaction,
    expiring_nonce_offset: Option<usize>,
) -> Tip20TransferBlockstmTx<'_> {
    let mut tx_env = tx.transaction.clone_tx_env();
    if let Some(expiring_nonce_offset) = expiring_nonce_offset
        && tx.transaction.is_expiring_nonce()
        && let Some(tempo_tx_env) = tx_env.tempo_tx_env.as_mut()
    {
        tempo_tx_env.expiring_nonce_idx = Some(expiring_nonce_offset);
    }

    Tip20TransferBlockstmTx {
        tx_env,
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
