use alloy_primitives::Address;
use reth_evm::Database;
use reth_tasks::{TaskExecutor, WorkerPool};
use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    sync::mpsc::{self, Receiver, Sender},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{
    Tip20TransferBlockstmFallback, Tip20TransferBlockstmPlan, Tip20TransferBlockstmTx,
    build_tip20_transfer_blockstm_plan,
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::TipFeeManager,
};
use tempo_transaction_pool::best::BestTransaction;

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

#[derive(Debug)]
struct PlanningResult {
    sequence: usize,
    item: Result<PlannedTransfer, Tip20TransferBlockstmFallback>,
}

/// Ordered TIP-20 BlockSTM planner backed by the payload prewarming worker pool.
pub(crate) struct Planner<'a> {
    pool: &'a WorkerPool,
    ctx: PlanningContext,
    tx: Sender<PlanningResult>,
    rx: Receiver<PlanningResult>,
    next_sequence: usize,
    next_emit: usize,
    in_flight: usize,
    max_in_flight: usize,
    buffered: BTreeMap<usize, Result<PlannedTransfer, Tip20TransferBlockstmFallback>>,
}

impl<'a> Planner<'a> {
    pub(crate) fn new(executor: &'a TaskExecutor, ctx: PlanningContext) -> Self {
        let pool = executor.prewarming_pool();
        let (tx, rx) = mpsc::channel();
        Self {
            pool,
            ctx,
            tx,
            rx,
            next_sequence: 0,
            next_emit: 0,
            in_flight: 0,
            max_in_flight: (pool.current_num_threads() * 2).max(1),
            buffered: BTreeMap::new(),
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.in_flight >= self.max_in_flight
    }

    pub(crate) fn schedule(&mut self, tx: BestTransaction) {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.in_flight += 1;

        let result_tx = self.tx.clone();
        let ctx = self.ctx;
        self.pool.spawn(move || {
            let item = build_tip20_transfer_blockstm_plan(
                &candidate(&tx),
                ctx.validator_token,
                ctx.beneficiary,
                ctx.basefee,
                ctx.blob_gasprice,
                ctx.spec,
            )
            .map(|plan| PlannedTransfer { tx, plan });
            let _ = result_tx.send(PlanningResult { sequence, item });
        });
    }

    pub(crate) fn next(
        &mut self,
    ) -> Option<Result<PlannedTransfer, Tip20TransferBlockstmFallback>> {
        loop {
            if let Some(item) = self.buffered.remove(&self.next_emit) {
                self.next_emit += 1;
                self.in_flight -= 1;
                return Some(item);
            }
            if self.in_flight == 0 {
                return None;
            }

            let result = self.rx.recv().ok()?;
            self.buffered.insert(result.sequence, result.item);
        }
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
