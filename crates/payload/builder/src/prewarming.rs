use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    },
};

use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_sol_types::SolInterface;
use reth_evm::{ConfigureEvm, Evm, EvmEnvFor};
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{
    StateProvider, StateProviderBox, StateProviderFactory, errors::provider::ProviderResult,
};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_evm::{TempoEvmConfig, evm::TempoEvm};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    nonce::slots as nonce_slots,
    storage::StorageKey as _,
    tip_fee_manager::slots as fee_manager_slots,
    tip20::{ITIP20, tip20_slots},
};
use tempo_primitives::TempoAddressExt;
use tempo_transaction_pool::best::BestTransaction;
use tracing::trace;

type PrewarmEvmState = Option<TempoEvm<StateProviderDatabase<StateProviderBox>>>;

/// Prewarming orchestrator that consumes source [`BestTransactions`] with bounded
/// lookahead, prewarms buffered transactions in parallel, and produces a new
/// [`BestTransactions`] iterator with the source order and invalidations triggered
/// by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    transactions_rx: Receiver<Option<BestTransaction>>,
    commands_tx: Sender<BestTransactionsCommand>,
    stop: Arc<AtomicBool>,
}

impl BestTransactionsPrewarming {
    /// Spawns prewarming for `best_txs` and returns a new [`BestTransactions`] iterator.
    pub(crate) fn new<Txs, Provider>(
        executor: TaskExecutor,
        evm_config: TempoEvmConfig,
        provider: Provider,
        parent_hash: B256,
        fee_recipient: Address,
        evm_env: EvmEnvFor<TempoEvmConfig>,
        prewarm_gas_limit: u64,
        tx_gas_limit_cap: u64,
        best_txs: Txs,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let (transactions_tx, transactions_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let builder_consumed_tx_count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let prewarm = PrewarmingExecutionContext {
            evm_config,
            provider,
            parent_hash,
            fee_recipient,
            evm_env,
            builder_consumed_tx_count: builder_consumed_tx_count.clone(),
            stop: stop.clone(),
        };
        let prewarm_executor = executor.clone();
        executor.spawn_blocking_named("builder-prewarm", move || {
            Self::start_prewarming(
                prewarm_executor,
                BestTransactionsPrewarmingContext {
                    best_txs,
                    transactions_tx,
                    commands_rx,
                    prewarm,
                    gas_budget: PrewarmingGasBudget::new(prewarm_gas_limit, tx_gas_limit_cap),
                    tip20_touch_gate: Tip20TouchGate::default(),
                    next_tx_index: 0,
                },
            );
        });

        Self {
            transactions_rx,
            commands_tx,
            stop,
        }
    }

    /// Runs the coordinator side of prewarming for a payload build.
    ///
    /// See [`BestTransactionsPrewarming`] for details.
    fn start_prewarming<Txs, Provider>(
        executor: TaskExecutor,
        mut ctx: BestTransactionsPrewarmingContext<Txs, Provider>,
    ) where
        Txs: BestTransactions<Item = BestTransaction>,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let pool = executor.prewarming_pool();
        // Use only part of the shared prewarming pool for builder lookahead so
        // mmap warming does not compete with block execution on every core.
        let buffered_lookahead = builder_prewarming_lookahead(pool.current_num_threads());

        pool.in_place_scope(|scope| {
            let mut buffered_txs = VecDeque::new();
            let fill_prewarming_buffer =
                |ctx: &mut BestTransactionsPrewarmingContext<Txs, Provider>,
                 buffered_txs: &mut VecDeque<IndexedTransaction>| {
                    while buffered_txs.len() < buffered_lookahead && !ctx.prewarm.is_stopped() {
                        let Some(tx) = ctx.next_transaction() else {
                            break;
                        };

                        let prewarm_job = tx
                            .should_prewarm
                            .then(|| (ctx.prewarm.clone(), tx.index, tx.transaction.clone()));
                        buffered_txs.push_back(tx);

                        if let Some((prewarm, tx_index, prewarm_tx)) = prewarm_job {
                            scope.spawn(move |_| {
                                Self::prewarm_transaction(prewarm, tx_index, prewarm_tx)
                            });
                        }
                    }
                };

            while let Ok(command) = ctx.commands_rx.recv() {
                match command {
                    BestTransactionsCommand::Advance => {
                        let tx = buffered_txs.pop_front().or_else(|| ctx.next_transaction());
                        let should_refill = tx.is_some();
                        let tx = tx.map(|tx| {
                            ctx.prewarm
                                .builder_consumed_tx_count
                                .store(tx.index + 1, Ordering::Relaxed);
                            tx.transaction
                        });
                        let _ = ctx.transactions_tx.send(tx);

                        if should_refill {
                            fill_prewarming_buffer(&mut ctx, &mut buffered_txs);
                        }
                    }
                    BestTransactionsCommand::Invalid(invalid) => {
                        ctx.best_txs.mark_invalid(&invalid.tx, invalid.kind);
                        buffered_txs.retain(|tx| {
                            !is_invalidated_buffered_transaction(&invalid.tx, &tx.transaction)
                        });
                        fill_prewarming_buffer(&mut ctx, &mut buffered_txs);
                    }
                    BestTransactionsCommand::NoUpdates => {
                        ctx.best_txs.no_updates();
                    }
                    BestTransactionsCommand::SkipBlobs(skip_blobs) => {
                        ctx.best_txs.set_skip_blobs(skip_blobs);
                    }
                    BestTransactionsCommand::Stop => {
                        ctx.prewarm.stop();
                        return;
                    }
                }
            }
        });

        pool.broadcast(pool.current_num_threads(), |_| {
            PREWARM_WORKER_STATE.with(|state| state.borrow_mut().clear());
        });
    }

    fn prewarm_transaction<Provider>(
        prewarm: PrewarmingExecutionContext<Provider>,
        tx_index: usize,
        tx: BestTransaction,
    ) where
        Provider: StateProviderFactory + Clone + 'static,
    {
        if prewarm.is_stopped() || prewarm.is_consumed_by_builder(tx_index) {
            return;
        }

        PREWARM_WORKER_STATE.with(|worker_state| {
            let mut worker_state = worker_state.borrow_mut();
            if worker_state.parent_hash != prewarm.parent_hash {
                worker_state.reset(prewarm.parent_hash);
            }

            if prewarm.is_stopped() || prewarm.is_consumed_by_builder(tx_index) {
                return;
            }

            let tx_hash = *tx.hash();
            let PrewarmWorkerState {
                state_provider,
                evm,
                touches,
                ..
            } = &mut *worker_state;

            let touched = if is_tip20_transfer_transaction(&tx) {
                if state_provider.is_none() {
                    *state_provider = prewarm.state_provider_for_ctx();
                }
                let Some(state_provider) = state_provider.as_ref() else {
                    return;
                };

                storage_touches_for_transaction(&tx, prewarm.fee_recipient, touches);

                for touch in touches.iter().copied() {
                    if prewarm.is_stopped() {
                        return;
                    }
                    if let Err(err) = touch.warm(state_provider.as_ref()) {
                        trace!(
                            target: "payload_builder",
                            %err,
                            ?tx_hash,
                            "Failed to prewarm transaction storage"
                        );
                        return;
                    }
                }

                Some(touches.len())
            } else {
                if prewarm.is_stopped() {
                    return;
                }
                if evm.is_none() {
                    *evm = prewarm.evm_for_ctx();
                }
                let Some(evm) = evm.as_mut() else {
                    return;
                };

                if let Err(err) = evm.transact_raw(tx.transaction.clone().into_with_tx_env().tx_env)
                {
                    trace!(
                        target: "payload_builder",
                        %err,
                        ?tx_hash,
                        "Failed to prewarm transaction by execution"
                    );
                    return;
                }

                None
            };

            trace!(
                target: "payload_builder",
                touched,
                ?tx_hash,
                "Prewarmed transaction"
            );
        });
    }
}

impl Drop for BestTransactionsPrewarming {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.commands_tx.send(BestTransactionsCommand::Stop);
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = BestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        self.commands_tx
            .send(BestTransactionsCommand::Advance)
            .ok()?;
        self.transactions_rx.recv().ok().flatten()
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::Invalid(InvalidTransaction {
                tx: transaction.clone(),
                kind,
            }));
    }

    fn no_updates(&mut self) {
        let _ = self.commands_tx.send(BestTransactionsCommand::NoUpdates);
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::SkipBlobs(skip_blobs));
    }
}

/// Context for prewarming best transactions for a payload build.
struct BestTransactionsPrewarmingContext<Txs, Provider> {
    best_txs: Txs,
    transactions_tx: Sender<Option<BestTransaction>>,
    commands_rx: Receiver<BestTransactionsCommand>,
    prewarm: PrewarmingExecutionContext<Provider>,
    gas_budget: PrewarmingGasBudget,
    tip20_touch_gate: Tip20TouchGate,
    next_tx_index: usize,
}

impl<Txs, Provider> BestTransactionsPrewarmingContext<Txs, Provider>
where
    Txs: BestTransactions<Item = BestTransaction>,
{
    fn next_transaction(&mut self) -> Option<IndexedTransaction> {
        let transaction = self.best_txs.next()?;
        let should_prewarm = self.gas_budget.reserve(&transaction)
            && self
                .tip20_touch_gate
                .should_prewarm(&transaction, self.prewarm.fee_recipient);
        let index = self.next_tx_index;
        self.next_tx_index += 1;
        Some(IndexedTransaction {
            index,
            transaction,
            should_prewarm,
        })
    }
}

#[derive(Default)]
struct Tip20TouchGate {
    recipient_touches: HashSet<StorageTouch>,
    touches_buffer: Vec<StorageTouch>,
}

impl Tip20TouchGate {
    fn should_prewarm(&mut self, tx: &BestTransaction, fee_recipient: Address) -> bool {
        if !is_tip20_transfer_transaction(tx) {
            return true;
        }

        tip20_recipient_touches_for_transaction(tx, fee_recipient, &mut self.touches_buffer);
        let mut has_new_touch = false;
        for touch in self.touches_buffer.iter().copied() {
            has_new_touch |= self.recipient_touches.insert(touch);
        }
        has_new_touch
    }
}

/// Approximate payload gas horizon for mmap warming.
///
/// This tracks every transaction pulled from the source iterator and gates only
/// whether buffered lookahead gets a warm job. Builder behavior is unchanged.
struct PrewarmingGasBudget {
    gas_limit: u64,
    tx_gas_limit_cap: u64,
    gas_used: u64,
}

impl PrewarmingGasBudget {
    const fn new(gas_limit: u64, tx_gas_limit_cap: u64) -> Self {
        Self {
            gas_limit,
            tx_gas_limit_cap,
            gas_used: 0,
        }
    }

    fn reserve(&mut self, tx: &BestTransaction) -> bool {
        let tx_gas = tx.gas_limit().min(self.tx_gas_limit_cap);
        let Some(next_gas_used) = self.gas_used.checked_add(tx_gas) else {
            return false;
        };

        if next_gas_used > self.gas_limit {
            return false;
        }

        self.gas_used = next_gas_used;
        true
    }
}

/// Transaction tagged with its source iterator order.
struct IndexedTransaction {
    index: usize,
    transaction: BestTransaction,
    should_prewarm: bool,
}

fn builder_prewarming_lookahead(pool_threads: usize) -> usize {
    pool_threads.saturating_add(1).max(2) / 2
}

/// Context needed to prewarm transaction storage independently of the real builder.
#[derive(Clone)]
struct PrewarmingExecutionContext<Provider> {
    evm_config: TempoEvmConfig,
    provider: Provider,
    parent_hash: B256,
    fee_recipient: Address,
    evm_env: EvmEnvFor<TempoEvmConfig>,
    /// Number of source transactions already handed to the builder.
    builder_consumed_tx_count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

struct PrewarmWorkerState {
    parent_hash: B256,
    state_provider: Option<StateProviderBox>,
    evm: PrewarmEvmState,
    touches: Vec<StorageTouch>,
}

impl Default for PrewarmWorkerState {
    fn default() -> Self {
        Self {
            parent_hash: B256::ZERO,
            state_provider: None,
            evm: None,
            touches: Vec::with_capacity(24),
        }
    }
}

impl PrewarmWorkerState {
    fn reset(&mut self, parent_hash: B256) {
        *self = Self {
            parent_hash,
            ..Self::default()
        };
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

thread_local! {
    static PREWARM_WORKER_STATE: RefCell<PrewarmWorkerState> =
        RefCell::new(PrewarmWorkerState::default());
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    fn evm_for_ctx(&self) -> PrewarmEvmState {
        let state_provider = match self.provider.state_by_block_hash(self.parent_hash) {
            Ok(provider) => provider,
            Err(err) => {
                trace!(
                    target: "payload_builder",
                    %err,
                    parent_hash = ?self.parent_hash,
                    "failed to build state provider for prewarm transaction"
                );
                return None;
            }
        };
        let state_provider = StateProviderDatabase::new(state_provider);
        let mut evm_env = self.evm_env.clone();
        evm_env.cfg_env.disable_nonce_check = true;
        evm_env.cfg_env.disable_balance_check = true;

        Some(self.evm_config.evm_with_env(state_provider, evm_env))
    }

    fn state_provider_for_ctx(&self) -> Option<StateProviderBox> {
        match self.provider.state_by_block_hash(self.parent_hash) {
            Ok(provider) => Some(provider),
            Err(err) => {
                trace!(
                    target: "payload_builder",
                    %err,
                    parent_hash = ?self.parent_hash,
                    "failed to build state provider for transaction prewarming"
                );
                None
            }
        }
    }

    fn is_consumed_by_builder(&self, tx_index: usize) -> bool {
        tx_index < self.builder_consumed_tx_count.load(Ordering::Relaxed)
    }

    fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum StorageTouch {
    Account(Address),
    Storage { address: Address, slot: U256 },
}

impl StorageTouch {
    fn warm(&self, state_provider: &dyn StateProvider) -> ProviderResult<()> {
        match *self {
            Self::Account(address) => {
                let _ = state_provider.basic_account(&address)?;
            }
            Self::Storage { address, slot } => {
                let _ = state_provider.storage(address, slot.into())?;
            }
        }

        Ok(())
    }
}

fn is_tip20_transfer_transaction(tx: &BestTransaction) -> bool {
    tx.transaction.is_payment() && is_tip20_transfer_calls(tx.transaction.inner().calls())
}

fn is_tip20_transfer_calls<'a>(calls: impl IntoIterator<Item = (TxKind, &'a Bytes)>) -> bool {
    let mut has_call = false;
    for (kind, input) in calls {
        has_call = true;
        if !is_tip20_transfer_call(kind, input) {
            return false;
        }
    }
    has_call
}

fn is_tip20_transfer_call(kind: TxKind, input: &[u8]) -> bool {
    let Some(token) = kind.to().copied() else {
        return false;
    };
    if !token.is_tip20() {
        return false;
    }

    matches!(
        ITIP20::ITIP20Calls::abi_decode(input),
        Ok(ITIP20::ITIP20Calls::transfer(_)
            | ITIP20::ITIP20Calls::transferWithMemo(_)
            | ITIP20::ITIP20Calls::transferFrom(_)
            | ITIP20::ITIP20Calls::transferFromWithMemo(_))
    )
}

fn storage_touches_for_transaction(
    tx: &BestTransaction,
    fee_recipient: Address,
    touches: &mut Vec<StorageTouch>,
) {
    touches.clear();
    let sender = tx.transaction.sender();
    let fee_payer = tx.transaction.inner().fee_payer(sender).unwrap_or(sender);
    let fee_token = tx.transaction.resolved_fee_token().unwrap_or_else(|| {
        tx.transaction
            .inner()
            .fee_token()
            .unwrap_or(DEFAULT_FEE_TOKEN)
    });

    add_tip20_fee_touches(touches, fee_token, fee_payer);
    add_fee_manager_touches(touches, fee_recipient, fee_token);

    if tx.transaction.is_payment() {
        for (kind, input) in tx.transaction.inner().calls() {
            add_tip20_call_touches(touches, sender, kind, input);
        }
    }

    add_expiring_nonce_touches(touches, tx);
}

fn tip20_recipient_touches_for_transaction(
    tx: &BestTransaction,
    fee_recipient: Address,
    touches: &mut Vec<StorageTouch>,
) {
    touches.clear();
    let sender = tx.transaction.sender();
    let fee_token = tx.transaction.resolved_fee_token().unwrap_or_else(|| {
        tx.transaction
            .inner()
            .fee_token()
            .unwrap_or(DEFAULT_FEE_TOKEN)
    });

    add_fee_manager_touches(touches, fee_recipient, fee_token);

    for (kind, input) in tx.transaction.inner().calls() {
        add_tip20_recipient_touches(touches, sender, kind, input);
    }
}

fn add_tip20_fee_touches(touches: &mut Vec<StorageTouch>, fee_token: Address, fee_payer: Address) {
    if !fee_token.is_tip20() {
        return;
    }

    add_tip20_common_touches(touches, fee_token);
    add_tip20_balance_touch(touches, fee_token, fee_payer);
    add_tip20_balance_touch(touches, fee_token, TIP_FEE_MANAGER_ADDRESS);
    add_tip20_reward_touches(touches, fee_token, fee_payer);
}

fn add_tip20_call_touches(
    touches: &mut Vec<StorageTouch>,
    sender: Address,
    kind: TxKind,
    input: &[u8],
) {
    let Some(token) = kind.to().copied() else {
        return;
    };
    if !token.is_tip20() {
        return;
    }

    add_tip20_common_touches(touches, token);
    let Ok(call) = ITIP20::ITIP20Calls::abi_decode(input) else {
        return;
    };

    match call {
        ITIP20::ITIP20Calls::transfer(call) => {
            add_tip20_balance_touch(touches, token, sender);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, sender);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferWithMemo(call) => {
            add_tip20_balance_touch(touches, token, sender);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, sender);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferFrom(call) => {
            add_tip20_balance_touch(touches, token, call.from);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_allowance_touch(touches, token, call.from, sender);
            add_tip20_reward_touches(touches, token, call.from);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferFromWithMemo(call) => {
            add_tip20_balance_touch(touches, token, call.from);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_allowance_touch(touches, token, call.from, sender);
            add_tip20_reward_touches(touches, token, call.from);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::approve(call) => {
            add_tip20_allowance_touch(touches, token, sender, call.spender);
        }
        ITIP20::ITIP20Calls::mint(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::mintWithMemo(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::burn(_) | ITIP20::ITIP20Calls::burnWithMemo(_) => {
            add_tip20_balance_touch(touches, token, sender);
            add_tip20_reward_touches(touches, token, sender);
        }
        _ => {}
    }
}

fn add_tip20_recipient_touches(
    touches: &mut Vec<StorageTouch>,
    sender: Address,
    kind: TxKind,
    input: &[u8],
) {
    let Some(token) = kind.to().copied() else {
        return;
    };
    if !token.is_tip20() {
        return;
    }
    add_tip20_common_touches(touches, token);
    let Ok(call) = ITIP20::ITIP20Calls::abi_decode(input) else {
        return;
    };

    match call {
        ITIP20::ITIP20Calls::transfer(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferWithMemo(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferFrom(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_allowance_touch(touches, token, call.from, sender);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferFromWithMemo(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_allowance_touch(touches, token, call.from, sender);
            add_tip20_reward_touches(touches, token, call.to);
        }
        _ => {}
    }
}

fn add_tip20_common_touches(touches: &mut Vec<StorageTouch>, token: Address) {
    add_account_touch(touches, token);
    add_storage_touch(touches, token, tip20_slots::CURRENCY);
    add_storage_touch(touches, token, tip20_slots::PAUSED);
    add_storage_touch(touches, token, tip20_slots::TRANSFER_POLICY_ID);
    add_storage_touch(touches, token, tip20_slots::GLOBAL_REWARD_PER_TOKEN);
    add_storage_touch(touches, token, tip20_slots::OPTED_IN_SUPPLY);
}

fn add_tip20_balance_touch(touches: &mut Vec<StorageTouch>, token: Address, account: Address) {
    add_storage_touch(touches, token, account.mapping_slot(tip20_slots::BALANCES));
}

fn add_tip20_allowance_touch(
    touches: &mut Vec<StorageTouch>,
    token: Address,
    owner: Address,
    spender: Address,
) {
    add_storage_touch(
        touches,
        token,
        spender.mapping_slot(owner.mapping_slot(tip20_slots::ALLOWANCES)),
    );
}

fn add_tip20_reward_touches(touches: &mut Vec<StorageTouch>, token: Address, account: Address) {
    let base_slot = account.mapping_slot(tip20_slots::USER_REWARD_INFO);
    add_storage_touch(touches, token, base_slot);
    add_storage_touch(touches, token, base_slot + U256::from(1));
    add_storage_touch(touches, token, base_slot + U256::from(2));
}

fn add_fee_manager_touches(
    touches: &mut Vec<StorageTouch>,
    fee_recipient: Address,
    fee_token: Address,
) {
    add_account_touch(touches, TIP_FEE_MANAGER_ADDRESS);
    add_storage_touch(
        touches,
        TIP_FEE_MANAGER_ADDRESS,
        fee_recipient.mapping_slot(fee_manager_slots::VALIDATOR_TOKENS),
    );
    add_storage_touch(
        touches,
        TIP_FEE_MANAGER_ADDRESS,
        fee_token.mapping_slot(fee_recipient.mapping_slot(fee_manager_slots::COLLECTED_FEES)),
    );
}

fn add_expiring_nonce_touches(touches: &mut Vec<StorageTouch>, tx: &BestTransaction) {
    let Some(expiring_nonce_slot) = tx.transaction.expiring_nonce_slot() else {
        return;
    };

    add_account_touch(touches, NONCE_PRECOMPILE_ADDRESS);
    add_storage_touch(touches, NONCE_PRECOMPILE_ADDRESS, expiring_nonce_slot);
    add_storage_touch(
        touches,
        NONCE_PRECOMPILE_ADDRESS,
        nonce_slots::EXPIRING_NONCE_RING_PTR,
    );
}

fn add_account_touch(touches: &mut Vec<StorageTouch>, address: Address) {
    add_unique_touch(touches, StorageTouch::Account(address));
}

fn add_storage_touch(touches: &mut Vec<StorageTouch>, address: Address, slot: U256) {
    add_account_touch(touches, address);
    add_unique_touch(touches, StorageTouch::Storage { address, slot });
}

fn add_unique_touch(touches: &mut Vec<StorageTouch>, touch: StorageTouch) {
    if !touches.contains(&touch) {
        touches.push(touch);
    }
}

/// Command sent by [`BestTransactionsPrewarming`] consumer.
#[derive(Debug)]
enum BestTransactionsCommand {
    Advance,
    Invalid(InvalidTransaction),
    NoUpdates,
    SkipBlobs(bool),
    Stop,
}

/// Invalid transaction encountered during execution.
#[derive(Debug)]
struct InvalidTransaction {
    tx: BestTransaction,
    kind: InvalidPoolTransactionError,
}

/// Returns whether the candidate transaction is invalidated by the given invalid transaction.
fn is_invalidated_buffered_transaction(
    invalid: &BestTransaction,
    candidate: &BestTransaction,
) -> bool {
    // Skip invalidation for expiring nonce transactions - they are independent
    // and should not block other expiring nonce txs from the same sender
    if invalid.transaction.is_expiring_nonce() {
        return false;
    }

    if invalid.transaction.is_aa_2d() {
        candidate
            .transaction
            .aa_transaction_id()
            .zip(invalid.transaction.aa_transaction_id())
            .is_some_and(|(candidate_id, invalid_id)| candidate_id.seq_id() == invalid_id.seq_id())
    } else {
        candidate.transaction.sender() == invalid.transaction.sender()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, Header, Signed, TxLegacy};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use alloy_sol_types::SolCall;
    use reth_evm::NextBlockEnvAttributes;
    use reth_primitives_traits::{
        Recovered, SealedHeader, transaction::error::InvalidTransactionError,
    };
    use reth_storage_api::noop::NoopProvider;
    use reth_transaction_pool::{
        TransactionOrigin, ValidPoolTransaction, identifier::TransactionId,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };
    use tempo_chainspec::TempoChainSpec;
    use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes};
    use tempo_primitives::{TempoHeader, TempoPrimitives, TempoTxEnvelope};
    use tempo_transaction_pool::transaction::TempoPooledTransaction;

    #[derive(Debug, Default)]
    struct TestLog {
        yielded: usize,
        empty_polls: usize,
        invalid: usize,
        no_updates: usize,
        skip_blobs: Vec<bool>,
    }

    struct TestBestTransactions {
        txs: VecDeque<BestTransaction>,
        log: Arc<Mutex<TestLog>>,
    }

    impl TestBestTransactions {
        fn new(txs: Vec<BestTransaction>, log: Arc<Mutex<TestLog>>) -> Self {
            Self {
                txs: txs.into(),
                log,
            }
        }
    }

    impl Iterator for TestBestTransactions {
        type Item = BestTransaction;

        fn next(&mut self) -> Option<Self::Item> {
            let tx = self.txs.pop_front();
            {
                let mut log = self.log.lock().unwrap();
                if tx.is_some() {
                    log.yielded += 1;
                } else {
                    log.empty_polls += 1;
                }
            }
            if tx.is_none() {
                thread::sleep(Duration::from_millis(1));
            }
            tx
        }
    }

    impl BestTransactions for TestBestTransactions {
        fn mark_invalid(&mut self, transaction: &Self::Item, _kind: InvalidPoolTransactionError) {
            self.log.lock().unwrap().invalid += 1;
            self.txs
                .retain(|tx| !is_invalidated_buffered_transaction(transaction, tx));
        }

        fn no_updates(&mut self) {
            self.log.lock().unwrap().no_updates += 1;
        }

        fn set_skip_blobs(&mut self, skip_blobs: bool) {
            self.log.lock().unwrap().skip_blobs.push(skip_blobs);
        }
    }

    fn test_tx(sender: Address, nonce: u64) -> BestTransaction {
        test_tx_with_gas_limit(sender, nonce, 21_000)
    }

    fn test_tx_with_gas_limit(sender: Address, nonce: u64, gas_limit: u64) -> BestTransaction {
        test_tx_with_call(
            sender,
            nonce,
            gas_limit,
            TxKind::Call(Address::random()),
            Bytes::new(),
        )
    }

    fn test_tip20_transfer_tx(sender: Address, nonce: u64, recipient: Address) -> BestTransaction {
        test_tx_with_call(
            sender,
            nonce,
            21_000,
            TxKind::Call(DEFAULT_FEE_TOKEN),
            Bytes::from(
                ITIP20::transferCall {
                    to: recipient,
                    amount: U256::from(1),
                }
                .abi_encode(),
            ),
        )
    }

    fn test_tx_with_call(
        sender: Address,
        nonce: u64,
        gas_limit: u64,
        to: TxKind,
        input: Bytes,
    ) -> BestTransaction {
        let tx = TxLegacy {
            chain_id: Some(42431),
            nonce,
            gas_price: 20_000_000_000,
            gas_limit,
            to,
            value: U256::ZERO,
            input,
        };
        let envelope =
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()));
        let pooled = TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender));
        Arc::new(ValidPoolTransaction {
            transaction_id: TransactionId::new(0u64.into(), nonce),
            transaction: pooled,
            propagate: true,
            timestamp: Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    fn prewarming(
        txs: Vec<BestTransaction>,
        log: Arc<Mutex<TestLog>>,
    ) -> BestTransactionsPrewarming {
        let executor = TaskExecutor::test();
        prewarming_with_executor(executor, txs, log)
    }

    fn prewarming_with_executor(
        executor: TaskExecutor,
        txs: Vec<BestTransaction>,
        log: Arc<Mutex<TestLog>>,
    ) -> BestTransactionsPrewarming {
        let evm_config = TempoEvmConfig::moderato();
        let provider =
            NoopProvider::<TempoChainSpec, TempoPrimitives>::new(evm_config.chain_spec().clone());
        let parent_header = SealedHeader::seal_slow(TempoHeader {
            inner: Header {
                number: 0,
                timestamp: 1,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1),
                ..Default::default()
            },
            general_gas_limit: 30_000_000,
            timestamp_millis_part: 0,
            shared_gas_limit: 0,
            ..Default::default()
        });
        let attributes = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: 2,
                suggested_fee_recipient: Address::ZERO,
                prev_randao: B256::ZERO,
                gas_limit: parent_header.gas_limit(),
                parent_beacon_block_root: None,
                withdrawals: None,
                extra_data: Default::default(),
                slot_number: None,
            },
            general_gas_limit: 30_000_000,
            shared_gas_limit: 0,
            timestamp_millis_part: 0,
            consensus_context: None,
            subblock_fee_recipients: Default::default(),
        };
        let evm_env = evm_config
            .next_evm_env(&parent_header, &attributes)
            .expect("test next block env");
        BestTransactionsPrewarming::new(
            executor,
            evm_config,
            provider,
            parent_header.hash(),
            Address::ZERO,
            evm_env,
            30_000_000,
            u64::MAX,
            TestBestTransactions::new(txs, log),
        )
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if condition() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(condition(), "condition did not become true before timeout");
    }

    #[test]
    fn prewarming_gas_budget_stops_after_limit() {
        let sender = Address::random();
        let tx1 = test_tx(sender, 0);
        let tx2 = test_tx(sender, 1);
        let mut budget = PrewarmingGasBudget::new(tx1.gas_limit(), u64::MAX);

        assert!(budget.reserve(&tx1));
        assert!(!budget.reserve(&tx2));
    }

    #[test]
    fn prewarming_gas_budget_applies_tx_gas_limit_cap() {
        let sender = Address::random();
        let tx1 = test_tx(sender, 0);
        let tx2 = test_tx(sender, 1);
        let tx3 = test_tx(sender, 2);
        let mut budget = PrewarmingGasBudget::new(20_000, 10_000);

        assert!(budget.reserve(&tx1));
        assert!(budget.reserve(&tx2));
        assert!(!budget.reserve(&tx3));
    }

    #[test]
    fn prewarming_gas_budget_rejects_oversized_tx_without_consuming_budget() {
        let sender = Address::random();
        let oversized = test_tx_with_gas_limit(sender, 0, 30_000);
        let fitting = test_tx_with_gas_limit(sender, 1, 10_000);
        let mut budget = PrewarmingGasBudget::new(20_000, u64::MAX);

        assert!(!budget.reserve(&oversized));
        assert!(budget.reserve(&fitting));
    }

    #[test]
    fn tip20_touch_gate_skips_repeated_recipient() {
        let sender = Address::random();
        let recipient = Address::random();
        let tx1 = test_tip20_transfer_tx(sender, 0, recipient);
        let tx2 = test_tip20_transfer_tx(sender, 1, recipient);
        let mut gate = Tip20TouchGate::default();

        assert!(gate.should_prewarm(&tx1, Address::ZERO));
        assert!(!gate.should_prewarm(&tx2, Address::ZERO));
    }

    #[test]
    fn tip20_touch_gate_allows_new_recipient() {
        let sender = Address::random();
        let tx1 = test_tip20_transfer_tx(sender, 0, Address::random());
        let tx2 = test_tip20_transfer_tx(sender, 1, Address::random());
        let mut gate = Tip20TouchGate::default();

        assert!(gate.should_prewarm(&tx1, Address::ZERO));
        assert!(gate.should_prewarm(&tx2, Address::ZERO));
    }

    #[test]
    fn tip20_touch_collection_dedups_overlapping_fee_and_call_slots() {
        let sender = Address::random();
        let recipient = Address::random();
        let token = DEFAULT_FEE_TOKEN;
        let mut touches = Vec::new();

        add_tip20_fee_touches(&mut touches, token, sender);
        add_tip20_call_touches(
            &mut touches,
            sender,
            TxKind::Call(token),
            &ITIP20::transferCall {
                to: recipient,
                amount: U256::from(1),
            }
            .abi_encode(),
        );

        for (index, touch) in touches.iter().enumerate() {
            assert!(
                !touches[index + 1..].contains(touch),
                "duplicate storage prewarm touch: {touch:?}"
            );
        }

        assert!(touches.contains(&StorageTouch::Account(token)));
        assert!(touches.contains(&StorageTouch::Storage {
            address: token,
            slot: sender.mapping_slot(tip20_slots::BALANCES)
        }));
        assert!(touches.contains(&StorageTouch::Storage {
            address: token,
            slot: recipient.mapping_slot(tip20_slots::BALANCES)
        }));
    }

    #[test]
    fn tip20_fast_path_is_limited_to_transfers() {
        let token = DEFAULT_FEE_TOKEN;
        let transfer = Bytes::from(
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );
        let transfer_from = Bytes::from(
            ITIP20::transferFromCall {
                from: Address::random(),
                to: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );
        let approve = Bytes::from(
            ITIP20::approveCall {
                spender: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );

        assert!(is_tip20_transfer_call(TxKind::Call(token), &transfer));
        assert!(is_tip20_transfer_calls(
            [&transfer, &transfer_from]
                .into_iter()
                .map(|input| (TxKind::Call(token), input)),
        ));
        assert!(!is_tip20_transfer_call(TxKind::Call(token), &approve));
        assert!(!is_tip20_transfer_calls(
            [&transfer, &approve]
                .into_iter()
                .map(|input| (TxKind::Call(token), input)),
        ));
    }

    #[test]
    fn source_ordering_is_unchanged_when_prewarming_is_enabled() {
        let sender = Address::random();
        let txs = vec![test_tx(sender, 0), test_tx(sender, 1), test_tx(sender, 2)];
        let expected = txs.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming(txs, log);
        let actual = (0..expected.len())
            .map(|_| *prewarming.next().expect("transaction").hash())
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn prewarming_window_limits_source_iterator_drain_after_first_advance() {
        let sender = Address::random();
        let executor = TaskExecutor::test();
        let prewarming_lookahead =
            builder_prewarming_lookahead(executor.prewarming_pool().current_num_threads());
        let first_advance_drain = prewarming_lookahead + 1;
        let txs = (0..first_advance_drain + 4)
            .map(|nonce| test_tx(sender, nonce as u64))
            .collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming_with_executor(executor, txs, log.clone());
        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().yielded, 0);

        assert!(prewarming.next().is_some());
        wait_until(|| log.lock().unwrap().yielded == first_advance_drain);
        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().yielded, first_advance_drain);

        assert!(prewarming.next().is_some());
        wait_until(|| log.lock().unwrap().yielded == first_advance_drain + 1);
    }

    #[test]
    fn empty_source_is_polled_once_per_advance() {
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming(Vec::new(), log.clone());

        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().empty_polls, 0);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == 1);
        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().empty_polls, 1);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == 2);
    }

    #[test]
    fn mark_invalid_filters_already_buffered_invalidated_transactions() {
        let sender = Address::random();
        let tx1 = test_tx(sender, 0);
        let tx2 = test_tx(sender, 1);
        let tx3 = test_tx(Address::random(), 0);
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming(vec![tx1.clone(), tx2.clone(), tx3.clone()], log.clone());
        assert_eq!(
            prewarming.next().as_ref().map(|tx| tx.hash()),
            Some(tx1.hash())
        );

        wait_until(|| log.lock().unwrap().yielded == 2);
        prewarming.mark_invalid(
            &tx1,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
        );

        let next = prewarming.next().expect("non-invalidated transaction");
        assert_eq!(next.hash(), tx3.hash());
        assert_ne!(next.hash(), tx2.hash());
        wait_until(|| log.lock().unwrap().invalid == 1);
    }

    #[test]
    fn commands_are_forwarded_to_source_iterator() {
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming(Vec::new(), log.clone());

        prewarming.no_updates();
        prewarming.set_skip_blobs(true);

        wait_until(|| {
            let log = log.lock().unwrap();
            log.no_updates == 1 && log.skip_blobs == vec![true]
        });
    }

    #[test]
    fn prewarming_does_not_use_shared_worker_state_slot() {
        let executor = TaskExecutor::test();
        let pool = executor.prewarming_pool();
        pool.init::<usize>(|existing| existing.map(|value| *value).unwrap_or(1));

        let sender = Address::random();
        let txs = vec![test_tx(sender, 0)];
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming_with_executor(executor.clone(), txs, log);

        assert!(prewarming.next().is_some());

        pool.broadcast(pool.current_num_threads(), |worker| {
            assert_eq!(*worker.get::<usize>(), 1);
        });
    }
}
