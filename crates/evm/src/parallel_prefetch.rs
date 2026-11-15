//! Lookahead state prefetch for parallel block execution.
//!
//! Threads beside the parallel executor's workers read the state each upcoming transaction is
//! expected to read, from what the transaction itself says, so that the workers find it in the
//! caches beneath the base database instead of reading it cold. Prefetching only reads the base
//! database: it never changes a block's result, and a wrong guess only costs a wasted read.

use crate::transaction::{TempoEvmTx, TempoTxEnv};
use alloy_primitives::{Address, TxKind, U256};
use evm2::evm::DynDatabaseRef;
use std::{
    borrow::Borrow,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, PaymentSlots};
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS, nonce,
    storage::StorageKey, tip_fee_manager, tip20, tip403_registry,
};
use tempo_primitives::{TempoAddressExt, transaction::TEMPO_EXPIRING_NONCE_KEY};

/// Slots of a holder's TIP-20 reward info, which every balance change of the holder reads.
const USER_REWARD_INFO_SLOTS: u64 = 3;

/// State a transaction is expected to read.
#[derive(Debug)]
pub(crate) enum PrefetchKey {
    /// An account, with its code.
    Account(Address),
    /// A storage slot.
    Storage(Address, U256),
    /// The fee payer's balance of its stored fee token preference, else of `fallback`.
    FeeToken {
        /// The fee payer.
        payer: Address,
        /// The token the fee is expected in when the payer stored no preference.
        fallback: Address,
    },
}

/// Returns the state `tx` is expected to read that other transactions are unlikely to have read
/// already: its sender's and fee payer's accounts, nonce and fee token balance, the balances and
/// reward info of the holders of the TIP-20 payments it makes and the contracts it calls.
pub(crate) fn prefetch_keys(tx: &TempoTxEnv) -> Vec<PrefetchKey> {
    let evm_tx: &TempoEvmTx = tx.borrow();
    if evm_tx.is_system_tx() {
        return Vec::new();
    }
    let sender = evm_tx.signer();
    let mut keys = Vec::new();
    let mut first_tip20 = None;
    for (kind, input) in evm_tx.calls() {
        let TxKind::Call(to) = kind else { continue };
        keys.push(PrefetchKey::Account(to));
        if !to.is_tip20() {
            continue;
        }
        first_tip20.get_or_insert(to);
        let Some(payment) = PaymentSlots::classify(input) else {
            continue;
        };
        if let Some(recipient) = payment.to() {
            push_holder(&mut keys, to, recipient);
            keys.push(PrefetchKey::Storage(
                TIP403_REGISTRY_ADDRESS,
                recipient.mapping_slot(tip403_registry::slots::RECEIVE_POLICIES),
            ));
        }
        push_holder(&mut keys, to, payment.from().unwrap_or(sender));
    }
    keys.push(PrefetchKey::Account(sender));
    if let Some(aa) = evm_tx.as_aa() {
        let nonce_key = aa.inner().tx().nonce_key;
        if !nonce_key.is_zero() && nonce_key != TEMPO_EXPIRING_NONCE_KEY {
            keys.push(PrefetchKey::Storage(
                NONCE_PRECOMPILE_ADDRESS,
                nonce_key.mapping_slot(sender.mapping_slot(nonce::slots::NONCES)),
            ));
        }
    }
    let payer = tx.fee_payer().unwrap_or(sender);
    if payer != sender {
        keys.push(PrefetchKey::Account(payer));
    }
    match evm_tx.fee_token() {
        Some(token) => keys.push(PrefetchKey::Storage(
            token,
            payer.mapping_slot(tip20::slots::BALANCES),
        )),
        None => keys.push(PrefetchKey::FeeToken {
            payer,
            fallback: first_tip20.unwrap_or(DEFAULT_FEE_TOKEN),
        }),
    }
    keys
}

/// Pushes the slots of `holder` that a balance change of TIP-20 `token` reads.
fn push_holder(keys: &mut Vec<PrefetchKey>, token: Address, holder: Address) {
    keys.push(PrefetchKey::Storage(
        token,
        holder.mapping_slot(tip20::slots::BALANCES),
    ));
    let reward_info = holder.mapping_slot(tip20::slots::USER_REWARD_INFO);
    for offset in 0..USER_REWARD_INFO_SLOTS {
        keys.push(PrefetchKey::Storage(
            token,
            reward_info.wrapping_add(U256::from(offset)),
        ));
    }
}

/// Transactions to prefetch, in block order.
#[derive(Debug, Default)]
struct PrefetchQueue {
    /// Each transaction's keys, taken when a thread claims it.
    keys: Vec<Vec<PrefetchKey>>,
    /// Whether every transaction of the block arrived.
    closed: bool,
}

/// Prefetches the state of a block's transactions ahead of the parallel executor's workers.
///
/// The thread that iterates the block's transactions pushes each transaction's keys as it
/// arrives, before the executor sees it, and [`Self::run`] threads read them in block order,
/// skipping the transactions the workers have likely started.
#[derive(Debug)]
pub(crate) struct Prefetcher {
    queue: Mutex<PrefetchQueue>,
    ready: Condvar,
    /// Threads waiting on `ready`.
    waiting: AtomicUsize,
    /// The next transaction to claim.
    next: AtomicUsize,
    /// One past the highest transaction a worker has executed.
    executed: AtomicUsize,
    /// Transactions the workers execute at once: the ones from `executed` on that they have
    /// likely started.
    workers: usize,
    stopped: AtomicBool,
}

impl Prefetcher {
    /// Creates a prefetcher ahead of `workers` workers.
    pub(crate) fn new(workers: usize) -> Self {
        Self {
            queue: Mutex::default(),
            ready: Condvar::new(),
            waiting: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
            executed: AtomicUsize::new(0),
            workers,
            stopped: AtomicBool::new(false),
        }
    }

    /// Queues the keys of the block's next transaction.
    pub(crate) fn push(&self, keys: Vec<PrefetchKey>) {
        self.queue.lock().unwrap().keys.push(keys);
        if self.waiting.load(Ordering::Acquire) > 0 {
            self.ready.notify_all();
        }
    }

    /// Marks the end of the block's transactions.
    pub(crate) fn close(&self) {
        self.queue.lock().unwrap().closed = true;
        self.ready.notify_all();
    }

    /// Stops prefetching: [`Self::run`] returns before its next read.
    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.close();
    }

    /// Records that a worker executed the transaction at `index`.
    pub(crate) fn executed(&self, index: usize) {
        self.executed.fetch_max(index + 1, Ordering::Relaxed);
    }

    /// Prefetches the queued transactions from `base` until the block ends or [`Self::stop`].
    pub(crate) fn run<B: DynDatabaseRef + ?Sized>(&self, base: &B) {
        while let Some(keys) = self.claim() {
            for key in keys {
                if self.stopped.load(Ordering::Acquire) {
                    return;
                }
                prefetch(base, key);
            }
        }
    }

    /// Claims the next transaction the workers have likely not started, waiting for it to
    /// arrive, and returns its keys, or `None` once the block ends.
    fn claim(&self) -> Option<Vec<PrefetchKey>> {
        let index = loop {
            let next = self.next.load(Ordering::Relaxed);
            let index = next.max(self.executed.load(Ordering::Relaxed) + self.workers);
            if self
                .next
                .compare_exchange_weak(next, index + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break index;
            }
        };
        let mut queue = self.queue.lock().unwrap();
        loop {
            if self.stopped.load(Ordering::Acquire) {
                return None;
            }
            if let Some(keys) = queue.keys.get_mut(index) {
                return Some(core::mem::take(keys));
            }
            if queue.closed {
                return None;
            }
            self.waiting.fetch_add(1, Ordering::AcqRel);
            queue = self.ready.wait(queue).unwrap();
            self.waiting.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Stops a [`Prefetcher`] when dropped, so that its threads end even if execution unwinds.
#[derive(Debug)]
pub(crate) struct StopOnDrop<'a>(pub(crate) &'a Prefetcher);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Reads `key` from `base`, ignoring the result.
fn prefetch<B: DynDatabaseRef + ?Sized>(base: &B, key: PrefetchKey) {
    match key {
        PrefetchKey::Account(address) => {
            if let Ok(Some(info)) = base.get_account(&address)
                && info.code.is_none()
                && !info.is_empty_code_hash()
            {
                let _ = base.get_code_by_hash(&info.code_hash);
            }
        }
        PrefetchKey::Storage(address, slot) => {
            let _ = base.get_storage(&address, &slot);
        }
        PrefetchKey::FeeToken { payer, fallback } => {
            let preference = base
                .get_storage(
                    &TIP_FEE_MANAGER_ADDRESS,
                    &payer.mapping_slot(tip_fee_manager::slots::USER_TOKENS),
                )
                .unwrap_or_default();
            let token = if preference.is_zero() {
                fallback
            } else {
                Address::from_word(preference.into())
            };
            let _ = base.get_storage(&token, &payer.mapping_slot(tip20::slots::BALANCES));
        }
    }
}
