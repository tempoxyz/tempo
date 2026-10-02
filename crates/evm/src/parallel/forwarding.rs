//! Bounded, advisory predecessor dependencies. These values are predictions:
//! the ordinary ordered read validation remains the authority for every result.

use super::{Env, ReadKey, ReadValue, TempoTxEnv};
use alloy_primitives::{U256, map::HashMap};
use alloy_sol_types::SolCall;
use reth_revm::state::EvmState;
use std::{
    collections::VecDeque,
    sync::{
        Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tempo_precompiles::{
    storage::StorageKey,
    tip20::{ITIP20, slots},
};
use tempo_primitives::TempoAddressExt;

#[derive(Debug)]
struct Hint {
    key: ReadKey,
    predecessor: Option<(usize, usize)>,
}

#[derive(Debug)]
struct Ready {
    queue: VecDeque<usize>,
    pending: Vec<usize>,
    remaining: usize,
}

#[derive(Debug)]
pub(super) struct Forwarding {
    hints: Vec<Vec<Hint>>,
    dependents: Vec<Vec<usize>>,
    values: Vec<OnceLock<Vec<Option<ReadValue>>>>,
    ready: Mutex<Ready>,
    wake: Condvar,
}

impl Forwarding {
    pub(super) fn new(inputs: &[(TempoTxEnv, Env)]) -> Self {
        let mut latest = HashMap::<ReadKey, (usize, usize)>::default();
        let mut hints = Vec::with_capacity(inputs.len());
        let mut dependents = vec![Vec::new(); inputs.len()];
        let mut pending = Vec::with_capacity(inputs.len());
        let mut queue = VecDeque::new();
        for (index, (tx, env)) in inputs.iter().enumerate() {
            let mut parents = Vec::new();
            let keys = keys(tx, env);
            let mut tx_hints = Vec::with_capacity(keys.len());
            for (position, key) in keys.into_iter().enumerate() {
                let predecessor = latest.insert(key, (index, position));
                if let Some((parent, _)) = predecessor {
                    parents.push(parent);
                }
                tx_hints.push(Hint { key, predecessor });
            }
            parents.sort_unstable();
            parents.dedup();
            pending.push(parents.len());
            if parents.is_empty() {
                queue.push_back(index);
            }
            for parent in parents {
                dependents[parent].push(index);
            }
            hints.push(tx_hints);
        }
        Self {
            hints,
            dependents,
            values: (0..inputs.len()).map(|_| OnceLock::new()).collect(),
            ready: Mutex::new(Ready {
                queue,
                pending,
                remaining: inputs.len(),
            }),
            wake: Condvar::new(),
        }
    }

    pub(super) fn next(&self, cancelled: &AtomicBool) -> Option<usize> {
        let mut ready = self.ready.lock().expect("prediction queue poisoned");
        loop {
            if cancelled.load(Ordering::Relaxed) || ready.remaining == 0 {
                return None;
            }
            if let Some(index) = ready.queue.pop_front() {
                return Some(index);
            }
            ready = self.wake.wait(ready).expect("prediction queue poisoned");
        }
    }

    pub(super) fn seed(
        &self,
        index: usize,
        prefetched: &HashMap<ReadKey, ReadValue>,
    ) -> HashMap<ReadKey, ReadValue> {
        self.hints[index]
            .iter()
            .filter_map(|hint| {
                let value = if let Some((parent, position)) = hint.predecessor {
                    self.values[parent].get().expect("predecessor completed")[position].as_ref()
                } else {
                    prefetched.get(&hint.key)
                };
                value.cloned().map(|value| (hint.key, value))
            })
            .collect()
    }

    pub(super) fn complete(
        &self,
        index: usize,
        state: Option<&EvmState>,
        seed: &HashMap<ReadKey, ReadValue>,
    ) {
        let values = self.hints[index]
            .iter()
            .map(|hint| {
                let inherited = || seed.get(&hint.key).cloned();
                let Some(state) = state else {
                    return inherited();
                };
                match hint.key {
                    ReadKey::Account(address) => {
                        match state.get(&address).filter(|account| account.is_touched()) {
                            Some(account) if account.is_selfdestructed() => {
                                Some(ReadValue::Account(None))
                            }
                            Some(account) => Some(ReadValue::Account(Some(account.info.clone()))),
                            None => inherited(),
                        }
                    }
                    ReadKey::Storage(address, slot) => {
                        match state.get(&address).filter(|account| account.is_touched()) {
                            Some(account) if account.is_selfdestructed() => {
                                Some(ReadValue::Storage(U256::ZERO))
                            }
                            Some(account) => account
                                .storage
                                .get(&slot)
                                .map(|slot| ReadValue::Storage(slot.present_value))
                                .or_else(|| {
                                    account
                                        .is_created()
                                        .then_some(ReadValue::Storage(U256::ZERO))
                                })
                                .or_else(inherited),
                            None => inherited(),
                        }
                    }
                    _ => inherited(),
                }
            })
            .collect();
        self.values[index]
            .set(values)
            .expect("one result per candidate");
        let mut ready = self.ready.lock().expect("prediction queue poisoned");
        ready.remaining -= 1;
        let mut newly_ready = 0;
        for &dependent in &self.dependents[index] {
            ready.pending[dependent] -= 1;
            if ready.pending[dependent] == 0 {
                ready.queue.push_back(dependent);
                newly_ready += 1;
            }
        }
        let done = ready.remaining == 0;
        drop(ready);
        if done {
            self.wake.notify_all();
        } else {
            for _ in 0..newly_ready {
                self.wake.notify_one();
            }
        }
    }

    pub(super) fn cancel(&self) {
        // Synchronize with the cancellation check before Condvar::wait so that
        // cancellation cannot be lost between checking and going to sleep.
        let _ready = self.ready.lock().unwrap_or_else(|error| error.into_inner());
        self.wake.notify_all();
    }
}

fn keys(tx: &TempoTxEnv, env: &Env) -> Vec<ReadKey> {
    let mut keys = vec![ReadKey::Account(tx.inner.caller)];
    let mut add = |key| {
        if !keys.contains(&key) {
            keys.push(key);
        }
    };
    let payer = tx.fee_payer().unwrap_or(tx.inner.caller);
    let call = tx.calls().next();
    let token = call
        .as_ref()
        .and_then(|(kind, _)| kind.to().copied())
        .filter(|token| token.is_tip20());
    for token in [
        Some(tempo_contracts::precompiles::DEFAULT_FEE_TOKEN),
        tx.fee_token,
        token,
    ]
    .into_iter()
    .flatten()
    {
        add(ReadKey::Storage(token, payer.mapping_slot(slots::BALANCES)));
    }
    if let Some(token) = token
        && let Some((_, input)) = call
        && let Ok(transfer) = ITIP20::transferCall::abi_decode(input)
    {
        for holder in [tx.inner.caller, transfer.to] {
            add(ReadKey::Storage(
                token,
                holder.mapping_slot(slots::BALANCES),
            ));
        }
    }
    if let Some((key, _)) = tempo_revm::replay::nonce_hint(
        tx,
        env.cfg_env.spec,
        env.block_env.timestamp.saturating_to(),
    ) {
        add(key);
    }
    keys
}
