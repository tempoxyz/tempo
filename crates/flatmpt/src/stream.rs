//! Execution-overlapped prefetch: warm the flat store's read-ahead buffer
//! with every record the finish-path apply will need, while the EVM is still
//! executing — the same overlap shape as reth's sparse-trie proof fetching.
//!
//! Unlike the earlier design, nothing here mutates the shared trie: the
//! worker accumulates net per-account changes from the executor's state hook,
//! and periodically routes them (read-only frontier walk) to record pointers,
//! reading those payloads into the store's read-ahead map. The authoritative
//! trie is only touched once, at payload-finish, by the ordinary
//! [`crate::FlatShadow::root_for`] apply — which then finds its records
//! already in RAM. An abandoned build just drops its prefetcher; there is
//! nothing to roll back.

use crate::FlatShadow;
use alloy_primitives::{U256, keccak256};
use mpt_flat_poc::{Key, StateOp};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::mpsc};

/// Accumulated slot-op count that triggers a prefetch pass.
const PREFETCH_OPS: usize = 8_192;

/// Net accumulated changes for one account since the last prefetch pass.
#[derive(Default)]
struct AcctAcc {
    destroyed: bool,
    info: Option<(u64, U256, [u8; 32])>,
    slots: HashMap<U256, U256>,
    cleared: bool,
}

struct Worker {
    shadow: &'static RwLock<FlatShadow>,
    acc: HashMap<alloy_primitives::Address, AcctAcc>,
    pending_slot_ops: usize,
    prefetched_ops: usize,
    passes: usize,
}

impl Worker {
    fn on_state(&mut self, state: revm::state::EvmState) {
        for (address, account) in &state {
            if !account.is_touched() {
                continue;
            }
            let e = self.acc.entry(*address).or_default();
            if account.is_selfdestructed() {
                e.destroyed = true;
                e.info = None;
                e.cleared = false;
                self.pending_slot_ops -= e.slots.len();
                e.slots.clear();
                continue;
            }
            if account.is_empty() {
                e.info = None;
                e.cleared = true;
            } else {
                e.info = Some((
                    account.info.nonce,
                    account.info.balance,
                    account.info.code_hash.0,
                ));
                e.cleared = false;
            }
            for (slot, s) in &account.storage {
                if s.present_value == s.original_value {
                    continue;
                }
                if e.slots.insert(*slot, s.present_value).is_none() {
                    self.pending_slot_ops += 1;
                }
            }
        }
        if self.pending_slot_ops >= PREFETCH_OPS {
            self.prefetch_pass();
        }
    }

    /// Materialize the accumulated net changes as ops and warm the read-ahead
    /// buffer for them. Read-only: takes the shadow's shared lock briefly for
    /// the routing walk; payload reads run outside any integration state.
    fn prefetch_pass(&mut self) {
        if self.acc.is_empty() {
            return;
        }
        let mut ops: Vec<(Key, StateOp)> =
            Vec::with_capacity(self.pending_slot_ops + self.acc.len() * 2);
        for (address, e) in self.acc.drain() {
            let key: Key = keccak256(address.as_slice()).0;
            if e.destroyed || e.cleared {
                ops.push((key, StateOp::DeleteAccount));
                if e.cleared {
                    continue;
                }
            }
            if let Some((nonce, balance, code_hash)) = e.info {
                ops.push((
                    key,
                    StateOp::SetAccount {
                        nonce,
                        balance,
                        code_hash,
                    },
                ));
                for (slot, present) in e.slots {
                    let slot_key: Key = keccak256(slot.to_be_bytes::<32>()).0;
                    ops.push((
                        key,
                        if present == U256::ZERO {
                            StateOp::DeleteStorage { slot: slot_key }
                        } else {
                            StateOp::SetStorage {
                                slot: slot_key,
                                value: mpt_flat_poc::eth::storage_value_rlp(present),
                            }
                        },
                    ));
                }
            }
        }
        self.pending_slot_ops = 0;
        self.prefetched_ops += ops.len();
        self.passes += 1;
        if let Err(e) = self.shadow.read().prefetch(&ops) {
            tracing::warn!(target: "flatmpt", err = %format!("{e:#}"), "prefetch pass failed (advisory)");
        }
    }
}

/// Handle to an in-flight prefetcher. Dropping it (cancelled build) simply
/// stops prefetching; unconsumed read-ahead entries are cleared by the next
/// apply.
pub struct FlatStream {
    tx: Option<mpsc::SyncSender<revm::state::EvmState>>,
    done_rx: mpsc::Receiver<(usize, usize)>,
}

impl FlatStream {
    /// Spawn the prefetch worker. Purely advisory — no shared state changes.
    pub fn begin(shadow: &'static RwLock<FlatShadow>) -> Self {
        let (tx, rx) = mpsc::sync_channel::<revm::state::EvmState>(1024);
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("flatmpt-prefetch".into())
            .spawn(move || {
                let mut w = Worker {
                    shadow,
                    acc: HashMap::new(),
                    pending_slot_ops: 0,
                    prefetched_ops: 0,
                    passes: 0,
                };
                for state in rx {
                    w.on_state(state);
                }
                w.prefetch_pass();
                let _ = done_tx.send((w.prefetched_ops, w.passes));
            })
            .expect("spawn flatmpt-prefetch");
        Self {
            tx: Some(tx),
            done_rx,
        }
    }

    /// State hook for the executor.
    pub fn hook(&self) -> impl revm::OnStateHook {
        let tx = self.tx.as_ref().expect("prefetcher active").clone();
        move |state: revm::state::EvmState| {
            let _ = tx.send(state);
        }
    }

    /// Stop prefetching and wait for the worker (so its final pass lands
    /// before the apply). Returns (ops prefetched, passes) for logging.
    pub fn finish(mut self) -> (usize, usize) {
        drop(self.tx.take());
        self.done_rx.recv().unwrap_or((0, 0))
    }
}

/// Whether execution-overlapped prefetch runs in root mode (default on;
/// `TEMPO_FLATMPT_STREAM=0` disables).
pub fn stream_enabled() -> bool {
    crate::mode() == crate::FlatMode::Root
        && std::env::var("TEMPO_FLATMPT_STREAM").as_deref() != Ok("0")
}
