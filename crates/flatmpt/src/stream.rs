//! Streamed block application: overlap the flat-MPT update with transaction
//! execution, the same way the sparse-trie task overlaps proof fetching.
//!
//! The payload builder installs [`FlatStream::hook`] as the executor's state
//! hook; every committed transaction's `EvmState` is shipped to a worker that
//! accumulates net per-account changes and applies them to the shared
//! [`FlatShadow`] in bounded chunks while execution continues. At
//! payload-finish only the residual chunk remains, so the critical-path cost
//! drops from "apply the whole block" to "apply the tail".
//!
//! Chunk inverses are chained: rolling back a streamed block (candidate
//! rebuild, reorg, abort) replays the chunk inverses in reverse. A dropped
//! stream that was never finished rolls itself back.

use crate::{FlatShadow, mode, FlatMode};
use alloy_primitives::{keccak256, B256, U256};
use mpt_flat_poc::{Key, StateOp};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::mpsc;

/// Slot-op count that triggers a chunk apply.
const CHUNK_OPS: usize = 8_192;

/// Net accumulated changes for one account since the last chunk flush.
#[derive(Default)]
struct AcctAcc {
    /// Account was selfdestructed (emit `DeleteAccount` before anything else).
    destroyed: bool,
    /// Present account fields, `None` after destruction or an EIP-158 clear.
    info: Option<(u64, U256, [u8; 32])>,
    /// Present values of changed slots.
    slots: HashMap<U256, U256>,
    /// Whether `info` was explicitly cleared (EIP-158) rather than never set.
    cleared: bool,
}

struct Worker {
    shadow: &'static RwLock<FlatShadow>,
    acc: HashMap<alloy_primitives::Address, AcctAcc>,
    pending_slot_ops: usize,
    /// Inverses of chunks applied so far, in apply order.
    inverses: Vec<Vec<(Key, StateOp)>>,
    streamed_ops: usize,
    chunk_apply_us: u64,
}

impl Worker {
    fn on_state(&mut self, state: revm::state::EvmState) -> anyhow::Result<()> {
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
                // Touched-and-empty: EIP-158 clear.
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
                    continue; // read or written back to original — no change
                }
                if e.slots.insert(*slot, s.present_value).is_none() {
                    self.pending_slot_ops += 1;
                }
            }
        }
        if self.pending_slot_ops >= CHUNK_OPS {
            self.flush()?;
        }
        Ok(())
    }

    /// Materialize the accumulated net changes as canonical ops and apply them
    /// as one chunk.
    fn flush(&mut self) -> anyhow::Result<()> {
        if self.acc.is_empty() {
            return Ok(());
        }
        let mut ops: Vec<(Key, StateOp)> = Vec::with_capacity(self.pending_slot_ops + self.acc.len() * 2);
        for (address, e) in self.acc.drain() {
            let key: Key = keccak256(address.as_slice()).0;
            if e.destroyed {
                ops.push((key, StateOp::DeleteAccount));
            } else if e.cleared {
                ops.push((key, StateOp::DeleteAccount));
                continue;
            }
            if let Some((nonce, balance, code_hash)) = e.info {
                ops.push((key, StateOp::SetAccount { nonce, balance, code_hash }));
                let mut slots: Vec<(Key, StateOp)> = e
                    .slots
                    .into_iter()
                    .map(|(slot, present)| {
                        let slot_key: Key = keccak256(slot.to_be_bytes::<32>()).0;
                        if present == U256::ZERO {
                            (slot_key, StateOp::DeleteStorage { slot: slot_key })
                        } else {
                            (
                                slot_key,
                                StateOp::SetStorage {
                                    slot: slot_key,
                                    value: mpt_flat_poc::eth::storage_value_rlp(present),
                                },
                            )
                        }
                    })
                    .collect();
                slots.sort_by(|a, b| a.0.cmp(&b.0));
                ops.extend(slots.into_iter().map(|(_, op)| (key, op)));
            }
        }
        self.pending_slot_ops = 0;
        ops.sort_by(|a, b| a.0.cmp(&b.0)); // stable: per-account sequences preserved
        self.streamed_ops += ops.len();
        let t = std::time::Instant::now();
        let inverse = self.shadow.write().apply_stream_chunk(ops)?;
        self.chunk_apply_us += t.elapsed().as_micros() as u64;
        self.inverses.push(inverse);
        Ok(())
    }
}

struct StreamOutcome {
    inverses: Vec<Vec<(Key, StateOp)>>,
    streamed_ops: usize,
    chunks: usize,
    chunk_apply_us: u64,
}

/// Handle to an in-flight streamed block application.
pub struct FlatStream {
    tx: Option<mpsc::SyncSender<revm::state::EvmState>>,
    done_rx: mpsc::Receiver<anyhow::Result<StreamOutcome>>,
    shadow: &'static RwLock<FlatShadow>,
    parent_number: u64,
    parent_root: B256,
    finished: bool,
}

impl FlatStream {
    /// Prepare the shared shadow at `parent` (rolling back a previous candidate
    /// if needed) and spawn the streaming worker.
    pub fn begin(
        shadow: &'static RwLock<FlatShadow>,
        parent_number: u64,
        parent_root: B256,
    ) -> anyhow::Result<Self> {
        shadow.write().begin_stream(parent_number, parent_root)?;
        let (tx, rx) = mpsc::sync_channel::<revm::state::EvmState>(1024);
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("flatmpt-stream".into())
            .spawn(move || {
                let mut w = Worker {
                    shadow,
                    acc: HashMap::new(),
                    pending_slot_ops: 0,
                    inverses: Vec::new(),
                    streamed_ops: 0,
                    chunk_apply_us: 0,
                };
                let mut result = Ok(());
                for state in rx {
                    if result.is_ok() {
                        result = w.on_state(state);
                    }
                }
                if result.is_ok() {
                    result = w.flush();
                }
                let _ = done_tx.send(result.map(|_| StreamOutcome {
                    chunks: w.inverses.len(),
                    inverses: w.inverses,
                    streamed_ops: w.streamed_ops,
                    chunk_apply_us: w.chunk_apply_us,
                }));
            })
            .expect("spawn flatmpt-stream");
        Ok(Self { tx: Some(tx), done_rx, shadow, parent_number, parent_root, finished: false })
    }

    /// State hook for the executor; ship each committed tx's state to the worker.
    pub fn hook(&self) -> impl revm::OnStateHook {
        let tx = self.tx.as_ref().expect("stream active").clone();
        move |state: revm::state::EvmState| {
            let _ = tx.send(state);
        }
    }

    /// Finalize: drain the stream, apply the residual chunk, and commit the
    /// block entry under `canonical_ops` (the memo fingerprint the validator
    /// will present). Returns the block's state root.
    pub fn finish(mut self, canonical_ops: Vec<(Key, StateOp)>) -> anyhow::Result<B256> {
        drop(self.tx.take()); // close channel; worker flushes and exits
        let outcome = self
            .done_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("flatmpt stream worker died"))??;
        self.finished = true;
        self.shadow.write().finish_stream(
            self.parent_number,
            self.parent_root,
            canonical_ops,
            outcome.inverses,
            outcome.streamed_ops,
            outcome.chunks,
            outcome.chunk_apply_us,
        )
    }
}

impl Drop for FlatStream {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Cancelled/failed build: unwind whatever chunks were applied.
        drop(self.tx.take());
        if let Ok(Ok(outcome)) = self.done_rx.recv() {
            if let Err(e) = self.shadow.write().abort_stream(outcome.inverses) {
                panic!("flatmpt stream abort failed to roll back: {e:#}");
            }
        } else {
            panic!("flatmpt stream worker failed mid-build; shadow state unknown");
        }
    }
}

/// True when streamed roots should be re-derived from canonical ops and
/// cross-checked (env `TEMPO_FLATMPT_STREAM_CHECK=1`).
pub fn stream_check() -> bool {
    std::env::var("TEMPO_FLATMPT_STREAM_CHECK").as_deref() == Ok("1")
}

/// Whether streaming is enabled for root mode (default on; env
/// `TEMPO_FLATMPT_STREAM=0` reverts to the serialized finish-path apply).
pub fn stream_enabled() -> bool {
    mode() == FlatMode::Root && std::env::var("TEMPO_FLATMPT_STREAM").as_deref() != Ok("0")
}
