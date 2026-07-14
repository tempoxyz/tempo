//! Background apply follower: the only writer of the flat store in sparse
//! commitment mode. The builder stamps the sparse-over-flat root and queues
//! the block's ops here; the follower applies them through the ordinary
//! `root_for` path off the slot deadline and asserts that the flat engine
//! reproduces the sparse commitment exactly — a continuous cross-check of the
//! two implementations. It also serves unwind requests when a sparse worker
//! finds an abandoned candidate still applied.

use crate::FlatShadow;
use alloy_primitives::B256;
use mpt_flat_poc::{Key, StateOp};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::Instant;

enum FollowJob {
    Apply {
        parent_number: u64,
        parent_root: B256,
        ops: Vec<(Key, StateOp)>,
        expected_root: B256,
    },
    EnsureParent(B256),
}

/// Handle to the process-wide follower thread.
pub struct Follower {
    tx: mpsc::Sender<FollowJob>,
    depth: Arc<AtomicUsize>,
}

static FOLLOWER: OnceLock<Follower> = OnceLock::new();

/// Sparse commitments whose flat applies are queued or recently done:
/// (parent_root, canonical ops fingerprint) → committed root. Lets the
/// validator accept a block it (or its builder) already committed without
/// waiting behind the follower's write lock — the follower's own
/// root cross-check remains the loud correctness gate.
static PENDING_ROOTS: parking_lot::Mutex<Vec<(B256, [u8; 32], B256)>> =
    parking_lot::Mutex::new(Vec::new());
const PENDING_CAP: usize = 64;

/// Look up the committed root for (parent, ops). Sorts `ops` into the
/// canonical per-account order as a side effect (same order `root_for` uses).
pub fn pending_root(parent_root: B256, ops: &mut [(Key, StateOp)]) -> Option<B256> {
    let pending = PENDING_ROOTS.lock();
    if !pending.iter().any(|(p, _, _)| *p == parent_root) {
        return None;
    }
    ops.sort_by(|a, b| a.0.cmp(&b.0));
    let fp = crate::ops_fingerprint(ops);
    pending.iter().rev().find(|(p, f, _)| *p == parent_root && *f == fp).map(|(_, _, r)| *r)
}

fn note_pending(parent_root: B256, fingerprint: [u8; 32], root: B256) {
    let mut pending = PENDING_ROOTS.lock();
    if pending.len() >= PENDING_CAP {
        pending.remove(0);
    }
    pending.push((parent_root, fingerprint, root));
}

/// One queued-but-not-yet-applied block's state changes, in point-read form.
/// Together with a [`mpt_flat_poc::FlatSnapshot`] of the flat at some ancestor
/// state, a chain of these serves exact parent-state reads without ever
/// touching the shadow lock — the builder never waits on the follower's apply.
pub struct PendingBlock {
    /// State root this block was built on.
    pub parent_root: B256,
    /// State root after this block (the sparse commitment).
    pub root: B256,
    /// keccak(address) → account fields, `None` = deleted.
    accounts: std::collections::HashMap<Key, Option<(u64, alloy_primitives::U256, [u8; 32])>>,
    /// keccak(address) → this block's storage writes for that account.
    storage: std::collections::HashMap<Key, PendingStorage>,
}

#[derive(Default)]
struct PendingStorage {
    /// Storage cleared this block (self-destruct / wipe): any slot not in
    /// `slots` reads as absent rather than falling through to the snapshot.
    wiped: bool,
    /// hashed slot → RLP value, `None` = deleted.
    slots: std::collections::HashMap<Key, Option<Vec<u8>>>,
}

impl PendingBlock {
    /// `ops` must be in canonical apply order (stable-sorted by account key,
    /// generation order preserved per key) — the same order `root_for` sees.
    fn from_ops(parent_root: B256, root: B256, ops: &[(Key, StateOp)]) -> Self {
        let mut accounts = std::collections::HashMap::new();
        let mut storage: std::collections::HashMap<Key, PendingStorage> =
            std::collections::HashMap::new();
        for (key, op) in ops {
            match op {
                StateOp::SetAccount { nonce, balance, code_hash } => {
                    accounts.insert(*key, Some((*nonce, *balance, *code_hash)));
                }
                StateOp::DeleteAccount => {
                    accounts.insert(*key, None);
                    let st = storage.entry(*key).or_default();
                    st.wiped = true;
                    st.slots.clear();
                }
                StateOp::WipeStorage => {
                    let st = storage.entry(*key).or_default();
                    st.wiped = true;
                    st.slots.clear();
                }
                StateOp::SetStorage { slot, value } => {
                    storage.entry(*key).or_default().slots.insert(*slot, Some(value.clone()));
                }
                StateOp::DeleteStorage { slot } => {
                    storage.entry(*key).or_default().slots.insert(*slot, None);
                }
            }
        }
        Self { parent_root, root, accounts, storage }
    }

    /// Outer `None` = this block didn't touch the account (fall through).
    pub fn account(&self, key: &Key) -> Option<Option<(u64, alloy_primitives::U256, [u8; 32])>> {
        self.accounts.get(key).copied()
    }

    /// Outer `None` = this block didn't determine the slot (fall through).
    pub fn storage(&self, account: &Key, slot: &Key) -> Option<Option<&[u8]>> {
        let st = self.storage.get(account)?;
        if let Some(v) = st.slots.get(slot) {
            return Some(v.as_deref());
        }
        st.wiped.then_some(None)
    }
}

/// Queued/unapplied blocks, oldest first. Kept small: entries leave as the
/// follower applies them; a hard cap guards unwind edge cases.
static PENDING_BLOCKS: parking_lot::Mutex<Vec<Arc<PendingBlock>>> =
    parking_lot::Mutex::new(Vec::new());
const PENDING_BLOCKS_CAP: usize = 64;

/// The flat snapshot published after the follower's most recent apply
/// (root at publish time, snapshot). Refreshed outside the shadow write lock.
static PUBLISHED_SNAPSHOT: parking_lot::Mutex<Option<(B256, mpt_flat_poc::FlatSnapshot)>> =
    parking_lot::Mutex::new(None);

/// Latest published (root, snapshot) — lock-free with respect to the
/// follower's applies (the mutex is held only for the clone).
pub fn published_snapshot() -> Option<(B256, mpt_flat_poc::FlatSnapshot)> {
    PUBLISHED_SNAPSHOT.lock().clone()
}

/// Publish the current shadow state as the read snapshot. Called by the
/// follower after each apply and by the shadow owner after anchoring.
pub fn publish_snapshot(shadow: &RwLock<FlatShadow>) {
    let g = shadow.read();
    let pair = (g.current_root(), g.snapshot());
    drop(g);
    *PUBLISHED_SNAPSHOT.lock() = Some(pair);
}

fn register_pending(block: Arc<PendingBlock>) {
    let mut q = PENDING_BLOCKS.lock();
    if q.len() >= PENDING_BLOCKS_CAP {
        q.remove(0);
    }
    q.push(block);
}

fn retire_pending(applied_root: B256) {
    PENDING_BLOCKS.lock().retain(|b| b.root != applied_root);
}

/// The chain of pending blocks leading `snapshot_root` → `parent_root`,
/// newest first (lookup order). `Some(vec![])` when the roots already match;
/// `None` when no complete chain exists (gap, unwind, follower ahead).
pub fn pending_chain(snapshot_root: B256, parent_root: B256) -> Option<Vec<Arc<PendingBlock>>> {
    if snapshot_root == parent_root {
        return Some(Vec::new());
    }
    let q = PENDING_BLOCKS.lock();
    let mut chain = Vec::new();
    let mut target = parent_root;
    while target != snapshot_root {
        let blk = q.iter().rev().find(|b| b.root == target)?;
        target = blk.parent_root;
        chain.push(blk.clone());
        if chain.len() > q.len() {
            return None; // cycle guard
        }
    }
    Some(chain)
}

/// Get (spawning on first use) the follower for the process-wide shadow.
pub fn follower(shadow: &'static RwLock<FlatShadow>) -> &'static Follower {
    FOLLOWER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<FollowJob>();
        let depth = Arc::new(AtomicUsize::new(0));
        let d = depth.clone();
        std::thread::Builder::new()
            .name("flatmpt-follower".into())
            .spawn(move || run(shadow, rx, d))
            .expect("spawn flatmpt-follower");
        Follower { tx, depth }
    })
}

/// Ask the follower to bring the flat store to `parent_root` if an abandoned
/// candidate on top of it is currently applied. No-op when the follower is
/// simply behind (pending applies will get there) or not yet spawned.
pub(crate) fn request_parent(parent_root: B256) {
    if let Some(f) = FOLLOWER.get() {
        let _ = f.tx.send(FollowJob::EnsureParent(parent_root));
    }
}

impl Follower {
    /// Queue a block for background application. `expected_root` is the
    /// sparse commitment the flat apply must reproduce.
    pub fn queue_apply(
        &self,
        parent_number: u64,
        parent_root: B256,
        mut ops: Vec<(Key, StateOp)>,
        expected_root: B256,
    ) {
        ops.sort_by(|a, b| a.0.cmp(&b.0));
        note_pending(parent_root, crate::ops_fingerprint(&ops), expected_root);
        // Must be registered before anyone can build on this block's state:
        // readers overlay pending blocks over the published snapshot.
        register_pending(Arc::new(PendingBlock::from_ops(parent_root, expected_root, &ops)));
        self.depth.fetch_add(1, Ordering::SeqCst);
        let _ = self.tx.send(FollowJob::Apply { parent_number, parent_root, ops, expected_root });
    }

    /// Blocks currently queued (not yet applied).
    pub fn depth(&self) -> usize {
        self.depth.load(Ordering::SeqCst)
    }
}

fn run(
    shadow: &'static RwLock<FlatShadow>,
    rx: mpsc::Receiver<FollowJob>,
    depth: Arc<AtomicUsize>,
) {
    for job in rx {
        match job {
            FollowJob::Apply { parent_number, parent_root, ops, expected_root } => {
                let t = Instant::now();
                let n_ops = ops.len();
                let res = shadow.write().root_for(parent_number, parent_root, ops);
                let queued = depth.fetch_sub(1, Ordering::SeqCst) - 1;
                match res {
                    Ok(root) if root == expected_root => {
                        publish_snapshot(shadow);
                        retire_pending(root);
                        crate::sparse::prune_overlays(root);
                        tracing::info!(
                            target: "flatmpt",
                            block = parent_number + 1,
                            n_ops,
                            apply_ms = t.elapsed().as_millis() as u64,
                            queued,
                            "follower applied block (root cross-check ok)"
                        );
                    }
                    Ok(root) => {
                        tracing::error!(
                            target: "flatmpt",
                            block = parent_number + 1,
                            flat = %root,
                            sparse = %expected_root,
                            "FLAT/SPARSE ROOT DIVERGENCE — aborting"
                        );
                        std::process::abort();
                    }
                    Err(e) => {
                        tracing::error!(
                            target: "flatmpt",
                            block = parent_number + 1,
                            err = %format!("{e:#}"),
                            "follower apply failed — aborting"
                        );
                        std::process::abort();
                    }
                }
            }
            FollowJob::EnsureParent(parent_root) => {
                let mut guard = shadow.write();
                if guard.current_root() == parent_root {
                    continue;
                }
                if guard.entries.iter().any(|e| e.root == parent_root.0) {
                    let t = Instant::now();
                    match guard.unwind_to(parent_root) {
                        Ok(()) => {
                            drop(guard);
                            publish_snapshot(shadow);
                            tracing::info!(
                                target: "flatmpt",
                                parent = %parent_root,
                                unwind_ms = t.elapsed().as_millis() as u64,
                                "follower unwound abandoned candidate"
                            )
                        }
                        Err(e) => tracing::warn!(
                            target: "flatmpt",
                            parent = %parent_root,
                            err = %format!("{e:#}"),
                            "follower unwind failed"
                        ),
                    }
                } else {
                    tracing::debug!(
                        target: "flatmpt",
                        parent = %parent_root,
                        "requested parent not applied here (follower behind — applies pending)"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    fn k(b: u8) -> Key {
        [b; 32]
    }

    #[test]
    fn pending_block_read_semantics() {
        let ops = vec![
            (k(1), StateOp::SetAccount { nonce: 7, balance: U256::from(100u64), code_hash: [0xcc; 32] }),
            (k(1), StateOp::SetStorage { slot: k(0xa), value: vec![0x01] }),
            (k(2), StateOp::DeleteAccount),
            // recreated contract: storage wiped, then one slot set
            (k(3), StateOp::WipeStorage),
            (k(3), StateOp::SetStorage { slot: k(0xb), value: vec![0x02] }),
            (k(4), StateOp::DeleteStorage { slot: k(0xc) }),
        ];
        let b = PendingBlock::from_ops(B256::ZERO, B256::repeat_byte(1), &ops);

        // touched account: full fields
        assert_eq!(b.account(&k(1)), Some(Some((7, U256::from(100u64), [0xcc; 32]))));
        // deleted account: definitive absence, storage reads absent too
        assert_eq!(b.account(&k(2)), Some(None));
        assert_eq!(b.storage(&k(2), &k(0xff)), Some(None));
        // untouched account: fall through
        assert_eq!(b.account(&k(9)), None);
        // set slot hit; untouched slot of a wiped account = definitive absence
        assert_eq!(b.storage(&k(3), &k(0xb)), Some(Some(&[0x02][..])));
        assert_eq!(b.storage(&k(3), &k(0xd)), Some(None));
        // deleted slot: definitive absence; sibling slot falls through
        assert_eq!(b.storage(&k(4), &k(0xc)), Some(None));
        assert_eq!(b.storage(&k(4), &k(0xe)), None);
        // slot of an entirely untouched account falls through
        assert_eq!(b.storage(&k(9), &k(0xa)), None);
    }

    #[test]
    fn pending_chain_walk() {
        let r = |b: u8| B256::repeat_byte(0xe0 | b);
        // register A(r0->r1) and B(r1->r2); unrelated C on a fork
        register_pending(Arc::new(PendingBlock::from_ops(r(0), r(1), &[])));
        register_pending(Arc::new(PendingBlock::from_ops(r(1), r(2), &[])));
        register_pending(Arc::new(PendingBlock::from_ops(r(0), r(3), &[])));

        assert_eq!(pending_chain(r(0), r(0)).map(|c| c.len()), Some(0));
        let chain = pending_chain(r(0), r(2)).expect("chain r0->r2");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].root, r(2)); // newest first
        assert_eq!(chain[1].root, r(1));
        assert_eq!(pending_chain(r(0), r(3)).map(|c| c.len()), Some(1));
        // no path to an unknown root
        assert!(pending_chain(r(0), B256::repeat_byte(0x77)).is_none());
        // retire the middle block: chain to r2 breaks
        retire_pending(r(1));
        assert!(pending_chain(r(0), r(2)).is_none());
        assert_eq!(pending_chain(r(1), r(2)).map(|c| c.len()), Some(1));
        retire_pending(r(2));
        retire_pending(r(3));
    }
}
