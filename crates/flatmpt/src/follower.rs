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
                        Ok(()) => tracing::info!(
                            target: "flatmpt",
                            parent = %parent_root,
                            unwind_ms = t.elapsed().as_millis() as u64,
                            "follower unwound abandoned candidate"
                        ),
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
