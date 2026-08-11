//! Flat-MPT state commitment for Tempo — an experimental alternative to the
//! sparse-trie state root.
//!
//! A single process-wide [`FlatShadow`] mirrors the canonical chain state in a
//! [`mpt_flat_poc::FlatMpt`] and answers "state root after this bundle on top
//! of this parent" for both the payload builder (block construction) and the
//! engine validator (block validation, via reth's `CustomStateRoot` seam).
//!
//! Activation is env-driven so stock binaries are unaffected:
//!   TEMPO_FLATMPT=<path>          enable; flat file lives at <path> (wiped on init)
//!   TEMPO_FLATMPT_MODE=compare    compute flat root alongside the sparse trie and
//!                                 assert parity per block (default; bring-up gate)
//!   TEMPO_FLATMPT_MODE=root       flat MPT is the sole commitment: the builder
//!                                 stamps its root and the validator checks against it
//!
//! The shadow bootstraps from the chain-spec genesis alloc on first use and
//! tracks a suffix of applied blocks with inverse diffs, so candidate-payload
//! rebuilds and short reorgs roll back cleanly, and the build→validate replay
//! of the same block is a memo hit rather than a second application.

pub mod cursors;
pub mod follower;
mod sparse;
mod stream;
pub use follower::{
    Follower, PendingBlock, follower, overlay_account, overlay_storage, pending_chain,
    publish_snapshot, published_snapshot,
};
pub use mpt_flat_poc::{AccountSeed, FlatMpt, FlatSnapshot};
pub use sparse::{RevealSink, SparseStats, SparseWorker, ops_to_post_state, sparse_enabled};
pub use stream::{FlatStream, stream_enabled};

pub fn storage_value_rlp(value: U256) -> Vec<u8> {
    mpt_flat_poc::eth::storage_value_rlp(value)
}

use alloy_primitives::{B256, U256, keccak256};
use alloy_rlp::Decodable as _;
use mpt_flat_poc::{Key, StateOp, hex};
use parking_lot::RwLock;
use std::{io::Write as _, sync::OnceLock, time::Instant};

/// How the flat MPT participates in the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlatMode {
    /// Disabled (env not set).
    Off,
    /// Compute flat roots alongside the regular pipeline and assert parity.
    Compare,
    /// Flat MPT is the node's state commitment (builder stamps, validator checks).
    Root,
}

/// The configured mode, from `TEMPO_FLATMPT` / `TEMPO_FLATMPT_MODE`.
pub fn mode() -> FlatMode {
    static MODE: OnceLock<FlatMode> = OnceLock::new();
    *MODE.get_or_init(|| {
        if std::env::var_os("TEMPO_FLATMPT").is_none() {
            return FlatMode::Off;
        }
        match std::env::var("TEMPO_FLATMPT_MODE").as_deref() {
            Ok("root") => FlatMode::Root,
            Ok("compare") | Err(_) => FlatMode::Compare,
            Ok(other) => panic!("TEMPO_FLATMPT_MODE must be `compare` or `root`, got `{other}`"),
        }
    })
}

/// One applied block in the retained chain suffix.
struct Entry {
    /// Block number this entry produced (parent number + 1).
    number: u64,
    /// Root of the state this entry was applied on.
    parent_root: [u8; 32],
    /// Root after applying `ops`.
    root: [u8; 32],
    /// keccak of the canonical (key-sorted) op list — the memo fingerprint.
    /// Storing the hash instead of the ops keeps the retained window's heap
    /// bounded (full vectors cost ~11 MB per 90k-op block).
    ops_hash: [u8; 32],
    /// Inverse diffs to roll this entry back: one per applied chunk, in apply
    /// order (a non-streamed block has exactly one).
    inverse: Vec<Vec<(Key, StateOp)>>,
}

/// Canonical fingerprint of a key-sorted op list. Chunk-parallel
/// (hash-of-chunk-hashes): the serial stream cost ~24ms at gas-cap blocks
/// on the builder's hot thread.
pub(crate) fn ops_fingerprint(ops: &[(Key, StateOp)]) -> [u8; 32] {
    const PAR_MIN: usize = 16_384;
    let threads = std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(4);
    if ops.len() < PAR_MIN || threads < 2 {
        return fingerprint_chunk(ops);
    }
    let chunk = ops.len().div_ceil(threads);
    let hashes: Vec<[u8; 32]> = std::thread::scope(|sc| {
        ops.chunks(chunk)
            .map(|c| sc.spawn(move || fingerprint_chunk(c)))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().expect("fingerprint chunk panicked"))
            .collect()
    });
    let mut h = alloy_primitives::Keccak256::new();
    for ch in &hashes {
        h.update(ch);
    }
    h.finalize().0
}

fn fingerprint_chunk(ops: &[(Key, StateOp)]) -> [u8; 32] {
    // Field-direct hashing: the old per-op `bincode_op` Vec allocation made
    // this allocation-bound (~22ms/120k ops regardless of parallelism).
    let mut h = alloy_primitives::Keccak256::new();
    for (key, op) in ops {
        h.update(key);
        match op {
            StateOp::SetAccount {
                nonce,
                balance,
                code_hash,
            } => {
                h.update([0u8]);
                h.update(nonce.to_be_bytes());
                h.update(balance.to_be_bytes::<32>());
                h.update(code_hash);
            }
            StateOp::DeleteAccount => h.update([1u8]),
            StateOp::WipeStorage => h.update([2u8]),
            StateOp::SetStorage { slot, value } => {
                h.update([3u8]);
                h.update(slot);
                h.update(value);
            }
            StateOp::DeleteStorage { slot } => {
                h.update([4u8]);
                h.update(slot);
            }
        }
    }
    h.finalize().0
}

pub struct FlatShadow {
    db: FlatMpt,
    entries: Vec<Entry>,
    /// Canonical header root accepted as the parent of this checkpoint.
    /// This differs from `db.root()` for block-0 databases initialized with state bloat.
    checkpoint_parent: Option<B256>,
    timings: std::io::BufWriter<std::fs::File>,
    blocks_since_persist: u64,
    /// Engine phase nanos accumulated since the last commit_entry (profiling builds).
    prof_acc: [u64; 8],
}

/// Retained rollback window (candidate rebuilds and reorgs deeper than this
/// fail loudly). Env `TEMPO_FLATMPT_WINDOW` overrides; the window's heap is
/// dominated by inverse diffs (~11 MB per full block).
fn window() -> usize {
    static W: OnceLock<usize> = OnceLock::new();
    *W.get_or_init(|| {
        std::env::var("TEMPO_FLATMPT_WINDOW")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(32)
    })
}
/// Persist the flat file every this many applied blocks.
const PERSIST_EVERY: u64 = 128;

impl FlatShadow {
    /// Create a fresh shadow from a complete checkpoint state. `load` must feed
    /// every account (including its full storage) in hashed-key order.
    fn init_from_checkpoint(
        path: &str,
        checkpoint_root: B256,
        load: impl FnOnce(&mut FlatMpt) -> anyhow::Result<(u64, u64)>,
    ) -> anyhow::Result<Self> {
        for suffix in ["", ".meta", ".meta.prev", ".timings"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
        let started = Instant::now();
        let mut db = FlatMpt::create_ram_build(path, mpt_flat_poc::Config::default())
            .map_err(|e| anyhow::anyhow!("checkpoint create: {e:#}"))?;
        let (accounts, slots) = load(&mut db)?;
        anyhow::ensure!(
            db.root() == checkpoint_root.0,
            "flat checkpoint root {} != canonical checkpoint root {checkpoint_root}",
            hex(db.root()),
        );
        db.persist()
            .map_err(|e| anyhow::anyhow!("checkpoint persist: {e:#}"))?;
        let timings = std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{path}.timings"))?,
        );
        tracing::info!(
            target: "flatmpt",
            root = %hex(db.root()), accounts, slots,
            elapsed_s = started.elapsed().as_secs(), path,
            "flat MPT initialized from canonical checkpoint"
        );
        Ok(Self {
            db,
            entries: Vec::new(),
            checkpoint_parent: None,
            timings,
            blocks_since_persist: 0,
            prof_acc: [0; 8],
        })
    }

    /// Create a fresh shadow at `path` (existing files wiped) holding exactly
    /// the genesis state, verified against `genesis_root`.
    fn init(
        path: &str,
        genesis_ops: Vec<(Key, StateOp)>,
        genesis_root: B256,
    ) -> anyhow::Result<Self> {
        for suffix in ["", ".meta", ".meta.prev", ".timings"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
        let mut db = FlatMpt::create(path, mpt_flat_poc::Config::default())
            .map_err(|e| anyhow::anyhow!("{e:#}"))?;
        let n_ops = genesis_ops.len();
        let (root, _) = db
            .apply_block(genesis_ops)
            .map_err(|e| anyhow::anyhow!("genesis apply: {e:#}"))?;
        anyhow::ensure!(
            root == genesis_root.0,
            "flat genesis root {} != chain-spec genesis root {genesis_root} ({n_ops} alloc ops)",
            hex(root),
        );
        db.persist().map_err(|e| anyhow::anyhow!("{e:#}"))?;
        let timings = std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{path}.timings"))?,
        );
        tracing::info!(target: "flatmpt", root = %hex(root), n_ops, path, "flat MPT initialized from genesis alloc");
        Ok(Self {
            db,
            entries: Vec::new(),
            checkpoint_parent: None,
            timings,
            blocks_since_persist: 0,
            prof_acc: [0; 8],
        })
    }

    /// Golden-restore init (billion-slot scale): copy a prebuilt dump-only
    /// checkpoint (built offline by the `build_golden` example) and apply the
    /// genesis alloc as a small overlay on top. Account-field updates preserve
    /// existing storage, and genesis slot writes overwrite colliding dump
    /// slots — the node's collision rule.
    fn init_from_golden(
        path: &str,
        genesis_ops: Vec<(Key, StateOp)>,
        golden: &str,
    ) -> anyhow::Result<Self> {
        for suffix in ["", ".meta", ".meta.prev", ".timings"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
        let t = std::time::Instant::now();
        std::fs::copy(golden, path)?;
        std::fs::copy(format!("{golden}.meta"), format!("{path}.meta"))?;
        let copy_s = t.elapsed().as_secs();
        let mut db = FlatMpt::open(path).map_err(|e| anyhow::anyhow!("golden open: {e:#}"))?;
        let n_alloc = genesis_ops.len();
        db.apply_block(genesis_ops)
            .map_err(|e| anyhow::anyhow!("genesis overlay: {e:#}"))?;
        db.persist().map_err(|e| anyhow::anyhow!("{e:#}"))?;
        tracing::info!(
            target: "flatmpt",
            root = %hex(db.root()), n_alloc, copy_s,
            elapsed_s = t.elapsed().as_secs(), path,
            "flat MPT restored from golden + genesis overlay"
        );
        let timings = std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{path}.timings"))?,
        );
        Ok(Self {
            db,
            entries: Vec::new(),
            checkpoint_parent: None,
            timings,
            blocks_since_persist: 0,
            prof_acc: [0; 8],
        })
    }

    /// Bloat-mode init: genesis alloc + state-bloat dump.
    ///
    /// Streams the dump straight into per-account seed maps (no intermediate op
    /// vector — at 100M+ slots that alone is >10 GB), merges the genesis alloc
    /// on top (genesis wins storage collisions, mirroring
    /// `tempo init-from-binary-dump`), and loads through the engine's seeded
    /// RAM-build path — the same one the mainnet loader used for 535M slots.
    /// Rebuilt every init: genesis regenerates per bench leg.
    fn init_with_bloat(
        path: &str,
        genesis_ops: Vec<(Key, StateOp)>,
        dump: &str,
    ) -> anyhow::Result<Self> {
        use std::io::Read as _;
        for suffix in ["", ".meta", ".meta.prev", ".timings"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
        let t = std::time::Instant::now();

        struct Acc {
            nonce: u64,
            balance: U256,
            code_hash: [u8; 32],
            slots: std::collections::HashMap<Key, Vec<u8>>,
        }
        impl Default for Acc {
            fn default() -> Self {
                Self {
                    nonce: 0,
                    balance: U256::ZERO,
                    code_hash: mpt_flat_poc::eth::EMPTY_CODE_HASH.0,
                    slots: std::collections::HashMap::new(),
                }
            }
        }
        let mut accs: std::collections::HashMap<Key, Acc> = std::collections::HashMap::new();

        // 1) Dump, streamed. 2) Genesis alloc second — its inserts overwrite
        //    colliding dump slots, which is exactly the node's collision rule.
        let mut f = std::io::BufReader::with_capacity(64 << 20, std::fs::File::open(dump)?);
        let mut header = [0u8; 40];
        let mut n_dump: usize = 0;
        loop {
            match f.read_exact(&mut header) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            anyhow::ensure!(&header[0..8] == b"TEMPOSB\0", "bad bloat magic");
            anyhow::ensure!(
                u16::from_be_bytes([header[8], header[9]]) == 1,
                "bad bloat version"
            );
            let key: Key = keccak256(&header[12..32]).0;
            let pair_count = u64::from_be_bytes(header[32..40].try_into().unwrap());
            let acc = accs.entry(key).or_default();
            let mut pair = [0u8; 64];
            for _ in 0..pair_count {
                f.read_exact(&mut pair)?;
                let value = U256::from_be_slice(&pair[32..64]);
                if value == U256::ZERO {
                    continue;
                }
                acc.slots.insert(
                    keccak256(&pair[0..32]).0,
                    mpt_flat_poc::eth::storage_value_rlp(value),
                );
                n_dump += 1;
            }
        }
        let n_alloc = genesis_ops.len();
        for (key, op) in genesis_ops {
            match op {
                StateOp::SetAccount {
                    nonce,
                    balance,
                    code_hash,
                } => {
                    let acc = accs.entry(key).or_default();
                    acc.nonce = nonce;
                    acc.balance = balance;
                    acc.code_hash = code_hash;
                }
                StateOp::SetStorage { slot, value } => {
                    accs.entry(key).or_default().slots.insert(slot, value);
                }
                _ => anyhow::bail!("unexpected op in bloat init"),
            }
        }

        let mut batch: Vec<(Key, mpt_flat_poc::AccountSeed)> = accs
            .into_iter()
            .map(|(key, acc)| {
                let mut slots: Vec<(Key, Vec<u8>)> = acc.slots.into_iter().collect();
                slots.sort_by(|a, b| a.0.cmp(&b.0));
                (
                    key,
                    mpt_flat_poc::AccountSeed {
                        nonce: acc.nonce,
                        balance: acc.balance,
                        code_hash: acc.code_hash,
                        slots,
                    },
                )
            })
            .collect();
        batch.sort_by(|a, b| a.0.cmp(&b.0));

        let mut db = FlatMpt::create_ram_build(path, mpt_flat_poc::Config::default())
            .map_err(|e| anyhow::anyhow!("{e:#}"))?;
        db.insert_batch_accounts(batch)
            .map_err(|e| anyhow::anyhow!("bloat seed insert: {e:#}"))?;
        db.persist().map_err(|e| anyhow::anyhow!("{e:#}"))?;
        let root = db.root();
        drop(db);
        // Reopen without RAM-build so live block applies use the normal path.
        let db = FlatMpt::open(path).map_err(|e| anyhow::anyhow!("reopen: {e:#}"))?;
        anyhow::ensure!(db.root() == root, "root changed across reopen");
        tracing::info!(
            target: "flatmpt",
            root = %hex(root), n_alloc, n_dump,
            elapsed_s = t.elapsed().as_secs(), path,
            "flat MPT initialized from genesis alloc + bloat dump (seeded RAM build)"
        );
        let timings = std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{path}.timings"))?,
        );
        Ok(Self {
            db,
            entries: Vec::new(),
            checkpoint_parent: None,
            timings,
            blocks_since_persist: 0,
            prof_acc: [0; 8],
        })
    }

    /// The live flat trie (read-only walks; callers hold the shadow's lock).
    pub fn db(&self) -> &FlatMpt {
        &self.db
    }

    /// Active-file utilization of the flat store (gc scheduling input).
    pub fn utilization(&self) -> f64 {
        self.db.utilization()
    }

    /// Root of the live flat state.
    pub fn current_root(&self) -> B256 {
        B256::from(self.db.root())
    }

    /// O(1) lock-free read snapshot of the flat store (Arc-COW frontier).
    pub fn snapshot(&self) -> mpt_flat_poc::FlatSnapshot {
        self.db.snapshot()
    }

    /// True when the live flat state is the given parent. A block-0 checkpoint
    /// may accept the genesis header root as an alias because state bloat changes
    /// the database root without rewriting the canonical genesis header.
    pub fn at_parent(&self, parent_root: B256) -> bool {
        self.db.root() == parent_root.0
            || (self.entries.is_empty() && self.checkpoint_parent == Some(parent_root))
            || (self.entries.is_empty()
                && (std::env::var_os("TEMPO_FLATMPT_BLOAT").is_some()
                    || std::env::var_os("TEMPO_FLATMPT_GOLDEN").is_some()))
    }

    /// State root after applying `ops` on the state whose root is `parent_root`.
    ///
    /// The shadow advances optimistically: the applied block stays applied, and a
    /// later call whose parent is an *ancestor* rolls back through inverse diffs
    /// first. A repeat call for an already-applied block (same parent, same ops —
    /// the validator replaying what the builder built) returns the memoized root.
    pub fn root_for(
        &mut self,
        parent_number: u64,
        parent_root: B256,
        mut ops: Vec<(Key, StateOp)>,
    ) -> anyhow::Result<B256> {
        // Account interleaving differs between two executions of the same block
        // (bundle state is a hash map); per-account op sequences are what carry
        // ordering semantics. Stable-sort by account key → canonical fingerprint.
        ops.sort_by(|a, b| a.0.cmp(&b.0));

        // Memo: the validator re-deriving the block the builder just applied.
        let fingerprint = ops_fingerprint(&ops);
        if let Some(e) = self
            .entries
            .iter()
            .rev()
            .find(|e| e.number == parent_number + 1 && e.parent_root == parent_root.0)
        {
            if e.ops_hash == fingerprint {
                return Ok(B256::from(e.root));
            }
            // Same parent, different payload: a rebuilt candidate. Fall through —
            // the rollback loop below unwinds to the shared parent state.
        }

        self.unwind_to(parent_root)?;

        let n_ops = ops.len();
        let t = Instant::now();
        mpt_flat_poc::prof::reset();
        let (root, inverse) = self
            .db
            .apply_block(ops.clone())
            .map_err(|e| anyhow::anyhow!("apply: {e:#}"))?;
        for (i, (n, _)) in mpt_flat_poc::prof::snapshot().iter().enumerate() {
            self.prof_acc[i] += n;
        }
        let apply_us = t.elapsed().as_micros() as u64;
        self.db.prefetch_clear();
        debug_assert_eq!(root, self.db.root());

        self.commit_entry(
            parent_number,
            parent_root,
            fingerprint,
            vec![inverse],
            n_ops,
            0,
            apply_us,
        )
    }

    /// Warm the store's read-ahead buffer for a batch of ops (read-only;
    /// advisory — see [`FlatStream`]).
    pub fn prefetch(&self, ops: &[(Key, StateOp)]) -> anyhow::Result<()> {
        self.db
            .prefetch_block(ops)
            .map_err(|e| anyhow::anyhow!("{e:#}"))
    }

    /// Point-read an account by address: (nonce, balance, code_hash).
    /// `&self` — runs concurrently with other readers under the RwLock; the
    /// first-touch argument makes reads-during-streaming safe (any key the
    /// executor asks the provider for is untouched so far this block, so the
    /// flat state holds the parent value for it).
    pub fn read_account(
        &self,
        address: &[u8; 20],
    ) -> anyhow::Result<Option<(u64, U256, [u8; 32])>> {
        let key: Key = keccak256(address).0;
        let Some(rlp) = self
            .db
            .get_value(&key)
            .map_err(|e| anyhow::anyhow!("{e:#}"))?
        else {
            return Ok(None);
        };
        // RLP([nonce, balance, storage_root, code_hash])
        let mut buf = rlp.as_slice();
        let header = alloy_rlp::Header::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        anyhow::ensure!(header.list, "account leaf is not a list");
        let nonce = u64::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        let balance = U256::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        let _storage_root = B256::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        let code_hash = B256::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Some((nonce, balance, code_hash.0)))
    }

    /// Decode an account leaf RLP into (nonce, balance, code_hash).
    pub fn decode_account_rlp(rlp: &[u8]) -> anyhow::Result<(u64, U256, [u8; 32])> {
        let mut buf = rlp;
        let header = alloy_rlp::Header::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        anyhow::ensure!(header.list, "account leaf is not a list");
        let nonce = u64::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        let balance = U256::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        let _storage_root = B256::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        let code_hash = B256::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok((nonce, balance, code_hash.0))
    }

    /// Point-read a storage slot (present value; `None`/zero absent).
    pub fn read_slot(&self, address: &[u8; 20], slot: &[u8; 32]) -> anyhow::Result<Option<U256>> {
        let account_key: Key = keccak256(address).0;
        let slot_key: Key = keccak256(slot).0;
        let Some(rlp) = self
            .db
            .get_storage(&account_key, &slot_key)
            .map_err(|e| anyhow::anyhow!("{e:#}"))?
        else {
            return Ok(None);
        };
        let mut buf = rlp.as_slice();
        let value = U256::decode(&mut buf).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Some(value))
    }

    /// Roll the live state back until its root equals `parent_root`.
    fn unwind_to(&mut self, parent_root: B256) -> anyhow::Result<()> {
        // Bloat mode: `init-from-binary-dump` computes the post-dump state root
        // but leaves the genesis HEADER carrying the alloc-only root, so the
        // first build's parent anchor cannot match by construction. Anchor on
        // our own post-dump root instead — block 1 validation through the
        // engine (CustomStateRoot) remains the hard correctness gate.
        if self.entries.is_empty()
            && self.db.root() != parent_root.0
            && (self.checkpoint_parent == Some(parent_root)
                || std::env::var_os("TEMPO_FLATMPT_BLOAT").is_some()
                || std::env::var_os("TEMPO_FLATMPT_GOLDEN").is_some())
        {
            tracing::warn!(
                target: "flatmpt",
                header_root = %parent_root,
                live_root = %hex(self.db.root()),
                "genesis header carries the pre-dump root; anchoring on the post-dump state"
            );
            return Ok(());
        }
        while self.db.root() != parent_root.0 {
            let e = self.entries.pop().ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown parent: root {} not in retained window (live root {})",
                    parent_root,
                    hex(self.db.root()),
                )
            })?;
            for inv in e.inverse.into_iter().rev() {
                self.db
                    .apply_block(inv)
                    .map_err(|e| anyhow::anyhow!("rollback: {e:#}"))?;
            }
            tracing::debug!(target: "flatmpt", unwound = e.number, "flat MPT rolled back");
        }
        Ok(())
    }

    /// Record an applied block: timings line, retained-window entry, persist cadence.
    #[allow(clippy::too_many_arguments)]
    fn commit_entry(
        &mut self,
        parent_number: u64,
        parent_root: B256,
        ops_hash: [u8; 32],
        inverse: Vec<Vec<(Key, StateOp)>>,
        n_ops: usize,
        chunks: usize,
        apply_us: u64,
    ) -> anyhow::Result<B256> {
        let root = self.db.root();
        let number = parent_number + 1;
        let p = &self.prof_acc;
        serde_json::to_writer(
            &mut self.timings,
            &serde_json::json!({
                "block": number, "n_ops": n_ops, "apply_us": apply_us, "chunks": chunks,
                "keccak_ms": p[0] / 1_000_000, "ser_ms": p[1] / 1_000_000,
                "deser_ms": p[2] / 1_000_000, "read_ms": p[3] / 1_000_000,
                "write_ms": p[4] / 1_000_000, "flush_ms": p[5] / 1_000_000,
            }),
        )?;
        self.prof_acc = [0; 8];
        self.timings.write_all(b"\n")?;
        self.timings.flush()?;

        self.entries.push(Entry {
            number,
            parent_root: parent_root.0,
            root,
            ops_hash,
            inverse,
        });
        if self.entries.len() > window() {
            self.entries.remove(0);
        }

        self.blocks_since_persist += 1;
        if self.blocks_since_persist >= PERSIST_EVERY {
            self.db
                .persist()
                .map_err(|e| anyhow::anyhow!("persist: {e:#}"))?;
            self.blocks_since_persist = 0;
        }

        tracing::debug!(target: "flatmpt", block = number, n_ops, chunks, apply_us, root = %hex(root), "flat root");
        Ok(B256::from(root))
    }

    /// Run one bounded garbage-collection pass (evacuate under-utilized
    /// regions). Off the slot critical path — the follower calls this after
    /// each apply. Generation-aware pins make it safe under live snapshots.
    pub fn gc_step(&mut self) -> anyhow::Result<usize> {
        self.db.gc_step().map_err(|e| anyhow::anyhow!("gc: {e:#}"))
    }

    /// Install phase of the split background GC (see the flatmpt-gc thread in
    /// `follower`): re-verify + swap the pointers a background collect
    /// prepared. Brief — pure RAM walks and frees, no region IO.
    pub fn gc_install(&mut self, batch: mpt_flat_poc::GcBatch) -> anyhow::Result<(usize, usize)> {
        self.db
            .gc_install(batch)
            .map_err(|e| anyhow::anyhow!("gc install: {e:#}"))
    }
}

/// The process-wide shadow. First caller initializes it from the genesis alloc
/// (supplied lazily so only the winning caller pays for it); returns `None` when
/// the flat MPT is disabled.
///
/// With `TEMPO_FLATMPT_BLOAT=<file>` the state-bloat binary dump (the same one
/// `tempo init-from-binary-dump` loads) is applied on top of the alloc, and the
/// resulting checkpoint is cached as `<path>.golden*` — later inits with the
/// same dump restore by file copy instead of re-applying millions of slots.
/// In bloat mode the genesis-root assertion is skipped here (the header root is
/// only known post-dump); the first `root_for`/`begin_stream` parent check is
/// the gate instead.
static SHADOW: OnceLock<Option<RwLock<FlatShadow>>> = OnceLock::new();

pub fn shadow(
    genesis: impl FnOnce() -> (Vec<(Key, StateOp)>, B256),
) -> Option<&'static RwLock<FlatShadow>> {
    SHADOW
        .get_or_init(|| {
            if mode() == FlatMode::Off {
                return None;
            }
            let path = std::env::var("TEMPO_FLATMPT").expect("TEMPO_FLATMPT checked by mode()");
            let bloat = std::env::var("TEMPO_FLATMPT_BLOAT").ok();
            let golden = std::env::var("TEMPO_FLATMPT_GOLDEN").ok();
            let (ops, root) = genesis();
            let shadow = match (golden, bloat) {
                (Some(prefix), _) => FlatShadow::init_from_golden(&path, ops, &prefix),
                (None, Some(dump)) => FlatShadow::init_with_bloat(&path, ops, &dump),
                (None, None) => FlatShadow::init(&path, ops, root),
            };
            Some(RwLock::new(shadow.expect("flat MPT genesis init failed")))
        })
        .as_ref()
}

/// Initialize the process-wide shadow from a complete canonical checkpoint.
/// Subsequent calls to [`shadow`] reuse this instance.
pub fn shadow_from_checkpoint(
    checkpoint_number: u64,
    checkpoint_root: B256,
    checkpoint_parent: B256,
    load: impl FnOnce(&mut FlatMpt) -> anyhow::Result<(u64, u64)>,
) -> Option<&'static RwLock<FlatShadow>> {
    SHADOW
        .get_or_init(|| {
            if mode() == FlatMode::Off {
                return None;
            }
            let path = std::env::var("TEMPO_FLATMPT").expect("TEMPO_FLATMPT checked by mode()");
            let anchor_path = format!("{path}.anchor");
            let reopened = (|| -> anyhow::Result<Option<FlatShadow>> {
                let anchor = match std::fs::read_to_string(&anchor_path) {
                    Ok(anchor) => anchor,
                    Err(_) => return Ok(None),
                };
                let mut fields = anchor.split_whitespace();
                let anchor_number: u64 = fields
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing flat anchor number"))?
                    .parse()?;
                let anchor_root = fields
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing flat anchor root"))?;
                if anchor_number != checkpoint_number {
                    return Ok(None);
                }
                let db = FlatMpt::open(&path).map_err(|e| anyhow::anyhow!("checkpoint open: {e:#}"))?;
                if hex(db.root()) != anchor_root {
                    return Ok(None);
                }
                let timings = std::io::BufWriter::new(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(format!("{path}.timings"))?,
                );
                let shadow = FlatShadow {
                    db,
                    entries: Vec::new(),
                    checkpoint_parent: (checkpoint_parent != checkpoint_root)
                        .then_some(checkpoint_parent),
                    timings,
                    blocks_since_persist: 0,
                    prof_acc: [0; 8],
                };
                if shadow.current_root() != checkpoint_root {
                    return Ok(None);
                }
                tracing::info!(target: "flatmpt", block = checkpoint_number, root = %checkpoint_root, "flat MPT reopened at canonical checkpoint");
                Ok(Some(shadow))
            })()
            .expect("flat MPT checkpoint reopen failed");
            let shadow = reopened.unwrap_or_else(|| {
                let mut shadow = FlatShadow::init_from_checkpoint(&path, checkpoint_root, load)
                    .expect("flat MPT checkpoint init failed");
                shadow.checkpoint_parent =
                    (checkpoint_parent != checkpoint_root).then_some(checkpoint_parent);
                shadow
            });
            std::fs::write(
                &anchor_path,
                format!("{checkpoint_number} {}\n", hex(shadow.db.root())),
            )
            .expect("write flat MPT anchor");
            Some(RwLock::new(shadow))
        })
        .as_ref()
}

/// Map an alloy genesis alloc to flat-MPT ops (hashed keys).
pub fn genesis_to_ops(genesis: &alloy_genesis::Genesis) -> Vec<(Key, StateOp)> {
    let mut ops: Vec<(Key, StateOp)> = Vec::new();
    for (address, account) in &genesis.alloc {
        let key: Key = keccak256(address.as_slice()).0;
        let code_hash = account
            .code
            .as_ref()
            .map(|c| keccak256(c).0)
            .unwrap_or(mpt_flat_poc::eth::EMPTY_CODE_HASH.0);
        ops.push((
            key,
            StateOp::SetAccount {
                nonce: account.nonce.unwrap_or(0),
                balance: account.balance,
                code_hash,
            },
        ));
        for (slot, value) in account.storage.iter().flatten() {
            let v = U256::from_be_bytes(value.0);
            if v == U256::ZERO {
                continue;
            }
            ops.push((
                key,
                StateOp::SetStorage {
                    slot: keccak256(slot.as_slice()).0,
                    value: mpt_flat_poc::eth::storage_value_rlp(v),
                },
            ));
        }
    }
    ops
}

/// Map an executed block's `BundleState` to flat-MPT ops (hashed keys).
///
/// Same semantics as the mainnet ExEx: `was_destroyed` → wipe, `info: None`
/// without destruction → EIP-158 clear, zero-valued slots → deletions.
pub fn bundle_to_ops(bundle: &revm::database::BundleState) -> Vec<(Key, StateOp)> {
    // The keccaks (one per address + one per touched slot) dominate this
    // fn at monster blocks (~34ms serial at 120k ops); fan the per-account
    // work across threads and concatenate.
    let accounts: Vec<_> = bundle.state.iter().collect();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(4);
    if accounts.len() >= 1024 && threads > 1 {
        let chunk = accounts.len().div_ceil(threads);
        return std::thread::scope(|sc| {
            accounts
                .chunks(chunk)
                .map(|c| sc.spawn(move || bundle_chunk_to_ops(c)))
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join().expect("bundle_to_ops chunk panicked"))
                .collect()
        });
    }
    bundle_chunk_to_ops(&accounts)
}

fn bundle_chunk_to_ops(
    accounts: &[(&alloy_primitives::Address, &revm::database::BundleAccount)],
) -> Vec<(Key, StateOp)> {
    let mut ops: Vec<(Key, StateOp)> = Vec::new();
    for (address, acct) in accounts.iter().copied() {
        let key: Key = keccak256(address.as_slice()).0;
        let destroyed = acct.status.was_destroyed();
        if destroyed {
            ops.push((key, StateOp::DeleteAccount));
        }
        match &acct.info {
            Some(info) => {
                ops.push((
                    key,
                    StateOp::SetAccount {
                        nonce: info.nonce,
                        balance: info.balance,
                        code_hash: info.code_hash.0,
                    },
                ));
            }
            None => {
                if !destroyed {
                    // Touched-and-cleared (EIP-158) or otherwise gone.
                    ops.push((key, StateOp::DeleteAccount));
                }
                continue;
            }
        }
        // Emit slot ops in sorted slot order: bundle storage is a hash map, and a
        // canonical per-account order is what lets the validator's op list match
        // the builder's memoized one exactly.
        let mut slots: Vec<(Key, StateOp)> = Vec::with_capacity(acct.storage.len());
        for (slot, value) in &acct.storage {
            let slot_key: Key = keccak256(slot.to_be_bytes::<32>()).0;
            let present = value.present_value();
            if present == U256::ZERO {
                slots.push((slot_key, StateOp::DeleteStorage { slot: slot_key }));
            } else {
                slots.push((
                    slot_key,
                    StateOp::SetStorage {
                        slot: slot_key,
                        value: mpt_flat_poc::eth::storage_value_rlp(present),
                    },
                ));
            }
        }
        slots.sort_by(|a, b| a.0.cmp(&b.0));
        ops.extend(slots.into_iter().map(|(_, op)| (key, op)));
    }
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(byte: u8, nonce: u64) -> (Key, StateOp) {
        (
            keccak256([byte; 20]).0,
            StateOp::SetAccount {
                nonce,
                balance: U256::from(1u64),
                code_hash: mpt_flat_poc::eth::EMPTY_CODE_HASH.0,
            },
        )
    }

    #[test]
    fn advance_memo_and_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.flat");
        let path = path.to_str().unwrap();

        let genesis = vec![acct(1, 1)];
        let mut db =
            FlatMpt::create(format!("{path}.oracle"), mpt_flat_poc::Config::default()).unwrap();
        let (genesis_root, _) = db.apply_block(genesis.clone()).unwrap();

        let mut s = FlatShadow::init(path, genesis, B256::from(genesis_root)).unwrap();

        // Block 1 on genesis.
        let r1 = s
            .root_for(0, B256::from(genesis_root), vec![acct(2, 1)])
            .unwrap();
        // Validator replay: memo hit, same root, state still at block 1.
        let r1b = s
            .root_for(0, B256::from(genesis_root), vec![acct(2, 1)])
            .unwrap();
        assert_eq!(r1, r1b);

        // Block 2 on block 1.
        let r2 = s.root_for(1, r1, vec![acct(3, 1)]).unwrap();
        assert_ne!(r1, r2);

        // Rebuilt candidate for block 2 (same parent, different payload): rollback + apply.
        let r2alt = s.root_for(1, r1, vec![acct(4, 7)]).unwrap();
        assert_ne!(r2, r2alt);

        // Deep re-parent back to genesis.
        let r1c = s
            .root_for(0, B256::from(genesis_root), vec![acct(2, 1)])
            .unwrap();
        assert_eq!(r1, r1c);

        // Unknown parent fails loudly.
        assert!(
            s.root_for(5, B256::from([9u8; 32]), vec![acct(5, 1)])
                .is_err()
        );
    }

    #[test]
    fn checkpoint_parent_alias_accepts_block_zero_header_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.flat");
        let path = path.to_str().unwrap();
        let genesis = vec![acct(1, 1)];
        let mut oracle =
            FlatMpt::create(format!("{path}.oracle"), mpt_flat_poc::Config::default()).unwrap();
        let (checkpoint_root, _) = oracle.apply_block(genesis.clone()).unwrap();
        let header_root = B256::from([9u8; 32]);

        let mut shadow = FlatShadow::init(path, genesis, B256::from(checkpoint_root)).unwrap();
        shadow.checkpoint_parent = Some(header_root);

        assert!(shadow.at_parent(header_root));
        shadow.unwind_to(header_root).unwrap();
        assert_eq!(shadow.current_root(), B256::from(checkpoint_root));
    }

    #[test]
    fn prefetch_is_advisory_and_root_neutral() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.flat");
        let path = path.to_str().unwrap();

        let genesis = vec![acct(1, 1), acct(10, 1), acct(11, 1)];
        let mut oracle =
            FlatMpt::create(format!("{path}.oracle"), mpt_flat_poc::Config::default()).unwrap();
        let (genesis_root, _) = oracle.apply_block(genesis.clone()).unwrap();
        let g = B256::from(genesis_root);

        let mut s = FlatShadow::init(path, genesis, g).unwrap();

        // Prefetch warms the read-ahead buffer; the apply consumes it and the
        // root matches a never-prefetched oracle apply of the same ops.
        let block = vec![acct(2, 1), acct(3, 1)];
        s.prefetch(&block).unwrap();
        let r1 = s.root_for(0, g, block.clone()).unwrap();
        let (oracle_root, _) = oracle.apply_block(block.clone()).unwrap();
        assert_eq!(r1.0, oracle_root);

        // A prefetch pass that is never consumed (abandoned build) must not
        // disturb subsequent applies.
        s.prefetch(&[acct(7, 9)]).unwrap();
        let r1b = s.root_for(0, g, block).unwrap();
        assert_eq!(r1, r1b, "memo hit unaffected by stale prefetch");
        let r2 = s.root_for(1, r1, vec![acct(4, 2)]).unwrap();
        assert_ne!(r1, r2);
    }

    /// The builder hands `ops_to_post_state(bundle_to_ops(bundle))` to the
    /// engine as the block's hashed state (persisted to the hashed tables and
    /// served from the in-memory overlay), so it must agree with reth's own
    /// bundle derivation on every op shape: create, update, EOA vs contract,
    /// selfdestruct, destroy-then-recreate, touched-and-cleared (EIP-158),
    /// slot set / clear.
    #[test]
    fn ops_hashed_state_matches_reth_bundle_derivation() {
        use alloy_primitives::{Address, KECCAK256_EMPTY};
        use revm::{
            database::{AccountStatus, BundleAccount, states::bundle_state::BundleState},
            state::AccountInfo,
        };

        let addr = |b: u8| Address::from([b; 20]);
        let info = |nonce: u64, code: Option<B256>| AccountInfo {
            nonce,
            balance: U256::from(1000 + nonce),
            code_hash: code.unwrap_or(KECCAK256_EMPTY),
            ..Default::default()
        };
        let slot = |k: u64, orig: u64, present: u64| {
            (
                U256::from(k),
                revm::database::states::StorageSlot::new_changed(
                    U256::from(orig),
                    U256::from(present),
                ),
            )
        };

        let mut state: alloy_primitives::map::AddressMap<BundleAccount> = Default::default();
        // Plain EOA update.
        state.insert(
            addr(1),
            BundleAccount::new(
                None,
                Some(info(7, None)),
                Default::default(),
                AccountStatus::Changed,
            ),
        );
        // Contract with slot writes and a slot cleared to zero.
        state.insert(
            addr(2),
            BundleAccount::new(
                Some(info(1, Some(B256::repeat_byte(0xcc)))),
                Some(info(2, Some(B256::repeat_byte(0xcc)))),
                [slot(1, 0, 42), slot(2, 9, 0), slot(3, 0, 5)]
                    .into_iter()
                    .collect(),
                AccountStatus::Changed,
            ),
        );
        // Selfdestructed.
        state.insert(
            addr(3),
            BundleAccount::new(
                Some(info(3, None)),
                None,
                Default::default(),
                AccountStatus::Destroyed,
            ),
        );
        // Destroyed then recreated with fresh storage.
        state.insert(
            addr(4),
            BundleAccount::new(
                Some(info(4, Some(B256::repeat_byte(0xdd)))),
                Some(info(1, Some(B256::repeat_byte(0xdd)))),
                [slot(7, 0, 11)].into_iter().collect(),
                AccountStatus::DestroyedChanged,
            ),
        );
        // Touched and cleared (EIP-158): present info None, not destroyed.
        state.insert(
            addr(5),
            BundleAccount::new(
                Some(info(0, None)),
                None,
                Default::default(),
                AccountStatus::LoadedNotExisting,
            ),
        );
        let bundle = BundleState {
            state,
            ..Default::default()
        };

        let ops = bundle_to_ops(&bundle);
        let ours = ops_to_post_state(&ops);
        let reths = reth_trie::HashedPostState::from_bundle_state::<reth_trie::KeccakKeyHasher>(
            &bundle.state,
        );

        // Account maps must agree exactly (reth normalizes the empty code
        // hash to None; ops_to_post_state mirrors that).
        assert_eq!(ours.accounts, reths.accounts, "account maps diverge");

        // Storage: compare effective semantics per account touched by either
        // side — wiped flag for live accounts, and every slot's effective
        // value (wiped + absent ⇒ zero).
        let all: std::collections::BTreeSet<B256> = ours
            .storages
            .keys()
            .chain(reths.storages.keys())
            .copied()
            .collect();
        for acct in all {
            let o = ours.storages.get(&acct);
            let r = reths.storages.get(&acct);
            let deleted = matches!(ours.accounts.get(&acct), Some(None));
            if !deleted {
                assert_eq!(
                    o.map(|s| s.wiped).unwrap_or(false),
                    r.map(|s| s.wiped).unwrap_or(false),
                    "wiped flag diverges for live account {acct}"
                );
            }
            let keys: std::collections::BTreeSet<B256> = o
                .map(|s| s.storage.keys().copied().collect::<Vec<_>>())
                .unwrap_or_default()
                .into_iter()
                .chain(
                    r.map(|s| s.storage.keys().copied().collect::<Vec<_>>())
                        .unwrap_or_default(),
                )
                .collect();
            for k in keys {
                let ov = o
                    .and_then(|s| s.storage.get(&k).copied())
                    .unwrap_or_default();
                let rv = r
                    .and_then(|s| s.storage.get(&k).copied())
                    .unwrap_or_default();
                assert_eq!(ov, rv, "slot {k} of {acct} diverges");
            }
        }
    }
}
