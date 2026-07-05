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

mod stream;
pub use stream::{stream_check, stream_enabled, FlatStream};

use alloy_primitives::{keccak256, B256, U256};
use mpt_flat_poc::{hex, FlatMpt, Key, StateOp};
use parking_lot::Mutex;
use std::io::Write as _;
use std::sync::OnceLock;
use std::time::Instant;

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
    /// The applied ops, key-stable-sorted (memo fingerprint).
    ops: Vec<(Key, StateOp)>,
    /// Inverse diffs to roll this entry back: one per applied chunk, in apply
    /// order (a non-streamed block has exactly one).
    inverse: Vec<Vec<(Key, StateOp)>>,
}

pub struct FlatShadow {
    db: FlatMpt,
    entries: Vec<Entry>,
    timings: std::io::BufWriter<std::fs::File>,
    blocks_since_persist: u64,
    /// A streamed block application is in progress (chunks applied, no entry yet).
    in_flight: bool,
}

/// Retained rollback window (candidate rebuilds and reorgs deeper than this fail loudly).
const WINDOW: usize = 128;
/// Persist the flat file every this many applied blocks.
const PERSIST_EVERY: u64 = 128;

impl FlatShadow {
    /// Create a fresh shadow at `path` (existing files wiped) holding exactly
    /// the genesis state, verified against `genesis_root`.
    fn init(path: &str, genesis_ops: Vec<(Key, StateOp)>, genesis_root: B256) -> anyhow::Result<Self> {
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
        Ok(Self { db, entries: Vec::new(), timings, blocks_since_persist: 0, in_flight: false })
    }

    /// Bloat-mode init: genesis alloc + state-bloat dump, with a golden
    /// checkpoint cache keyed on the dump's size+mtime.
    fn init_with_bloat(path: &str, genesis_ops: Vec<(Key, StateOp)>, dump: &str) -> anyhow::Result<Self> {
        let meta = std::fs::metadata(dump)?;
        let marker = format!("{} {}", meta.len(), meta.modified()?.duration_since(std::time::UNIX_EPOCH)?.as_secs());
        let golden_ok = std::fs::read_to_string(format!("{path}.golden.marker"))
            .is_ok_and(|m| m.trim() == marker);

        for suffix in ["", ".meta", ".meta.prev", ".timings"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
        if golden_ok {
            std::fs::copy(format!("{path}.golden"), path)?;
            std::fs::copy(format!("{path}.golden.meta"), format!("{path}.meta"))?;
            let db = FlatMpt::open(path).map_err(|e| anyhow::anyhow!("{e:#}"))?;
            let timings = std::io::BufWriter::new(
                std::fs::OpenOptions::new().create(true).append(true).open(format!("{path}.timings"))?,
            );
            tracing::info!(target: "flatmpt", root = %hex(db.root()), path, "flat MPT restored from golden bloat checkpoint");
            return Ok(Self { db, entries: Vec::new(), timings, blocks_since_persist: 0, in_flight: false });
        }

        let mut db = FlatMpt::create(path, mpt_flat_poc::Config::default())
            .map_err(|e| anyhow::anyhow!("{e:#}"))?;
        let n_alloc = genesis_ops.len();
        db.apply_block(genesis_ops).map_err(|e| anyhow::anyhow!("genesis apply: {e:#}"))?;
        let t = std::time::Instant::now();
        let dump_ops = bloat_dump_to_ops(dump)?;
        let n_dump = dump_ops.len();
        // Chunked so peak memory stays bounded and progress is visible.
        for chunk in dump_ops.chunks(1 << 20) {
            db.apply_block(chunk.to_vec()).map_err(|e| anyhow::anyhow!("bloat apply: {e:#}"))?;
        }
        db.persist().map_err(|e| anyhow::anyhow!("{e:#}"))?;
        tracing::info!(
            target: "flatmpt",
            root = %hex(db.root()), n_alloc, n_dump,
            elapsed_s = t.elapsed().as_secs(), path,
            "flat MPT initialized from genesis alloc + bloat dump"
        );
        std::fs::copy(path, format!("{path}.golden"))?;
        std::fs::copy(format!("{path}.meta"), format!("{path}.golden.meta"))?;
        std::fs::write(format!("{path}.golden.marker"), marker)?;
        let timings = std::io::BufWriter::new(
            std::fs::OpenOptions::new().create(true).append(true).open(format!("{path}.timings"))?,
        );
        Ok(Self { db, entries: Vec::new(), timings, blocks_since_persist: 0, in_flight: false })
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
        if let Some(e) = self
            .entries
            .iter()
            .rev()
            .find(|e| e.number == parent_number + 1 && e.parent_root == parent_root.0)
        {
            if e.ops == ops {
                return Ok(B256::from(e.root));
            }
            // Same parent, different payload: a rebuilt candidate. Fall through —
            // the rollback loop below unwinds to the shared parent state.
        }

        anyhow::ensure!(
            !self.in_flight,
            "root_for while a streamed block is in flight (parent {parent_number})"
        );

        self.unwind_to(parent_root)?;

        let n_ops = ops.len();
        let t = Instant::now();
        let (root, inverse) = self
            .db
            .apply_block(ops.clone())
            .map_err(|e| anyhow::anyhow!("apply: {e:#}"))?;
        let apply_us = t.elapsed().as_micros() as u64;
        debug_assert_eq!(root, self.db.root());

        self.commit_entry(parent_number, parent_root, ops, vec![inverse], n_ops, 0, apply_us)
    }

    /// Roll the live state back until its root equals `parent_root`.
    fn unwind_to(&mut self, parent_root: B256) -> anyhow::Result<()> {
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
        ops: Vec<(Key, StateOp)>,
        inverse: Vec<Vec<(Key, StateOp)>>,
        n_ops: usize,
        chunks: usize,
        apply_us: u64,
    ) -> anyhow::Result<B256> {
        let root = self.db.root();
        let number = parent_number + 1;
        serde_json::to_writer(
            &mut self.timings,
            &serde_json::json!({
                "block": number, "n_ops": n_ops, "apply_us": apply_us, "chunks": chunks,
            }),
        )?;
        self.timings.write_all(b"\n")?;
        self.timings.flush()?;

        self.entries.push(Entry { number, parent_root: parent_root.0, root, ops, inverse });
        if self.entries.len() > WINDOW {
            self.entries.remove(0);
        }

        self.blocks_since_persist += 1;
        if self.blocks_since_persist >= PERSIST_EVERY {
            self.db.persist().map_err(|e| anyhow::anyhow!("persist: {e:#}"))?;
            self.blocks_since_persist = 0;
        }

        tracing::debug!(target: "flatmpt", block = number, n_ops, chunks, apply_us, root = %hex(root), "flat root");
        Ok(B256::from(root))
    }

    /// Start a streamed application on top of `parent_root` (unwinding a
    /// previous candidate for the same height first).
    pub(crate) fn begin_stream(&mut self, parent_number: u64, parent_root: B256) -> anyhow::Result<()> {
        anyhow::ensure!(!self.in_flight, "another streamed block is already in flight");
        // A repeat/candidate build for an already-applied height memo-hits in
        // root_for but must physically unwind here, since we are about to apply.
        let _ = parent_number;
        self.unwind_to(parent_root)?;
        self.in_flight = true;
        Ok(())
    }

    /// Apply one streamed chunk; returns its inverse.
    pub(crate) fn apply_stream_chunk(
        &mut self,
        ops: Vec<(Key, StateOp)>,
    ) -> anyhow::Result<Vec<(Key, StateOp)>> {
        anyhow::ensure!(self.in_flight, "stream chunk without begin_stream");
        let (_root, inverse) = self
            .db
            .apply_block(ops)
            .map_err(|e| anyhow::anyhow!("stream chunk apply: {e:#}"))?;
        Ok(inverse)
    }

    /// Finalize a streamed block: optionally cross-check against the canonical
    /// op list, then commit the entry (fingerprinted by `canonical_ops`, which
    /// is what the validator will present).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_stream(
        &mut self,
        parent_number: u64,
        parent_root: B256,
        mut canonical_ops: Vec<(Key, StateOp)>,
        inverses: Vec<Vec<(Key, StateOp)>>,
        streamed_ops: usize,
        chunks: usize,
        chunk_apply_us: u64,
    ) -> anyhow::Result<B256> {
        anyhow::ensure!(self.in_flight, "finish_stream without begin_stream");
        self.in_flight = false;
        canonical_ops.sort_by(|a, b| a.0.cmp(&b.0));

        if stream_check() {
            // Re-derive the root from the canonical ops and require equality —
            // catches any divergence between streamed EvmState mapping and
            // bundle semantics. Debug tool: doubles the apply cost.
            let streamed_root = self.db.root();
            for inv in inverses.iter().rev() {
                self.db
                    .apply_block(inv.clone())
                    .map_err(|e| anyhow::anyhow!("stream-check rollback: {e:#}"))?;
            }
            let (canon_root, canon_inverse) = self
                .db
                .apply_block(canonical_ops.clone())
                .map_err(|e| anyhow::anyhow!("stream-check apply: {e:#}"))?;
            assert_eq!(
                hex(canon_root),
                hex(streamed_root),
                "STREAMED ROOT DIVERGES FROM CANONICAL at block {}",
                parent_number + 1
            );
            return self.commit_entry(
                parent_number,
                parent_root,
                canonical_ops,
                vec![canon_inverse],
                streamed_ops,
                chunks,
                chunk_apply_us,
            );
        }

        self.commit_entry(
            parent_number,
            parent_root,
            canonical_ops,
            inverses,
            streamed_ops,
            chunks,
            chunk_apply_us,
        )
    }

    /// Abort an in-flight stream, rolling back all applied chunks.
    pub(crate) fn abort_stream(&mut self, inverses: Vec<Vec<(Key, StateOp)>>) -> anyhow::Result<()> {
        self.in_flight = false;
        for inv in inverses.into_iter().rev() {
            self.db
                .apply_block(inv)
                .map_err(|e| anyhow::anyhow!("stream abort rollback: {e:#}"))?;
        }
        Ok(())
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
pub fn shadow(
    genesis: impl FnOnce() -> (Vec<(Key, StateOp)>, B256),
) -> Option<&'static Mutex<FlatShadow>> {
    static SHADOW: OnceLock<Option<Mutex<FlatShadow>>> = OnceLock::new();
    SHADOW
        .get_or_init(|| {
            if mode() == FlatMode::Off {
                return None;
            }
            let path = std::env::var("TEMPO_FLATMPT").expect("TEMPO_FLATMPT checked by mode()");
            let bloat = std::env::var("TEMPO_FLATMPT_BLOAT").ok();
            let (ops, root) = genesis();
            let shadow = match bloat {
                None => FlatShadow::init(&path, ops, root),
                Some(dump) => FlatShadow::init_with_bloat(&path, ops, &dump),
            };
            Some(Mutex::new(shadow.expect("flat MPT genesis init failed")))
        })
        .as_ref()
}

/// Parse a `TEMPOSB` state-bloat dump into storage ops (keccak-hashed keys).
fn bloat_dump_to_ops(dump: &str) -> anyhow::Result<Vec<(Key, StateOp)>> {
    use std::io::Read as _;
    let mut f = std::io::BufReader::with_capacity(64 << 20, std::fs::File::open(dump)?);
    let mut ops: Vec<(Key, StateOp)> = Vec::new();
    let mut header = [0u8; 40];
    loop {
        match f.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        anyhow::ensure!(&header[0..8] == b"TEMPOSB\0", "bad bloat magic");
        anyhow::ensure!(u16::from_be_bytes([header[8], header[9]]) == 1, "bad bloat version");
        let address = &header[12..32];
        let key: Key = keccak256(address).0;
        let pair_count = u64::from_be_bytes(header[32..40].try_into().unwrap());
        let mut pair = [0u8; 64];
        for _ in 0..pair_count {
            f.read_exact(&mut pair)?;
            let slot_key: Key = keccak256(&pair[0..32]).0;
            let value = U256::from_be_slice(&pair[32..64]);
            if value == U256::ZERO {
                continue;
            }
            ops.push((
                key,
                StateOp::SetStorage {
                    slot: slot_key,
                    value: mpt_flat_poc::eth::storage_value_rlp(value),
                },
            ));
        }
    }
    Ok(ops)
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
    let mut ops: Vec<(Key, StateOp)> = Vec::new();
    for (address, acct) in &bundle.state {
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
        let mut db = FlatMpt::create(format!("{path}.oracle"), mpt_flat_poc::Config::default()).unwrap();
        let (genesis_root, _) = db.apply_block(genesis.clone()).unwrap();

        let mut s = FlatShadow::init(path, genesis, B256::from(genesis_root)).unwrap();

        // Block 1 on genesis.
        let r1 = s.root_for(0, B256::from(genesis_root), vec![acct(2, 1)]).unwrap();
        // Validator replay: memo hit, same root, state still at block 1.
        let r1b = s.root_for(0, B256::from(genesis_root), vec![acct(2, 1)]).unwrap();
        assert_eq!(r1, r1b);

        // Block 2 on block 1.
        let r2 = s.root_for(1, r1, vec![acct(3, 1)]).unwrap();
        assert_ne!(r1, r2);

        // Rebuilt candidate for block 2 (same parent, different payload): rollback + apply.
        let r2alt = s.root_for(1, r1, vec![acct(4, 7)]).unwrap();
        assert_ne!(r2, r2alt);

        // Deep re-parent back to genesis.
        let r1c = s.root_for(0, B256::from(genesis_root), vec![acct(2, 1)]).unwrap();
        assert_eq!(r1, r1c);

        // Unknown parent fails loudly.
        assert!(s.root_for(5, B256::from([9u8; 32]), vec![acct(5, 1)]).is_err());
    }

    #[test]
    fn stream_lifecycle_chunked_inverses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.flat");
        let path = path.to_str().unwrap();

        // Keep >=2 keys live at every point: the engine does not support
        // collapsing the trie below two keys (never happens on a real chain).
        let genesis = vec![acct(1, 1), acct(10, 1), acct(11, 1)];
        let mut oracle =
            FlatMpt::create(format!("{path}.oracle"), mpt_flat_poc::Config::default()).unwrap();
        let (genesis_root, _) = oracle.apply_block(genesis.clone()).unwrap();
        let g = B256::from(genesis_root);

        let mut s = FlatShadow::init(path, genesis, g).unwrap();

        // Streamed block 1 in two chunks == one-shot apply of both.
        let (oneshot_root, _) = oracle
            .apply_block(vec![acct(2, 1), acct(3, 1)])
            .unwrap();
        s.begin_stream(0, g).unwrap();
        let i1 = s.apply_stream_chunk(vec![acct(2, 1)]).unwrap();
        let i2 = s.apply_stream_chunk(vec![acct(3, 1)]).unwrap();
        let r1 = s
            .finish_stream(0, g, vec![acct(2, 1), acct(3, 1)], vec![i1, i2], 2, 2, 0)
            .unwrap();
        assert_eq!(r1.0, oneshot_root);

        // Validator replay with canonical ops memo-hits the streamed entry.
        let r1b = s.root_for(0, g, vec![acct(2, 1), acct(3, 1)]).unwrap();
        assert_eq!(r1, r1b);

        // Candidate rebuild on the same parent: chunked entry unwinds cleanly.
        let r1alt = s.root_for(0, g, vec![acct(7, 9)]).unwrap();
        assert_ne!(r1, r1alt);

        // Aborted stream rolls its chunks back.
        s.begin_stream(0, g).unwrap();
        let j1 = s.apply_stream_chunk(vec![acct(8, 1)]).unwrap();
        s.abort_stream(vec![j1]).unwrap();
        assert_eq!(s.db.root(), genesis_root);
    }
}
