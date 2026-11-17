//! Out-of-state expiring nonce set and its commitment.
//!
//! Replay hashes are grouped into buckets by the transaction's `valid_before` second. Each bucket
//! is a Merkle Patricia Trie keyed by replay hash, and the set root is a Merkle Patricia Trie keyed
//! by `valid_before` (as a big-endian 32-byte word) whose values are the RLP-encoded bucket roots.
//!
//! A replay hash commits to its transaction's `valid_before`, so a replay always lands in the
//! bucket of the original, and a whole bucket expires at once when the block timestamp reaches its
//! second instead of evicting entries one by one.
//!
//! Before T16 the set runs in shadow mode next to the `NonceManager` ring: the ring stays
//! authoritative, and every block's expiring nonce transactions are checked against and inserted
//! into the set, so the two can be compared. From T16 (TIP-1173) the set is authoritative: the
//! block executor rejects replays against it, the ring is no longer written, and the set root is
//! committed in the block header's `expiring_nonce_root`.
//!
//! The set starts empty at the first T16 block, so its root is verifiable from headers alone.
//! Entries recorded before T16 stay in the frozen `expiringNonceSeen` map, which the handler still
//! reads during the first `MAX_EXPIRY_SECS` after activation (see [`in_activation_window`]).
//!
//! [`PartialExpiringNonceSet`] verifies a block's set transition statelessly from a pool of trie nodes, for the
//! zone prover.

mod witness;
pub use witness::{BlockParams, PartialExpiringNonceSet, WitnessError, WitnessTrie};

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use alloy_consensus::transaction::TxHashRef;
use alloy_primitives::{Address, B256, Keccak256, U256, map::B256Map};
use parking_lot::Mutex;
use reth_evm::{BlockExecutionError, BlockValidationError};
use reth_trie_common::{EMPTY_ROOT_HASH, HashBuilder, Nibbles};
use reth_trie_sparse::{
    ArenaParallelSparseTrie, LeafUpdate, SparseTrie, TrieNodeEpoch, errors::SparseTrieError,
};
use schnellru::{ByLength, LruMap};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoTxEnvelope;
use tracing::{debug, error, trace};

/// Number of block snapshots kept. Covers the unfinalized branches a node executes on top of.
const SNAPSHOT_CAPACITY: u32 = 16;

/// Number of built payloads whose sets wait for assembly.
const STAGED_CAPACITY: u32 = 16;

/// Number of assembled payloads whose sets are kept by hash. Kept apart from block snapshots:
/// a node assembles far more payloads than it executes blocks (RPC pending blocks rebuild
/// continuously), and they must not evict the sets of the chain it builds on.
const BUILT_CAPACITY: u32 = 16;

/// RLP value stored for every replay hash: trie leaves cannot be empty.
const PRESENT: [u8; 1] = [0x01];

/// Replay-protection entry of one expiring nonce transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExpiringNonce {
    /// Replay hash, as the handler computes it for the active fork.
    pub hash: B256,
    /// The transaction's `valid_before`, which selects its bucket.
    pub valid_before: u64,
}

impl ExpiringNonce {
    /// Returns the entry of `tx` signed by `sender` under `spec`, or `None` when `tx` doesn't
    /// use expiring nonce replay protection.
    ///
    /// Matches the handler: expiring nonces start at T1, and T1B switches the replay hash from the
    /// transaction hash to the sender-scoped transaction identifier.
    pub fn from_tx(tx: &TempoTxEnvelope, sender: Address, spec: TempoHardfork) -> Option<Self> {
        if !spec.is_t1() {
            return None;
        }
        let aa = tx.as_aa().filter(|aa| aa.tx().is_expiring_nonce_tx())?;
        // The handler rejects expiring nonce transactions without `valid_before`.
        let valid_before = aa.tx().valid_before?.get();
        let hash = if spec.is_t1b() {
            tx.unique_tx_identifier(sender)
        } else {
            *tx.tx_hash()
        };
        Some(Self { hash, valid_before })
    }
}

/// Errors from updating an [`ExpiringNonceSet`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A bucket trie asked for a proof. Buckets are built from empty and always fully revealed,
    /// so this is an invariant violation.
    #[error("expiring nonce bucket {valid_before} is not fully revealed")]
    BlindedBucket {
        /// The bucket's `valid_before` second.
        valid_before: u64,
    },
    /// The bucket trie rejected an update.
    #[error("expiring nonce bucket trie update failed")]
    Trie(#[from] SparseTrieError),
}

/// The set of unexpired replay hashes at one block, with its root.
///
/// Cloning is cheap: buckets are shared and copied on write.
#[derive(Debug, Clone)]
pub struct ExpiringNonceSet {
    buckets: BTreeMap<u64, Arc<Bucket>>,
    root: B256,
    /// Whether the set was derived under T16 rules. A pre-T16 (shadow) set is not the parent set
    /// of the first T16 block, which starts empty.
    authoritative: bool,
}

impl Default for ExpiringNonceSet {
    fn default() -> Self {
        Self {
            buckets: BTreeMap::new(),
            root: EMPTY_ROOT_HASH,
            authoritative: false,
        }
    }
}

impl ExpiringNonceSet {
    /// Returns the set's root.
    pub const fn root(&self) -> B256 {
        self.root
    }

    /// Returns whether the set was derived under T16 rules.
    pub const fn is_authoritative(&self) -> bool {
        self.authoritative
    }

    /// Marks the set as derived under T16 rules, or not.
    pub fn set_authoritative(&mut self, authoritative: bool) {
        self.authoritative = authoritative;
    }

    /// Returns whether `entry` is in the set.
    pub fn contains(&self, entry: &ExpiringNonce) -> bool {
        self.buckets.get(&entry.valid_before).is_some_and(|bucket| {
            bucket
                .trie
                .get_leaf_value(&Nibbles::unpack(entry.hash))
                .is_some()
        })
    }

    /// Drops every bucket with `valid_before <= timestamp` and recomputes the root.
    pub fn expire(&mut self, timestamp: u64) {
        self.buckets = match timestamp.checked_add(1) {
            Some(first_live) => self.buckets.split_off(&first_live),
            None => BTreeMap::new(),
        };
        self.root = root_of(
            self.buckets
                .iter()
                .map(|(valid_before, bucket)| (*valid_before, bucket.root)),
        );
    }

    /// Returns the number of live entries in the set.
    pub fn len(&self) -> usize {
        self.buckets.values().map(|bucket| bucket.len).sum()
    }

    /// Returns whether the set holds no entries.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Returns the number of non-empty buckets.
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Advances the set to a block at `timestamp` containing `entries`.
    ///
    /// Drops every bucket with `valid_before <= timestamp`, inserts `entries`, and recomputes the
    /// root. Returns the entries that were already in the set: replays the set would have rejected.
    pub fn apply(
        &mut self,
        timestamp: u64,
        entries: &[ExpiringNonce],
    ) -> Result<Vec<ExpiringNonce>, Error> {
        self.apply_inner(timestamp, entries, true)
    }

    /// Like [`Self::apply`] for entries already checked against this set, as the block executor
    /// does before each transaction: skips the per-entry lookups in the existing buckets.
    fn apply_checked(&mut self, timestamp: u64, entries: &[ExpiringNonce]) -> Result<(), Error> {
        self.apply_inner(timestamp, entries, false).map(|_| ())
    }

    fn apply_inner(
        &mut self,
        timestamp: u64,
        entries: &[ExpiringNonce],
        check_replays: bool,
    ) -> Result<Vec<ExpiringNonce>, Error> {
        self.buckets = match timestamp.checked_add(1) {
            Some(first_live) => self.buckets.split_off(&first_live),
            None => BTreeMap::new(),
        };

        let mut replays = Vec::new();
        let mut updates = BTreeMap::<u64, B256Map<LeafUpdate>>::new();
        for entry in entries {
            let pending = updates.entry(entry.valid_before).or_default();
            if (check_replays && self.contains(entry)) || pending.contains_key(&entry.hash) {
                replays.push(*entry);
                continue;
            }
            pending.insert(entry.hash, LeafUpdate::Changed(PRESENT.to_vec()));
        }

        for (valid_before, mut leaves) in updates {
            if leaves.is_empty() {
                continue;
            }
            let bucket = Arc::make_mut(self.buckets.entry(valid_before).or_default());
            bucket.len += leaves.len();
            bucket.keys.push(leaves.keys().copied().collect());
            let mut blinded = false;
            bucket
                .trie
                .update_leaves(&mut leaves, |_, _| blinded = true)?;
            if blinded || !leaves.is_empty() {
                return Err(Error::BlindedBucket { valid_before });
            }
            bucket.root = bucket.trie.root(TrieNodeEpoch::UNMODIFIED);
        }

        self.root = root_of(
            self.buckets
                .iter()
                .map(|(valid_before, bucket)| (*valid_before, bucket.root)),
        );
        Ok(replays)
    }
}

/// Expiring nonce set snapshots by block hash, shared by block execution, payload assembly and the
/// node task that follows the canonical chain.
#[derive(Debug, Clone)]
pub struct ExpiringNonceSets {
    inner: Arc<Mutex<Snapshots>>,
}

impl Default for ExpiringNonceSets {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Snapshots {
                by_block: LruMap::new(ByLength::new(SNAPSHOT_CAPACITY)),
                built: LruMap::new(ByLength::new(BUILT_CAPACITY)),
                staged: LruMap::new(ByLength::new(STAGED_CAPACITY)),
            })),
        }
    }
}

impl ExpiringNonceSets {
    /// Returns whether the set at `block_hash` is known.
    pub fn contains(&self, block_hash: B256) -> bool {
        let inner = self.inner.lock();
        inner.by_block.peek(&block_hash).is_some() || inner.built.peek(&block_hash).is_some()
    }

    /// Stores `set` as the set at `block_hash`.
    pub fn insert(&self, block_hash: B256, set: ExpiringNonceSet) {
        self.inner.lock().by_block.insert(block_hash, set);
    }

    /// Derives the set of a block at `timestamp` containing `entries` from the set at
    /// `parent_hash`, without storing it.
    ///
    /// Logs every entry the set already held, since the authoritative ring accepted it. Returns
    /// `None` when the parent's set is unknown or the update fails.
    pub fn derive(
        &self,
        parent_hash: B256,
        timestamp: u64,
        entries: &[ExpiringNonce],
    ) -> Option<ExpiringNonceSet> {
        self.derive_with(parent_hash, timestamp, entries, false)
    }

    /// Like [`Self::derive`], under T16 rules when `authoritative`: a pre-T16 parent set is
    /// replaced by an empty set, since the first T16 block starts from empty, and the result is
    /// marked authoritative.
    pub fn derive_with(
        &self,
        parent_hash: B256,
        timestamp: u64,
        entries: &[ExpiringNonce],
        authoritative: bool,
    ) -> Option<ExpiringNonceSet> {
        let Some(mut set) = self.inner.lock().lookup(parent_hash) else {
            debug!(target: "evm::expiring_nonces", %parent_hash, "Parent expiring nonce set unknown");
            return None;
        };
        if authoritative && !set.is_authoritative() {
            set = ExpiringNonceSet::default();
        }
        set.set_authoritative(authoritative);
        let replays = match set.apply(timestamp, entries) {
            Ok(replays) => replays,
            Err(err) => {
                error!(target: "evm::expiring_nonces", %parent_hash, %err, "Failed to update expiring nonce set");
                return None;
            }
        };
        if !replays.is_empty() {
            metrics::counter!("tempo_expiring_nonce_set_divergences_total")
                .increment(replays.len() as u64);
        }
        for replay in replays {
            error!(
                target: "evm::expiring_nonces",
                %parent_hash,
                hash = %replay.hash,
                valid_before = replay.valid_before,
                "Expiring nonce set diverges from the ring: the ring accepted a hash the set holds"
            );
        }
        debug!(target: "evm::expiring_nonces", %parent_hash, root = %set.root(), entries = entries.len(), "Derived expiring nonce set");
        Some(set)
    }

    /// Returns the set at `block_hash`, if known.
    pub fn get(&self, block_hash: B256) -> Option<ExpiringNonceSet> {
        self.inner.lock().lookup(block_hash)
    }

    /// Returns the root of the set staged under `key`, if any.
    pub fn staged_root(&self, key: B256) -> Option<B256> {
        self.inner
            .lock()
            .staged
            .peek(&key)
            .map(ExpiringNonceSet::root)
    }

    /// Stages the set of a payload that is not assembled yet under `key` (see [`staged_key`]).
    pub fn stage(&self, key: B256, set: ExpiringNonceSet) {
        self.inner.lock().staged.insert(key, set);
    }

    /// Stores the set staged under `key` as the set of the assembled payload `block_hash`.
    /// Returns `false` when nothing is staged under `key`.
    pub fn promote(&self, key: B256, block_hash: impl FnOnce() -> B256) -> bool {
        let mut inner = self.inner.lock();
        let Some(set) = inner.staged.remove(&key) else {
            return false;
        };
        inner.built.insert(block_hash(), set);
        true
    }
}

/// Returns the key a payload's set is staged under: the set depends only on the parent's set,
/// the block timestamp and the payload's expiring nonce transactions, in order.
pub fn staged_key(parent_hash: B256, timestamp: u64, tx_hashes: &[B256]) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(parent_hash);
    hasher.update(timestamp.to_be_bytes());
    for tx_hash in tx_hashes {
        hasher.update(tx_hash);
    }
    hasher.finalize()
}

#[derive(Debug)]
struct Snapshots {
    by_block: LruMap<B256, ExpiringNonceSet, ByLength>,
    /// Sets of assembled payloads; one moves to `by_block` once something builds on it.
    built: LruMap<B256, ExpiringNonceSet, ByLength>,
    staged: LruMap<B256, ExpiringNonceSet, ByLength>,
}

impl Snapshots {
    /// Returns the set at `block_hash`, moving an assembled payload's set into the block
    /// snapshots on first use.
    fn lookup(&mut self, block_hash: B256) -> Option<ExpiringNonceSet> {
        if let Some(set) = self.by_block.get(&block_hash) {
            return Some(set.clone());
        }
        let set = self.built.remove(&block_hash)?;
        self.by_block.insert(block_hash, set.clone());
        Some(set)
    }
}

/// One `valid_before` second's replay hashes.
#[derive(Debug, Clone)]
struct Bucket {
    trie: ArenaParallelSparseTrie,
    root: B256,
    len: usize,
    /// The bucket's replay hashes, to build witness proofs from.
    keys: Vec<Arc<[B256]>>,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            trie: ArenaParallelSparseTrie::default(),
            root: EMPTY_ROOT_HASH,
            len: 0,
            keys: Vec::new(),
        }
    }
}

/// Returns the set-trie key of bucket `valid_before`: the 32-byte big-endian word, which keeps
/// ascending `valid_before` in ascending path order.
pub fn bucket_key(valid_before: u64) -> B256 {
    B256::from(U256::from(valid_before))
}

/// Returns whether a T16 block at `timestamp` still reads the frozen pre-T16 `expiringNonceSeen`
/// map: entries recorded before T16 activation at `activation` can be live until
/// `activation + max_expiry_secs`.
pub fn in_activation_window(activation: u64, timestamp: u64, max_expiry_secs: u64) -> bool {
    timestamp < activation.saturating_add(max_expiry_secs)
}

/// Returns whether a block at `timestamp` with `spec` is a T16 block in the activation window of
/// `chain_spec`'s T16 schedule.
pub fn t16_activation_window(
    chain_spec: &impl tempo_chainspec::spec::TempoHardforks,
    timestamp: u64,
    spec: TempoHardfork,
) -> bool {
    if !spec.is_t16() {
        return false;
    }
    match chain_spec.tempo_fork_activation(TempoHardfork::T16) {
        reth_chainspec::ForkCondition::Timestamp(activation) => {
            in_activation_window(activation, timestamp, spec.expiring_nonce_max_expiry_secs())
        }
        // Not scheduled by timestamp: active from genesis, so nothing predates it.
        _ => false,
    }
}

/// Returns the Nonce precompile slot of `expiringNonceSeen[hash]`, which holds the entry's
/// `valid_before` when the pre-T16 ring recorded it.
pub fn frozen_seen_slot(hash: B256) -> U256 {
    tempo_precompiles::nonce::NonceManager::new().expiring_nonce_seen[hash].slot()
}

/// T16+ (TIP-1173): a transaction rejected because its expiring nonce entry is already in the set.
///
/// Wraps the [`evm2::registry::HandlerError`] so
/// [`crate::TempoInvalidTransaction::from_invalid_tx_error`] recovers
/// [`crate::TempoInvalidTransaction::ExpiringNonceReplay`] like any handler rejection.
#[derive(Debug)]
pub struct ExpiringNonceReplayError(evm2::registry::HandlerError);

impl ExpiringNonceReplayError {
    /// Returns the block error rejecting transaction `tx_hash` as a replay.
    pub fn block_error(tx_hash: B256) -> BlockExecutionError {
        BlockValidationError::InvalidTx {
            hash: tx_hash,
            error: Box::new(Self(evm2::registry::HandlerError::from(
                crate::TempoInvalidTransaction::ExpiringNonceReplay,
            ))),
        }
        .into()
    }
}

impl core::fmt::Display for ExpiringNonceReplayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for ExpiringNonceReplayError {}

impl reth_evm::InvalidTxError for ExpiringNonceReplayError {
    fn as_any(&self) -> &(dyn core::any::Any + 'static) {
        &self.0
    }
}

/// One block's expiring nonce bookkeeping, shared by the L1 and zone block executors.
///
/// Before T16 it records entries and derives the shadow set at the end of the block. From T16 it
/// rejects replays against the parent's set and the block's own entries before each transaction
/// executes, then derives the set, checks a sealed block's header root and stores the set (or
/// stages a payload's set until it is assembled).
#[derive(Debug)]
pub struct BlockExpiringNonces {
    /// `None` when the caller verifies the set itself, as the zone prover does.
    sets: Option<ExpiringNonceSets>,
    /// Whether the block falls in the activation window and must also read the frozen ring.
    frozen_window: bool,
    parent_hash: B256,
    block_hash: Option<B256>,
    header_root: Option<B256>,
    timestamp: u64,
    authoritative: bool,
    entries: Vec<ExpiringNonce>,
    tx_hashes: Vec<B256>,
    /// T16+: the parent's set with this block's expired buckets dropped, loaded on first use.
    base: Option<ExpiringNonceSet>,
    /// T16+: entries committed earlier in this block.
    pending: HashSet<ExpiringNonce>,
}

impl BlockExpiringNonces {
    /// Starts a block at `timestamp` on top of `parent_hash`. `block_hash` and `header_root` are
    /// known when executing a sealed block; `authoritative` is whether T16 is active, and
    /// `frozen_window` whether the block is in the activation window (see
    /// [`in_activation_window`]). Without `sets` only the frozen ring is checked.
    pub fn new(
        sets: Option<ExpiringNonceSets>,
        parent_hash: B256,
        block_hash: Option<B256>,
        header_root: Option<B256>,
        timestamp: u64,
        authoritative: bool,
        frozen_window: bool,
    ) -> Self {
        Self {
            sets,
            frozen_window: authoritative && frozen_window,
            parent_hash,
            block_hash,
            header_root,
            timestamp,
            authoritative,
            entries: Vec::new(),
            tx_hashes: Vec::new(),
            base: None,
            pending: HashSet::new(),
        }
    }

    /// Returns whether the set is authoritative for this block (T16+).
    pub const fn is_authoritative(&self) -> bool {
        self.authoritative
    }

    /// Returns the parent's set as this block sees it, with expired buckets dropped.
    ///
    /// A parent set derived before T16 is replaced by an empty set: the first T16 block starts
    /// from empty. An unknown parent set fails the block.
    fn base(&mut self) -> Result<&ExpiringNonceSet, BlockExecutionError> {
        if self.base.is_none() {
            let sets = self
                .sets
                .as_ref()
                .ok_or_else(|| BlockExecutionError::msg("expiring nonce sets are disabled"))?;
            let parent = sets.get(self.parent_hash).ok_or_else(|| {
                BlockExecutionError::msg(format!(
                    "expiring nonce set of parent {} is unknown",
                    self.parent_hash
                ))
            })?;
            let mut set = if parent.is_authoritative() {
                parent
            } else {
                ExpiringNonceSet::default()
            };
            set.expire(self.timestamp);
            self.base = Some(set);
        }
        Ok(self.base.as_ref().expect("loaded above"))
    }

    /// T16+: rejects `entry` of transaction `tx_hash` if the set already holds it, or, in the
    /// activation window, if the frozen ring holds it unexpired. `read_frozen` reads a Nonce
    /// precompile storage slot. Does nothing before T16.
    pub fn check(
        &mut self,
        tx_hash: B256,
        entry: &ExpiringNonce,
        read_frozen: impl FnOnce(U256) -> Result<U256, BlockExecutionError>,
    ) -> Result<(), BlockExecutionError> {
        if !self.authoritative {
            return Ok(());
        }
        if self.frozen_window
            && read_frozen(frozen_seen_slot(entry.hash))? > U256::from(self.timestamp)
        {
            trace!(target: "evm::expiring_nonces", ?tx_hash, hash = %entry.hash, "Rejecting: replay of a pre-T16 expiring nonce");
            return Err(ExpiringNonceReplayError::block_error(tx_hash));
        }
        if self.sets.is_none() {
            return Ok(());
        }
        let replay = self.pending.contains(entry) || self.base()?.contains(entry);
        if replay {
            trace!(target: "evm::expiring_nonces", ?tx_hash, hash = %entry.hash, "Rejecting: expiring nonce replay");
            return Err(ExpiringNonceReplayError::block_error(tx_hash));
        }
        Ok(())
    }

    /// Records the entry of committed transaction `tx_hash`.
    pub fn record(&mut self, tx_hash: B256, entry: ExpiringNonce) {
        if self.authoritative {
            self.pending.insert(entry);
        }
        self.entries.push(entry);
        self.tx_hashes.push(tx_hash);
    }

    /// Returns the entries recorded so far, in commit order.
    pub fn entries(&self) -> &[ExpiringNonce] {
        &self.entries
    }

    /// Derives and stores the block's set. From T16 returns its root, after checking it against a
    /// sealed block's header.
    pub fn finish(mut self) -> Result<Option<B256>, BlockExecutionError> {
        let Some(sets) = self.sets.clone() else {
            return Ok(None);
        };
        if !self.authoritative {
            if let Some(set) = sets.derive(self.parent_hash, self.timestamp, &self.entries) {
                self.store(set);
            }
            return Ok(None);
        }

        let mut set = self.base()?.clone();
        // Every entry was checked against the set and the block before its transaction executed.
        set.apply_checked(self.timestamp, &self.entries)
            .map_err(BlockExecutionError::other)?;
        set.set_authoritative(true);
        let root = set.root();
        if self.block_hash.is_some() && self.header_root != Some(root) {
            return Err(BlockValidationError::msg(format!(
                "expiring nonce root mismatch: header {:?}, computed {root}",
                self.header_root
            ))
            .into());
        }
        metrics::gauge!("tempo_expiring_nonce_set_entries").set(set.len() as f64);
        metrics::gauge!("tempo_expiring_nonce_set_buckets").set(set.bucket_count() as f64);
        self.store(set);
        Ok(Some(root))
    }

    fn store(&self, set: ExpiringNonceSet) {
        let Some(sets) = self.sets.as_ref() else {
            return;
        };
        match self.block_hash {
            Some(block_hash) => sets.insert(block_hash, set),
            None => sets.stage(
                staged_key(self.parent_hash, self.timestamp, &self.tx_hashes),
                set,
            ),
        }
    }
}

/// Returns the root of the trie mapping each `valid_before` to its bucket root, given in
/// ascending `valid_before` order.
fn root_of(buckets: impl IntoIterator<Item = (u64, B256)>) -> B256 {
    let mut builder = HashBuilder::default();
    for (valid_before, bucket_root) in buckets {
        builder.add_leaf(
            Nibbles::unpack(bucket_key(valid_before)),
            &alloy_rlp::encode(bucket_root),
        );
    }
    builder.root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembled_payloads_do_not_evict_block_snapshots() {
        let sets = ExpiringNonceSets::default();
        let parent = B256::repeat_byte(1);
        sets.insert(parent, ExpiringNonceSet::default());
        // Far more assembled payloads (such as RPC pending blocks) than snapshots.
        for i in 0..u64::from(SNAPSHOT_CAPACITY + BUILT_CAPACITY) * 4 {
            let key = keccak256(i.to_be_bytes());
            sets.stage(key, ExpiringNonceSet::default());
            assert!(sets.promote(key, || keccak256((i + 1_000_000).to_be_bytes())));
        }
        assert!(sets.get(parent).is_some());
        // The most recent payload is still known, and moves into the block snapshots on use.
        let last = keccak256(
            (u64::from(SNAPSHOT_CAPACITY + BUILT_CAPACITY) * 4 - 1 + 1_000_000).to_be_bytes(),
        );
        assert!(sets.get(last).is_some());
        assert!(sets.inner.lock().by_block.peek(&last).is_some());
    }
    use alloy_primitives::keccak256;

    fn entry(seed: u64, valid_before: u64) -> ExpiringNonce {
        ExpiringNonce {
            hash: keccak256(seed.to_be_bytes()),
            valid_before,
        }
    }

    /// Root computed from scratch with `HashBuilder` for every level.
    fn reference_root(entries: &[ExpiringNonce]) -> B256 {
        let mut buckets = BTreeMap::<u64, Vec<B256>>::new();
        for entry in entries {
            buckets
                .entry(entry.valid_before)
                .or_default()
                .push(entry.hash);
        }
        root_of(buckets.into_iter().map(|(valid_before, mut hashes)| {
            hashes.sort();
            let mut builder = HashBuilder::default();
            for hash in hashes {
                builder.add_leaf(Nibbles::unpack(hash), &PRESENT);
            }
            (valid_before, builder.root())
        }))
    }

    #[test]
    fn empty_set_has_empty_root() -> Result<(), Error> {
        let mut set = ExpiringNonceSet::default();
        assert_eq!(set.root(), EMPTY_ROOT_HASH);
        assert!(set.apply(100, &[])?.is_empty());
        assert_eq!(set.root(), EMPTY_ROOT_HASH);
        Ok(())
    }

    #[test]
    fn root_matches_reference_and_ignores_order() -> Result<(), Error> {
        let entries: Vec<_> = (0..500).map(|i| entry(i, 101 + i % 7)).collect();

        let mut forward = ExpiringNonceSet::default();
        forward.apply(100, &entries[..250])?;
        forward.apply(100, &entries[250..])?;

        let mut reversed_entries = entries.clone();
        reversed_entries.reverse();
        let mut reversed = ExpiringNonceSet::default();
        reversed.apply(100, &reversed_entries)?;

        assert_eq!(forward.root(), reference_root(&entries));
        assert_eq!(forward.root(), reversed.root());
        Ok(())
    }

    #[test]
    fn rejects_replays_until_bucket_expires() -> Result<(), Error> {
        let first = entry(1, 110);
        let mut set = ExpiringNonceSet::default();
        assert!(set.apply(100, &[first])?.is_empty());
        assert!(set.contains(&first));

        // Replayed in a later block and within the same block.
        let second = entry(2, 110);
        assert_eq!(
            set.apply(105, &[first, second, second])?,
            vec![first, second]
        );
        assert_eq!(set.root(), reference_root(&[first, second]));

        // The bucket expires once the timestamp reaches `valid_before`.
        assert!(set.apply(110, &[])?.is_empty());
        assert!(!set.contains(&first));
        assert_eq!(set.root(), EMPTY_ROOT_HASH);
        Ok(())
    }

    #[test]
    fn expiry_drops_only_elapsed_buckets() -> Result<(), Error> {
        let early = entry(1, 101);
        let late = entry(2, 102);
        let mut set = ExpiringNonceSet::default();
        set.apply(100, &[early, late])?;
        set.apply(101, &[])?;
        assert!(!set.contains(&early));
        assert!(set.contains(&late));
        assert_eq!(set.root(), reference_root(&[late]));
        Ok(())
    }

    #[test]
    fn clones_are_copy_on_write() -> Result<(), Error> {
        let mut parent = ExpiringNonceSet::default();
        parent.apply(100, &[entry(1, 110)])?;
        let parent_root = parent.root();

        let mut child = parent.clone();
        child.apply(101, &[entry(2, 110)])?;

        assert_eq!(parent.root(), parent_root);
        assert!(!parent.contains(&entry(2, 110)));
        assert_ne!(child.root(), parent_root);
        Ok(())
    }

    #[test]
    fn derives_from_known_parents_and_promotes_staged_sets() {
        let sets = ExpiringNonceSets::default();
        let genesis = B256::repeat_byte(1);
        sets.insert(genesis, ExpiringNonceSet::default());
        assert!(sets.derive(B256::repeat_byte(9), 100, &[]).is_none());

        let block = B256::repeat_byte(2);
        let set = sets
            .derive(genesis, 100, &[entry(1, 110)])
            .expect("parent is known");
        let key = staged_key(genesis, 100, &[B256::repeat_byte(7)]);
        sets.stage(key, set.clone());
        assert!(!sets.promote(staged_key(genesis, 101, &[B256::repeat_byte(7)]), || block));
        assert!(!sets.contains(block));
        assert!(sets.promote(key, || block));
        assert!(!sets.promote(key, || block));

        let child = sets.derive(block, 101, &[]).expect("promoted set is known");
        assert_eq!(child.root(), set.root());
    }
}
