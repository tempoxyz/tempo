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
    collections::{BTreeMap, HashMap, HashSet},
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

/// Number of unpinned assembled payloads (RPC pending blocks) whose sets are kept. Nothing builds
/// on them, so evicting one costs at most a recomputation.
const UNPINNED_CAPACITY: u32 = 16;

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

    /// Returns the entries of `block`'s transactions under `spec`, in block order.
    pub fn from_block(
        block: &reth_primitives_traits::RecoveredBlock<tempo_primitives::Block>,
        spec: TempoHardfork,
    ) -> Vec<Self> {
        block
            .transactions_with_sender()
            .filter_map(|(sender, tx)| Self::from_tx(tx, *sender, spec))
            .collect()
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
    /// Whether buckets keep their replay hashes for [`Self::witness`]. Only nodes that serve
    /// expiring nonce witnesses (zone nodes) need them; the bucket tries cannot list their leaves.
    witness_keys: bool,
}

impl Default for ExpiringNonceSet {
    fn default() -> Self {
        Self {
            buckets: BTreeMap::new(),
            root: EMPTY_ROOT_HASH,
            authoritative: false,
            witness_keys: false,
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

    /// Returns this set as the parent set of a block, under T16 rules when `authoritative`.
    ///
    /// The first T16 block starts from an empty set, so a pre-T16 (shadow) set is replaced by an
    /// empty one when `authoritative`.
    pub fn for_block(self, authoritative: bool) -> Self {
        if authoritative && !self.authoritative {
            return Self {
                authoritative,
                witness_keys: self.witness_keys,
                ..Self::default()
            };
        }
        Self {
            authoritative,
            ..self
        }
    }

    /// Returns whether the set keeps the replay hashes [`Self::witness`] needs.
    pub const fn has_witness_keys(&self) -> bool {
        self.witness_keys
    }

    /// Keeps the replay hashes of entries inserted from now on, for [`Self::witness`].
    pub fn retain_witness_keys(mut self) -> Self {
        self.witness_keys = true;
        self
    }

    /// Returns whether `tx`, signed by `sender` under `spec`, is an expiring nonce transaction
    /// already in the set.
    pub fn contains_tx(&self, tx: &TempoTxEnvelope, sender: Address, spec: TempoHardfork) -> bool {
        ExpiringNonce::from_tx(tx, sender, spec).is_some_and(|entry| self.contains(&entry))
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
        self.drop_expired(timestamp);
        self.refresh_root();
    }

    fn drop_expired(&mut self, timestamp: u64) {
        self.buckets = match timestamp.checked_add(1) {
            Some(first_live) => self.buckets.split_off(&first_live),
            None => BTreeMap::new(),
        };
    }

    fn refresh_root(&mut self) {
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
        self.drop_expired(timestamp);

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
            if self.witness_keys {
                bucket.keys.push(leaves.keys().copied().collect());
            }
            let mut blinded = false;
            bucket
                .trie
                .update_leaves(&mut leaves, |_, _| blinded = true)?;
            if blinded || !leaves.is_empty() {
                return Err(Error::BlindedBucket { valid_before });
            }
            bucket.root = bucket.trie.root(TrieNodeEpoch::UNMODIFIED);
        }

        self.refresh_root();
        Ok(replays)
    }
}

/// Expiring nonce set snapshots by block hash, shared by block execution, payload building and
/// assembly, the transaction pool, and the node task that follows the canonical chain.
///
/// Retention follows finality, not recency. Consensus only builds on the finalized block or on
/// unfinalized blocks, so every set a future block can start from is either:
///
/// - the set of an unfinalized block this node executed or built: pinned
///   until finality passes its height, on every branch; or
/// - the set of a canonical (finalized or persisted) block: kept, or rebuilt from the provider
///   through the [`ExpiringNonceSets::set_rebuilder`] hook when it is missing (after a restart).
///
/// Sets of payloads that nothing builds on (RPC pending blocks) live in a small LRU instead.
#[derive(Clone)]
pub struct ExpiringNonceSets {
    inner: Arc<Mutex<Snapshots>>,
    rebuilder: Arc<std::sync::OnceLock<Rebuilder>>,
}

/// Rebuilds the set at a canonical block hash, returning its block number with it.
type Rebuilder = Box<dyn Fn(B256) -> Option<(u64, ExpiringNonceSet)> + Send + Sync>;

impl core::fmt::Debug for ExpiringNonceSets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("ExpiringNonceSets")
            .field("pinned", &inner.pinned.len())
            .field("staged", &inner.staged.len())
            .field("finalized", &inner.finalized)
            .finish_non_exhaustive()
    }
}

impl Default for ExpiringNonceSets {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Snapshots {
                pinned: HashMap::default(),
                unpinned: LruMap::new(ByLength::new(UNPINNED_CAPACITY)),
                staged: HashMap::default(),
                finalized: None,
                witness_keys: false,
            })),
            rebuilder: Default::default(),
        }
    }
}

impl ExpiringNonceSets {
    /// Makes sets created from now on keep the replay hashes witnesses need (zone nodes).
    pub fn retain_witness_keys(&self) {
        self.inner.lock().witness_keys = true;
    }

    /// Returns an empty set, keeping witness keys if this store does.
    pub fn empty(&self) -> ExpiringNonceSet {
        let set = ExpiringNonceSet::default();
        if self.inner.lock().witness_keys {
            set.retain_witness_keys()
        } else {
            set
        }
    }

    /// Installs the hook that rebuilds the set of a canonical block from the provider when it is
    /// not held. The node installs it once at startup; later calls are ignored.
    pub fn set_rebuilder(
        &self,
        rebuild: impl Fn(B256) -> Option<(u64, ExpiringNonceSet)> + Send + Sync + 'static,
    ) {
        let _ = self.rebuilder.set(Box::new(rebuild));
    }

    /// Returns whether the set at `block_hash` is held.
    pub fn contains(&self, block_hash: B256) -> bool {
        let inner = self.inner.lock();
        inner.pinned.contains_key(&block_hash) || inner.unpinned.peek(&block_hash).is_some()
    }

    /// Stores `set` as the set of block `number` with `block_hash`, kept until finality passes
    /// `number`.
    pub fn insert(&self, block_hash: B256, number: u64, set: ExpiringNonceSet) {
        let mut inner = self.inner.lock();
        if inner.is_final_or_stale(block_hash, number) {
            return;
        }
        inner.pinned.insert(block_hash, (number, set));
    }

    /// Keeps the assembled payload `block_hash`'s set until finality passes its height. The payload
    /// builder calls this for payloads it hands to consensus, which the engine inserts without
    /// executing them again.
    pub fn pin(&self, block_hash: B256) {
        let mut inner = self.inner.lock();
        if let Some((number, set)) = inner.unpinned.remove(&block_hash)
            && !inner.is_final_or_stale(block_hash, number)
        {
            inner.pinned.insert(block_hash, (number, set));
        }
    }

    /// Drops every set finality made unreachable: below `number`, and at `number` other than
    /// `block_hash`'s. Consensus never builds on those. The previously finalized block's set is
    /// kept too: when finality follows the head (zone sequencers), the newest block's execution
    /// witness still needs its parent's set, which this avoids rebuilding.
    pub fn prune_finalized(&self, number: u64, block_hash: B256) {
        let mut inner = self.inner.lock();
        if inner.finalized.is_some_and(|(n, _)| n > number) {
            return;
        }
        let previous = inner
            .finalized
            .replace((number, block_hash))
            .map(|(_, hash)| hash);
        let keep =
            |hash: &B256, n: u64| n > number || *hash == block_hash || Some(*hash) == previous;
        inner.pinned.retain(|hash, (n, _)| keep(hash, *n));
        let stale: Vec<B256> = inner
            .unpinned
            .iter()
            .filter(|(hash, (n, _))| !keep(hash, *n))
            .map(|(hash, _)| *hash)
            .collect();
        for hash in stale {
            inner.unpinned.remove(&hash);
        }
        inner.staged.retain(|_, (n, _)| *n > number);
        metrics::gauge!("tempo_expiring_nonce_sets_pinned").set(inner.pinned.len() as f64);
    }

    /// Derives the set of a block at `timestamp` containing `entries` from the set at
    /// `parent_hash`, under T16 rules when `authoritative` (see [`ExpiringNonceSet::for_block`]),
    /// without storing it.
    ///
    /// Logs every entry the parent set already held: before T16 the authoritative ring accepted
    /// it, so the shadow set diverges. Returns `None` when the parent's set is unknown or the
    /// update fails.
    pub fn derive(
        &self,
        parent_hash: B256,
        timestamp: u64,
        entries: &[ExpiringNonce],
        authoritative: bool,
    ) -> Option<ExpiringNonceSet> {
        let Some(mut set) = self.parent(parent_hash, authoritative) else {
            debug!(target: "evm::expiring_nonces", %parent_hash, "Parent expiring nonce set unknown");
            return None;
        };
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

    /// Returns the set at `block_hash` if it is held. Does not rebuild.
    pub fn get(&self, block_hash: B256) -> Option<ExpiringNonceSet> {
        self.inner.lock().get(block_hash)
    }

    /// Returns the set at `block_hash`, rebuilding it from the provider when it is not held. Only a
    /// canonical block's set can be rebuilt; every unfinalized block's set is held.
    pub fn get_or_rebuild(&self, block_hash: B256) -> Option<ExpiringNonceSet> {
        if let Some(set) = self.get(block_hash) {
            return Some(set);
        }
        let rebuild = self.rebuilder.get()?;
        let (number, set) = rebuild(block_hash)?;
        debug!(target: "evm::expiring_nonces", %block_hash, number, "Rebuilt missing expiring nonce set");
        self.insert(block_hash, number, set.clone());
        Some(set)
    }

    /// Returns the set a child of `block_hash` starts from (see
    /// [`ExpiringNonceSet::for_block`]), rebuilding `block_hash`'s set when it is not held.
    pub fn parent(&self, block_hash: B256, authoritative: bool) -> Option<ExpiringNonceSet> {
        self.get_or_rebuild(block_hash)
            .map(|set| set.for_block(authoritative))
    }

    /// Returns the set at `block_hash` if it is held and was derived under T16 rules: the set T16
    /// replay checks against. A pre-T16 (shadow) set is ignored, since the first T16 block starts
    /// empty. Does not rebuild: callers use it to skip work early.
    pub fn authoritative(&self, block_hash: B256) -> Option<ExpiringNonceSet> {
        self.get(block_hash)
            .filter(ExpiringNonceSet::is_authoritative)
    }

    /// Returns the root of the set staged under `key`, if any.
    pub fn staged_root(&self, key: B256) -> Option<B256> {
        self.inner
            .lock()
            .staged
            .get(&key)
            .map(|(_, set)| set.root())
    }

    /// Stages the set of a payload for block `number` that is not assembled yet under `key` (see
    /// [`staged_key`]).
    pub fn stage(&self, key: B256, number: u64, set: ExpiringNonceSet) {
        let mut inner = self.inner.lock();
        if inner.finalized.is_some_and(|(n, _)| number <= n) {
            return;
        }
        inner.staged.insert(key, (number, set));
    }

    /// Stores the set staged under `key` as the set of the assembled payload `block_hash`, until
    /// [`Self::pin`] keeps it or newer payloads push it out. Returns `false` when nothing is
    /// staged under `key`.
    pub fn promote(&self, key: B256, block_hash: impl FnOnce() -> B256) -> bool {
        let mut inner = self.inner.lock();
        let Some(entry) = inner.staged.remove(&key) else {
            return false;
        };
        inner.unpinned.insert(block_hash(), entry);
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

struct Snapshots {
    /// Sets of blocks this node executed and payloads it handed to consensus, by hash, with their
    /// block numbers. Dropped only when finality passes their height.
    pinned: HashMap<B256, (u64, ExpiringNonceSet)>,
    /// Sets of assembled payloads nothing builds on yet (RPC pending blocks), most recent first.
    unpinned: LruMap<B256, (u64, ExpiringNonceSet), ByLength>,
    /// Sets of payloads executed but not assembled yet, by [`staged_key`], with block numbers.
    staged: HashMap<B256, (u64, ExpiringNonceSet)>,
    /// The last finalized block seen, by number and hash.
    finalized: Option<(u64, B256)>,
    /// Whether new sets keep witness keys.
    witness_keys: bool,
}

impl Snapshots {
    fn get(&mut self, block_hash: B256) -> Option<ExpiringNonceSet> {
        if let Some((_, set)) = self.pinned.get(&block_hash) {
            return Some(set.clone());
        }
        self.unpinned.get(&block_hash).map(|(_, set)| set.clone())
    }

    /// Returns whether block `number` with `block_hash` is at or below finality and not the
    /// finalized block itself: no future block can build on it.
    fn is_final_or_stale(&self, block_hash: B256, number: u64) -> bool {
        self.finalized
            .is_some_and(|(n, hash)| number < n || (number == n && block_hash != hash))
    }
}

/// One `valid_before` second's replay hashes.
#[derive(Debug, Clone)]
struct Bucket {
    trie: ArenaParallelSparseTrie,
    root: B256,
    len: usize,
    /// The bucket's replay hashes, one chunk per update, to build witness proofs from. Empty
    /// unless the set keeps witness keys.
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
    number: u64,
    timestamp: u64,
    spec: TempoHardfork,
    authoritative: bool,
    entries: Vec<ExpiringNonce>,
    tx_hashes: Vec<B256>,
    /// T16+: the parent's set with this block's expired buckets dropped, loaded on first use.
    base: Option<ExpiringNonceSet>,
    /// T16+: entries committed earlier in this block.
    pending: HashSet<ExpiringNonce>,
}

impl Default for BlockExpiringNonces {
    /// An inert pre-T16 block with no sets.
    fn default() -> Self {
        Self {
            sets: None,
            frozen_window: false,
            parent_hash: B256::ZERO,
            block_hash: None,
            header_root: None,
            number: 0,
            timestamp: 0,
            spec: TempoHardfork::default(),
            authoritative: false,
            entries: Vec::new(),
            tx_hashes: Vec::new(),
            base: None,
            pending: HashSet::new(),
        }
    }
}

impl BlockExpiringNonces {
    /// Starts block `number` at `timestamp` under `spec`, described by `ctx` (its parent, and its
    /// hash and header root when executing a sealed block). `frozen_window` is whether the block
    /// is in the activation window (see [`in_activation_window`]). Without `sets` only the frozen
    /// ring is checked.
    pub fn new(
        sets: Option<ExpiringNonceSets>,
        ctx: &crate::TempoBlockExecutionCtx<'_>,
        number: u64,
        timestamp: u64,
        spec: TempoHardfork,
        frozen_window: bool,
    ) -> Self {
        let authoritative = spec.is_t16();
        Self {
            sets,
            frozen_window: authoritative && frozen_window,
            parent_hash: ctx.inner.parent_hash,
            block_hash: ctx.block_hash,
            header_root: ctx.expiring_nonce_root,
            number,
            timestamp,
            spec,
            authoritative,
            entries: Vec::new(),
            tx_hashes: Vec::new(),
            base: None,
            pending: HashSet::new(),
        }
    }

    /// Returns the expiring nonce entry of `tx` signed by `sender` under this block's fork.
    pub fn entry(&self, tx: &TempoTxEnvelope, sender: Address) -> Option<ExpiringNonce> {
        ExpiringNonce::from_tx(tx, sender, self.spec)
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
            let mut set = sets.parent(self.parent_hash, true).ok_or_else(|| {
                BlockExecutionError::msg(format!(
                    "expiring nonce set of parent {} is unknown",
                    self.parent_hash
                ))
            })?;
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
            if let Some(set) = sets.derive(self.parent_hash, self.timestamp, &self.entries, false) {
                self.store(set);
            }
            return Ok(None);
        }

        let mut set = self.base()?.clone();
        // Every entry was checked against the set and the block before its transaction executed.
        set.apply_checked(self.timestamp, &self.entries)
            .map_err(BlockExecutionError::other)?;
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
            Some(block_hash) => sets.insert(block_hash, self.number, set),
            None => sets.stage(
                staged_key(self.parent_hash, self.timestamp, &self.tx_hashes),
                self.number,
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

    /// Worst case for copy-on-write: every block touches every bucket.
    /// Run: cargo test -p tempo-evm --release --lib worst_case_bucket_cow -- --ignored --nocapture
    #[test]
    #[ignore]
    fn worst_case_bucket_cow() {
        fn rss_mb() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .unwrap()
                .lines()
                .find(|l| l.starts_with("VmRSS"))
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap()
                .parse::<u64>()
                .unwrap()
                / 1024
        }
        let buckets: u64 = std::env::var("BUCKETS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        let per_bucket: u64 = std::env::var("PER_BUCKET")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        let snapshots: usize = std::env::var("SNAPSHOTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(48);
        let base = rss_mb();
        let mut set = ExpiringNonceSet::default();
        let mut seed = 0u64;
        for b in 0..buckets {
            let entries: Vec<_> = (0..per_bucket)
                .map(|_| {
                    seed += 1;
                    entry(seed, 1_000 + b)
                })
                .collect();
            set.apply(1, &entries).unwrap();
        }
        let one = rss_mb() - base;
        println!("one set: {} entries, {one} MB", buckets * per_bucket);
        let mut kept = vec![set.clone()];
        let t = std::time::Instant::now();
        for _ in 0..snapshots {
            let mut next = kept.last().unwrap().clone();
            let entries: Vec<_> = (0..buckets)
                .map(|b| {
                    seed += 1;
                    entry(seed, 1_000 + b)
                })
                .collect();
            next.apply(1, &entries).unwrap();
            kept.push(next);
        }
        println!(
            "{} snapshots, each touching all {buckets} buckets: {} MB total ({} MB/snapshot), {:?}/block",
            snapshots,
            rss_mb() - base,
            (rss_mb() - base - one) / snapshots as u64,
            t.elapsed() / snapshots as u32
        );
    }

    #[test]
    fn unpinned_payloads_never_evict_pinned_sets() {
        let sets = ExpiringNonceSets::default();
        let parent = B256::repeat_byte(1);
        sets.insert(parent, 1, ExpiringNonceSet::default());
        // Far more assembled payloads (such as RPC pending blocks) than the unpinned cache holds.
        let payload = |i: u64| keccak256((i + 1_000_000).to_be_bytes());
        for i in 0..u64::from(UNPINNED_CAPACITY) * 4 {
            let key = keccak256(i.to_be_bytes());
            sets.stage(key, 2, ExpiringNonceSet::default());
            assert!(sets.promote(key, || payload(i)));
        }
        assert!(sets.get(parent).is_some());
        assert!(
            sets.get(payload(0)).is_none(),
            "oldest unpinned payload is evicted"
        );
        // A pinned payload survives any number of later payloads.
        let last = payload(u64::from(UNPINNED_CAPACITY) * 4 - 1);
        sets.pin(last);
        for i in 1_000..1_000 + u64::from(UNPINNED_CAPACITY) * 4 {
            let key = keccak256(i.to_be_bytes());
            sets.stage(key, 2, ExpiringNonceSet::default());
            sets.promote(key, || payload(i));
        }
        assert!(sets.get(last).is_some());
    }

    #[test]
    fn unfinalized_sets_are_kept_until_finality_passes_them() {
        let sets = ExpiringNonceSets::default();
        let hash = |n: u8, branch: u8| {
            B256::from([
                n, branch, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ])
        };
        // Two branches, 100 blocks deep: far more than any capacity bound would keep.
        for n in 1..=100u8 {
            for branch in 0..2 {
                sets.insert(hash(n, branch), n.into(), ExpiringNonceSet::default());
            }
        }
        sets.prune_finalized(49, hash(49, 0));
        sets.prune_finalized(50, hash(50, 0));
        assert!(
            sets.contains(hash(49, 0)),
            "the previously finalized block's set is kept"
        );
        for n in 1..49u8 {
            assert!(!sets.contains(hash(n, 0)) && !sets.contains(hash(n, 1)));
        }
        assert!(!sets.contains(hash(49, 1)));
        assert!(
            sets.contains(hash(50, 0)),
            "the finalized block's set is kept"
        );
        assert!(
            !sets.contains(hash(50, 1)),
            "a sibling of the finalized block is unreachable"
        );
        for n in 51..=100u8 {
            assert!(
                sets.contains(hash(n, 0)) && sets.contains(hash(n, 1)),
                "block {n}"
            );
        }
        // Sets at or below finality are not stored again, and finality never moves back.
        sets.insert(hash(10, 0), 10, ExpiringNonceSet::default());
        assert!(!sets.contains(hash(10, 0)));
        sets.prune_finalized(20, hash(20, 0));
        assert!(sets.contains(hash(60, 1)));
    }

    #[test]
    fn missing_canonical_sets_are_rebuilt() {
        let sets = ExpiringNonceSets::default();
        let canonical = B256::repeat_byte(3);
        let mut rebuilt = ExpiringNonceSet::default().for_block(true);
        rebuilt.apply(10, &[entry(1, 20)]).unwrap();
        let expected = rebuilt.root();
        sets.set_rebuilder(move |hash| (hash == canonical).then(|| (5, rebuilt.clone())));
        assert!(sets.get(canonical).is_none());
        assert_eq!(sets.parent(canonical, true).unwrap().root(), expected);
        assert!(sets.contains(canonical), "a rebuilt set is kept");
        assert!(sets.parent(B256::repeat_byte(4), true).is_none());
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
        sets.insert(genesis, 0, ExpiringNonceSet::default());
        assert!(sets.derive(B256::repeat_byte(9), 100, &[], false).is_none());

        let block = B256::repeat_byte(2);
        let set = sets
            .derive(genesis, 100, &[entry(1, 110)], false)
            .expect("parent is known");
        let key = staged_key(genesis, 100, &[B256::repeat_byte(7)]);
        sets.stage(key, 1, set.clone());
        assert!(!sets.promote(staged_key(genesis, 101, &[B256::repeat_byte(7)]), || block));
        assert!(!sets.contains(block));
        assert!(sets.promote(key, || block));
        assert!(!sets.promote(key, || block));

        let child = sets
            .derive(block, 101, &[], false)
            .expect("promoted set is known");
        assert_eq!(child.root(), set.root());
    }
}
