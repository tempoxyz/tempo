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
//! The set runs in shadow mode next to the `NonceManager` ring: the ring stays authoritative, and
//! every block's expiring nonce transactions are checked against and inserted into the set, so the
//! two can be compared before the root is committed in the block header.
// TODO: commit the root in the block header and drop the ring at the hardfork that activates it.

use std::{collections::BTreeMap, sync::Arc};

use alloy_consensus::transaction::TxHashRef;
use alloy_primitives::{Address, B256, Keccak256, U256, map::B256Map};
use parking_lot::Mutex;
use reth_trie_common::{EMPTY_ROOT_HASH, HashBuilder, Nibbles};
use reth_trie_sparse::{
    ArenaParallelSparseTrie, LeafUpdate, SparseTrie, TrieNodeEpoch, errors::SparseTrieError,
};
use schnellru::{ByLength, LruMap};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoTxEnvelope;
use tracing::{debug, error};

/// Number of block snapshots kept. Covers the unfinalized branches a node executes on top of.
const SNAPSHOT_CAPACITY: u32 = 256;

/// Number of built payloads whose sets wait for assembly.
const STAGED_CAPACITY: u32 = 16;

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
}

impl Default for ExpiringNonceSet {
    fn default() -> Self {
        Self {
            buckets: BTreeMap::new(),
            root: EMPTY_ROOT_HASH,
        }
    }
}

impl ExpiringNonceSet {
    /// Returns the set's root.
    pub const fn root(&self) -> B256 {
        self.root
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

    /// Advances the set to a block at `timestamp` containing `entries`.
    ///
    /// Drops every bucket with `valid_before <= timestamp`, inserts `entries`, and recomputes the
    /// root. Returns the entries that were already in the set: replays the set would have rejected.
    pub fn apply(
        &mut self,
        timestamp: u64,
        entries: &[ExpiringNonce],
    ) -> Result<Vec<ExpiringNonce>, Error> {
        self.buckets = match timestamp.checked_add(1) {
            Some(first_live) => self.buckets.split_off(&first_live),
            None => BTreeMap::new(),
        };

        let mut replays = Vec::new();
        let mut updates = BTreeMap::<u64, B256Map<LeafUpdate>>::new();
        for entry in entries {
            let pending = updates.entry(entry.valid_before).or_default();
            if self.contains(entry) || pending.contains_key(&entry.hash) {
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
                staged: LruMap::new(ByLength::new(STAGED_CAPACITY)),
            })),
        }
    }
}

impl ExpiringNonceSets {
    /// Returns whether the set at `block_hash` is known.
    pub fn contains(&self, block_hash: B256) -> bool {
        self.inner.lock().by_block.peek(&block_hash).is_some()
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
        let Some(mut set) = self.inner.lock().by_block.get(&parent_hash).cloned() else {
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

    /// Stages the set of a payload that is not assembled yet under `key` (see [`staged_key`]).
    pub fn stage(&self, key: B256, set: ExpiringNonceSet) {
        self.inner.lock().staged.insert(key, set);
    }

    /// Stores the set staged under `key` as the set at `block_hash`. Returns `false` when
    /// nothing is staged under `key`.
    pub fn promote(&self, key: B256, block_hash: impl FnOnce() -> B256) -> bool {
        let mut inner = self.inner.lock();
        let Some(set) = inner.staged.remove(&key) else {
            return false;
        };
        inner.by_block.insert(block_hash(), set);
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
    staged: LruMap<B256, ExpiringNonceSet, ByLength>,
}

/// One `valid_before` second's replay hashes.
#[derive(Debug, Clone)]
struct Bucket {
    trie: ArenaParallelSparseTrie,
    root: B256,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            trie: ArenaParallelSparseTrie::default(),
            root: EMPTY_ROOT_HASH,
        }
    }
}

/// Returns the root of the trie mapping each `valid_before` to its bucket root, given in
/// ascending `valid_before` order.
fn root_of(buckets: impl IntoIterator<Item = (u64, B256)>) -> B256 {
    let mut builder = HashBuilder::default();
    for (valid_before, bucket_root) in buckets {
        // Big-endian keys keep ascending `valid_before` in ascending path order.
        let key = B256::from(U256::from(valid_before));
        builder.add_leaf(Nibbles::unpack(key), &alloy_rlp::encode(bucket_root));
    }
    builder.root()
}

#[cfg(test)]
mod tests {
    use super::*;
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
