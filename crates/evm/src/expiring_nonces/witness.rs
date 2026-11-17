//! Stateless verification of expiring nonce set transitions (TIP-1173).
//!
//! A verifier that does not hold the set, such as the zone prover, starts from a committed root
//! and a pool of RLP-encoded trie nodes indexed by hash. [`PartialExpiringNonceSet`] reveals the
//! set trie and bucket tries from that pool and applies each block's transition: it drops expired
//! buckets, proves every entry absent, inserts it, and recomputes the root. A path the pool does
//! not reveal fails with [`WitnessError::MissingNode`], so a witness can omit nodes but cannot fake
//! an absence.
//!
//! [`ExpiringNonceSet::witness`] produces the pool for one block from a full set by running the
//! same transition against it and proving every path the transition asks for, so the node and the
//! verifier agree on what a witness must contain.

use super::{ExpiringNonce, ExpiringNonceSet, PRESENT, bucket_key};
use alloy_primitives::{B256, Bytes, keccak256, map::B256Map};
use alloy_rlp::Decodable;
use reth_trie_common::{
    EMPTY_ROOT_HASH, HashBuilder, Nibbles, ProofTrieNodeV2, TrieNode, depth_first_cmp,
    proof::ProofRetainer,
};
use reth_trie_sparse::{
    LeafLookup, LeafLookupError, LeafUpdate, RevealableSparseTrie, SparseTrie, TrieNodeEpoch,
};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

/// Upper bound on reveal rounds for one lookup or update: one per trie level, with slack.
const MAX_REVEAL_ROUNDS: usize = 256;

/// The trie a node belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WitnessTrie {
    /// The set trie, keyed by `valid_before`.
    Set,
    /// The bucket trie of one `valid_before` second, keyed by replay hash.
    Bucket(u64),
}

/// Errors from verifying an expiring nonce set transition against a witness.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessError {
    /// The witness does not reveal a node the transition needs.
    #[error("expiring nonce witness does not reveal {trie:?} path {key}")]
    MissingNode {
        /// The trie the node belongs to.
        trie: WitnessTrie,
        /// A key whose path runs through the missing node.
        key: B256,
    },
    /// A witness node is not a valid trie node.
    #[error("expiring nonce witness holds an invalid trie node")]
    InvalidNode,
    /// The revealed trie rejected an operation.
    #[error("expiring nonce witness trie operation failed")]
    Trie,
    /// An entry is already in the set.
    #[error("expiring nonce replay: {hash} in bucket {valid_before}")]
    Replay {
        /// The replay hash.
        hash: B256,
        /// Its bucket.
        valid_before: u64,
    },
    /// An entry's `valid_before` is outside `(timestamp, timestamp + max_expiry_secs]`.
    #[error("expiring nonce valid_before {valid_before} outside the accepted window")]
    Expiry {
        /// The entry's `valid_before`.
        valid_before: u64,
    },
    /// Generating a witness did not converge.
    #[error("expiring nonce witness generation did not converge")]
    Generation,
}

/// What a block's set transition depends on besides its entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockParams {
    /// The parent block's timestamp. Every bucket of the parent set has `valid_before` above it.
    pub parent_timestamp: u64,
    /// The block's timestamp.
    pub timestamp: u64,
    /// The block's `MAX_EXPIRY_SECS`.
    pub max_expiry_secs: u64,
}

impl BlockParams {
    /// Buckets this block can expire: `(parent_timestamp, timestamp]`, capped at the parent's
    /// window, beyond which the parent set holds no bucket.
    fn expiring(&self) -> std::ops::RangeInclusive<u64> {
        let last = self
            .timestamp
            .min(self.parent_timestamp.saturating_add(self.max_expiry_secs));
        self.parent_timestamp.saturating_add(1)..=last
    }

    fn check_window(&self, entry: &ExpiringNonce) -> Result<(), WitnessError> {
        let v = entry.valid_before;
        if v <= self.timestamp || v > self.timestamp.saturating_add(self.max_expiry_secs) {
            return Err(WitnessError::Expiry { valid_before: v });
        }
        Ok(())
    }
}

/// An expiring nonce set revealed only where a witness pool covers it.
#[derive(Debug)]
pub struct PartialExpiringNonceSet {
    pool: B256Map<Bytes>,
    set: RevealableSparseTrie,
    /// Buckets loaded or changed so far, by `valid_before`.
    buckets: BTreeMap<u64, RevealableSparseTrie>,
}

impl PartialExpiringNonceSet {
    /// Starts from the set committed by `root`, revealed from `nodes`.
    ///
    /// Pass [`EMPTY_ROOT_HASH`] for an empty set, such as the parent of the first T16 block.
    pub fn new(root: B256, nodes: impl IntoIterator<Item = Bytes>) -> Result<Self, WitnessError> {
        let pool: B256Map<Bytes> = nodes
            .into_iter()
            .map(|node| (keccak256(&node), node))
            .collect();
        let set = reveal_root(root, &pool, WitnessTrie::Set)?;
        Ok(Self {
            pool,
            set,
            buckets: BTreeMap::new(),
        })
    }

    /// Adds nodes to the pool, for a later block of a batch.
    pub fn extend_pool(&mut self, nodes: impl IntoIterator<Item = Bytes>) {
        self.pool
            .extend(nodes.into_iter().map(|node| (keccak256(&node), node)));
    }

    /// Returns the current set root.
    pub fn root(&mut self) -> Result<B256, WitnessError> {
        self.set
            .root(TrieNodeEpoch::UNMODIFIED)
            .ok_or(WitnessError::Trie)
    }

    /// Applies one block's transition and returns the new set root.
    ///
    /// On error the set is left part-way through the block and must not be reused.
    pub fn apply(
        &mut self,
        params: &BlockParams,
        entries: &[ExpiringNonce],
    ) -> Result<B256, WitnessError> {
        // Expire: drop every bucket of the parent set with valid_before <= timestamp.
        let mut removals = B256Map::default();
        for valid_before in params.expiring() {
            let key = bucket_key(valid_before);
            if lookup(&mut self.set, &self.pool, WitnessTrie::Set, key)? == LeafLookup::Exists {
                removals.insert(key, LeafUpdate::Changed(Vec::new()));
            }
            self.buckets.remove(&valid_before);
        }
        update(&mut self.set, &self.pool, WitnessTrie::Set, removals)?;

        // Check and insert each entry, in body order.
        let mut touched = BTreeSet::new();
        for entry in entries {
            params.check_window(entry)?;
            let trie = WitnessTrie::Bucket(entry.valid_before);
            self.load_bucket(entry.valid_before)?;
            let bucket = self.buckets.get_mut(&entry.valid_before).expect("loaded");
            if lookup(bucket, &self.pool, trie, entry.hash)? == LeafLookup::Exists {
                return Err(WitnessError::Replay {
                    hash: entry.hash,
                    valid_before: entry.valid_before,
                });
            }
            update(
                bucket,
                &self.pool,
                trie,
                B256Map::from_iter([(entry.hash, LeafUpdate::Changed(PRESENT.to_vec()))]),
            )?;
            touched.insert(entry.valid_before);
        }

        // Commit: write the touched buckets' roots into the set trie.
        let mut roots = B256Map::default();
        for valid_before in touched {
            let bucket = self.buckets.get_mut(&valid_before).expect("touched");
            let root = bucket
                .root(TrieNodeEpoch::UNMODIFIED)
                .ok_or(WitnessError::Trie)?;
            roots.insert(
                bucket_key(valid_before),
                LeafUpdate::Changed(alloy_rlp::encode(root)),
            );
        }
        update(&mut self.set, &self.pool, WitnessTrie::Set, roots)?;
        self.root()
    }

    /// Loads bucket `valid_before` from the set trie, unless already loaded.
    fn load_bucket(&mut self, valid_before: u64) -> Result<(), WitnessError> {
        if self.buckets.contains_key(&valid_before) {
            return Ok(());
        }
        let key = bucket_key(valid_before);
        let bucket = match lookup(&mut self.set, &self.pool, WitnessTrie::Set, key)? {
            LeafLookup::NonExistent => RevealableSparseTrie::revealed_empty(),
            LeafLookup::Exists => {
                let value = self
                    .set
                    .as_revealed_ref()
                    .and_then(|set| set.get_leaf_value(&Nibbles::unpack(key)))
                    .ok_or(WitnessError::Trie)?;
                let root =
                    B256::decode(&mut value.as_slice()).map_err(|_| WitnessError::InvalidNode)?;
                reveal_root(root, &self.pool, WitnessTrie::Bucket(valid_before))?
            }
        };
        self.buckets.insert(valid_before, bucket);
        Ok(())
    }
}

impl ExpiringNonceSet {
    /// Returns the witness a verifier needs to apply a block with `params` and `entries` to this
    /// set: deduplicated RLP-encoded trie nodes, unordered.
    ///
    /// This set must already be the parent's set as seen by the block (pass the empty set for the
    /// first T16 block). A replay or window error is returned as is.
    pub fn witness(
        &self,
        params: &BlockParams,
        entries: &[ExpiringNonce],
    ) -> Result<Vec<Bytes>, WitnessError> {
        // Start from the paths every block needs, then add the ones the transition asks for,
        // mostly the siblings that collapse when a bucket is deleted.
        let mut targets = BTreeMap::<WitnessTrie, BTreeSet<B256>>::new();
        let set_targets = targets.entry(WitnessTrie::Set).or_default();
        set_targets.extend(params.expiring().map(bucket_key));
        set_targets.extend(entries.iter().map(|entry| bucket_key(entry.valid_before)));
        for entry in entries {
            if self.buckets.contains_key(&entry.valid_before) {
                targets
                    .entry(WitnessTrie::Bucket(entry.valid_before))
                    .or_default()
                    .insert(entry.hash);
            }
        }

        // Each retry adds a target that was not there before, and the tries are finite.
        let max_rounds = 4 * (entries.len() + targets.values().map(BTreeSet::len).sum::<usize>())
            + MAX_REVEAL_ROUNDS;
        for _ in 0..max_rounds {
            let nodes = self.proof_nodes(&targets);
            // Revealing the root can itself need more nodes: a root extension whose subtree no
            // target enters is proven without the branch below it.
            let result = PartialExpiringNonceSet::new(self.root, nodes.iter().cloned())
                .and_then(|mut partial| partial.apply(params, entries));
            match result {
                Ok(_) => return Ok(nodes),
                Err(WitnessError::MissingNode { trie, key }) => {
                    if !targets.entry(trie).or_default().insert(key) {
                        return Err(WitnessError::Generation);
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Err(WitnessError::Generation)
    }

    /// Returns the nodes proving every target key in its trie, deduplicated.
    fn proof_nodes(&self, targets: &BTreeMap<WitnessTrie, BTreeSet<B256>>) -> Vec<Bytes> {
        let mut seen = HashSet::new();
        let mut nodes = Vec::new();
        for (trie, keys) in targets {
            let leaves: Vec<(B256, Vec<u8>)> = match trie {
                WitnessTrie::Set => self
                    .buckets
                    .iter()
                    .map(|(v, bucket)| (bucket_key(*v), alloy_rlp::encode(bucket.root)))
                    .collect(),
                WitnessTrie::Bucket(v) => {
                    let Some(bucket) = self.buckets.get(v) else {
                        continue;
                    };
                    let mut keys: Vec<B256> = bucket
                        .keys
                        .iter()
                        .flat_map(|chunk| chunk.iter().copied())
                        .collect();
                    keys.sort_unstable();
                    keys.into_iter().map(|k| (k, PRESENT.to_vec())).collect()
                }
            };
            let retainer = ProofRetainer::from_iter(keys.iter().map(|k| Nibbles::unpack(*k)));
            let mut builder = HashBuilder::default().with_proof_retainer(retainer);
            for (key, value) in &leaves {
                builder.add_leaf(Nibbles::unpack(*key), value);
            }
            builder.root();
            for (_, node) in builder.take_proof_nodes().into_inner() {
                if seen.insert(keccak256(&node)) {
                    nodes.push(node);
                }
            }
        }
        nodes
    }
}

/// Reveals the trie rooted at `root` from `pool`.
fn reveal_root(
    root: B256,
    pool: &B256Map<Bytes>,
    which: WitnessTrie,
) -> Result<RevealableSparseTrie, WitnessError> {
    if root == EMPTY_ROOT_HASH {
        return Ok(RevealableSparseTrie::revealed_empty());
    }
    let node = pool.get(&root).ok_or(WitnessError::MissingNode {
        trie: which,
        key: B256::ZERO,
    })?;
    let mut nodes = decode_subtree(Nibbles::default(), node, pool)?;
    if !nodes.iter().any(|node| node.path.is_empty()) {
        return Err(WitnessError::MissingNode {
            trie: which,
            key: blocked_key(&Nibbles::default(), node)?,
        });
    }
    let mut trie = RevealableSparseTrie::blind();
    trie.reveal_v2_proof_nodes(&mut nodes, false)
        .map_err(|_| WitnessError::InvalidNode)?;
    Ok(trie)
}

fn decode(bytes: &[u8]) -> Result<TrieNode, WitnessError> {
    TrieNode::decode(&mut &bytes[..]).map_err(|_| WitnessError::InvalidNode)
}

/// Decodes every node reachable from `node` at `path` through `pool`, as V2 proof nodes.
///
/// V2 nodes merge an extension into its child branch, so an extension whose child the pool lacks
/// is left out, together with its subtree.
fn decode_subtree(
    path: Nibbles,
    node: &Bytes,
    pool: &B256Map<Bytes>,
) -> Result<Vec<ProofTrieNodeV2>, WitnessError> {
    let resolve = |child: &reth_trie_common::RlpNode| -> Result<Option<TrieNode>, WitnessError> {
        match child.as_hash() {
            Some(hash) => pool.get(&hash).map(|bytes| decode(bytes)).transpose(),
            None => decode(child.as_slice()).map(Some),
        }
    };
    let mut out = Vec::new();
    let mut queue = VecDeque::from([(decode(node)?, path)]);
    while let Some((node, path)) = queue.pop_front() {
        match &node {
            TrieNode::Branch(branch) => {
                if path.len() >= 64 {
                    return Err(WitnessError::InvalidNode);
                }
                for (idx, child) in branch.as_ref().children() {
                    let Some(child) = child else { continue };
                    if let Some(child) = resolve(child)? {
                        let mut child_path = path;
                        child_path.push_unchecked(idx);
                        queue.push_back((child, child_path));
                    }
                }
            }
            TrieNode::Extension(ext) => {
                if path.len() + ext.key.len() > 64 {
                    return Err(WitnessError::InvalidNode);
                }
                let Some(child) = resolve(&ext.child)? else {
                    continue;
                };
                queue.push_back((child, path.join(&ext.key)));
            }
            TrieNode::Leaf(leaf) => {
                if path.len() + leaf.key.len() != 64 {
                    return Err(WitnessError::InvalidNode);
                }
            }
            TrieNode::EmptyRoot => {}
        }
        out.push((path, node, None));
    }
    out.sort_by(|(a, _, _), (b, _, _)| depth_first_cmp(a, b));
    Ok(ProofTrieNodeV2::from_sorted_trie_nodes(out))
}

/// Returns a key whose proof reveals what blocks revealing `node` at `path`: the node itself, or
/// for an extension, its child.
fn blocked_key(path: &Nibbles, node: &Bytes) -> Result<B256, WitnessError> {
    Ok(match decode(node)? {
        TrieNode::Extension(ext) => padded_key(&path.join(&ext.key)),
        _ => padded_key(path),
    })
}

/// Pads a trie path with zero nibbles to a full 32-byte key.
fn padded_key(path: &Nibbles) -> B256 {
    let mut bytes = [0u8; 32];
    for (i, nibble) in path.to_vec().into_iter().take(64).enumerate() {
        bytes[i / 2] |= if i % 2 == 0 { nibble << 4 } else { nibble };
    }
    B256::from(bytes)
}

/// Looks up `key`, revealing blinded nodes on its path from `pool`.
fn lookup(
    trie: &mut RevealableSparseTrie,
    pool: &B256Map<Bytes>,
    which: WitnessTrie,
    key: B256,
) -> Result<LeafLookup, WitnessError> {
    let path = Nibbles::unpack(key);
    let revealed = trie.as_revealed_mut().ok_or(WitnessError::Trie)?;
    for _ in 0..MAX_REVEAL_ROUNDS {
        match revealed.find_leaf(&path, None) {
            Ok(result) => return Ok(result),
            Err(LeafLookupError::BlindedNode {
                path: blinded,
                hash,
            }) => {
                let node = pool.get(&hash).ok_or(WitnessError::MissingNode {
                    trie: which,
                    key: padded_key(&blinded),
                })?;
                let mut nodes = decode_subtree(blinded, node, pool)?;
                if !nodes.iter().any(|node| node.path == blinded) {
                    return Err(WitnessError::MissingNode {
                        trie: which,
                        key: blocked_key(&blinded, node)?,
                    });
                }
                revealed
                    .reveal_nodes(&mut nodes)
                    .map_err(|_| WitnessError::InvalidNode)?;
            }
            Err(LeafLookupError::ValueMismatch { .. }) => return Err(WitnessError::Trie),
        }
    }
    Err(WitnessError::Trie)
}

/// Applies `updates`, revealing the blinded nodes the trie asks for from `pool`.
fn update(
    trie: &mut RevealableSparseTrie,
    pool: &B256Map<Bytes>,
    which: WitnessTrie,
    mut updates: B256Map<LeafUpdate>,
) -> Result<(), WitnessError> {
    for _ in 0..MAX_REVEAL_ROUNDS {
        if updates.is_empty() {
            return Ok(());
        }
        let mut required = Vec::new();
        trie.update_leaves(&mut updates, |key, _| required.push(key))
            .map_err(|_| WitnessError::Trie)?;
        if updates.is_empty() {
            return Ok(());
        }
        if required.is_empty() {
            return Err(WitnessError::Trie);
        }
        // Walking a required key's path reveals the blinded node it runs through.
        for key in required {
            lookup(trie, pool, which, key)?;
        }
    }
    Err(WitnessError::Trie)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seed: u64, valid_before: u64) -> ExpiringNonce {
        ExpiringNonce {
            hash: keccak256(seed.to_be_bytes()),
            valid_before,
        }
    }

    fn params(parent_timestamp: u64, timestamp: u64) -> BlockParams {
        BlockParams {
            parent_timestamp,
            timestamp,
            max_expiry_secs: 300,
        }
    }

    /// A set with many buckets, built over 20 blocks; returns it and its last timestamp.
    fn populated() -> (ExpiringNonceSet, u64) {
        let mut set = ExpiringNonceSet::default();
        let mut seed = 0;
        for timestamp in 100..120u64 {
            let entries: Vec<_> = (0..40)
                .map(|i| {
                    seed += 1;
                    entry(seed, timestamp + 1 + i % 30)
                })
                .collect();
            assert!(set.apply(timestamp, &entries).unwrap().is_empty());
        }
        (set, 119)
    }

    fn verify(set: &ExpiringNonceSet, block: &BlockParams, entries: &[ExpiringNonce]) -> B256 {
        let nodes = set.witness(block, entries).unwrap();
        let root = PartialExpiringNonceSet::new(set.root(), nodes)
            .unwrap()
            .apply(block, entries)
            .unwrap();
        let mut full = set.clone();
        assert!(full.apply(block.timestamp, entries).unwrap().is_empty());
        assert_eq!(root, full.root());
        root
    }

    #[test]
    fn witness_verifies_inserts_and_expiry() {
        let (set, parent) = populated();
        let entries: Vec<_> = (0..50)
            .map(|i| entry(10_000 + i, parent + 4 + i % 20))
            .collect();
        verify(&set, &params(parent, parent + 3), &entries);
    }

    #[test]
    fn witness_verifies_expiry_only() {
        let (set, parent) = populated();
        for gap in [1, 7, 29, 31, 1_000] {
            verify(&set, &params(parent, parent + gap), &[]);
        }
    }

    #[test]
    fn witness_verifies_single_bucket_and_empty_set() {
        let mut set = ExpiringNonceSet::default();
        verify(&set, &params(99, 100), &[entry(1, 150)]);
        set.apply(100, &[entry(1, 150)]).unwrap();
        // Deleting the only bucket empties the set.
        verify(&set, &params(100, 150), &[]);
        verify(&set, &params(100, 101), &[entry(2, 150), entry(3, 151)]);
    }

    #[test]
    fn witness_verifies_when_targets_bypass_root_extension() {
        // Buckets 1000 and 1001 share all but the last nibble, so the set trie's root is an
        // extension. Bucket 1200 diverges inside it, so its path never reaches the branch.
        let mut set = ExpiringNonceSet::default();
        set.apply(900, &[entry(1, 1000), entry(2, 1001)]).unwrap();
        verify(&set, &params(900, 901), &[entry(3, 1200)]);
        verify(&set, &params(900, 901), &[]);
        verify(&set, &params(900, 1000), &[entry(4, 1200)]);
    }

    #[test]
    fn removing_any_node_fails_the_proof() {
        let (set, parent) = populated();
        let block = params(parent, parent + 2);
        let entries = [entry(20_000, parent + 10), entry(20_001, parent + 25)];
        let nodes = set.witness(&block, &entries).unwrap();
        assert!(!nodes.is_empty());
        for i in 0..nodes.len() {
            let mut partial_nodes = nodes.clone();
            partial_nodes.remove(i);
            let result = PartialExpiringNonceSet::new(set.root(), partial_nodes)
                .and_then(|mut partial| partial.apply(&block, &entries));
            assert!(
                matches!(result, Err(WitnessError::MissingNode { .. })),
                "removing node {i} must fail the proof: {result:?}"
            );
        }
    }

    #[test]
    fn replay_is_rejected() {
        let (set, parent) = populated();
        // The 6th entry of the last block: still live.
        let live = entry(19 * 40 + 6, parent + 1 + 5);
        assert!(set.contains(&live));
        // A block that expires nothing, so the proof needs only the entry's paths.
        let block = params(parent, parent);
        let nodes = set.proof_nodes(&BTreeMap::from([
            (
                WitnessTrie::Set,
                BTreeSet::from([bucket_key(live.valid_before)]),
            ),
            (
                WitnessTrie::Bucket(live.valid_before),
                BTreeSet::from([live.hash]),
            ),
        ]));
        let result = PartialExpiringNonceSet::new(set.root(), nodes)
            .unwrap()
            .apply(&block, &[live]);
        assert!(
            matches!(result, Err(WitnessError::Replay { .. })),
            "{result:?}"
        );
        let fresh = entry(99_999, parent + 9);
        assert!(matches!(
            set.witness(&block, &[fresh, fresh]),
            Err(WitnessError::Replay { .. })
        ));
    }

    #[test]
    fn batch_of_blocks_verifies_with_merged_pool() {
        let (mut set, mut parent) = populated();
        // A non-empty root needs its root node.
        assert!(matches!(
            PartialExpiringNonceSet::new(set.root(), []),
            Err(WitnessError::MissingNode { .. })
        ));
        let mut partial: Option<PartialExpiringNonceSet> = None;
        let mut seed = 50_000;
        for _ in 0..6 {
            let block = params(parent, parent + 2);
            let entries: Vec<_> = (0..20)
                .map(|i| {
                    seed += 1;
                    entry(seed, block.timestamp + 1 + i % 10)
                })
                .collect();
            let nodes = set.witness(&block, &entries).unwrap();
            let partial = match partial.as_mut() {
                Some(partial) => {
                    partial.extend_pool(nodes);
                    partial
                }
                None => partial.insert(PartialExpiringNonceSet::new(set.root(), nodes).unwrap()),
            };
            let root = partial.apply(&block, &entries).unwrap();
            assert!(set.apply(block.timestamp, &entries).unwrap().is_empty());
            assert_eq!(root, set.root());
            parent = block.timestamp;
        }
    }

    #[test]
    fn window_is_enforced() {
        let set = ExpiringNonceSet::default();
        let block = params(99, 100);
        for valid_before in [100, 401] {
            let result = PartialExpiringNonceSet::new(set.root(), [])
                .unwrap()
                .apply(&block, &[entry(1, valid_before)]);
            assert!(matches!(result, Err(WitnessError::Expiry { .. })));
        }
    }
}
