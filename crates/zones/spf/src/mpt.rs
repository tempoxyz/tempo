//! Merkle Patricia Trie witness validation.
//!
//! The construction and read pattern is adapted from
//! [`paradigmxyz/stateless`'s `StatelessSparseTrie`](https://github.com/paradigmxyz/stateless/blob/3d2fc174df31f5b0d5d4d831dc7e1607ea541531/crates/tries/src/default.rs).
//! A flat witness is indexed by node hash, revealed into Reth's
//! [`reth_trie_sparse::SparseStateTrie`], and checked against the committed
//! pre-state root before it can serve reads.
//!
//! Read-only checkpoints use [`WitnessPathReader`] instead, which decodes only
//! the nodes on each read's path.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256, map::B256Map};
use reth_trie_common::{
    DecodedMultiProofV2, EMPTY_ROOT_HASH, HashedPostState, Nibbles, TrieAccount, TrieNode,
};
use reth_trie_sparse::{LeafUpdate, RevealableSparseTrie, SparseStateTrie, TrieNodeEpoch};

/// Fully revealed, root-bound stateless trie.
#[derive(Debug)]
pub(crate) struct StatelessSparseTrie {
    inner: SparseStateTrie,
}

impl StatelessSparseTrie {
    /// Construct and validate a sparse trie rooted at `state_root` from witness
    /// nodes indexed by [`index_witness_nodes`].
    pub(crate) fn new(
        state_root: B256,
        nodes: &B256Map<Bytes>,
    ) -> Result<Self, StatelessSparseTrieError> {
        let mut inner = SparseStateTrie::new();
        if state_root == EMPTY_ROOT_HASH {
            inner.set_accounts_trie(RevealableSparseTrie::revealed_empty());
            return Ok(Self { inner });
        }
        if !nodes.contains_key(&state_root) {
            return Err(StatelessSparseTrieError::MissingStateRootNode { state_root });
        }

        guarded(|| {
            let multiproof = DecodedMultiProofV2::from_witness(state_root, nodes)
                .map_err(|_| StatelessSparseTrieError::InvalidNodeEncoding)?;
            inner
                .reveal_decoded_multiproof_v2(multiproof)
                .map_err(|_| StatelessSparseTrieError::InvalidSparseTrie)?;

            let actual_root = inner
                .root(TrieNodeEpoch::UNMODIFIED)
                .map_err(|_| StatelessSparseTrieError::InvalidSparseTrie)?;
            if actual_root != state_root {
                return Err(StatelessSparseTrieError::StateRootMismatch {
                    expected: state_root,
                    actual: actual_root,
                });
            }

            Ok(Self { inner })
        })
    }

    /// Return the proven account, or `None` for a complete non-membership
    /// proof.
    pub(crate) fn account(
        &self,
        address: Address,
    ) -> Result<Option<TrieAccount>, StatelessSparseTrieError> {
        guarded(|| {
            let hashed_address = keccak256(address);
            if let Some(value) = self.inner.get_account_value(&hashed_address) {
                return decode_account(value, address).map(Some);
            }
            if !self.inner.is_account_revealed(hashed_address) {
                return Err(StatelessSparseTrieError::IncompleteAccountProof { account: address });
            }
            Ok(None)
        })
    }

    /// Return the proven storage value, or zero for a complete non-membership
    /// proof or an empty account storage trie.
    pub(crate) fn storage(
        &self,
        address: Address,
        slot: U256,
    ) -> Result<U256, StatelessSparseTrieError> {
        guarded(|| {
            let hashed_address = keccak256(address);
            let hashed_slot = keccak256(slot.to_be_bytes::<32>());
            if let Some(value) = self
                .inner
                .get_storage_slot_value(&hashed_address, &hashed_slot)
            {
                return decode_storage_value(value, address, slot);
            }

            let Some(account) = self.account(address)? else {
                return Ok(U256::ZERO);
            };
            if account.storage_root != EMPTY_ROOT_HASH
                && !self
                    .inner
                    .check_valid_storage_witness(hashed_address, hashed_slot)
            {
                return Err(StatelessSparseTrieError::IncompleteStorageProof {
                    account: address,
                    slot,
                });
            }
            Ok(U256::ZERO)
        })
    }

    /// Apply the supplied execution changes to this revealed state trie and
    /// calculate the resulting state root.
    pub(crate) fn calculate_state_root(
        &mut self,
        state: HashedPostState,
    ) -> Result<B256, StatelessSparseTrieError> {
        guarded(|| {
            let HashedPostState { accounts, storages } = state;
            let mut storage_updates = storages.into_iter().collect::<Vec<_>>();
            storage_updates.sort_unstable_by_key(|(address, _)| *address);

            let mut storage_roots = B256Map::default();
            for (hashed_address, storage) in storage_updates {
                let current_account = self.trie_account(hashed_address)?;
                let has_revealed_storage = self.inner.storage_trie_ref(&hashed_address).is_some();
                if current_account
                    .as_ref()
                    .is_some_and(|account| account.storage_root != EMPTY_ROOT_HASH)
                    && !has_revealed_storage
                {
                    return Err(StatelessSparseTrieError::IncompleteStateUpdate);
                }

                let mut storage_trie = self
                    .inner
                    .take_storage_trie(&hashed_address)
                    .unwrap_or_else(RevealableSparseTrie::revealed_empty);

                let mut updates = storage
                    .storage
                    .into_iter()
                    .map(|(slot, value)| {
                        let value = if value.is_zero() {
                            Vec::new()
                        } else {
                            alloy_rlp::encode_fixed_size(&value).to_vec()
                        };
                        (slot, LeafUpdate::Changed(value))
                    })
                    .collect::<B256Map<_>>();
                storage_trie
                    .update_leaves(&mut updates, |_, _| {})
                    .map_err(|_| StatelessSparseTrieError::InvalidSparseTrie)?;
                if !updates.is_empty() {
                    return Err(StatelessSparseTrieError::IncompleteStateUpdate);
                }

                let storage_root = storage_trie
                    .root(TrieNodeEpoch::UNMODIFIED)
                    .ok_or(StatelessSparseTrieError::InvalidSparseTrie)?;
                self.inner.insert_storage_trie(hashed_address, storage_trie);
                storage_roots.insert(hashed_address, storage_root);
            }

            let mut account_updates = B256Map::default();
            for (hashed_address, account) in accounts {
                let update = match account {
                    Some(account) => {
                        let storage_root = storage_roots.remove(&hashed_address).unwrap_or(
                            self.trie_account(hashed_address)?
                                .map(|account| account.storage_root)
                                .unwrap_or(EMPTY_ROOT_HASH),
                        );
                        LeafUpdate::Changed(alloy_rlp::encode(
                            account.into_trie_account(storage_root),
                        ))
                    }
                    None => {
                        storage_roots.remove(&hashed_address);
                        LeafUpdate::Changed(Vec::new())
                    }
                };
                account_updates.insert(hashed_address, update);
            }

            for (hashed_address, storage_root) in storage_roots {
                let Some(mut account) = self.trie_account(hashed_address)? else {
                    return Err(StatelessSparseTrieError::IncompleteStateUpdate);
                };
                account.storage_root = storage_root;
                account_updates.insert(
                    hashed_address,
                    LeafUpdate::Changed(alloy_rlp::encode(account)),
                );
            }

            self.inner
                .trie_mut()
                .update_leaves(&mut account_updates, |_, _| {})
                .map_err(|_| StatelessSparseTrieError::InvalidSparseTrie)?;
            if !account_updates.is_empty() {
                return Err(StatelessSparseTrieError::IncompleteStateUpdate);
            }

            self.inner
                .root(TrieNodeEpoch::UNMODIFIED)
                .map_err(|_| StatelessSparseTrieError::InvalidSparseTrie)
        })
    }

    fn trie_account(
        &self,
        hashed_address: B256,
    ) -> Result<Option<TrieAccount>, StatelessSparseTrieError> {
        self.inner
            .get_account_value(&hashed_address)
            .map(|value| decode_hashed_account(value))
            .transpose()
    }
}

/// Read-only view of the state committed by `state_root`, served from a witness
/// node pool by walking each read's path from the root.
///
/// Nodes are looked up by their keccak hash, so every node on a path is bound
/// to the root. Only the nodes on the read's path are decoded, so a read costs
/// the same however many other nodes the pool holds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WitnessPathReader<'a> {
    /// Root every read starts from.
    state_root: B256,
    /// Witness nodes keyed by the keccak hash of their encoding, from
    /// [`decode_witness_nodes`].
    nodes: &'a B256Map<TrieNode>,
}

impl<'a> WitnessPathReader<'a> {
    /// Create a reader for `state_root` over nodes decoded by
    /// [`decode_witness_nodes`].
    pub(crate) const fn new(state_root: B256, nodes: &'a B256Map<TrieNode>) -> Self {
        Self { state_root, nodes }
    }

    /// Return the proven account, or `None` for a complete non-membership
    /// proof.
    pub(crate) fn account(
        &self,
        address: Address,
    ) -> Result<Option<TrieAccount>, StatelessSparseTrieError> {
        match self.walk(self.state_root, keccak256(address))? {
            PathEnd::Leaf(value) => decode_account(&value, address).map(Some),
            PathEnd::Absent => Ok(None),
            PathEnd::Blinded => {
                Err(StatelessSparseTrieError::IncompleteAccountProof { account: address })
            }
        }
    }

    /// Return the proven storage value, or zero for a complete non-membership
    /// proof or an absent account.
    pub(crate) fn storage(
        &self,
        address: Address,
        slot: U256,
    ) -> Result<U256, StatelessSparseTrieError> {
        let Some(account) = self.account(address)? else {
            return Ok(U256::ZERO);
        };
        match self.walk(account.storage_root, keccak256(slot.to_be_bytes::<32>()))? {
            PathEnd::Leaf(value) => decode_storage_value(&value, address, slot),
            PathEnd::Absent => Ok(U256::ZERO),
            PathEnd::Blinded => Err(StatelessSparseTrieError::IncompleteStorageProof {
                account: address,
                slot,
            }),
        }
    }

    /// Follow `key` from `root` until it ends at a leaf, proves absence, or
    /// reaches a node the pool does not hold.
    fn walk(&self, root: B256, key: B256) -> Result<PathEnd, StatelessSparseTrieError> {
        if root == EMPTY_ROOT_HASH {
            return Ok(PathEnd::Absent);
        }
        let Some(mut node) = self.nodes.get(&root) else {
            return Ok(PathEnd::Blinded);
        };
        let path = Nibbles::unpack(key);
        let mut depth = 0;
        // Holds a child embedded in its parent's encoding, which has no pool entry.
        let mut inline;
        loop {
            let child = match node {
                TrieNode::EmptyRoot => return Ok(PathEnd::Absent),
                TrieNode::Leaf(leaf) => {
                    let rest = path.slice(depth..);
                    if leaf.key.len() != rest.len() {
                        return Err(StatelessSparseTrieError::InvalidSparseTrie);
                    }
                    return Ok(if leaf.key == rest {
                        PathEnd::Leaf(leaf.value.clone())
                    } else {
                        PathEnd::Absent
                    });
                }
                TrieNode::Extension(extension) => {
                    if !path.slice(depth..).starts_with(&extension.key) {
                        return Ok(PathEnd::Absent);
                    }
                    depth += extension.key.len();
                    &extension.child
                }
                TrieNode::Branch(branch) => {
                    if depth == path.len() {
                        return Err(StatelessSparseTrieError::InvalidSparseTrie);
                    }
                    let nibble = path.get_unchecked(depth);
                    depth += 1;
                    if !branch.state_mask.is_bit_set(nibble) {
                        return Ok(PathEnd::Absent);
                    }
                    // Children are stored in nibble order for the set bits of the mask. Decoding
                    // builds the mask from the present children, so the stack always matches it.
                    let index = (branch.state_mask.get() & ((1 << nibble) - 1)).count_ones();
                    branch
                        .stack
                        .get(index as usize)
                        .ok_or(StatelessSparseTrieError::InvalidSparseTrie)?
                }
            };
            node = match child.as_hash() {
                Some(hash) => match self.nodes.get(&hash) {
                    Some(node) => node,
                    None => return Ok(PathEnd::Blinded),
                },
                None => {
                    inline = alloy_rlp::decode_exact::<TrieNode>(child.as_ref())
                        .map_err(|_| StatelessSparseTrieError::InvalidNodeEncoding)?;
                    &inline
                }
            };
        }
    }
}

/// Where a key's path from a root ends.
enum PathEnd {
    /// The leaf for the key, holding its value.
    Leaf(Vec<u8>),
    /// The trie proves the key is absent.
    Absent,
    /// The path reaches a node the pool does not hold.
    Blinded,
}

fn decode_account(value: &[u8], address: Address) -> Result<TrieAccount, StatelessSparseTrieError> {
    alloy_rlp::decode_exact(value)
        .map_err(|_| StatelessSparseTrieError::InvalidAccountValue { account: address })
}

fn decode_storage_value(
    value: &[u8],
    account: Address,
    slot: U256,
) -> Result<U256, StatelessSparseTrieError> {
    alloy_rlp::decode_exact(value)
        .map_err(|_| StatelessSparseTrieError::InvalidStorageValue { account, slot })
}

fn decode_hashed_account(value: &[u8]) -> Result<TrieAccount, StatelessSparseTrieError> {
    alloy_rlp::decode_exact(value).map_err(|_| StatelessSparseTrieError::InvalidSparseTrie)
}

/// Index a flat witness node pool by node hash, rejecting duplicate nodes.
pub(crate) fn index_witness_nodes(
    node_pool: &[Bytes],
) -> Result<B256Map<Bytes>, StatelessSparseTrieError> {
    // This is the flat-witness indexing step from `StatelessSparseTrie`.
    let mut nodes = B256Map::default();
    for node in node_pool {
        let node_hash = keccak256(node);
        if nodes.insert(node_hash, node.clone()).is_some() {
            return Err(StatelessSparseTrieError::DuplicateNodeHash { node_hash });
        }
    }
    Ok(nodes)
}

/// Decode every node of a pool indexed by [`index_witness_nodes`] once, keyed by
/// the same hashes, so reads walk decoded nodes instead of decoding them again.
pub(crate) fn decode_witness_nodes(
    nodes: &B256Map<Bytes>,
) -> Result<B256Map<TrieNode>, StatelessSparseTrieError> {
    nodes
        .iter()
        .map(|(hash, bytes)| {
            let node = alloy_rlp::decode_exact(bytes)
                .map_err(|_| StatelessSparseTrieError::InvalidNodeEncoding)?;
            Ok((*hash, node))
        })
        .collect()
}

/// The pinned Reth helper assumes internally consistent paths in a few places.
/// Convert any invariant panic caused by untrusted RLP into an ordinary witness
/// error.
fn guarded<T>(
    operation: impl FnOnce() -> Result<T, StatelessSparseTrieError>,
) -> Result<T, StatelessSparseTrieError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .unwrap_or(Err(StatelessSparseTrieError::InvalidSparseTrie))
}

/// Errors emitted while constructing or reading a stateless sparse trie.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatelessSparseTrieError {
    /// `node_pool` is not deduplicated by node hash.
    #[error("duplicate trie node hash in witness: {node_hash:?}")]
    DuplicateNodeHash { node_hash: B256 },
    /// A trie node needed to reconstruct the supplied proof is not valid RLP.
    #[error("invalid RLP-encoded trie node in witness")]
    InvalidNodeEncoding,
    /// The node pool does not provide the node committed by the state root.
    #[error("state root is absent from the node pool: {state_root:?}")]
    MissingStateRootNode { state_root: B256 },
    /// Reth rejected the witness while reconstructing the sparse trie.
    #[error("state witness is not a valid sparse trie proof")]
    InvalidSparseTrie,
    /// The reconstructed trie does not hash to the committed state root.
    #[error("state root mismatch: expected {expected:?}, got {actual:?}")]
    StateRootMismatch { expected: B256, actual: B256 },
    /// The witness does not reveal a complete account proof for an execution
    /// read.
    #[error("incomplete account proof for {account:?}")]
    IncompleteAccountProof { account: Address },
    /// A revealed account leaf is not a canonical trie account value.
    #[error("invalid account leaf for {account:?}")]
    InvalidAccountValue { account: Address },
    /// The witness does not reveal a complete storage proof for an execution
    /// read.
    #[error("incomplete storage proof for {account:?} at {slot:?}")]
    IncompleteStorageProof { account: Address, slot: U256 },
    /// A revealed storage leaf is not an RLP-encoded `U256`.
    #[error("invalid storage leaf for {account:?} at {slot:?}")]
    InvalidStorageValue { account: Address, slot: U256 },
    /// The execution changed an account or storage path not completely revealed
    /// by the witness.
    #[error("incomplete witness for an executed state update")]
    IncompleteStateUpdate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_trie_common::{
        BranchNode, ExtensionNode, HashBuilder, LeafNode, RlpNode, TrieMask, proof::ProofRetainer,
    };
    use std::collections::BTreeMap;

    /// Builds the trie over `leaves` and returns its root with the proof nodes for `targets`.
    fn prove(leaves: &BTreeMap<B256, Vec<u8>>, targets: &[B256]) -> (B256, Vec<Bytes>) {
        let retainer = ProofRetainer::new(targets.iter().map(|key| Nibbles::unpack(key)).collect());
        let mut builder = HashBuilder::default().with_proof_retainer(retainer);
        for (key, value) in leaves {
            builder.add_leaf(Nibbles::unpack(key), value);
        }
        let root = builder.root();
        let nodes = builder
            .take_proof_nodes()
            .into_nodes_sorted()
            .into_iter()
            .map(|(_, node)| node)
            .collect();
        (root, nodes)
    }

    #[test]
    fn path_reader_matches_sparse_trie() {
        let slot_key = |slot: u64| keccak256(U256::from(slot).to_be_bytes::<32>());
        let storage = (1..=64u64)
            .map(|slot| (slot_key(slot), alloy_rlp::encode(U256::from(slot * 1_000))))
            .collect::<BTreeMap<_, _>>();
        let slots = [U256::from(7), U256::from(64), U256::from(1_000)];
        let (storage_root, storage_nodes) = prove(
            &storage,
            &slots.map(|slot| keccak256(slot.to_be_bytes::<32>())),
        );

        let address = |index: u64| Address::left_padding_from(&index.to_be_bytes());
        let with_storage = address(1_000_000);
        let mut accounts = (0..500u64)
            .map(|index| {
                let account = TrieAccount {
                    nonce: index,
                    balance: U256::from(index),
                    ..Default::default()
                };
                (keccak256(address(index)), alloy_rlp::encode(account))
            })
            .collect::<BTreeMap<_, _>>();
        accounts.insert(
            keccak256(with_storage),
            alloy_rlp::encode(TrieAccount {
                storage_root,
                ..Default::default()
            }),
        );
        let read = [address(3), address(499), address(9_999), with_storage];
        let (state_root, account_nodes) = prove(&accounts, &read.map(keccak256));

        let pool = account_nodes
            .iter()
            .chain(&storage_nodes)
            .cloned()
            .collect::<Vec<_>>();
        let nodes = index_witness_nodes(&pool).unwrap();
        let decoded = decode_witness_nodes(&nodes).unwrap();
        let reader = WitnessPathReader::new(state_root, &decoded);
        let trie = StatelessSparseTrie::new(state_root, &nodes).unwrap();
        for address in read {
            assert_eq!(reader.account(address), trie.account(address));
        }
        assert_eq!(reader.account(address(3)).unwrap().unwrap().nonce, 3);
        assert_eq!(reader.account(address(9_999)), Ok(None));
        for slot in slots {
            assert_eq!(
                reader.storage(with_storage, slot),
                trie.storage(with_storage, slot)
            );
        }
        assert_eq!(
            reader.storage(with_storage, U256::from(7)),
            Ok(U256::from(7_000))
        );
        assert_eq!(
            reader.storage(with_storage, U256::from(1_000)),
            Ok(U256::ZERO)
        );
        assert_eq!(
            reader.storage(address(9_999), U256::from(7)),
            Ok(U256::ZERO)
        );

        // Without the storage proof the account still resolves, but its slots do not.
        let account_only =
            decode_witness_nodes(&index_witness_nodes(&account_nodes).unwrap()).unwrap();
        let reader = WitnessPathReader::new(state_root, &account_only);
        assert!(reader.account(with_storage).unwrap().is_some());
        assert_eq!(
            reader.storage(with_storage, U256::from(7)),
            Err(StatelessSparseTrieError::IncompleteStorageProof {
                account: with_storage,
                slot: U256::from(7),
            })
        );

        // A path through a node missing from the pool is an incomplete proof.
        let root_only = decoded
            .iter()
            .filter(|(hash, _)| **hash == state_root)
            .map(|(hash, node)| (*hash, node.clone()))
            .collect::<B256Map<_>>();
        assert_eq!(
            WitnessPathReader::new(state_root, &root_only).account(address(3)),
            Err(StatelessSparseTrieError::IncompleteAccountProof {
                account: address(3)
            })
        );
        assert_eq!(
            WitnessPathReader::new(EMPTY_ROOT_HASH, &B256Map::default()).account(address(3)),
            Ok(None)
        );
    }

    /// Indexes `nodes` by hash and returns the first node's hash as the root.
    fn pool(nodes: &[TrieNode]) -> (B256, B256Map<TrieNode>) {
        let nodes = nodes
            .iter()
            .map(|node| Bytes::from(alloy_rlp::encode(node)))
            .collect::<Vec<_>>();
        let decoded = decode_witness_nodes(&index_witness_nodes(&nodes).unwrap()).unwrap();
        (keccak256(&nodes[0]), decoded)
    }

    #[test]
    fn path_reader_rejects_invalid_node_encoding() {
        let mut leaf = alloy_rlp::encode(TrieNode::Leaf(LeafNode::new(
            Nibbles::unpack(keccak256(Address::ZERO)),
            vec![0x80],
        )));
        leaf.push(0x80);
        for invalid in [vec![0xc2, 0x80], leaf] {
            let invalid = Bytes::from(invalid);
            let root = keccak256(&invalid);
            let nodes = B256Map::from_iter([(root, invalid)]);
            assert_eq!(
                decode_witness_nodes(&nodes),
                Err(StatelessSparseTrieError::InvalidNodeEncoding)
            );
        }
    }

    #[test]
    fn path_reader_rejects_leaf_not_ending_at_full_depth() {
        let (root, nodes) = pool(&[TrieNode::Leaf(LeafNode::new(
            Nibbles::from_nibbles([1, 2, 3]),
            vec![0x80],
        ))]);
        assert_eq!(
            WitnessPathReader::new(root, &nodes).account(Address::ZERO),
            Err(StatelessSparseTrieError::InvalidSparseTrie)
        );
    }

    #[test]
    fn path_reader_rejects_branch_past_full_depth() {
        let branch = TrieNode::Branch(BranchNode::new(
            vec![
                RlpNode::word_rlp(&B256::ZERO),
                RlpNode::word_rlp(&B256::ZERO),
            ],
            TrieMask::new(0b11),
        ));
        let extension = TrieNode::Extension(ExtensionNode::new(
            Nibbles::unpack(keccak256(Address::ZERO)),
            RlpNode::from_rlp(&alloy_rlp::encode(&branch)),
        ));
        let (root, nodes) = pool(&[extension, branch]);
        assert_eq!(
            WitnessPathReader::new(root, &nodes).account(Address::ZERO),
            Err(StatelessSparseTrieError::InvalidSparseTrie)
        );
    }

    #[test]
    fn account_decoders_require_exact_rlp_and_preserve_errors() {
        let address = Address::repeat_byte(0x42);
        let account = TrieAccount {
            nonce: 7,
            balance: U256::MAX,
            ..Default::default()
        };
        let encoded = alloy_rlp::encode(&account);
        assert_eq!(decode_account(&encoded, address), Ok(account.clone()));
        assert_eq!(decode_hashed_account(&encoded), Ok(account));

        let mut invalid = (0..encoded.len())
            .map(|len| encoded[..len].to_vec())
            .collect::<Vec<_>>();
        for suffix in [&[0][..], &[0x80][..], encoded.as_slice()] {
            invalid.push([encoded.as_slice(), suffix].concat());
        }
        for bytes in invalid {
            assert_eq!(
                decode_account(&bytes, address),
                Err(StatelessSparseTrieError::InvalidAccountValue { account: address })
            );
            assert_eq!(
                decode_hashed_account(&bytes),
                Err(StatelessSparseTrieError::InvalidSparseTrie)
            );
        }
    }

    #[test]
    fn storage_decoder_requires_exact_rlp_and_preserves_error_context() {
        let account = Address::repeat_byte(0x42);
        let slot = U256::from(17);
        for value in [U256::ZERO, U256::from(127), U256::from(128), U256::MAX] {
            let encoded = alloy_rlp::encode(value);
            assert_eq!(decode_storage_value(&encoded, account, slot), Ok(value));
            let mut invalid = (0..encoded.len())
                .map(|len| encoded[..len].to_vec())
                .collect::<Vec<_>>();
            invalid.push([encoded.as_slice(), &[0x80]].concat());
            for bytes in invalid {
                assert_eq!(
                    decode_storage_value(&bytes, account, slot),
                    Err(StatelessSparseTrieError::InvalidStorageValue { account, slot })
                );
            }
        }
        // A non-canonical integer must remain invalid too.
        assert_eq!(
            decode_storage_value(&[0x81, 0x01], account, slot),
            Err(StatelessSparseTrieError::InvalidStorageValue { account, slot })
        );
    }
}
