//! Merkle Patricia Trie witness validation.
//!
//! The construction and read pattern is adapted from
//! [`paradigmxyz/stateless`'s `StatelessSparseTrie`](https://github.com/paradigmxyz/stateless/blob/3d2fc174df31f5b0d5d4d831dc7e1607ea541531/crates/tries/src/default.rs).
//! A flat witness is indexed by node hash, revealed into Reth's
//! [`reth_trie_sparse::SparseStateTrie`], and checked against the committed
//! pre-state root before it can serve reads.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256, map::B256Map};
use reth_trie_common::{DecodedMultiProofV2, EMPTY_ROOT_HASH, HashedPostState, TrieAccount};
use reth_trie_sparse::{LeafUpdate, RevealableSparseTrie, SparseStateTrie, TrieNodeEpoch};

/// Fully revealed, root-bound stateless trie.
#[derive(Debug)]
pub(crate) struct StatelessSparseTrie {
    inner: SparseStateTrie,
}

impl StatelessSparseTrie {
    /// Construct and validate a sparse trie from a flat witness node pool.
    pub(crate) fn new(
        state_root: B256,
        node_pool: &[Bytes],
    ) -> Result<Self, StatelessSparseTrieError> {
        // This is the flat-witness indexing step from `StatelessSparseTrie`.
        let mut nodes = B256Map::default();

        for node in node_pool {
            let node_hash = keccak256(node);
            if nodes.insert(node_hash, node.clone()).is_some() {
                return Err(StatelessSparseTrieError::DuplicateNodeHash { node_hash });
            }
        }

        let mut inner = SparseStateTrie::new();
        if state_root == EMPTY_ROOT_HASH {
            inner.set_accounts_trie(RevealableSparseTrie::revealed_empty());
            return Ok(Self { inner });
        }
        if !nodes.contains_key(&state_root) {
            return Err(StatelessSparseTrieError::MissingStateRootNode { state_root });
        }

        guarded(|| {
            let multiproof = DecodedMultiProofV2::from_witness(state_root, &nodes)
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

    #[test]
    fn account_decoders_require_exact_rlp_and_preserve_errors() {
        let address = Address::repeat_byte(0x42);
        let account = TrieAccount {
            nonce: 7,
            balance: U256::MAX,
            ..Default::default()
        };
        let encoded = alloy_rlp::encode(account);
        assert_eq!(decode_account(&encoded, address), Ok(account));
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
