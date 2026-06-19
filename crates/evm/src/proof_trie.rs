//! Provable Contract Trie input helpers.
//!
//! TIP-1082 proof roots are computed by feeding provable-account updates into a sparse MPT and
//! using the same trie-root machinery as the canonical state root. This slice intentionally has no
//! migrated accounts and an empty active whitelist, so the proof trie input has no account leaves.

use alloy_primitives::Address;
use reth_trie_common::TrieInput;

/// Builds the sparse MPT input for the active TIP-1082 provable-account whitelist.
///
/// A non-empty whitelist requires the persisted proof-trie stream/migration path, which is outside
/// this implementation slice. Returning `None` makes callers fail closed instead of deriving a root
/// from an incomplete one-block snapshot.
pub fn proof_trie_input_for_provable_accounts(provable_accounts: &[Address]) -> Option<TrieInput> {
    provable_accounts.is_empty().then(TrieInput::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_whitelist_uses_empty_sparse_trie_input() {
        let input =
            proof_trie_input_for_provable_accounts(&[]).expect("empty whitelist is supported");

        assert!(input.state.accounts.is_empty());
        assert!(input.state.storages.is_empty());
        assert!(input.nodes.account_nodes.is_empty());
        assert!(input.nodes.storage_tries.is_empty());
    }

    #[test]
    fn non_empty_whitelist_requires_persisted_proof_trie_stream() {
        assert!(proof_trie_input_for_provable_accounts(&[Address::repeat_byte(0x11)]).is_none());
    }
}
