//! Provable Contract Trie input helpers.
//!
//! TIP-1082 proof roots are computed by filtering the post-execution bundle state to the active
//! provable-account whitelist, hashing that filtered state, and feeding it into the sparse MPT root
//! pipeline. Whitelist membership alone never creates an account leaf; only changed whitelisted
//! accounts present in the bundle state are streamed as proof-trie updates.

use alloy_primitives::{Address, map::AddressMap};
use reth_revm::db::states::{BundleAccount, BundleState};
use reth_trie_common::{HashedPostState, KeccakKeyHasher, TrieInput};

/// Returns the subset of `bundle_state` that should be streamed into the TIP-1082 proof trie.
///
/// Accounts outside `provable_accounts` are ignored. Whitelisted accounts that are absent from the
/// bundle state are also ignored; the sparse proof trie already carries their parent state.
pub fn filter_bundle_state_for_provable_accounts(
    bundle_state: &BundleState,
    provable_accounts: &[Address],
) -> AddressMap<BundleAccount> {
    provable_accounts
        .iter()
        .filter_map(|address| {
            bundle_state
                .account(address)
                .cloned()
                .map(|account| (*address, account))
        })
        .collect()
}

/// Hashes whitelisted bundle-state updates for the TIP-1082 proof trie.
pub fn proof_hashed_state_from_bundle_state(
    bundle_state: &BundleState,
    provable_accounts: &[Address],
) -> HashedPostState {
    let filtered = filter_bundle_state_for_provable_accounts(bundle_state, provable_accounts);
    HashedPostState::from_bundle_state::<KeccakKeyHasher>(&filtered)
}

/// Builds sparse MPT input from whitelisted bundle-state updates.
pub fn proof_trie_input_from_bundle_state(
    bundle_state: &BundleState,
    provable_accounts: &[Address],
) -> TrieInput {
    TrieInput::from_state(proof_hashed_state_from_bundle_state(
        bundle_state,
        provable_accounts,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, keccak256};
    use reth_revm::{
        db::states::{AccountStatus, StorageSlot},
        state::AccountInfo,
    };

    fn account(nonce: u64) -> AccountInfo {
        AccountInfo {
            nonce,
            balance: U256::from(nonce + 1),
            code_hash: Default::default(),
            account_id: None,
            code: None,
        }
    }

    fn bundle_account(nonce: u64) -> BundleAccount {
        BundleAccount::new(
            None,
            Some(account(nonce)),
            Default::default(),
            AccountStatus::Changed,
        )
    }

    fn bundle_state(accounts: impl IntoIterator<Item = (Address, BundleAccount)>) -> BundleState {
        let state = AddressMap::from_iter(accounts);
        let state_size = state.values().map(BundleAccount::size_hint).sum();
        BundleState {
            state,
            contracts: Default::default(),
            reverts: Default::default(),
            state_size,
            reverts_size: 0,
        }
    }

    #[test]
    fn empty_whitelist_uses_empty_sparse_trie_input() {
        let address = Address::repeat_byte(0x11);
        let bundle_state = bundle_state([(address, bundle_account(1))]);

        let input = proof_trie_input_from_bundle_state(&bundle_state, &[]);

        assert!(input.state.accounts.is_empty());
        assert!(input.state.storages.is_empty());
        assert!(input.nodes.account_nodes.is_empty());
        assert!(input.nodes.storage_tries.is_empty());
    }

    #[test]
    fn filters_bundle_state_to_whitelisted_accounts_before_hashing() {
        let whitelisted = Address::repeat_byte(0x11);
        let other = Address::repeat_byte(0x22);
        let bundle_state =
            bundle_state([(whitelisted, bundle_account(1)), (other, bundle_account(2))]);

        let filtered = filter_bundle_state_for_provable_accounts(&bundle_state, &[whitelisted]);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key(&whitelisted));
        assert!(!filtered.contains_key(&other));

        let hashed = proof_hashed_state_from_bundle_state(&bundle_state, &[whitelisted]);
        assert!(hashed.accounts.contains_key(&keccak256(whitelisted)));
        assert!(!hashed.accounts.contains_key(&keccak256(other)));
    }

    #[test]
    fn whitelisted_account_absent_from_bundle_state_is_not_inserted() {
        let whitelisted = Address::repeat_byte(0x11);
        let other = Address::repeat_byte(0x22);
        let bundle_state = bundle_state([(other, bundle_account(2))]);

        let hashed = proof_hashed_state_from_bundle_state(&bundle_state, &[whitelisted]);
        assert!(hashed.is_empty());
    }

    #[test]
    fn whitelisted_storage_update_is_hashed() {
        let address = Address::repeat_byte(0x11);
        let slot = U256::from(1);
        let value = U256::from(2);
        let account = BundleAccount::new(
            Some(account(1)),
            Some(account(1)),
            [(slot, StorageSlot::new_changed(U256::ZERO, value))]
                .into_iter()
                .collect(),
            AccountStatus::Changed,
        );
        let bundle_state = bundle_state([(address, account)]);

        let hashed = proof_hashed_state_from_bundle_state(&bundle_state, &[address]);
        let hashed_address = keccak256(address);

        assert!(hashed.accounts.contains_key(&hashed_address));
        assert!(hashed.storages.contains_key(&hashed_address));
    }

    #[test]
    fn destroyed_whitelisted_account_is_hashed_as_deletion() {
        let address = Address::repeat_byte(0x11);
        let account = BundleAccount::new(
            Some(account(1)),
            None,
            [(
                U256::from(1),
                StorageSlot::new_changed(U256::from(7), U256::ZERO),
            )]
            .into_iter()
            .collect(),
            AccountStatus::Destroyed,
        );
        let bundle_state = bundle_state([(address, account)]);

        let hashed = proof_hashed_state_from_bundle_state(&bundle_state, &[address]);
        let hashed_address = keccak256(address);

        assert_eq!(hashed.accounts.get(&hashed_address), Some(&None));
        assert!(
            hashed
                .storages
                .get(&hashed_address)
                .is_some_and(|storage| storage.wiped)
        );
    }
}
