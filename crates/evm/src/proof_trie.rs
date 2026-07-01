//! Provable Contract Trie input helpers.
//!
//! TIP-1082 proof roots are computed by filtering the post-execution bundle state to the active
//! provable-account whitelist, hashing that filtered state, and feeding it into the sparse MPT root
//! pipeline. Whitelist membership alone never creates an account leaf; only changed whitelisted
//! accounts present in the bundle state are streamed as proof-trie updates.

use alloy_primitives::{Address, map::AddressMap};
use reth_errors::ProviderResult;
use reth_revm::db::states::{BundleAccount, BundleState};
use reth_storage_api::HashedPostStateProvider;
use reth_trie_common::{HashedPostState, HashedStorage, KeccakKeyHasher, KeyHasher, TrieInput};

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
            let account = bundle_state.account(address)?;
            has_provable_state_update(account).then(|| (*address, account.clone()))
        })
        .collect()
}

/// Hashes whitelisted bundle-state updates for the TIP-1082 proof trie.
pub fn proof_hashed_state_from_bundle_state(
    bundle_state: &BundleState,
    provable_accounts: &[Address],
) -> HashedPostState {
    let mut hashed_state = HashedPostState::with_capacity(provable_accounts.len());

    for address in provable_accounts {
        let Some(account) = bundle_state.account(address) else {
            continue;
        };

        let hashed_address = KeccakKeyHasher::hash_key(address);

        if account.is_info_changed() {
            hashed_state
                .accounts
                .insert(hashed_address, account.info.as_ref().map(Into::into));
        }

        let mut changed_storage = account
            .storage
            .iter()
            .filter(|(_, slot)| slot.is_changed())
            .map(|(slot, value)| {
                (
                    KeccakKeyHasher::hash_key(&alloy_primitives::B256::from(*slot)),
                    value.present_value,
                )
            })
            .peekable();

        if account.was_destroyed() {
            hashed_state
                .storages
                .insert(hashed_address, HashedStorage::new(true));
        } else if changed_storage.peek().is_some() {
            hashed_state.storages.insert(
                hashed_address,
                HashedStorage::from_iter(false, changed_storage),
            );
        }
    }

    hashed_state
}

/// Loads full whitelisted proof-trie state and overlays whitelisted bundle-state updates.
pub fn proof_hashed_state_from_provider_and_bundle(
    provider: &impl HashedPostStateProvider,
    bundle_state: &BundleState,
    provable_accounts: &[Address],
) -> ProviderResult<HashedPostState> {
    let mut state = provider.hashed_post_state_for_accounts(provable_accounts)?;
    state.extend(proof_hashed_state_from_bundle_state(
        bundle_state,
        provable_accounts,
    ));
    Ok(state)
}

fn has_provable_state_update(account: &BundleAccount) -> bool {
    account.is_info_changed()
        || account.was_destroyed()
        || account.storage.values().any(|slot| slot.is_changed())
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
    fn read_only_whitelisted_account_is_not_hashed() {
        let address = Address::repeat_byte(0x11);
        let account = BundleAccount::new(
            Some(account(1)),
            Some(account(1)),
            [(U256::from(1), StorageSlot::new(U256::from(7)))]
                .into_iter()
                .collect(),
            AccountStatus::Loaded,
        );
        let bundle_state = bundle_state([(address, account)]);

        let filtered = filter_bundle_state_for_provable_accounts(&bundle_state, &[address]);
        let hashed = proof_hashed_state_from_bundle_state(&bundle_state, &[address]);
        let input = proof_trie_input_from_bundle_state(&bundle_state, &[address]);

        assert!(filtered.is_empty());
        assert!(hashed.is_empty());
        assert!(input.state.is_empty());
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

        assert!(!hashed.accounts.contains_key(&hashed_address));
        assert!(hashed.storages.contains_key(&hashed_address));
    }

    #[test]
    fn unchanged_whitelisted_storage_slot_is_not_hashed() {
        let address = Address::repeat_byte(0x11);
        let slot = U256::from(1);
        let account = BundleAccount::new(
            Some(account(1)),
            Some(account(1)),
            [(slot, StorageSlot::new(U256::from(7)))]
                .into_iter()
                .collect(),
            AccountStatus::Changed,
        );
        let bundle_state = bundle_state([(address, account)]);

        let hashed = proof_hashed_state_from_bundle_state(&bundle_state, &[address]);

        assert!(hashed.is_empty());
    }

    #[test]
    fn storage_update_without_account_info_change_does_not_hash_account_leaf() {
        let address = Address::repeat_byte(0x11);
        let slot = U256::from(1);
        let account = BundleAccount::new(
            Some(account(1)),
            Some(account(1)),
            [(slot, StorageSlot::new_changed(U256::ZERO, U256::from(7)))]
                .into_iter()
                .collect(),
            AccountStatus::Changed,
        );
        let bundle_state = bundle_state([(address, account)]);
        let hashed_address = keccak256(address);

        let hashed = proof_hashed_state_from_bundle_state(&bundle_state, &[address]);

        assert!(!hashed.accounts.contains_key(&hashed_address));
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
