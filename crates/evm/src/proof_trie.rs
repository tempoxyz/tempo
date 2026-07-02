//! Provable Contract Trie helpers.
//!
//! TIP-1082 proof roots are computed over a standalone secure MPT that only contains the active
//! provable-account whitelist. This module provides both the old bundle-update filtering helpers
//! and the no-persistence path, which rebuilds the whitelisted account trie from the parent state
//! provider plus the post-execution bundle state.

use alloy_consensus::constants::EMPTY_ROOT_HASH;
use alloy_primitives::{Address, B256, map::AddressMap};
use reth_primitives_traits::Account;
use reth_revm::db::states::{BundleAccount, BundleState};
use reth_storage_api::{StateProvider, errors::provider::ProviderResult};
use reth_trie_common::{
    HashedPostState, HashedStorage, KeccakKeyHasher, TrieInput, root::state_root_unhashed,
};

/// Root of an empty TIP-1082 proof trie.
pub const EMPTY_PROOF_ROOT_HASH: B256 = EMPTY_ROOT_HASH;

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

/// Recomputes the TIP-1082 proof root from canonical parent state and the current bundle state.
///
/// This does not rely on persisted proof-trie nodes. For every active whitelisted account, it
/// materializes the post-execution account leaf, computes that account's post-execution storage
/// root through the canonical state provider, and builds a fresh whitelist-only account trie.
pub fn proof_root_from_state_provider(
    state_provider: &(impl StateProvider + ?Sized),
    bundle_state: &BundleState,
    provable_accounts: &[Address],
) -> ProviderResult<B256> {
    proof_root_from_accounts(state_provider, provable_accounts, |address| {
        proof_account_from_state_provider(state_provider, bundle_state, address)
    })
}

/// Recomputes the TIP-1082 proof root from canonical parent state and hashed post-state updates.
///
/// This is the validation-side equivalent of [`proof_root_from_state_provider`]. Reth's engine
/// validation hook exposes hashed post-state updates instead of the original bundle state, so this
/// applies whitelisted account/storage deltas by hashed address while reading unchanged account
/// leaves from the parent state provider.
pub fn proof_root_from_hashed_post_state(
    state_provider: &(impl StateProvider + ?Sized),
    hashed_post_state: &HashedPostState,
    provable_accounts: &[Address],
) -> ProviderResult<B256> {
    proof_root_from_accounts(state_provider, provable_accounts, |address| {
        proof_account_from_hashed_post_state(state_provider, hashed_post_state, address)
    })
}

fn proof_root_from_accounts(
    state_provider: &(impl StateProvider + ?Sized),
    provable_accounts: &[Address],
    mut proof_account: impl FnMut(Address) -> ProviderResult<(Option<Account>, HashedStorage)>,
) -> ProviderResult<B256> {
    let mut accounts = Vec::with_capacity(provable_accounts.len());

    for address in provable_accounts {
        let (account, hashed_storage) = proof_account(*address)?;

        let Some(account) = account else {
            continue;
        };

        let storage_root = state_provider.storage_root(*address, hashed_storage)?;
        if account.is_empty() && storage_root == EMPTY_ROOT_HASH {
            continue;
        }

        accounts.push((*address, account.into_trie_account(storage_root)));
    }

    Ok(state_root_unhashed(accounts))
}

fn proof_account_from_state_provider(
    state_provider: &(impl StateProvider + ?Sized),
    bundle_state: &BundleState,
    address: Address,
) -> ProviderResult<(Option<Account>, HashedStorage)> {
    if let Some(account) = bundle_state.account(&address) {
        return Ok((
            account.info.as_ref().map(Account::from),
            proof_hashed_storage_from_bundle_account(account),
        ));
    }

    Ok((
        state_provider.basic_account(&address)?,
        HashedStorage::default(),
    ))
}

fn proof_account_from_hashed_post_state(
    state_provider: &(impl StateProvider + ?Sized),
    hashed_post_state: &HashedPostState,
    address: Address,
) -> ProviderResult<(Option<Account>, HashedStorage)> {
    let hashed_address = alloy_primitives::keccak256(address);
    let account = match hashed_post_state.accounts.get(&hashed_address) {
        Some(account) => *account,
        None => state_provider.basic_account(&address)?,
    };
    let hashed_storage = hashed_post_state
        .storages
        .get(&hashed_address)
        .cloned()
        .unwrap_or_default();

    Ok((account, hashed_storage))
}

fn proof_hashed_storage_from_bundle_account(account: &BundleAccount) -> HashedStorage {
    HashedStorage::from_plain_storage(
        account.status,
        account
            .storage
            .iter()
            .map(|(slot, value)| (slot, &value.present_value)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{
        B256, U256, keccak256,
        map::{AddressMap, B256Map},
    };
    use reth_primitives_traits::Account;
    use reth_revm::{
        db::states::{AccountStatus, StorageSlot},
        state::AccountInfo,
    };
    use reth_storage_api::{
        BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
        StateProvider, StateRootProvider, noop::NoopProvider,
    };
    use reth_trie_common::{HashedStorage, root::storage_root_unsorted};

    #[derive(Debug, Clone, Default)]
    struct ProofStateProvider {
        inner: NoopProvider,
        accounts: AddressMap<Account>,
        storage: AddressMap<Vec<(B256, U256)>>,
    }

    impl ProofStateProvider {
        fn with_account(mut self, address: Address, account: Account) -> Self {
            self.accounts.insert(address, account);
            self
        }

        fn with_storage(mut self, address: Address, storage: Vec<(B256, U256)>) -> Self {
            self.storage.insert(address, storage);
            self
        }
    }

    impl AsRef<NoopProvider> for ProofStateProvider {
        fn as_ref(&self) -> &NoopProvider {
            &self.inner
        }
    }

    impl reth_storage_api::AccountReader for ProofStateProvider {
        fn basic_account(
            &self,
            address: &Address,
        ) -> reth_storage_api::errors::provider::ProviderResult<Option<Account>> {
            Ok(self.accounts.get(address).copied())
        }
    }

    impl reth_storage_api::StorageRootProvider for ProofStateProvider {
        fn storage_root(
            &self,
            address: Address,
            hashed_storage: HashedStorage,
        ) -> reth_storage_api::errors::provider::ProviderResult<B256> {
            let mut storage: B256Map<U256> = if hashed_storage.wiped {
                Default::default()
            } else {
                self.storage
                    .get(&address)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect()
            };

            for (slot, value) in hashed_storage.storage {
                if value.is_zero() {
                    storage.remove(&slot);
                } else {
                    storage.insert(slot, value);
                }
            }

            Ok(storage_root_unsorted(storage))
        }

        fn storage_proof(
            &self,
            address: Address,
            slot: B256,
            hashed_storage: HashedStorage,
        ) -> reth_storage_api::errors::provider::ProviderResult<reth_trie_common::StorageProof>
        {
            self.inner.storage_proof(address, slot, hashed_storage)
        }

        fn storage_multiproof(
            &self,
            address: Address,
            slots: &[B256],
            hashed_storage: HashedStorage,
        ) -> reth_storage_api::errors::provider::ProviderResult<reth_trie_common::StorageMultiProof>
        {
            self.inner
                .storage_multiproof(address, slots, hashed_storage)
        }
    }

    reth_storage_api::delegate_impls_to_as_ref!(
        for ProofStateProvider =>
        BlockHashReader {
            fn block_hash(&self, number: u64) -> reth_storage_api::errors::provider::ProviderResult<Option<B256>>;
            fn canonical_hashes_range(&self, start: alloy_primitives::BlockNumber, end: alloy_primitives::BlockNumber) -> reth_storage_api::errors::provider::ProviderResult<Vec<B256>>;
        }
        StateProvider {
            fn storage(&self, account: Address, storage_key: alloy_primitives::StorageKey) -> reth_storage_api::errors::provider::ProviderResult<Option<alloy_primitives::StorageValue>>;
        }
        BytecodeReader {
            fn bytecode_by_hash(&self, code_hash: &B256) -> reth_storage_api::errors::provider::ProviderResult<Option<reth_primitives_traits::Bytecode>>;
        }
        StateRootProvider {
            fn state_root(&self, state: HashedPostState) -> reth_storage_api::errors::provider::ProviderResult<B256>;
            fn state_root_from_nodes(&self, input: TrieInput) -> reth_storage_api::errors::provider::ProviderResult<B256>;
            fn state_root_with_updates(&self, state: HashedPostState) -> reth_storage_api::errors::provider::ProviderResult<(B256, reth_trie_common::updates::TrieUpdates)>;
            fn state_root_from_nodes_with_updates(&self, input: TrieInput) -> reth_storage_api::errors::provider::ProviderResult<(B256, reth_trie_common::updates::TrieUpdates)>;
        }
        StateProofProvider {
            fn proof(&self, input: TrieInput, address: Address, slots: &[B256]) -> reth_storage_api::errors::provider::ProviderResult<reth_trie_common::AccountProof>;
            fn multiproof(&self, input: TrieInput, targets: reth_trie_common::MultiProofTargets) -> reth_storage_api::errors::provider::ProviderResult<reth_trie_common::MultiProof>;
            fn witness(&self, input: TrieInput, target: HashedPostState, mode: reth_trie_common::ExecutionWitnessMode) -> reth_storage_api::errors::provider::ProviderResult<Vec<alloy_primitives::Bytes>>;
        }
        HashedPostStateProvider {
            fn hashed_post_state(&self, bundle_state: &reth_revm::db::BundleState) -> HashedPostState;
        }
    );

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

    #[test]
    fn proof_root_uses_whitelist_only_account_trie() {
        let whitelisted = Address::repeat_byte(0x11);
        let other = Address::repeat_byte(0x22);
        let provider = ProofStateProvider::default()
            .with_account(
                whitelisted,
                Account {
                    nonce: 1,
                    balance: U256::from(2),
                    bytecode_hash: None,
                },
            )
            .with_account(
                other,
                Account {
                    nonce: 9,
                    balance: U256::from(9),
                    bytecode_hash: None,
                },
            );

        let root =
            proof_root_from_state_provider(&provider, &BundleState::default(), &[whitelisted])
                .unwrap();
        let expected = state_root_unhashed([(
            whitelisted,
            Account {
                nonce: 1,
                balance: U256::from(2),
                bytecode_hash: None,
            }
            .into_trie_account(EMPTY_ROOT_HASH),
        )]);

        assert_eq!(root, expected);
    }

    #[test]
    fn proof_root_applies_bundle_account_and_storage_updates() {
        let address = Address::repeat_byte(0x11);
        let slot = U256::from(1);
        let value = U256::from(7);
        let provider = ProofStateProvider::default()
            .with_account(
                address,
                Account {
                    nonce: 1,
                    balance: U256::from(2),
                    bytecode_hash: None,
                },
            )
            .with_storage(address, vec![(keccak256(B256::from(slot)), U256::from(3))]);
        let bundle_state = bundle_state([(
            address,
            BundleAccount::new(
                Some(account(1)),
                Some(account(2)),
                [(slot, StorageSlot::new_changed(U256::from(3), value))]
                    .into_iter()
                    .collect(),
                AccountStatus::Changed,
            ),
        )]);

        let root = proof_root_from_state_provider(&provider, &bundle_state, &[address]).unwrap();
        let storage_root = storage_root_unsorted([(keccak256(B256::from(slot)), value)]);
        let expected = state_root_unhashed([(
            address,
            Account::from(account(2)).into_trie_account(storage_root),
        )]);

        assert_eq!(root, expected);
    }

    #[test]
    fn proof_root_applies_hashed_post_state_account_and_storage_updates() {
        let address = Address::repeat_byte(0x11);
        let slot = U256::from(1);
        let value = U256::from(7);
        let provider = ProofStateProvider::default()
            .with_account(
                address,
                Account {
                    nonce: 1,
                    balance: U256::from(2),
                    bytecode_hash: None,
                },
            )
            .with_storage(address, vec![(keccak256(B256::from(slot)), U256::from(3))]);
        let hashed_address = keccak256(address);
        let hashed_state = HashedPostState::default()
            .with_accounts([(hashed_address, Some(Account::from(account(2))))])
            .with_storages([(
                hashed_address,
                HashedStorage::from_iter(false, [(keccak256(B256::from(slot)), value)]),
            )]);

        let root = proof_root_from_hashed_post_state(&provider, &hashed_state, &[address]).unwrap();
        let storage_root = storage_root_unsorted([(keccak256(B256::from(slot)), value)]);
        let expected = state_root_unhashed([(
            address,
            Account::from(account(2)).into_trie_account(storage_root),
        )]);

        assert_eq!(root, expected);
    }
}
