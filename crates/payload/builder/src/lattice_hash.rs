use alloy_primitives::{B256, U256};
use commonware_cryptography::lthash::LtHash;
use reth_primitives_traits::Account;
use reth_trie_common::{HashedPostState, HashedStorage};

const ACCOUNT_TAG: u8 = 0;
const STORAGE_WIPE_TAG: u8 = 1;
const STORAGE_SLOT_TAG: u8 = 2;

/// Computes an order-independent lattice hash over finalized account and storage changes.
pub(crate) fn calculate_lattice_state_root(hashed_state: &HashedPostState) -> B256 {
    let mut hash = LtHash::new();

    let mut accounts = hashed_state.accounts.iter().collect::<Vec<_>>();
    accounts.sort_unstable_by_key(|(address, _)| **address);
    for (address, account) in accounts {
        hash.add(account_leaf(*address, account.as_ref()).as_slice());
    }

    let mut storages = hashed_state.storages.iter().collect::<Vec<_>>();
    storages.sort_unstable_by_key(|(address, _)| **address);
    for (address, storage) in storages {
        add_storage_leaves(&mut hash, *address, storage);
    }

    B256::from(hash.checksum().0)
}

fn add_storage_leaves(hash: &mut LtHash, address: B256, storage: &HashedStorage) {
    if storage.wiped {
        let mut leaf = Vec::with_capacity(1 + 32);
        leaf.push(STORAGE_WIPE_TAG);
        leaf.extend_from_slice(address.as_slice());
        hash.add(leaf.as_slice());
    }

    let mut slots = storage.storage.iter().collect::<Vec<_>>();
    slots.sort_unstable_by_key(|(slot, _)| **slot);
    for (slot, value) in slots {
        let mut leaf = Vec::with_capacity(1 + 32 + 32 + 32);
        leaf.push(STORAGE_SLOT_TAG);
        leaf.extend_from_slice(address.as_slice());
        leaf.extend_from_slice(slot.as_slice());
        leaf.extend_from_slice(u256_be_bytes(*value).as_slice());
        hash.add(leaf.as_slice());
    }
}

fn account_leaf(address: B256, account: Option<&Account>) -> Vec<u8> {
    let mut leaf = Vec::with_capacity(1 + 32 + 1 + 8 + 32 + 32);
    leaf.push(ACCOUNT_TAG);
    leaf.extend_from_slice(address.as_slice());
    match account {
        Some(account) => {
            leaf.push(1);
            leaf.extend_from_slice(&account.nonce.to_be_bytes());
            leaf.extend_from_slice(u256_be_bytes(account.balance).as_slice());
            leaf.extend_from_slice(account.get_bytecode_hash().as_slice());
        }
        None => leaf.push(0),
    }
    leaf
}

fn u256_be_bytes(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{b256, uint};
    use reth_trie_common::HashedStorage;

    #[test]
    fn lattice_state_root_is_order_independent() {
        let account_a = b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let account_b = b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let slot_a = b256!("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let slot_b = b256!("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

        let mut first = HashedPostState::default();
        first.accounts.insert(account_a, None);
        first.accounts.insert(account_b, Some(test_account(7)));
        first.storages.insert(
            account_b,
            HashedStorage::from_iter(false, [(slot_a, uint!(1_U256)), (slot_b, uint!(2_U256))]),
        );

        let mut second = HashedPostState::default();
        second.accounts.insert(account_b, Some(test_account(7)));
        second.accounts.insert(account_a, None);
        second.storages.insert(
            account_b,
            HashedStorage::from_iter(false, [(slot_b, uint!(2_U256)), (slot_a, uint!(1_U256))]),
        );

        assert_eq!(
            calculate_lattice_state_root(&first),
            calculate_lattice_state_root(&second)
        );
    }

    #[test]
    fn lattice_state_root_changes_with_state() {
        let account = b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let mut first = HashedPostState::default();
        first.accounts.insert(account, Some(test_account(1)));

        let mut second = HashedPostState::default();
        second.accounts.insert(account, Some(test_account(2)));

        assert_ne!(
            calculate_lattice_state_root(&first),
            calculate_lattice_state_root(&second)
        );
    }

    fn test_account(nonce: u64) -> Account {
        Account {
            nonce,
            balance: uint!(42_U256),
            bytecode_hash: None,
        }
    }
}
