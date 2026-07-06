use crate::updates::PageStateUpdates;
use alloy_primitives::{B256, U256, keccak256, map::B256Map};
use reth_trie::{HashedPostState, HashedStorage};
use std::sync::LazyLock;

static SENTINEL_SLOT: LazyLock<B256> = LazyLock::new(|| keccak256(b"tempo/page-root-sentinel/v1"));
static SENTINEL_SLOT_HASHED: LazyLock<B256> = LazyLock::new(|| keccak256(SENTINEL_SLOT.as_slice()));

pub fn sentinel_slot() -> B256 {
    *SENTINEL_SLOT
}

pub fn sentinel_slot_hashed() -> B256 {
    *SENTINEL_SLOT_HASHED
}

pub fn root_to_storage_value(root: B256) -> U256 {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(root.as_slice());
    U256::from_be_bytes(bytes)
}

pub fn apply(hashed_state: &mut HashedPostState, updates: &PageStateUpdates) {
    for (address, account) in &updates.accounts {
        let hashed_address = keccak256(address);
        hashed_state.storages.insert(
            hashed_address,
            HashedStorage {
                wiped: true,
                storage: B256Map::from_iter([(
                    sentinel_slot_hashed(),
                    root_to_storage_value(account.new_root),
                )]),
            },
        );
    }
}
