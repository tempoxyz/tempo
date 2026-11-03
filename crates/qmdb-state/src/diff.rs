//! Per-block batches from execution output.

use alloy_primitives::{U256, keccak256};
use reth_trie_common::bundle_state::BundleState;

use crate::layout::{self, AccountRecord, Write};

/// Returns the batch for one block: a write for every key whose value the block changed, sorted
/// by key.
///
/// `bundle` must cover exactly one block, so each original value is the value before the block.
/// Reth reports every slot a block touched; slots whose value did not change are left out, since
/// writing them would still change the QMDB root.
///
/// A destroyed account's earlier slots need no deletes. EIP-6780 lets `SELFDESTRUCT` destroy only
/// an account created in the same transaction, and EIP-7610 forbids creating an account whose
/// storage is not empty, so a destroyed account had no slots before the block.
pub fn block_writes(bundle: &BundleState) -> Result<Vec<Write>, layout::Error> {
    let mut writes = Vec::new();
    for (address, account) in &bundle.state {
        let hashed_address = keccak256(address);
        if account.info != account.original_info {
            let value = account
                .info
                .as_ref()
                .map(|info| {
                    AccountRecord::new(
                        info.nonce,
                        info.balance,
                        Some(info.code_hash),
                        info.extension.as_ref(),
                    )
                    .map(|record| record.encode())
                })
                .transpose()?;
            writes.push(Write {
                key: layout::account_key(hashed_address),
                value,
            });
        }

        let destroyed = account.was_destroyed();
        for (slot, entry) in &account.storage {
            let original = if destroyed {
                U256::ZERO
            } else {
                entry.previous_or_original_value
            };
            if entry.present_value == original {
                continue;
            }
            let value =
                (!entry.present_value.is_zero()).then(|| layout::slot_value(entry.present_value));
            let hashed_slot = keccak256(slot.to_be_bytes::<32>());
            writes.push(Write {
                key: layout::slot_key(hashed_address, hashed_slot),
                value,
            });
        }
    }
    writes.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use evm2::evm::AccountInfo;
    use reth_trie_common::bundle_state::{AccountStatus, BundleAccount, StorageSlot};

    fn info(nonce: u64) -> AccountInfo {
        AccountInfo {
            nonce,
            ..Default::default()
        }
    }

    fn bundle(address: Address, account: BundleAccount) -> BundleState {
        let mut bundle = BundleState::default();
        bundle.state.insert(address, account);
        bundle
    }

    fn slot(original: u64, present: u64) -> StorageSlot {
        StorageSlot {
            previous_or_original_value: U256::from(original),
            present_value: U256::from(present),
        }
    }

    #[test]
    fn skips_unchanged_account_and_slots() {
        let address = Address::repeat_byte(1);
        let storage = [(U256::from(1), slot(5, 5)), (U256::from(2), slot(5, 6))];
        let account = BundleAccount::new(
            Some(info(1)),
            Some(info(1)),
            storage.into_iter().collect(),
            AccountStatus::Changed,
        );
        let writes = block_writes(&bundle(address, account)).unwrap();
        let hashed = keccak256(address);
        assert_eq!(
            writes,
            vec![Write {
                key: layout::slot_key(hashed, keccak256(U256::from(2).to_be_bytes::<32>())),
                value: Some(layout::slot_value(U256::from(6))),
            }]
        );
    }

    #[test]
    fn zeroed_slot_and_removed_account_delete_their_keys() {
        let address = Address::repeat_byte(2);
        let storage = [(U256::from(1), slot(5, 0))];
        let account = BundleAccount::new(
            Some(info(1)),
            None,
            storage.into_iter().collect(),
            AccountStatus::Changed,
        );
        let writes = block_writes(&bundle(address, account)).unwrap();
        assert_eq!(writes.len(), 2);
        assert!(writes.iter().all(|write| write.value.is_none()));
        assert!(writes.windows(2).all(|pair| pair[0].key < pair[1].key));
    }

    #[test]
    fn destroyed_account_treats_original_slots_as_zero() {
        let address = Address::repeat_byte(3);
        // Created, destroyed and recreated in the block: the slot was written once (stale
        // original 9 is ignored) and another was set and cleared again.
        let storage = [(U256::from(1), slot(9, 4)), (U256::from(2), slot(9, 0))];
        let account = BundleAccount::new(
            None,
            Some(info(1)),
            storage.into_iter().collect(),
            AccountStatus::DestroyedChanged,
        );
        let writes = block_writes(&bundle(address, account)).unwrap();
        let hashed = keccak256(address);
        let mut expected = vec![
            Write {
                key: layout::account_key(hashed),
                value: Some(
                    AccountRecord::new(1, U256::ZERO, Some(info(1).code_hash), &[])
                        .unwrap()
                        .encode(),
                ),
            },
            Write {
                key: layout::slot_key(hashed, keccak256(U256::from(1).to_be_bytes::<32>())),
                value: Some(layout::slot_value(U256::from(4))),
            },
        ];
        expected.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(writes, expected);
    }
}
