//! Storage-key helpers for semantic action coverage.

use crate::blockstm::rw_set::BlockStmAccessKey;
use alloy_primitives::{Address, B256, U256, keccak256};
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, storage::StorageKey as _, tip20::tip20_slots,
};

/// TIP20 storage slot for `total_supply`.
pub const TIP20_TOTAL_SUPPLY_SLOT: u64 = 8;
/// TIP20 storage slot for `balances`.
pub const TIP20_BALANCES_SLOT: u64 = 9;
/// TIP20 storage slot for `allowances`.
pub const TIP20_ALLOWANCES_SLOT: u64 = 10;

/// Fee manager storage slot for `validator_tokens`.
pub const FEE_MANAGER_VALIDATOR_TOKENS_SLOT: u64 = 0;
/// Fee manager storage slot for `user_tokens`.
pub const FEE_MANAGER_USER_TOKENS_SLOT: u64 = 1;
/// Fee manager storage slot for `collected_fees`.
pub const FEE_MANAGER_COLLECTED_FEES_SLOT: u64 = 2;

/// Nonce manager storage slot for `expiring_nonce_seen`.
pub const EXPIRING_NONCE_SEEN_SLOT: u64 = 1;
/// Nonce manager storage slot for `expiring_nonce_ring`.
pub const EXPIRING_NONCE_RING_SLOT: u64 = 2;
/// Nonce manager storage slot for `expiring_nonce_ring_ptr`.
pub const EXPIRING_NONCE_RING_PTR_SLOT: u64 = 3;

/// Returns the Block-STM key for a TIP20 balance slot.
pub fn tip20_balance_key(token: Address, account: Address) -> BlockStmAccessKey {
    BlockStmAccessKey::Storage {
        address: token,
        slot: account.mapping_slot(tip20_slots::BALANCES),
    }
}

/// Returns the Block-STM key for a TIP20 allowance slot.
pub fn tip20_allowance_key(token: Address, owner: Address, spender: Address) -> BlockStmAccessKey {
    BlockStmAccessKey::Storage {
        address: token,
        slot: spender.mapping_slot(owner.mapping_slot(tip20_slots::ALLOWANCES)),
    }
}

/// Returns the Block-STM key for TIP20 total supply.
pub fn tip20_total_supply_key(token: Address) -> BlockStmAccessKey {
    BlockStmAccessKey::Storage {
        address: token,
        slot: tip20_slots::TOTAL_SUPPLY,
    }
}

/// Returns the Block-STM key for a fee-manager collected fee slot.
pub fn fee_manager_collected_fees_key(beneficiary: Address, token: Address) -> BlockStmAccessKey {
    BlockStmAccessKey::Storage {
        address: TIP_FEE_MANAGER_ADDRESS,
        slot: nested_mapping_slot(
            address_word(beneficiary),
            address_word(token),
            FEE_MANAGER_COLLECTED_FEES_SLOT,
        ),
    }
}

/// Returns the Block-STM key for a validator fee-token preference.
pub fn fee_manager_validator_token_key(validator: Address) -> BlockStmAccessKey {
    BlockStmAccessKey::Storage {
        address: TIP_FEE_MANAGER_ADDRESS,
        slot: mapping_slot(
            address_word(validator),
            U256::from(FEE_MANAGER_VALIDATOR_TOKENS_SLOT),
        ),
    }
}

/// Returns the Block-STM key for a user fee-token preference.
pub fn fee_manager_user_token_key(user: Address) -> BlockStmAccessKey {
    BlockStmAccessKey::Storage {
        address: TIP_FEE_MANAGER_ADDRESS,
        slot: mapping_slot(address_word(user), U256::from(FEE_MANAGER_USER_TOKENS_SLOT)),
    }
}

/// Returns the Block-STM key for an expiring nonce seen-set entry.
pub fn expiring_nonce_seen_key(hash: B256) -> BlockStmAccessKey {
    BlockStmAccessKey::Storage {
        address: NONCE_PRECOMPILE_ADDRESS,
        slot: mapping_slot(hash.0, U256::from(EXPIRING_NONCE_SEEN_SLOT)),
    }
}

/// Returns the Block-STM key for an expiring nonce ring entry.
pub fn expiring_nonce_ring_key(index: u32) -> BlockStmAccessKey {
    BlockStmAccessKey::Storage {
        address: NONCE_PRECOMPILE_ADDRESS,
        slot: mapping_slot(
            U256::from(index).to_be_bytes::<32>(),
            U256::from(EXPIRING_NONCE_RING_SLOT),
        ),
    }
}

/// Returns the Block-STM key for the expiring nonce ring pointer.
pub fn expiring_nonce_ring_ptr_key() -> BlockStmAccessKey {
    BlockStmAccessKey::Storage {
        address: NONCE_PRECOMPILE_ADDRESS,
        slot: U256::from(EXPIRING_NONCE_RING_PTR_SLOT),
    }
}

fn nested_mapping_slot(outer_key: [u8; 32], inner_key: [u8; 32], base_slot: u64) -> U256 {
    let outer_slot = mapping_slot(outer_key, U256::from(base_slot));
    mapping_slot(inner_key, outer_slot)
}

fn mapping_slot(key: [u8; 32], base_slot: U256) -> U256 {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&key);
    bytes[32..].copy_from_slice(&base_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(bytes).0)
}

fn address_word(address: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn blockstm_actions_tip20_balance_slots_are_token_scoped() {
        let account = address!("0x00000000000000000000000000000000000000aa");
        let token_a = address!("0x20c0000000000000000000000000000000000001");
        let token_b = address!("0x20c0000000000000000000000000000000000002");

        assert_ne!(
            tip20_balance_key(token_a, account),
            tip20_balance_key(token_b, account)
        );
    }

    #[test]
    fn blockstm_actions_nonce_ring_pointer_key_uses_documented_slot() {
        assert_eq!(
            expiring_nonce_ring_ptr_key(),
            BlockStmAccessKey::Storage {
                address: NONCE_PRECOMPILE_ADDRESS,
                slot: U256::from(EXPIRING_NONCE_RING_PTR_SLOT),
            }
        );
    }
}
