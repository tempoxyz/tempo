//! Version-one native TIP-20 read layout, shared by off-chain proof consumers.
//! The precompile's generated layout is checked against these protocol constants at compile time.

use alloy_primitives::{Address, B256, U256, keccak256};

/// Current layout through T14. A future layout change must add a version, not reinterpret V1.
pub const TOTAL_SUPPLY_SLOT: U256 = U256::from_limbs([8, 0, 0, 0]);
pub const BALANCES_SLOT: U256 = U256::from_limbs([9, 0, 0, 0]);
pub const ALLOWANCES_SLOT: U256 = U256::from_limbs([10, 0, 0, 0]);

/// Native mappings left-pad address keys to one word, then hash with the base slot.
pub fn address_mapping_slot(address: Address, base: U256) -> U256 {
    let mut bytes = [0u8; 64];
    bytes[12..32].copy_from_slice(address.as_slice());
    bytes[32..].copy_from_slice(&base.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(bytes).0)
}

pub fn balance_slot(holder: Address) -> B256 {
    address_mapping_slot(holder, BALANCES_SLOT).into()
}

pub fn allowance_slot(owner: Address, spender: Address) -> B256 {
    address_mapping_slot(spender, address_mapping_slot(owner, ALLOWANCES_SLOT)).into()
}
