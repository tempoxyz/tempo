use alloy::primitives::{U256, keccak256};

pub const fn pad_to_32(x: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let mut i = 0;
    // Note: This is not idiomatic but it's the cleanest
    // way to make this function const as far as I can tell.
    while i < x.len() && i < 32 {
        buf[i] = x[i];
        i += 1;
    }
    buf
}

/// Compute storage slot for a mapping
#[inline]
pub fn mapping_slot<T: AsRef<[u8]>>(key: T, mapping_slot: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&pad_to_32(key.as_ref()));
    buf[32..].copy_from_slice(&mapping_slot.to_le_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

/// Compute storage slot for a double mapping (mapping\[key1\]\[key2\])
#[inline]
pub fn double_mapping_slot<T: AsRef<[u8]>, U: AsRef<[u8]>>(
    key1: T,
    key2: U,
    base_slot: U256,
) -> U256 {
    let intermediate_slot = mapping_slot(key1, base_slot);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&pad_to_32(key2.as_ref()));
    buf[32..].copy_from_slice(&intermediate_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
    use std::str::FromStr;

    #[test]
    fn test_mapping_slot_deterministic() {
        let key = U256::from(123).to_be_bytes::<32>();
        let slot1 = mapping_slot(key, U256::ZERO);
        let slot2 = mapping_slot(key, U256::ZERO);

        assert_eq!(slot1, slot2);
    }

    #[test]
    fn test_different_keys_different_slots() {
        let key1 = U256::from(123).to_be_bytes::<32>();
        let key2 = U256::from(456).to_be_bytes::<32>();

        let slot1 = mapping_slot(key1, U256::ZERO);
        let slot2 = mapping_slot(key2, U256::ZERO);

        assert_ne!(slot1, slot2);
    }

    #[test]
    fn test_tip20_balance_slots() {
        // Test balance slot calculation for TIP20 tokens (slot 10)
        let alice = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
        let bob = Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();

        let alice_balance_slot = mapping_slot(alice, U256::from(10));
        let bob_balance_slot = mapping_slot(bob, U256::from(10));

        println!("Alice balance slot: 0x{alice_balance_slot:064x}");
        println!("Bob balance slot: 0x{bob_balance_slot:064x}");

        // Verify they're different
        assert_ne!(alice_balance_slot, bob_balance_slot);
    }

    #[test]
    fn test_tip20_allowance_slots() {
        // Test allowance slot calculation for TIP20 tokens (slot 11)
        let alice = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
        let tip_fee_mgr = Address::from_str("0xfeec000000000000000000000000000000000000").unwrap();

        let allowance_slot = double_mapping_slot(alice, tip_fee_mgr, U256::from(11));

        println!("Alice->TipFeeManager allowance slot: 0x{allowance_slot:064x}");

        // Just verify it's calculated consistently
        let allowance_slot2 = double_mapping_slot(alice, tip_fee_mgr, U256::from(11));
        assert_eq!(allowance_slot, allowance_slot2);
    }

    #[test]
    fn test_double_mapping_different_keys() {
        let alice = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
        let bob = Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
        let spender = Address::from_str("0xfeec000000000000000000000000000000000000").unwrap();

        let alice_allowance = double_mapping_slot(alice, spender, U256::from(11));
        let bob_allowance = double_mapping_slot(bob, spender, U256::from(11));

        assert_ne!(alice_allowance, bob_allowance);
    }
}
