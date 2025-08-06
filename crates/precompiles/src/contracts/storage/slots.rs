use alloy::primitives::{keccak256, U256};

/// Compute storage slot for a mapping
pub fn mapping_slot<T: AsRef<[u8]>>(key: T, mapping_slot: u64) -> U256 {
    let mut data = Vec::new();
    data.extend_from_slice(key.as_ref());
    data.extend_from_slice(&mapping_slot.to_le_bytes());
    U256::from_be_bytes(keccak256(&data).0)
}

/// Compute storage slot for a double mapping (mapping[key1][key2])
pub fn double_mapping_slot<T: AsRef<[u8]>, U: AsRef<[u8]>>(key1: T, key2: U, base_slot: u64) -> U256 {
    let intermediate_slot = mapping_slot(key1, base_slot);
    let mut data = Vec::new();
    data.extend_from_slice(key2.as_ref());
    data.extend_from_slice(&intermediate_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(&data).0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_slot_deterministic() {
        let key = U256::from(123).to_be_bytes::<32>();
        let slot1 = mapping_slot(key, 0);
        let slot2 = mapping_slot(key, 0);

        assert_eq!(slot1, slot2);
    }

    #[test]
    fn test_different_keys_different_slots() {
        let key1 = U256::from(123).to_be_bytes::<32>();
        let key2 = U256::from(456).to_be_bytes::<32>();

        let slot1 = mapping_slot(key1, 0);
        let slot2 = mapping_slot(key2, 0);

        assert_ne!(slot1, slot2);
    }
}
