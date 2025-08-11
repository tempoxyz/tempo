use alloy::primitives::{U256, keccak256};

pub const fn to_u256(x: u64) -> U256 {
    let mut limbs = [0; 4];
    limbs[0] = x;
    U256::from_limbs(limbs)
}

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
}
