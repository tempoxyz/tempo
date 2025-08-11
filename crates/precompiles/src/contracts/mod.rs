pub mod roles;
pub mod storage;
pub mod tip20;
pub mod tip20_factory;
pub mod tip403_registry;
pub mod tip4217_registry;
pub mod types;

use alloy::primitives::{Address, address};
pub use storage::{StorageProvider, evm::EvmStorageProvider, hashmap::HashMapStorageProvider};
pub use tip20::TIP20Token;
pub use tip20_factory::TIP20Factory;
pub use tip403_registry::TIP403Registry;
pub use tip4217_registry::TIP4217Registry;
pub use types::{ITIP20, ITIP20Factory, ITIP403Registry, ITIP4217Registry};

pub const TIP403_REGISTRY_ADDRESS: Address = address!("0x403C000000000000000000000000000000000000");
pub const TIP20_FACTORY_ADDRESS: Address = address!("0x20FC000000000000000000000000000000000000");
pub const TIP4217_REGISTRY_ADDRESS: Address =
    address!("0x4217C00000000000000000000000000000000000");
const TIP20_TOKEN_PREFIX: [u8; 12] = [
    0x20, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Converts a token ID to its corresponding contract address
/// Uses the pattern: TIP20_TOKEN_PREFIX ++ token_id
pub fn token_id_to_address(token_id: u64) -> Address {
    let mut address_bytes = [0u8; 20];
    address_bytes[..12].copy_from_slice(&TIP20_TOKEN_PREFIX);
    address_bytes[12..20].copy_from_slice(&token_id.to_be_bytes());
    Address::from(address_bytes)
}

pub fn address_is_token_address(address: &Address) -> bool {
    address.as_slice().starts_with(&TIP20_TOKEN_PREFIX)
}

pub fn address_to_token_id_unchecked(address: &Address) -> u64 {
    u64::from_be_bytes(address.as_slice()[12..20].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;

    use super::*;

    #[test]
    fn test_token_id_to_address_values() {
        assert_eq!(
            token_id_to_address(0),
            address!("0x20C0000000000000000000000000000000000000")
        );

        assert_eq!(
            token_id_to_address(1),
            address!("0x20C0000000000000000000000000000000000001")
        );

        // Test max u64
        assert_eq!(
            token_id_to_address(u64::MAX),
            address!("0x20C000000000000000000000FFFFFFFFFFFFFFFF")
        );

        assert_eq!(
            token_id_to_address(0x123456789ABCDEF0u64),
            address!("0x20C000000000000000000000123456789ABCDEF0")
        );
    }

    #[test]
    fn test_token_id_to_address_base_pattern() {
        // Verify that all addresses start with 0x20 and have zeros in the middle
        for token_id in 1..=1_000_000 {
            let address = token_id_to_address(token_id);
            let bytes = address.0.0;

            // First byte should be 0x20
            assert_eq!(bytes[0], 0x20);
            // Second byte should be 0xC0
            assert_eq!(bytes[1], 0xC0);

            // Bytes 2-11 should be zero
            for &byte in &bytes[2..12] {
                assert_eq!(byte, 0);
            }

            // Last 8 bytes should match the token_id in big-endian format
            let token_bytes = token_id.to_be_bytes();
            assert_eq!(&bytes[12..20], &token_bytes);
        }
    }

    #[test]
    fn test_address_to_token_id_unchecked() {
        assert_eq!(address_to_token_id_unchecked(&token_id_to_address(0)), (0));
        assert_eq!(address_to_token_id_unchecked(&token_id_to_address(1)), (1));
        assert_eq!(
            address_to_token_id_unchecked(&token_id_to_address(u64::MAX)),
            (u64::MAX)
        );
        assert_eq!(
            address_to_token_id_unchecked(&token_id_to_address(0x123456789ABCDEF0u64)),
            (0x123456789ABCDEF0u64)
        );
    }
}
