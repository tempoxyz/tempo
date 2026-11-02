//! TIP-1094 zone address registry (zone-side precompile at `0xFDC0…`) and the zone deposit
//! address format shared by Tempo routing and zone processing.

pub use IZoneAddressRegistry::IZoneAddressRegistryErrors as ZoneAddressRegistryError;

use alloy_primitives::{Address, FixedBytes, address};

crate::sol! {
    #[sol(abi)]
    #[derive(Debug, PartialEq, Eq)]
    interface IZoneAddressRegistry {
        /// Register `recipient` and return its master ID. Repeating a (recipient, salt) request
        /// returns the original ID.
        function registerMaster(address recipient, bytes32 salt) external returns (bytes4 masterId);

        error InvalidMasterAddress();
        error MasterIdSpaceExhausted();
    }
}

/// Zone-side registry address. TIP-1022 uses the same address on Tempo; the zone registry is
/// independent of it.
pub const ZONE_ADDRESS_REGISTRY_ADDRESS: Address =
    address!("0xFDC0000000000000000000000000000000000000");

/// Magic bytes at `[4:13]` of every zone deposit address.
pub const ZONE_DEPOSIT_ADDRESS_MAGIC: [u8; 9] = [0xFC; 9];

/// Fixed FF1 decryption tariff from TIP-1094. Not benchmarked yet.
pub const ZVDA_DECRYPT_GAS: u64 = 10_000;

/// Domain prefix of a registration request hash.
pub const ZVDA_MASTER_REQUEST_DOMAIN: &[u8] = b"TEMPO-ZVDA-MASTER-v1";

/// Prefix of the FF1 tweak; followed by the decimal version and the 4-byte zone ID.
pub const ZVDA_TWEAK_PREFIX: &[u8] = b"TEMPO-ZVDA-v";

/// Decoded fields of a zone deposit address. The version may be `0x00`, which no key selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneDepositAddress {
    pub zone_id: u32,
    pub version: u8,
    pub ciphertext: FixedBytes<6>,
}

impl ZoneDepositAddress {
    /// Returns `true` if `address` is in the reserved zone deposit address format.
    pub fn is_reserved(address: &Address) -> bool {
        address.as_slice()[4..13] == ZONE_DEPOSIT_ADDRESS_MAGIC
    }

    /// Decodes a reserved address, or returns `None` without the magic bytes.
    pub fn decode(address: &Address) -> Option<Self> {
        if !Self::is_reserved(address) {
            return None;
        }
        let bytes = address.as_slice();
        Some(Self {
            zone_id: u32::from_be_bytes(bytes[0..4].try_into().expect("4 bytes")),
            version: bytes[13],
            ciphertext: FixedBytes::from_slice(&bytes[14..20]),
        })
    }

    /// Encodes the 20-byte address.
    pub fn encode(&self) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0..4].copy_from_slice(&self.zone_id.to_be_bytes());
        bytes[4..13].copy_from_slice(&ZONE_DEPOSIT_ADDRESS_MAGIC);
        bytes[13] = self.version;
        bytes[14..20].copy_from_slice(self.ciphertext.as_slice());
        Address::from(bytes)
    }
}

/// FF1 tweak: `"TEMPO-ZVDA-v" || decimal(version) || zoneId`, at most 19 bytes. Returns the
/// buffer and the used length.
pub fn zvda_tweak(version: u8, zone_id: u32) -> ([u8; 19], usize) {
    let mut out = [0u8; 19];
    let mut len = ZVDA_TWEAK_PREFIX.len();
    out[..len].copy_from_slice(ZVDA_TWEAK_PREFIX);
    let digits = [version / 100, (version / 10) % 10, version % 10];
    let first = digits.iter().position(|d| *d != 0).unwrap_or(2);
    for digit in &digits[first..] {
        out[len] = b'0' + digit;
        len += 1;
    }
    out[len..len + 4].copy_from_slice(&zone_id.to_be_bytes());
    (out, len + 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    #[test]
    fn deposit_address_round_trips() {
        let address = address!("0x00000007fcfcfcfcfcfcfcfcfc015a951fcc7419");
        let decoded = ZoneDepositAddress::decode(&address).unwrap();
        assert_eq!(decoded.zone_id, 7);
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.ciphertext, FixedBytes::from(hex!("5a951fcc7419")));
        assert_eq!(decoded.encode(), address);
        assert!(ZoneDepositAddress::decode(&Address::repeat_byte(0xfd)).is_none());
    }

    #[test]
    fn tweak_uses_decimal_version_without_leading_zeros() {
        let (t, n) = zvda_tweak(1, 0x01020304);
        assert_eq!(&t[..n], hex!("54454D504F2D5A5644412D763101020304"));
        let (t, n) = zvda_tweak(10, 0x01020304);
        assert_eq!(&t[..n], hex!("54454D504F2D5A5644412D76313001020304"));
        let (t, n) = zvda_tweak(255, 0);
        assert_eq!(&t[..n], b"TEMPO-ZVDA-v255\0\0\0\0");
    }
}
