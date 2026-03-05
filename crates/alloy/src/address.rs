//! Tempo bech32m address encoding.
//!
//! Provides [`TempoAddress`], a human-readable address format for Tempo using bech32m encoding
//! ([BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)).
//!
//! # Address Format
//!
//! Mainnet addresses (no zone) use the `tempo` HRP:
//! ```text
//! tempo1<payload><checksum>
//! ```
//!
//! Zone addresses use the `tempoz` HRP:
//! ```text
//! tempoz1<payload><checksum>
//! ```
//!
//! The payload is `[0x00 version] [compact_size zone_id if zone] [20-byte address]`.
//!
//! # Examples
//!
//! ```
//! use alloy_primitives::address;
//! use tempo_alloy::address::TempoAddress;
//!
//! // Mainnet address (no zone)
//! let addr = TempoAddress::new(address!("742d35CC6634c0532925a3B844bc9e7595F2Bd28"), None);
//! assert_eq!(addr.to_string(), "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0");
//!
//! // Zone address
//! let addr = TempoAddress::with_zone(
//!     address!("742d35CC6634c0532925a3B844bc9e7595F2Bd28"),
//!     1,
//! );
//! assert_eq!(addr.to_string(), "tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj");
//!
//! // Parse from string
//! let parsed: TempoAddress = "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0".parse().unwrap();
//! assert_eq!(parsed.address(), address!("742d35CC6634c0532925a3B844bc9e7595F2Bd28"));
//! ```

use alloy_primitives::Address;
use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use core::fmt;
use core::str::FromStr;

/// HRP for mainnet addresses (no zone).
const HRP_TEMPO: &str = "tempo";

/// HRP for zone addresses.
const HRP_TEMPOZ: &str = "tempoz";

/// Current address format version.
const VERSION: u8 = 0x00;

/// A Tempo address with optional zone ID, encoded using bech32m.
///
/// `TempoAddress` wraps an [`Address`] with an optional `zone_id`. When serialized, it produces
/// a bech32m-encoded string using the `tempo` HRP (no zone) or `tempoz` HRP (with zone).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TempoAddress {
    /// The underlying 20-byte address.
    address: Address,
    /// Optional zone identifier.
    zone_id: Option<u64>,
}

impl TempoAddress {
    /// Creates a new [`TempoAddress`].
    pub const fn new(address: Address, zone_id: Option<u64>) -> Self {
        Self { address, zone_id }
    }

    /// Creates a new [`TempoAddress`] with a zone.
    pub const fn with_zone(address: Address, zone_id: u64) -> Self {
        Self {
            address,
            zone_id: Some(zone_id),
        }
    }

    /// Returns the underlying [`Address`].
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Returns the zone ID, if any.
    pub const fn zone_id(&self) -> Option<u64> {
        self.zone_id
    }

    /// Returns `true` if this is a zone address.
    pub const fn is_zone(&self) -> bool {
        self.zone_id.is_some()
    }

    /// Validates a bech32m-encoded Tempo address string.
    pub fn validate(s: &str) -> bool {
        s.parse::<Self>().is_ok()
    }

    /// Encodes the address payload as bytes.
    ///
    /// Format: `[0x00 version] [compact_size zone_id if zone] [20-byte address]`
    fn encode_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(22); // version + 20-byte address + optional zone
        payload.push(VERSION);
        if let Some(zone_id) = self.zone_id {
            encode_compact_size(&mut payload, zone_id);
        }
        payload.extend_from_slice(self.address.as_slice());
        payload
    }
}

// ---------------------------------------------------------------------------
// Display / FromStr
// ---------------------------------------------------------------------------

impl fmt::Display for TempoAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp_str = if self.zone_id.is_some() {
            HRP_TEMPOZ
        } else {
            HRP_TEMPO
        };
        let hrp = Hrp::parse_unchecked(hrp_str);
        let payload = self.encode_payload();
        let encoded = bech32::encode::<Bech32m>(hrp, &payload).map_err(|_| fmt::Error)?;
        f.write_str(&encoded)
    }
}

impl FromStr for TempoAddress {
    type Err = TempoAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let checked = CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|e| TempoAddressError::Bech32(e.to_string()))?;

        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();

        let hrp_str = hrp.to_string();
        let has_zone = match hrp_str.as_str() {
            HRP_TEMPO => false,
            HRP_TEMPOZ => true,
            _ => return Err(TempoAddressError::InvalidHrp(hrp_str)),
        };

        if data.is_empty() {
            return Err(TempoAddressError::InvalidPayload("empty payload"));
        }

        if data[0] != VERSION {
            return Err(TempoAddressError::UnsupportedVersion(data[0]));
        }

        let rest = &data[1..];

        let (zone_id, addr_bytes) = if has_zone {
            let (zone_id, consumed) = decode_compact_size(rest)?;
            (Some(zone_id), &rest[consumed..])
        } else {
            (None, rest)
        };

        if addr_bytes.len() != 20 {
            return Err(TempoAddressError::InvalidPayload(
                "address must be 20 bytes",
            ));
        }

        let address = Address::from_slice(addr_bytes);

        Ok(Self { address, zone_id })
    }
}

// ---------------------------------------------------------------------------
// Conversion traits
// ---------------------------------------------------------------------------

impl From<Address> for TempoAddress {
    fn from(address: Address) -> Self {
        Self {
            address,
            zone_id: None,
        }
    }
}

impl From<TempoAddress> for Address {
    fn from(tempo: TempoAddress) -> Self {
        tempo.address
    }
}

// ---------------------------------------------------------------------------
// Serde
// ---------------------------------------------------------------------------

impl serde::Serialize for TempoAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for TempoAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error type for [`TempoAddress`] parsing and validation.
#[derive(Debug, thiserror::Error)]
pub enum TempoAddressError {
    /// Bech32m decode error.
    #[error("bech32m decode error: {0}")]
    Bech32(String),
    /// Invalid HRP.
    #[error("invalid HRP: expected \"tempo\" or \"tempoz\", got \"{0}\"")]
    InvalidHrp(String),
    /// Unsupported version byte.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    /// Malformed payload.
    #[error("invalid payload: {0}")]
    InvalidPayload(&'static str),
    /// Malformed compact size.
    #[error("invalid compact size encoding")]
    InvalidCompactSize,
}

// ---------------------------------------------------------------------------
// CompactSize (Bitcoin varint) encoding
// ---------------------------------------------------------------------------

/// Encodes a `u64` value in Bitcoin's CompactSize (varint) format.
///
/// - `0..=252`:        1 byte
/// - `253..=65535`:    `0xFD` + LE u16
/// - `65536..=u32::MAX`: `0xFE` + LE u32
/// - `>u32::MAX`:      `0xFF` + LE u64
fn encode_compact_size(buf: &mut Vec<u8>, val: u64) {
    if val <= 252 {
        buf.push(val as u8);
    } else if val <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Decodes a CompactSize value from a byte slice.
///
/// Returns `(value, bytes_consumed)`.
fn decode_compact_size(data: &[u8]) -> Result<(u64, usize), TempoAddressError> {
    if data.is_empty() {
        return Err(TempoAddressError::InvalidCompactSize);
    }

    match data[0] {
        0xFD => {
            if data.len() < 3 {
                return Err(TempoAddressError::InvalidCompactSize);
            }
            let val = u16::from_le_bytes([data[1], data[2]]);
            Ok((val as u64, 3))
        }
        0xFE => {
            if data.len() < 5 {
                return Err(TempoAddressError::InvalidCompactSize);
            }
            let val = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            Ok((val as u64, 5))
        }
        0xFF => {
            if data.len() < 9 {
                return Err(TempoAddressError::InvalidCompactSize);
            }
            let val = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            Ok((val, 9))
        }
        v => Ok((v as u64, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const ADDR: Address = address!("742d35CC6634c0532925a3B844bc9e7595F2Bd28");

    #[test]
    fn encode_no_zone() {
        let ta = TempoAddress::new(ADDR, None);
        assert_eq!(
            ta.to_string(),
            "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"
        );
    }

    #[test]
    fn encode_zone_1() {
        let ta = TempoAddress::with_zone(ADDR, 1);
        assert_eq!(
            ta.to_string(),
            "tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj"
        );
    }

    #[test]
    fn encode_zone_1000() {
        let ta = TempoAddress::with_zone(ADDR, 1000);
        assert_eq!(
            ta.to_string(),
            "tempoz1qr77sqm5956uce35cpfjjfdrhpzte8n4jhet62qxx4zvx"
        );
    }

    #[test]
    fn encode_zone_65535() {
        let ta = TempoAddress::with_zone(ADDR, 65535);
        assert_eq!(
            ta.to_string(),
            "tempoz1qr7lllm5956uce35cpfjjfdrhpzte8n4jhet62q8pdj6j"
        );
    }

    #[test]
    fn encode_zone_65536() {
        let ta = TempoAddress::with_zone(ADDR, 65536);
        assert_eq!(
            ta.to_string(),
            "tempoz1qrlqqqqpqp6z6dwvvc6vq5efyk3ms39une6etu4a9qdupk5c"
        );
    }

    #[test]
    fn encode_zone_u32_max() {
        let ta = TempoAddress::with_zone(ADDR, 4294967295);
        assert_eq!(
            ta.to_string(),
            "tempoz1qrl0llllla6z6dwvvc6vq5efyk3ms39une6etu4a9qnk36qy"
        );
    }

    #[test]
    fn encode_zone_u32_max_plus_one() {
        let ta = TempoAddress::with_zone(ADDR, 4294967296);
        assert_eq!(
            ta.to_string(),
            "tempoz1qrlsqqqqqqqsqqqqwskntnrxxnq9x2f95wuyf0y7wk2l90fg4306kk"
        );
    }

    #[test]
    fn roundtrip_no_zone() {
        let ta = TempoAddress::new(ADDR, None);
        let s = ta.to_string();
        let parsed: TempoAddress = s.parse().unwrap();
        assert_eq!(parsed, ta);
    }

    #[test]
    fn roundtrip_with_zone() {
        for zone_id in [1, 252, 253, 1000, 65535, 65536, 4294967295, 4294967296] {
            let ta = TempoAddress::with_zone(ADDR, zone_id);
            let s = ta.to_string();
            let parsed: TempoAddress = s.parse().unwrap();
            assert_eq!(parsed, ta, "roundtrip failed for zone_id={zone_id}");
        }
    }

    #[test]
    fn validate_valid() {
        assert!(TempoAddress::validate(
            "tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0"
        ));
        assert!(TempoAddress::validate(
            "tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj"
        ));
    }

    #[test]
    fn validate_invalid() {
        assert!(!TempoAddress::validate(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ));
        assert!(!TempoAddress::validate("not_a_bech32_string"));
        assert!(!TempoAddress::validate(""));
    }

    #[test]
    fn from_address() {
        let ta: TempoAddress = ADDR.into();
        assert_eq!(ta.address(), ADDR);
        assert_eq!(ta.zone_id(), None);
    }

    #[test]
    fn into_address() {
        let ta = TempoAddress::with_zone(ADDR, 42);
        let addr: Address = ta.into();
        assert_eq!(addr, ADDR);
    }

    #[test]
    fn serde_roundtrip() {
        let ta = TempoAddress::with_zone(ADDR, 1000);
        let json = serde_json::to_string(&ta).unwrap();
        assert_eq!(
            json,
            "\"tempoz1qr77sqm5956uce35cpfjjfdrhpzte8n4jhet62qxx4zvx\""
        );
        let parsed: TempoAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ta);
    }

    #[test]
    fn invalid_version_rejected() {
        // Manually craft a payload with version 0x01 — encode and check it fails to parse.
        let hrp = Hrp::parse_unchecked(HRP_TEMPO);
        let mut payload = vec![0x01];
        payload.extend_from_slice(ADDR.as_slice());
        let encoded = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        let err = encoded.parse::<TempoAddress>().unwrap_err();
        assert!(matches!(err, TempoAddressError::UnsupportedVersion(1)));
    }

    #[test]
    fn wrong_hrp_rejected() {
        let hrp = Hrp::parse_unchecked("bitcoin");
        let mut payload = vec![VERSION];
        payload.extend_from_slice(ADDR.as_slice());
        let encoded = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        let err = encoded.parse::<TempoAddress>().unwrap_err();
        assert!(matches!(err, TempoAddressError::InvalidHrp(_)));
    }

    #[test]
    fn compact_size_encoding() {
        let cases: Vec<(u64, Vec<u8>)> = vec![
            (0, vec![0x00]),
            (252, vec![252]),
            (253, vec![0xFD, 253, 0]),
            (65535, vec![0xFD, 0xFF, 0xFF]),
            (65536, vec![0xFE, 0x00, 0x00, 0x01, 0x00]),
            (4294967295, vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]),
            (
                4294967296,
                vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ),
        ];

        for (val, expected) in cases {
            let mut buf = Vec::new();
            encode_compact_size(&mut buf, val);
            assert_eq!(buf, expected, "encode_compact_size({val})");

            let (decoded, consumed) = decode_compact_size(&buf).unwrap();
            assert_eq!(decoded, val, "decode_compact_size({val})");
            assert_eq!(consumed, buf.len(), "consumed bytes for {val}");
        }
    }
}
