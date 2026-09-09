use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_rlp::{BufMut, Decodable, Encodable, RlpDecodable, RlpEncodable};

/// Nonce key prefix marking a subblock transaction.
pub const TEMPO_SUBBLOCK_NONCE_KEY_PREFIX: u8 = 0x5b;

/// Returns true if the given nonce key has the [`TEMPO_SUBBLOCK_NONCE_KEY_PREFIX`].
#[inline]
pub fn has_sub_block_nonce_key_prefix(nonce_key: &U256) -> bool {
    nonce_key.byte(31) == TEMPO_SUBBLOCK_NONCE_KEY_PREFIX
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum SubBlockVersion {
    /// Subblock version 1.
    V1 = 1,
}

impl From<SubBlockVersion> for u8 {
    fn from(value: SubBlockVersion) -> Self {
        value as Self
    }
}

impl TryFrom<u8> for SubBlockVersion {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(value),
        }
    }
}

impl Encodable for SubBlockVersion {
    fn encode(&self, out: &mut dyn BufMut) {
        u8::from(*self).encode(out);
    }

    fn length(&self) -> usize {
        u8::from(*self).length()
    }
}

impl Decodable for SubBlockVersion {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        u8::decode(buf)?
            .try_into()
            .map_err(|_| alloy_rlp::Error::Custom("invalid subblock version"))
    }
}

/// Metadata for an included subblock.
#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct SubBlockMetadata {
    /// Version of the subblock.
    pub version: SubBlockVersion,
    /// Validator that submitted the subblock.
    pub validator: B256,
    /// Recipient of the fees for the subblock.
    pub fee_recipient: Address,
    /// Signature of the subblock.
    pub signature: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn test_has_sub_block_nonce_key_prefix() {
        // Valid prefix in MSB (byte 31)
        let with_prefix = U256::from(TEMPO_SUBBLOCK_NONCE_KEY_PREFIX) << 248;
        assert!(has_sub_block_nonce_key_prefix(&with_prefix));

        // Zero has no prefix
        assert!(!has_sub_block_nonce_key_prefix(&U256::ZERO));

        // Max value has 0xff in MSB, not 0x5b
        assert!(!has_sub_block_nonce_key_prefix(&U256::MAX));

        // Prefix in LSB (byte 0), not MSB
        assert!(!has_sub_block_nonce_key_prefix(&U256::from(
            TEMPO_SUBBLOCK_NONCE_KEY_PREFIX
        )));
    }

    #[test]
    fn test_subblock_version_conversion() {
        // Valid V1
        assert_eq!(SubBlockVersion::try_from(1u8), Ok(SubBlockVersion::V1));
        assert_eq!(u8::from(SubBlockVersion::V1), 1);

        // Invalid versions
        assert_eq!(SubBlockVersion::try_from(0u8), Err(0));
        assert_eq!(SubBlockVersion::try_from(2u8), Err(2));
        assert_eq!(SubBlockVersion::try_from(255u8), Err(255));

        // RLP encode/decode
        let mut buf = Vec::new();
        SubBlockVersion::V1.encode(&mut buf);
        assert_eq!(buf.len(), SubBlockVersion::V1.length());
        let decoded = SubBlockVersion::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, SubBlockVersion::V1);

        // Invalid version decode
        let invalid_buf = [2u8];
        assert!(SubBlockVersion::decode(&mut invalid_buf.as_slice()).is_err());
    }
}
