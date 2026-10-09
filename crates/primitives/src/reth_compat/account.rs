//! Tempo's typed payload for the Reth account extension.

use alloc::vec::Vec;
use alloy_primitives::B256;
use reth_primitives_traits::Account;

/// Deployed-code payload size of one chunk.
pub const CODE_CHUNK_SIZE: usize = 12 * 1024;

const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 5;

/// Typed Tempo account metadata committed through Reth's opaque account extension.
///
/// The chunk count is derived from `code_size`; it is intentionally absent from the wire format.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TempoAccountExtension {
    /// Size of the complete deployed bytecode.
    code_size: u32,
    /// Keccak hash of every original chunk payload, in index order.
    code_chunk_hashes: Vec<B256>,
}

/// Invalid Tempo account-extension payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TempoAccountExtensionError {
    /// The payload uses an unknown format version.
    UnsupportedVersion(u8),
    /// The number of hashes does not match the count derived from `code_size`.
    InvalidHashCount { expected: usize, actual: usize },
    /// The byte payload is too short or is not an exact sequence of hashes.
    InvalidLength(usize),
}

impl core::fmt::Display for TempoAccountExtensionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported account extension {version}")
            }
            Self::InvalidHashCount { expected, actual } => {
                write!(f, "expected {expected} code chunk hashes, got {actual}")
            }
            Self::InvalidLength(length) => write!(f, "invalid account extension length {length}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TempoAccountExtensionError {}

impl TempoAccountExtension {
    /// Creates validated account metadata.
    pub fn new(
        code_size: u32,
        code_chunk_hashes: Vec<B256>,
    ) -> Result<Self, TempoAccountExtensionError> {
        let expected = chunk_count(code_size);
        let actual = code_chunk_hashes.len();
        if actual != expected {
            return Err(TempoAccountExtensionError::InvalidHashCount { expected, actual });
        }
        Ok(Self {
            code_size,
            code_chunk_hashes,
        })
    }

    /// Returns the number of chunks derived from the deployed-code size.
    pub const fn chunk_count(&self) -> usize {
        chunk_count(self.code_size)
    }

    /// Returns the complete deployed-code size.
    pub const fn code_size(&self) -> u32 {
        self.code_size
    }

    /// Returns the ordered chunk payload hashes.
    pub fn code_chunk_hashes(&self) -> &[B256] {
        &self.code_chunk_hashes
    }

    /// Encodes this metadata for Reth's opaque account extension.
    ///
    /// Empty code uses an empty extension to preserve the canonical four-field account leaf.
    pub fn encode(&self) -> Vec<u8> {
        if self.code_size == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(HEADER_LEN + self.code_chunk_hashes.len() * 32);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.code_size.to_be_bytes());
        for hash in &self.code_chunk_hashes {
            out.extend_from_slice(hash.as_slice());
        }
        out
    }

    /// Decodes and validates Reth account-extension bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TempoAccountExtensionError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        if bytes.len() < HEADER_LEN || !(bytes.len() - HEADER_LEN).is_multiple_of(32) {
            return Err(TempoAccountExtensionError::InvalidLength(bytes.len()));
        }
        if bytes[0] != FORMAT_VERSION {
            return Err(TempoAccountExtensionError::UnsupportedVersion(bytes[0]));
        }
        let code_size = u32::from_be_bytes(bytes[1..HEADER_LEN].try_into().unwrap());
        if code_size == 0 {
            return Err(TempoAccountExtensionError::InvalidLength(bytes.len()));
        }
        let (hash_bytes, remainder) = bytes[HEADER_LEN..].as_chunks::<32>();
        debug_assert!(remainder.is_empty());
        let hashes = hash_bytes.iter().map(B256::from).collect();
        Self::new(code_size, hashes)
    }

    /// Attaches this payload to a Reth account.
    pub fn attach(self, account: Account) -> Account {
        account.with_extension(self.encode())
    }

    /// Reads typed metadata from a Reth account.
    pub fn from_account(account: &Account) -> Result<Self, TempoAccountExtensionError> {
        Self::decode(account.extension.as_ref())
    }
}

const fn chunk_count(code_size: u32) -> usize {
    (code_size as usize).div_ceil(CODE_CHUNK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::U256;
    use reth_codecs::Compact;

    fn metadata() -> TempoAccountExtension {
        TempoAccountExtension::new(
            CODE_CHUNK_SIZE as u32 + 7,
            vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
        )
        .unwrap()
    }

    #[test]
    fn round_trip_derives_chunk_count() {
        let metadata = metadata();
        assert_eq!(metadata.chunk_count(), 2);
        assert_eq!(
            TempoAccountExtension::decode(&metadata.encode()).unwrap(),
            metadata
        );
        assert_eq!(TempoAccountExtension::default().encode(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_inconsistent_or_malformed_payloads() {
        assert_eq!(
            TempoAccountExtension::new(1, vec![]),
            Err(TempoAccountExtensionError::InvalidHashCount {
                expected: 1,
                actual: 0
            })
        );
        assert!(matches!(
            TempoAccountExtension::decode(&[2, 0, 0, 0, 1]),
            Err(TempoAccountExtensionError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            TempoAccountExtension::decode(&[1, 0, 0, 0, 1, 0]),
            Err(TempoAccountExtensionError::InvalidLength(6))
        ));
    }

    #[test]
    fn reth_compact_and_trie_round_trips_preserve_metadata() {
        let account = metadata().attach(Account::new(
            7,
            U256::from(42),
            Some(B256::repeat_byte(0x44)),
        ));
        let mut compact = Vec::new();
        let len = account.to_compact(&mut compact);
        let (decoded, rest) = Account::from_compact(&compact, len);
        assert!(rest.is_empty());
        assert_eq!(
            TempoAccountExtension::from_account(&decoded).unwrap(),
            metadata()
        );

        let plain = Account::new(7, U256::from(42), Some(B256::repeat_byte(0x44)));
        let extended_hash = account
            .clone()
            .into_trie_account(B256::ZERO)
            .trie_hash_slow();
        let plain_hash = plain.into_trie_account(B256::ZERO).trie_hash_slow();
        assert_ne!(extended_hash, plain_hash);
        let from_trie = Account::from(account.into_trie_account(B256::ZERO));
        assert_eq!(
            TempoAccountExtension::from_account(&from_trie).unwrap(),
            metadata()
        );
    }
}
