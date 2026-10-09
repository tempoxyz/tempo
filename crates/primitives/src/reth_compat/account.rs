//! Tempo's typed payload for the Reth account extension.

use alloc::vec::Vec;
use alloy_primitives::B256;
use reth_primitives_traits::Account;

/// Deployed-code payload size of one chunk.
pub const CODE_CHUNK_SIZE: usize = 12 * 1024;

const CONFIG_COMMITMENT_LEN: usize = 1 + B256::len_bytes();
const CODE_CHUNKS_HEADER_LEN: usize = 5;

/// Version discriminator stored as the first byte of Tempo's account extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TempoAccountExtensionVersion {
    /// TIP-1108 account-configuration commitment.
    ConfigCommitment = 0,
    /// Chunked-bytecode metadata.
    CodeChunks = 1,
}

impl TryFrom<u8> for TempoAccountExtensionVersion {
    type Error = TempoAccountExtensionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ConfigCommitment),
            1 => Ok(Self::CodeChunks),
            version => Err(TempoAccountExtensionError::UnsupportedVersion(version)),
        }
    }
}

/// Typed Tempo metadata committed through Reth's opaque account extension.
///
/// The normal account `code_hash` remains the hash of the complete bytecode. The
/// `CodeChunks` version adds the complete size and ordered payload hashes needed
/// to resolve individual chunks without changing the base account fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TempoAccountExtension {
    /// No fifth account field.
    #[default]
    Empty,
    /// TIP-1108 account-configuration commitment.
    ConfigCommitment(B256),
    /// Metadata for independently stored bytecode chunks.
    CodeChunks {
        /// Size of the complete deployed bytecode.
        code_size: u32,
        /// Keccak hash of every original chunk payload, in index order.
        code_chunk_hashes: Vec<B256>,
    },
}

/// Invalid Tempo account-extension payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TempoAccountExtensionError {
    /// The payload uses an unknown format version.
    UnsupportedVersion(u8),
    /// The number of hashes does not match the count derived from `code_size`.
    InvalidHashCount { expected: usize, actual: usize },
    /// The byte payload is too short or is not an exact sequence of fields.
    InvalidLength(usize),
    /// A zero configuration commitment was encoded explicitly.
    ExplicitZeroCommitment,
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
            Self::ExplicitZeroCommitment => write!(f, "explicit zero account commitment"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TempoAccountExtensionError {}

impl TempoAccountExtension {
    /// Creates validated chunked-code metadata.
    pub fn code_chunks(
        code_size: u32,
        code_chunk_hashes: Vec<B256>,
    ) -> Result<Self, TempoAccountExtensionError> {
        let expected = chunk_count(code_size);
        let actual = code_chunk_hashes.len();
        if code_size == 0 || actual != expected {
            return Err(TempoAccountExtensionError::InvalidHashCount { expected, actual });
        }
        Ok(Self::CodeChunks {
            code_size,
            code_chunk_hashes,
        })
    }

    /// Creates a tagged account-configuration commitment.
    pub fn config_commitment(commitment: B256) -> Result<Self, TempoAccountExtensionError> {
        if commitment.is_zero() {
            return Err(TempoAccountExtensionError::ExplicitZeroCommitment);
        }
        Ok(Self::ConfigCommitment(commitment))
    }

    /// Returns the encoded version, if this extension is present.
    pub const fn version(&self) -> Option<TempoAccountExtensionVersion> {
        match self {
            Self::Empty => None,
            Self::ConfigCommitment(_) => Some(TempoAccountExtensionVersion::ConfigCommitment),
            Self::CodeChunks { .. } => Some(TempoAccountExtensionVersion::CodeChunks),
        }
    }

    /// Returns the complete deployed-code size for chunk metadata.
    pub const fn code_size(&self) -> Option<u32> {
        match self {
            Self::CodeChunks { code_size, .. } => Some(*code_size),
            _ => None,
        }
    }

    /// Returns the number of chunks derived from the deployed-code size.
    pub const fn chunk_count(&self) -> Option<usize> {
        match self.code_size() {
            Some(code_size) => Some(chunk_count(code_size)),
            None => None,
        }
    }

    /// Returns the ordered chunk payload hashes when this is chunk metadata.
    pub fn code_chunk_hashes(&self) -> Option<&[B256]> {
        match self {
            Self::CodeChunks {
                code_chunk_hashes, ..
            } => Some(code_chunk_hashes),
            _ => None,
        }
    }

    /// Returns the account-configuration commitment when this is that version.
    pub const fn commitment(&self) -> Option<B256> {
        match self {
            Self::ConfigCommitment(commitment) => Some(*commitment),
            _ => None,
        }
    }

    /// Encodes this value for Reth's opaque account extension.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::ConfigCommitment(commitment) => {
                let mut out = Vec::with_capacity(CONFIG_COMMITMENT_LEN);
                out.push(TempoAccountExtensionVersion::ConfigCommitment as u8);
                out.extend_from_slice(commitment.as_slice());
                out
            }
            Self::CodeChunks {
                code_size,
                code_chunk_hashes,
            } => {
                let mut out =
                    Vec::with_capacity(CODE_CHUNKS_HEADER_LEN + code_chunk_hashes.len() * 32);
                out.push(TempoAccountExtensionVersion::CodeChunks as u8);
                out.extend_from_slice(&code_size.to_be_bytes());
                for hash in code_chunk_hashes {
                    out.extend_from_slice(hash.as_slice());
                }
                out
            }
        }
    }

    /// Decodes and validates Reth account-extension bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TempoAccountExtensionError> {
        let Some((&version, payload)) = bytes.split_first() else {
            return Ok(Self::Empty);
        };
        match TempoAccountExtensionVersion::try_from(version)? {
            TempoAccountExtensionVersion::ConfigCommitment => {
                if bytes.len() != CONFIG_COMMITMENT_LEN {
                    return Err(TempoAccountExtensionError::InvalidLength(bytes.len()));
                }
                let commitment = B256::from_slice(payload);
                Self::config_commitment(commitment)
            }
            TempoAccountExtensionVersion::CodeChunks => {
                if bytes.len() < CODE_CHUNKS_HEADER_LEN
                    || !(bytes.len() - CODE_CHUNKS_HEADER_LEN).is_multiple_of(32)
                {
                    return Err(TempoAccountExtensionError::InvalidLength(bytes.len()));
                }
                let code_size =
                    u32::from_be_bytes(bytes[1..CODE_CHUNKS_HEADER_LEN].try_into().unwrap());
                if code_size == 0 {
                    return Err(TempoAccountExtensionError::InvalidLength(bytes.len()));
                }
                let (hash_bytes, remainder) = bytes[CODE_CHUNKS_HEADER_LEN..].as_chunks::<32>();
                debug_assert!(remainder.is_empty());
                let hashes = hash_bytes.iter().map(B256::from).collect();
                Self::code_chunks(code_size, hashes)
            }
        }
    }

    /// Attaches this payload to a Reth account without changing its canonical code hash.
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
        TempoAccountExtension::code_chunks(
            CODE_CHUNK_SIZE as u32 + 7,
            vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
        )
        .unwrap()
    }

    #[test]
    fn versions_round_trip_without_changing_the_account_code_hash() {
        let metadata = metadata();
        assert_eq!(
            metadata.version(),
            Some(TempoAccountExtensionVersion::CodeChunks)
        );
        assert_eq!(metadata.chunk_count(), Some(2));
        assert_eq!(
            TempoAccountExtension::decode(&metadata.encode()).unwrap(),
            metadata
        );

        let commitment = TempoAccountExtension::config_commitment(B256::repeat_byte(0x33)).unwrap();
        assert_eq!(
            commitment.version(),
            Some(TempoAccountExtensionVersion::ConfigCommitment)
        );
        assert_eq!(
            TempoAccountExtension::decode(&commitment.encode()).unwrap(),
            commitment
        );
        assert_eq!(TempoAccountExtension::Empty.encode(), Vec::<u8>::new());

        let code_hash = B256::repeat_byte(0x44);
        let account = metadata.attach(Account::new(7, U256::from(42), Some(code_hash)));
        assert_eq!(account.bytecode_hash, Some(code_hash));
    }

    #[test]
    fn rejects_inconsistent_or_malformed_payloads() {
        assert_eq!(
            TempoAccountExtension::code_chunks(1, vec![]),
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
        assert_eq!(
            TempoAccountExtension::decode(&[0; CONFIG_COMMITMENT_LEN]),
            Err(TempoAccountExtensionError::ExplicitZeroCommitment)
        );
    }

    #[test]
    fn reth_compact_and_trie_round_trips_preserve_each_version() {
        for metadata in [
            TempoAccountExtension::config_commitment(B256::repeat_byte(9)).unwrap(),
            metadata(),
        ] {
            let account = metadata.clone().attach(Account::new(
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
                metadata
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
                metadata
            );
        }
    }
}
