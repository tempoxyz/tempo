//! Keys and values of the QMDB state.
//!
//! Every entry has a 32-byte key and a 104-byte value:
//!
//! | Entry   | Key                                                  | Value                                                    |
//! |---------|------------------------------------------------------|----------------------------------------------------------|
//! | Account | `keccak256(0x00 ‖ keccak256(address))`               | `nonce (8, BE) ‖ balance (32) ‖ code_hash (32) ‖ commitment (32)` |
//! | Slot    | `keccak256(0x01 ‖ keccak256(address) ‖ keccak256(slot))` | `value (32) ‖ zero (72)`                                 |
//!
//! Keys derive from the hashed address and slot, so the import reads MDBX's hashed tables
//! directly. The leading tag separates account and slot keys. Slots are padded to the account
//! size because one fixed-value database benchmarked faster than variable-size values, and only a
//! few percent slower than splitting accounts and slots into two databases.
//!
//! The commitment is the TIP-1108 configuration hash from the account extension, zero when the
//! account has none. Code stays in MDBX: the value commits to it through `code_hash`.

use alloy_primitives::{B256, KECCAK256_EMPTY, U256, keccak256};
use commonware_utils::sequence::FixedBytes;

/// QMDB key of an account or a storage slot.
pub type Key = FixedBytes<32>;

/// QMDB value of an account or a storage slot.
pub type Value = FixedBytes<VALUE_LEN>;

/// Size of every value, the size of an account record.
pub const VALUE_LEN: usize = 104;

const ACCOUNT_TAG: u8 = 0x00;
const SLOT_TAG: u8 = 0x01;
/// Format tag of a non-empty TIP-1108 account extension, see `tempo_primitives::account`.
const COMMITMENT_FORMAT_TAG: u8 = 0;

/// One write of a batch: `None` deletes the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write {
    /// Key written.
    pub key: Key,
    /// New value, or `None` to delete the key.
    pub value: Option<Value>,
}

/// The account fields the state commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountRecord {
    /// Account nonce.
    pub nonce: u64,
    /// Native balance, always zero on Tempo today but still committed.
    pub balance: U256,
    /// Hash of the account's code, [`KECCAK256_EMPTY`] without code.
    pub code_hash: B256,
    /// TIP-1108 configuration commitment, zero when the account has none.
    pub commitment: B256,
}

/// Error decoding an account extension into a commitment.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The extension is neither empty nor a tagged 32-byte commitment.
    #[error("account extension of {len} bytes with tag {tag:?} is not a TIP-1108 commitment")]
    InvalidExtension {
        /// Length of the extension.
        len: usize,
        /// First byte of the extension, if any.
        tag: Option<u8>,
    },
}

impl AccountRecord {
    /// Builds a record from account fields and the raw account extension.
    ///
    /// Execution already validated the extension against the hardfork, so this only checks
    /// its shape: empty, or the format tag followed by a 32-byte hash.
    pub fn new(
        nonce: u64,
        balance: U256,
        code_hash: Option<B256>,
        extension: &[u8],
    ) -> Result<Self, Error> {
        let commitment = match extension {
            [] => B256::ZERO,
            [COMMITMENT_FORMAT_TAG, hash @ ..] if hash.len() == 32 => B256::from_slice(hash),
            _ => {
                return Err(Error::InvalidExtension {
                    len: extension.len(),
                    tag: extension.first().copied(),
                });
            }
        };
        Ok(Self {
            nonce,
            balance,
            code_hash: code_hash.unwrap_or(KECCAK256_EMPTY),
            commitment,
        })
    }

    /// Encodes the record as a QMDB value.
    pub fn encode(&self) -> Value {
        let mut out = [0u8; VALUE_LEN];
        out[..8].copy_from_slice(&self.nonce.to_be_bytes());
        out[8..40].copy_from_slice(&self.balance.to_be_bytes::<32>());
        out[40..72].copy_from_slice(self.code_hash.as_slice());
        out[72..].copy_from_slice(self.commitment.as_slice());
        FixedBytes::new(out)
    }
}

/// Returns the key of the account at `hashed_address` (`keccak256(address)`).
pub fn account_key(hashed_address: B256) -> Key {
    let mut preimage = [0u8; 33];
    preimage[0] = ACCOUNT_TAG;
    preimage[1..].copy_from_slice(hashed_address.as_slice());
    FixedBytes::new(keccak256(preimage).0)
}

/// Returns the key of slot `hashed_slot` (`keccak256(slot)`) of the account at `hashed_address`.
pub fn slot_key(hashed_address: B256, hashed_slot: B256) -> Key {
    let mut preimage = [0u8; 65];
    preimage[0] = SLOT_TAG;
    preimage[1..33].copy_from_slice(hashed_address.as_slice());
    preimage[33..].copy_from_slice(hashed_slot.as_slice());
    FixedBytes::new(keccak256(preimage).0)
}

/// Encodes a non-zero slot value as a QMDB value. Zero slots are absent, never stored.
pub fn slot_value(value: U256) -> Value {
    let mut out = [0u8; VALUE_LEN];
    out[..32].copy_from_slice(&value.to_be_bytes::<32>());
    FixedBytes::new(out)
}

/// Encodes the commit metadata of a batch: the number of the block it ends at.
///
/// The block hash cannot be committed: the header carrying this root determines it.
pub(crate) fn block_metadata(number: u64) -> Value {
    let mut out = [0u8; VALUE_LEN];
    out[..8].copy_from_slice(&number.to_be_bytes());
    FixedBytes::new(out)
}

/// Decodes the block number from commit metadata written by [`block_metadata`].
pub(crate) fn decode_block_metadata(value: &Value) -> u64 {
    let mut number = [0u8; 8];
    number.copy_from_slice(&value.as_ref()[..8]);
    u64::from_be_bytes(number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn account_record_encodes_fields_in_order() {
        let commitment =
            b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
        let extension = [&[COMMITMENT_FORMAT_TAG][..], commitment.as_slice()].concat();
        let record = AccountRecord::new(7, U256::from(9), None, &extension).unwrap();
        let value = record.encode();
        let bytes = value.as_ref();
        assert_eq!(&bytes[..8], &7u64.to_be_bytes());
        assert_eq!(U256::from_be_slice(&bytes[8..40]), U256::from(9));
        assert_eq!(&bytes[40..72], KECCAK256_EMPTY.as_slice());
        assert_eq!(&bytes[72..], commitment.as_slice());
    }

    #[test]
    fn empty_extension_is_zero_commitment() {
        let record = AccountRecord::new(0, U256::ZERO, Some(B256::repeat_byte(2)), &[]).unwrap();
        assert_eq!(record.commitment, B256::ZERO);
        assert_eq!(record.code_hash, B256::repeat_byte(2));
    }

    #[test]
    fn rejects_malformed_extension() {
        assert_eq!(
            AccountRecord::new(0, U256::ZERO, None, &[1; 33]),
            Err(Error::InvalidExtension {
                len: 33,
                tag: Some(1)
            })
        );
        assert_eq!(
            AccountRecord::new(0, U256::ZERO, None, &[0; 5]),
            Err(Error::InvalidExtension {
                len: 5,
                tag: Some(0)
            })
        );
    }

    #[test]
    fn account_and_slot_keys_are_domain_separated() {
        let address = B256::repeat_byte(3);
        assert_ne!(account_key(address), slot_key(address, B256::ZERO));
        assert_ne!(slot_key(address, B256::ZERO), slot_key(B256::ZERO, address));
    }

    #[test]
    fn block_metadata_round_trips() {
        assert_eq!(
            decode_block_metadata(&block_metadata(u64::MAX - 1)),
            u64::MAX - 1
        );
    }
}
