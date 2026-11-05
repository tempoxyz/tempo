//! Keys and values of the QMDB state.
//!
//! Accounts and storage slots live in two ordered fixed-value databases, so slots are stored
//! at their own size instead of padded to the account size:
//!
//! | Database | Key                                          | Value                                                             |
//! |----------|----------------------------------------------|-------------------------------------------------------------------|
//! | Accounts | `keccak256(address)`                         | `nonce (8, BE) ‖ balance (32) ‖ code_hash (32) ‖ commitment (32)` |
//! | Slots    | `keccak256(keccak256(address) ‖ keccak256(slot))` | `value (32, BE)`                                                   |
//!
//! Keys derive from the hashed address and slot, so the import reads MDBX's hashed tables
//! directly, and accounts arrive already in key order. The state root commits to both
//! databases' roots (see [`state_root`]).
//!
//! The commitment is the TIP-1108 configuration hash from the account extension, zero when the
//! account has none. Code stays in MDBX: the value commits to it through `code_hash`.

use alloy_primitives::{B256, KECCAK256_EMPTY, U256, keccak256};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_utils::sequence::FixedBytes;
use reth_primitives_traits::Account;

/// QMDB key of an account or a storage slot.
pub type Key = FixedBytes<32>;

/// Size of an account value.
pub const ACCOUNT_LEN: usize = 104;

/// Size of a slot value.
pub const SLOT_LEN: usize = 32;

/// Value in the accounts database.
pub type AccountValue = FixedBytes<ACCOUNT_LEN>;

/// Value in the slots database.
pub type SlotValue = FixedBytes<SLOT_LEN>;

/// Format tag of a non-empty TIP-1108 account extension, see `tempo_primitives::account`.
const COMMITMENT_FORMAT_TAG: u8 = 0;

/// One write of a batch: `None` deletes the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write<V> {
    /// Key written.
    pub key: Key,
    /// New value, or `None` to delete the key.
    pub value: Option<V>,
}

/// The writes of one batch to both databases, each sorted by key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Writes {
    /// Writes to the accounts database.
    pub accounts: Vec<Write<AccountValue>>,
    /// Writes to the slots database.
    pub slots: Vec<Write<SlotValue>>,
}

impl Writes {
    /// Returns the number of writes to both databases.
    pub const fn len(&self) -> usize {
        self.accounts.len() + self.slots.len()
    }

    /// Returns whether the batch writes nothing.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
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

    /// Encodes the record as an accounts-database value.
    pub fn encode(&self) -> AccountValue {
        let mut out = [0u8; ACCOUNT_LEN];
        out[..8].copy_from_slice(&self.nonce.to_be_bytes());
        out[8..40].copy_from_slice(&self.balance.to_be_bytes::<32>());
        out[40..72].copy_from_slice(self.code_hash.as_slice());
        out[72..].copy_from_slice(self.commitment.as_slice());
        FixedBytes::new(out)
    }

    /// Decodes an account value written by [`Self::encode`].
    pub fn decode(value: &AccountValue) -> Self {
        let bytes = value.as_ref();
        Self {
            nonce: u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes")),
            balance: U256::from_be_slice(&bytes[8..40]),
            code_hash: B256::from_slice(&bytes[40..72]),
            commitment: B256::from_slice(&bytes[72..]),
        }
    }

    /// Returns the account the record commits to: no bytecode hash when the code hash is
    /// [`KECCAK256_EMPTY`], and the commitment as a TIP-1108 account extension, empty when zero.
    pub fn into_account(self) -> Account {
        let extension = if self.commitment.is_zero() {
            Vec::new()
        } else {
            [&[COMMITMENT_FORMAT_TAG][..], self.commitment.as_slice()].concat()
        };
        Account {
            nonce: self.nonce,
            balance: self.balance,
            bytecode_hash: (self.code_hash != KECCAK256_EMPTY).then_some(self.code_hash),
            extension: extension.into(),
        }
    }
}

/// Returns the key of the account at `hashed_address` (`keccak256(address)`): the hashed
/// address itself.
pub fn account_key(hashed_address: B256) -> Key {
    FixedBytes::new(hashed_address.0)
}

/// Returns the key of slot `hashed_slot` (`keccak256(slot)`) of the account at `hashed_address`.
pub fn slot_key(hashed_address: B256, hashed_slot: B256) -> Key {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(hashed_address.as_slice());
    preimage[32..].copy_from_slice(hashed_slot.as_slice());
    FixedBytes::new(keccak256(preimage).0)
}

/// Encodes a non-zero slot value. Zero slots are absent, never stored.
pub fn slot_value(value: U256) -> SlotValue {
    FixedBytes::new(value.to_be_bytes::<32>())
}

/// Decodes a slot value written by [`slot_value`].
pub fn decode_slot_value(value: &SlotValue) -> U256 {
    U256::from_be_slice(value.as_ref())
}

/// Returns the state root: `sha256(accounts_root ‖ slots_root)`.
pub fn state_root(accounts_root: B256, slots_root: B256) -> B256 {
    B256::from_slice(Sha256::hash(&[accounts_root.as_slice(), slots_root.as_slice()]).as_ref())
}

/// Encodes the commit metadata of a batch: the number of the block it ends at.
///
/// The block hash cannot be committed: the header carrying this root determines it.
pub(crate) fn block_metadata<const N: usize>(number: u64) -> FixedBytes<N> {
    let mut out = [0u8; N];
    out[..8].copy_from_slice(&number.to_be_bytes());
    FixedBytes::new(out)
}

/// Decodes the block number from commit metadata written by [`block_metadata`].
pub(crate) fn decode_block_metadata<const N: usize>(value: &FixedBytes<N>) -> u64 {
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
    fn slot_keys_bind_address_and_slot_in_order() {
        let address = B256::repeat_byte(3);
        assert_ne!(slot_key(address, B256::ZERO), slot_key(B256::ZERO, address));
    }

    #[test]
    fn account_round_trips_through_its_value() {
        let commitment = B256::repeat_byte(0x11);
        let accounts = [
            Account::default(),
            Account {
                nonce: u64::MAX,
                balance: U256::MAX,
                bytecode_hash: Some(B256::repeat_byte(2)),
                extension: [&[COMMITMENT_FORMAT_TAG][..], commitment.as_slice()]
                    .concat()
                    .into(),
            },
        ];
        for account in accounts {
            let record = AccountRecord::new(
                account.nonce,
                account.balance,
                account.bytecode_hash,
                account.extension.as_ref(),
            )
            .unwrap();
            let decoded = AccountRecord::decode(&record.encode());
            assert_eq!(decoded, record);
            assert_eq!(decoded.into_account(), account);
        }
    }

    #[test]
    fn empty_code_hash_decodes_to_no_bytecode() {
        let record = AccountRecord::new(1, U256::ZERO, Some(KECCAK256_EMPTY), &[]).unwrap();
        assert_eq!(
            AccountRecord::decode(&record.encode())
                .into_account()
                .bytecode_hash,
            None
        );
    }

    #[test]
    fn slot_value_round_trips() {
        for value in [U256::from(1), U256::MAX] {
            assert_eq!(decode_slot_value(&slot_value(value)), value);
        }
    }

    #[test]
    fn state_root_depends_on_both_roots_in_order() {
        let (a, b) = (B256::repeat_byte(1), B256::repeat_byte(2));
        assert_ne!(state_root(a, b), state_root(b, a));
        assert_ne!(state_root(a, b), state_root(a, a));
    }

    #[test]
    fn block_metadata_round_trips() {
        assert_eq!(
            decode_block_metadata(&block_metadata::<SLOT_LEN>(u64::MAX - 1)),
            u64::MAX - 1
        );
        assert_eq!(decode_block_metadata(&block_metadata::<ACCOUNT_LEN>(3)), 3);
    }
}
