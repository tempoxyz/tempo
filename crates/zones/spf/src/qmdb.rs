//! Hankie QMDB witness validation (hankie decision 47).
//!
//! Each item in `TempoStateWitness::node_pool` is one `commonware-codec` encoded
//! [`StateProof`] returned by `hankie-rpc`'s `eth_getMultiProof`:
//!
//! - tag `0`: absent key (61-byte [`StateKey`] + `current::ordered::ExclusionProof`)
//! - tag `1`: present key (ordered `Update` operation + `current::proof::OperationProof`)
//!
//! [`QmdbWitnessPool`] decodes the pool once and indexes proofs by [`StateKey`]. Because a
//! Zone batch can span multiple L1 checkpoints with distinct state roots, each key holds a
//! list of proofs; a read succeeds when a proof in that bucket verifies against the requested
//! checkpoint's `state_root` using SHA-256.

use std::collections::HashMap;

use alloy_primitives::{Address, B256, Bytes, U256};
use bytes::{Buf as _, BufMut};
use commonware_codec::{
    Buf, Copying, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Hasher as _, Sha256, sha256};
use commonware_storage::{
    merkle::mmr,
    qmdb::{any::ordered, current::proof::constant::OperationProof, value::VariableEncoding},
};
use commonware_utils::{range::contains_cyclic, sequence::FixedBytes};
use thiserror::Error;

const HASH_PREFIX: usize = 8;
const PAYLOAD: usize = 52;
const KEY_LENGTH: usize = HASH_PREFIX + 1 + PAYLOAD;

const ACCOUNT_TAG: u8 = 0;
const SLOT_TAG: u8 = 1;

const ACCOUNT_VALUE: u8 = 0;
const SLOT_VALUE: u8 = 1;
const GENESIS_VALUE: u8 = 2;
const BATCH_VALUE: u8 = 3;
const FILLING_VALUE: u8 = 4;

/// The bitmap chunk size of hankie's QMDB, in bytes.
const CHUNK: usize = 32;

/// Proof tags in `Option`'s order: `None` is 0 and `Some` is 1.
const ABSENT: u8 = 0;
const PRESENT: u8 = 1;

pub(crate) type StateKey = FixedBytes<KEY_LENGTH>;
type Encoding = VariableEncoding<StateValue>;
type Update = ordered::Update<StateKey, Encoding>;

// Hankie's pinned commonware-storage revision (2026.10.0) tags QMDB operations with
// 0xD1/0xD2/0xD3, whereas Tempo's workspace commonware-storage (2026.11.0) uses 0/1/2.
// Encoding the operation leaf with hankie's tags lets us verify hankie's proofs directly
// with Tempo's workspace OperationProof without duplicating Commonware in the lockfile.
const HANKIE_UPDATE_CONTEXT: u8 = 0xD2;
const HANKIE_COMMIT_CONTEXT: u8 = 0xD3;
const EXCLUSION_KEY_VALUE: u8 = 0;
const EXCLUSION_COMMIT: u8 = 1;

#[derive(Clone, Debug)]
enum HankieOperation {
    Update(Update),
    Commit(Option<StateValue>, mmr::Location),
}

impl Write for HankieOperation {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Update(update) => {
                HANKIE_UPDATE_CONTEXT.write(buf);
                update.write(buf);
            }
            Self::Commit(metadata, floor) => {
                HANKIE_COMMIT_CONTEXT.write(buf);
                metadata.write(buf);
                floor.write(buf);
            }
        }
    }
}

impl EncodeSize for HankieOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Update(update) => update.encode_size(),
            Self::Commit(metadata, floor) => metadata.encode_size() + floor.encode_size(),
        }
    }
}

impl HankieOperation {
    fn read_update(buf: &mut impl Buf) -> Result<Update, CodecError> {
        match u8::read(buf)? {
            HANKIE_UPDATE_CONTEXT => Update::read_cfg(buf, &((), ())),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[derive(Clone, Debug)]
enum HankieExclusionProof {
    KeyValue(OperationProof<mmr::Family, sha256::Digest, CHUNK>, Update),
    Commit(
        OperationProof<mmr::Family, sha256::Digest, CHUNK>,
        Option<StateValue>,
    ),
}

impl HankieExclusionProof {
    fn read_cfg(buf: &mut impl Buf, max_digests: usize) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            EXCLUSION_KEY_VALUE => {
                let proof = OperationProof::read_cfg(buf, &max_digests)?;
                let update = Update::read_cfg(buf, &((), ()))?;
                Ok(Self::KeyValue(proof, update))
            }
            EXCLUSION_COMMIT => {
                let proof = OperationProof::read_cfg(buf, &max_digests)?;
                let metadata = Option::<StateValue>::read_cfg(buf, &())?;
                Ok(Self::Commit(proof, metadata))
            }
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }

    fn verify(&self, key: &StateKey, root: &sha256::Digest) -> bool {
        let (proof, op) = match self {
            Self::KeyValue(proof, update) => {
                if update.key == *key || !contains_cyclic(&update.key..&update.next_key, key) {
                    return false;
                }
                (proof, HankieOperation::Update(update.clone()))
            }
            Self::Commit(proof, metadata) => {
                (proof, HankieOperation::Commit(metadata.clone(), proof.loc))
            }
        };
        proof.verify::<Sha256, _>(op, root)
    }
}

/// Errors returned while decoding or verifying hankie QMDB state proofs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QmdbWitnessError {
    #[error("invalid QMDB state proof encoding")]
    InvalidProofEncoding,
    #[error("QMDB witness is missing proof for account {address}")]
    MissingAccountProof { address: Address },
    #[error("QMDB witness is missing proof for account {address} slot {slot}")]
    MissingStorageProof { address: Address, slot: U256 },
    #[error("QMDB state proof does not verify against state root {state_root}")]
    InvalidProof { state_root: B256 },
    #[error("QMDB state proof returned an unexpected value kind")]
    UnexpectedValueKind,
}

/// An account as hankie's QMDB stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Account {
    pub(crate) nonce: u64,
    pub(crate) balance: U256,
    pub(crate) code_hash: B256,
    pub(crate) extension: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Checkpoint {
    Genesis,
    Batch { number: u64, last_output: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StateValue {
    Account(Account),
    Slot(U256),
    Checkpoint(Checkpoint),
    Filling(u64),
}

impl Write for StateValue {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Account(account) => {
                ACCOUNT_VALUE.write(buf);
                account.nonce.write(buf);
                account.balance.to_be_bytes::<32>().write(buf);
                account.code_hash.0.write(buf);
                account.extension.len().write(buf);
                buf.put_slice(&account.extension);
            }
            Self::Slot(value) => {
                SLOT_VALUE.write(buf);
                value.to_be_bytes::<32>().write(buf);
            }
            Self::Checkpoint(Checkpoint::Genesis) => GENESIS_VALUE.write(buf),
            Self::Checkpoint(Checkpoint::Batch {
                number,
                last_output,
            }) => {
                BATCH_VALUE.write(buf);
                number.write(buf);
                last_output.write(buf);
            }
            Self::Filling(written) => {
                FILLING_VALUE.write(buf);
                written.write(buf);
            }
        }
    }
}

impl EncodeSize for StateValue {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Account(account) => {
                8 + 32 + 32 + account.extension.len().encode_size() + account.extension.len()
            }
            Self::Slot(_) => 32,
            Self::Checkpoint(Checkpoint::Genesis) => 0,
            Self::Checkpoint(Checkpoint::Batch { .. }) => 16,
            Self::Filling(_) => 8,
        }
    }
}

impl Read for StateValue {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(match u8::read(buf)? {
            ACCOUNT_VALUE => Self::Account(Account {
                nonce: u64::read(buf)?,
                balance: U256::from_be_bytes(<[u8; 32]>::read(buf)?),
                code_hash: B256::new(<[u8; 32]>::read(buf)?),
                extension: Vec::<u8>::read_cfg(buf, &(RangeCfg::from(..), ()))?.into(),
            }),
            SLOT_VALUE => Self::Slot(U256::from_be_bytes(<[u8; 32]>::read(buf)?)),
            GENESIS_VALUE => Self::Checkpoint(Checkpoint::Genesis),
            BATCH_VALUE => Self::Checkpoint(Checkpoint::Batch {
                number: u64::read(buf)?,
                last_output: u64::read(buf)?,
            }),
            FILLING_VALUE => Self::Filling(u64::read(buf)?),
            tag => return Err(CodecError::InvalidEnum(tag)),
        })
    }
}

/// The QMDB proof of one state key's value, or of its absence.
#[derive(Clone, Debug)]
enum StateProof {
    Present {
        update: Update,
        proof: OperationProof<mmr::Family, sha256::Digest, CHUNK>,
    },
    Absent {
        key: StateKey,
        proof: HankieExclusionProof,
    },
}

impl StateProof {
    fn key(&self) -> Option<&StateKey> {
        match self {
            Self::Present { update, .. } => Some(&update.key),
            Self::Absent { key, .. } => Some(key),
        }
    }

    fn verify(&self, key: &StateKey, root: &sha256::Digest) -> Result<Option<&StateValue>, ()> {
        match self {
            Self::Present { update, proof }
                if update.key == *key
                    && proof.verify::<Sha256, _>(HankieOperation::Update(update.clone()), root) =>
            {
                Ok(Some(&update.value))
            }
            Self::Absent { key: absent, proof } if absent == key && proof.verify(key, root) => {
                Ok(None)
            }
            _ => Err(()),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let max_digests = bytes.len() / 32 + 1;
        let mut buf = Copying(bytes);
        let proof = match u8::read(&mut buf)? {
            PRESENT => Self::Present {
                update: HankieOperation::read_update(&mut buf)?,
                proof: OperationProof::read_cfg(&mut buf, &max_digests)?,
            },
            ABSENT => Self::Absent {
                key: StateKey::read(&mut buf)?,
                proof: HankieExclusionProof::read_cfg(&mut buf, max_digests)?,
            },
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        if buf.has_remaining() {
            return Err(CodecError::ExtraData(buf.remaining()));
        }
        Ok(proof)
    }
}

pub(crate) fn account_key(address: &Address) -> StateKey {
    state_key(ACCOUNT_TAG, &[address.as_slice()])
}

pub(crate) fn slot_key(address: &Address, slot: &U256) -> StateKey {
    state_key(SLOT_TAG, &[address.as_slice(), &slot.to_be_bytes::<32>()])
}

fn state_key(tag: u8, parts: &[&[u8]]) -> StateKey {
    let mut bytes = [0u8; KEY_LENGTH];
    bytes[HASH_PREFIX] = tag;
    let mut end = HASH_PREFIX + 1;
    for part in parts {
        bytes[end..end + part.len()].copy_from_slice(part);
        end += part.len();
    }
    let hash = Sha256::hash(&[&bytes[HASH_PREFIX..]]);
    bytes[..HASH_PREFIX].copy_from_slice(&hash.as_ref()[..HASH_PREFIX]);
    StateKey::new(bytes)
}

/// Decoded batch-wide pool of hankie QMDB state proofs, indexed by [`StateKey`].
pub(crate) struct QmdbWitnessPool {
    proofs: HashMap<StateKey, Vec<StateProof>>,
}

impl core::fmt::Debug for QmdbWitnessPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QmdbWitnessPool")
            .field("keys", &self.proofs.len())
            .finish()
    }
}

impl QmdbWitnessPool {
    /// Decodes every proof in `node_pool` and indexes them by the key they claim to prove.
    pub(crate) fn decode(node_pool: &[Bytes]) -> Result<Self, QmdbWitnessError> {
        let mut proofs: HashMap<StateKey, Vec<StateProof>> =
            HashMap::with_capacity(node_pool.len());
        for raw in node_pool {
            let proof =
                StateProof::decode(raw).map_err(|_| QmdbWitnessError::InvalidProofEncoding)?;
            let key = proof
                .key()
                .ok_or(QmdbWitnessError::InvalidProofEncoding)?
                .clone();
            proofs.entry(key).or_default().push(proof);
        }
        Ok(Self { proofs })
    }

    /// Reads and verifies `slot` of `account` against `state_root`.
    pub(crate) fn storage(
        &self,
        state_root: B256,
        account: Address,
        slot: U256,
    ) -> Result<U256, QmdbWitnessError> {
        let key = slot_key(&account, &slot);
        let Some(candidates) = self.proofs.get(&key) else {
            return Err(QmdbWitnessError::MissingStorageProof {
                address: account,
                slot,
            });
        };
        let root = sha256::Digest::from(state_root.0);
        for proof in candidates {
            if let Ok(value) = proof.verify(&key, &root) {
                return match value {
                    None => Ok(U256::ZERO),
                    Some(StateValue::Slot(v)) => Ok(*v),
                    Some(_) => Err(QmdbWitnessError::UnexpectedValueKind),
                };
            }
        }
        Err(QmdbWitnessError::InvalidProof { state_root })
    }

    /// Reads and verifies `account` against `state_root`.
    pub(crate) fn account(
        &self,
        state_root: B256,
        account: Address,
    ) -> Result<Option<Account>, QmdbWitnessError> {
        let key = account_key(&account);
        let Some(candidates) = self.proofs.get(&key) else {
            return Err(QmdbWitnessError::MissingAccountProof { address: account });
        };
        let root = sha256::Digest::from(state_root.0);
        for proof in candidates {
            if let Ok(value) = proof.verify(&key, &root) {
                return match value {
                    None => Ok(None),
                    Some(StateValue::Account(acc)) => Ok(Some(acc.clone())),
                    Some(_) => Err(QmdbWitnessError::UnexpectedValueKind),
                };
            }
        }
        Err(QmdbWitnessError::InvalidProof { state_root })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_keys_match_hankie_layout() {
        let address = Address::repeat_byte(0x11);
        let first = slot_key(&address, &U256::from(0));
        let second = slot_key(&address, &U256::from(1));
        assert_ne!(first[..HASH_PREFIX], second[..HASH_PREFIX]);
        assert_eq!(
            first[HASH_PREFIX..HASH_PREFIX + 21],
            second[HASH_PREFIX..HASH_PREFIX + 21]
        );
        assert_ne!(account_key(&address), slot_key(&address, &U256::ZERO));
    }

    #[test]
    fn empty_pool_reports_missing_proof() {
        let pool = QmdbWitnessPool::decode(&[]).unwrap();
        let addr = Address::repeat_byte(0x22);
        let slot = U256::from(7);
        assert_eq!(
            pool.storage(B256::ZERO, addr, slot).unwrap_err(),
            QmdbWitnessError::MissingStorageProof {
                address: addr,
                slot,
            }
        );
        assert_eq!(
            pool.account(B256::ZERO, addr).unwrap_err(),
            QmdbWitnessError::MissingAccountProof { address: addr }
        );
    }

    #[test]
    fn invalid_encoding_is_rejected() {
        let err = QmdbWitnessPool::decode(&[Bytes::from_static(&[0x02, 0x00])]).unwrap_err();
        assert_eq!(err, QmdbWitnessError::InvalidProofEncoding);
    }

    #[test]
    fn verifies_real_hankie_state_proofs() {
        use alloy_primitives::{address, b256, bytes};

        let root = b256!("7367f03684b0ae41b8b46869f9bedd7da614e244580f3c7ce517d3f1446dd661");
        let other_root = b256!("4a058918ef757c156a7806fcc63df3296d948d33e258674a7bc1794c152ce58a");
        let store = address!("00000000000000000000000000000000000c0de1");
        let absent = address!("9999999999999999999999999999999999999999");

        let store_acc = bytes!(
            "01d260239be8720015190000000000000000000000000000000000000c0de100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b17a1253a236070c4043bdcfe23ea952c49feb94c277f3d475e463d8667198df008f4d1fccbd2c1e10007e5f4552091a69125d5dfcb7b8c2659029395bdf0000000000000000000000000000000000000000000000000000000000000000140000d1f1fb0f00000000000000000000000000000000000000000000000000002c0006102e881b182b03f588dd0499dbf822bebdcade04dc6d2d1e7fd6eda40b6d90681f7ca739f347062fedf196dd3d9396f23034727f54ea56d4677235f7a205fcc05d210a32320a4c121ef657d52d94df77a60c37c6800dc0291f760dfe6e16d0ec375fb46159067654c89d4ffc26aa85b96ece1ab912a7ef89c8a3d64ca11e7b05c480ab89b2b78fc8f20b141ab4cf5190d765709d8c65f72b4a164ef666a14185dc2d64c0b18d6182ed0dd2d64b80e52584483f4c1e7df27efe6a180df39520200105c6aa539a1dae324a75501c69352f6ef8c5281de8eaceb51fe1f1557ec5264fe7b1c261c23fda0df191855954f47c0b348d82431be5072fcb86fc09a4b0d96b"
        );
        let slot0 = bytes!(
            "01d2b98557de0bc6ee2d0100000000000000000000000000000000000c0de10000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000005d56e5b946e5a2e9b0051653000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000240000d1f1fb0f00000000000000000000000000000000000000000000000000002c000546ed3cb1193a8c2d257a657ec8f825877e0f579c370ea5ceb688064aa9b5dc6668dd09cb04de752334cfc27552aaf6c5dfc26cb9c57c75b53f575c9c432936e48f003ec5caee44bb482a182e2898c9db62ea7ea2c99a4a3aa9bfce11ba766f5abaf9b7ad6c7d104e36a36ad0eb86f5f754e2c747c5d47f0ef5e92e0ff78f6e60f1180cc83a0a172cec92c52526a4ee7a9fa993f9441e0f670595d12cb1ee6e700105c6aa539a1dae324a75501c69352f6ef8c5281de8eaceb51fe1f1557ec5264fe7b1c261c23fda0df191855954f47c0b348d82431be5072fcb86fc09a4b0d96b"
        );
        let slot1 = bytes!(
            "008b20ea115724a4370100000000000000000000000000000000000c0de1000000000000000000000000000000000000000000000000000000000000000100140000d1f1fb0f00000000000000000000000000000000000000000000000000002c0006102e881b182b03f588dd0499dbf822bebdcade04dc6d2d1e7fd6eda40b6d90681f7ca739f347062fedf196dd3d9396f23034727f54ea56d4677235f7a205fcc05d210a32320a4c121ef657d52d94df77a60c37c6800dc0291f760dfe6e16d0ec375fb46159067654c89d4ffc26aa85b96ece1ab912a7ef89c8a3d64ca11e7b05c480ab89b2b78fc8f20b141ab4cf5190d765709d8c65f72b4a164ef666a14185dc2d64c0b18d6182ed0dd2d64b80e52584483f4c1e7df27efe6a180df39520200105c6aa539a1dae324a75501c69352f6ef8c5281de8eaceb51fe1f1557ec5264fe7b1c261c23fda0df191855954f47c0b348d82431be5072fcb86fc09a4b0d96b60239be8720015190000000000000000000000000000000000000c0de100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b17a1253a236070c4043bdcfe23ea952c49feb94c277f3d475e463d8667198df008f4d1fccbd2c1e10007e5f4552091a69125d5dfcb7b8c2659029395bdf0000000000000000000000000000000000000000000000000000000000000000"
        );
        let absent_acc = bytes!(
            "001e213cccbc1d2cb40099999999999999999999999999999999999999990000000000000000000000000000000000000000000000000000000000000000002a0000d1f1fb0f00000000000000000000000000000000000000000000000000002c000446ed3cb1193a8c2d257a657ec8f825877e0f579c370ea5ceb688064aa9b5dc66bc50ecc21593206f8b372bba9bac97279134fbde77b6ad828cb39ce5985a1323a8105844362cc38b3f7fe54ba4d6d8f538b45342c832b07713e3ae4966e2194be8c4a67d68ab16e3d984e9cf033b9cf6327590bd699c1139730ae3d1611bfdca0105c6aa539a1dae324a75501c69352f6ef8c5281de8eaceb51fe1f1557ec5264fe7b1c261c23fda0df191855954f47c0b348d82431be5072fcb86fc09a4b0d96bfffc101c41d3ef1b004d5050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3001e877ea3eb79c1a5005a4d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );

        let pool = QmdbWitnessPool::decode(&[store_acc, slot0, slot1, absent_acc]).unwrap();

        let acc = pool.account(root, store).unwrap().expect("store account");
        assert_ne!(acc.code_hash, B256::ZERO);
        assert_eq!(
            pool.storage(root, store, U256::ZERO).unwrap(),
            U256::from(5)
        );
        assert_eq!(
            pool.storage(root, store, U256::from(1)).unwrap(),
            U256::ZERO
        );
        assert!(pool.account(root, absent).unwrap().is_none());

        assert_eq!(
            pool.account(other_root, store).unwrap_err(),
            QmdbWitnessError::InvalidProof {
                state_root: other_root
            }
        );
        assert_eq!(
            pool.storage(root, store, U256::from(2)).unwrap_err(),
            QmdbWitnessError::MissingStorageProof {
                address: store,
                slot: U256::from(2),
            }
        );
    }
}
