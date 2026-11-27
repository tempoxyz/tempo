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
    qmdb::{
        any::ordered,
        current::{ordered::proof::constant::ExclusionProof, proof::constant::OperationProof},
        value::VariableEncoding,
    },
};
use commonware_utils::sequence::FixedBytes;
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
type Operation = ordered::Operation<mmr::Family, StateKey, Encoding>;
type Update = ordered::Update<StateKey, Encoding>;

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
        proof: ExclusionProof<mmr::Family, StateKey, Encoding, sha256::Digest, CHUNK>,
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
                    && proof.verify::<Sha256, _>(Operation::Update(update.clone()), root) =>
            {
                Ok(Some(&update.value))
            }
            Self::Absent { key: absent, proof }
                if absent == key && proof.verify::<Sha256>(key, root) =>
            {
                Ok(None)
            }
            _ => Err(()),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let max_digests = bytes.len() / 32 + 1;
        let mut buf = Copying(bytes);
        let proof = match u8::read(&mut buf)? {
            PRESENT => {
                let Operation::Update(update) = Operation::read_cfg(&mut buf, &((), ()))? else {
                    return Err(CodecError::Invalid("StateProof", "not an update"));
                };
                Self::Present {
                    update,
                    proof: OperationProof::read_cfg(&mut buf, &max_digests)?,
                }
            }
            ABSENT => Self::Absent {
                key: StateKey::read(&mut buf)?,
                proof: ExclusionProof::read_cfg(&mut buf, &(max_digests, ((), ()), ()))?,
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

    /// Proofs that `cloakroom` served with `eth_getMultiProof` at block 5 of a one-validator
    /// network on Tempo's dev genesis: pathUSD's account, its slot 4 and absent slot 0, and an
    /// absent account. `other_root` is block 4's state root.
    #[test]
    fn verifies_real_hankie_state_proofs() {
        use alloy_primitives::{address, b256, bytes};

        let root = b256!("aec15fdd9878f3c77936e6605f982c11fd3a9f1a7a799c3383b08362d36b1339");
        let other_root = b256!("c93945162fc295b4c44551df7e404e9538aaec0edeaedb28c840b9d00b74ad09");
        let token = address!("20c0000000000000000000000000000000000000");
        let absent = address!("9999999999999999999999999999999999999999");

        let token_acc = bytes!(
            "01013f5f94b35c4d8fe30020c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a30040c232ea97c388d40120c0000000000000000000000000000000000002c39d774f18115b85b81494d65e588b565d73abc969333d1da7b0a0eb0729accd2600f8fffffbffffffffffff7fffffdffffffdffff7aef7d000000000000000000b70100084fe0b146ec453f3ec4c48de285b57833ee6e32df39fe296f352d88a3bfe075a6d8b500bf90beed9f0d07df1a11816648c2d3542243851dd960cef15ebb3935af5e99e50775b15ec18101760bda9eedbf1bb132e588329d90f9c01568ed89eb5496bb50399d8862d3d0cbb092b663481e1701b7c639176f1e196717d73528c4e7a40e552de38af06fe9f71974b772dcb85d16eeb5e44431e48503558166f3bafa40c83ee88c33778b97b31cdf7eae096e7bdcfae0237cd53fff0166dac9150531bd85cad562fcec7fd382beee270b72b7ba282c70186486e3582da9c3a68081b367b19d838aaa7de94c3cdb6f5ea849ec13199aab36cfaa2e2047eb1fa164ac8901dfb4b892ee11fae008818c90833677d3b372eb2bd070fbf7c266360092911dd48f078d495935334830273c79c19dd9f62f07da5ca2a9a49ec2d231963e363cef"
        );
        let slot4 = bytes!(
            "01010b37b795cb49b4aa0120c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040155534400000000000000000000000000000000000000000000000000000000060f0bc72407a443620120c0000000000000000000000000000000000000aab8bf5bafd4a7defe9190a92a4e6a1a5617d64b78425566059df2cc35285f64a10100f8fffffbffffffffffff7fffffdffffffdffff7aef7d000000000000000000b7010007d77877ebfacf9261a1fce75da73c5891a4157b7ebb13ede7c66263ba82f0bf4f758915a5c5ec9429476d4ac5a6c6cefcb3ef17f29b57d0de8c5021ddf145945c26c2bcbd21268c7885e3b1d7618623352267279feaa26c7297252a4fbe510019cddd87124f6095dc053e927ec91cdd7cab5294c8fad935f24fd500b3b37b2740117f1b63efa10dcb0c2daddea6183fc8f8909b6a1dd963b118cc1443239275527fe0481987079fd4f4318d2c844fdc8531512e96e5a43325b9c367e2203c2b5e2f0741b9fe19cc6c3535e1c9aa823db3b404c686c88feba7484180b905d97e4401dfb4b892ee11fae008818c90833677d3b372eb2bd070fbf7c266360092911dd48f078d495935334830273c79c19dd9f62f07da5ca2a9a49ec2d231963e363cef"
        );
        let slot0 = bytes!(
            "005f55da4360c0d2d40120c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003900f8fffffbffffffffffff7fffffdffffffdffff7aef7d000000000000000000b70100084fe0b146ec453f3ec4c48de285b57833ee6e32df39fe296f352d88a3bfe075a6d8b500bf90beed9f0d07df1a11816648c2d3542243851dd960cef15ebb3935af22832b9e39d0a71c01c66f1da37b7bd0c5ae57bf0a98adafc68fe35dae4b945a00d0fd33a97f09f81248f4f975b515d1ece1daf69fcc8661afb352b4963271148518c95aae1495ef636ea95afd3f2c9438e1e09c1e42ff59c363023264b3e4896e04ff5a4caa30e0222d2bd4210b5944610f30880aa8bc1d72c0350b4e1ecec702bbbd7f85652bf88c2c2506ec34c8a28b92a2385191ff8f9dd2bdb45fc60e0e67b19d838aaa7de94c3cdb6f5ea849ec13199aab36cfaa2e2047eb1fa164ac8901dfb4b892ee11fae008818c90833677d3b372eb2bd070fbf7c266360092911dd48f078d495935334830273c79c19dd9f62f07da5ca2a9a49ec2d231963e363cef5f184dc3b90f14010120c00000000000000000000000000000000000034aa7d878ced99e38cd20114097b6da04259057b1b890f87340f95f3cd79c3c55010000000000000000000000000000000000000000000000000000000000000001604ab3a65f9952e70120c0000000000000000000000000000000000001194520786657be1e093e5b2bc8663299ed491a0ac2a74bc3154a37ff1287fd7b"
        );
        let absent_acc = bytes!(
            "001e213cccbc1d2cb4009999999999999999999999999999999999999999000000000000000000000000000000000000000000000000000000000000000000b40100f8fffffbffffffffffff7fffffdffffffdffff7aef7d000000000000000000b7010006d77877ebfacf9261a1fce75da73c5891a4157b7ebb13ede7c66263ba82f0bf4f758915a5c5ec9429476d4ac5a6c6cefcb3ef17f29b57d0de8c5021ddf145945c6acf645cb048534bd128988a7fa54c81c8192ddeb756a315ec19a813e6e03f1311162cbfe32f52760495356b4110bd77a283d57573c5f4493a25d080c6f121f3c3ba03335dc9be259507a4cb086a3a4a00b3ab202679788364dfff5e34bf094bf1479031751d75cdbae7e380d6ebdba169895e413e454df42cf4f68775e9961301dfb4b892ee11fae008818c90833677d3b372eb2bd070fbf7c266360092911dd48f078d495935334830273c79c19dd9f62f07da5ca2a9a49ec2d231963e363cef1718f2bd411473da0020c000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3001e877ea3eb79c1a5005a4d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );

        let pool = QmdbWitnessPool::decode(&[token_acc, slot4, slot0, absent_acc]).unwrap();

        let acc = pool.account(root, token).unwrap().expect("pathUSD account");
        assert_ne!(acc.code_hash, B256::ZERO);
        assert_eq!(
            pool.storage(root, token, U256::from(4)).unwrap(),
            U256::from_be_bytes(
                b256!("5553440000000000000000000000000000000000000000000000000000000006").0
            )
        );
        assert_eq!(pool.storage(root, token, U256::ZERO).unwrap(), U256::ZERO);
        assert!(pool.account(root, absent).unwrap().is_none());

        assert_eq!(
            pool.account(other_root, token).unwrap_err(),
            QmdbWitnessError::InvalidProof {
                state_root: other_root
            }
        );
        assert_eq!(
            pool.storage(root, token, U256::from(2)).unwrap_err(),
            QmdbWitnessError::MissingStorageProof {
                address: token,
                slot: U256::from(2),
            }
        );
    }
}
