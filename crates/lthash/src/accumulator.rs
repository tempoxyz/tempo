//! The lthash accumulator and the canonical encoding of its elements.

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{B256, StorageValue};
use reth_primitives_traits::Account;

pub(crate) const LTHASH_ACCUMULATOR_LEN: usize = 2048;
const LTHASH_ACCUMULATOR_LANES: usize = LTHASH_ACCUMULATOR_LEN / 2;
pub(crate) const LTHASH_ACCOUNT_ELEMENT_LEN: usize = 105;
pub(crate) const LTHASH_STORAGE_ELEMENT_LEN: usize = 97;
const LTHASH_ACCOUNT_DOMAIN: u8 = 0x00;
const LTHASH_STORAGE_DOMAIN: u8 = 0x01;

/// A homomorphic hash of a set of state elements: adding and removing elements commutes, so
/// equal sets yield equal accumulators no matter the order updates were applied in.
///
/// The accumulator represents 2048 bytes of state, divided into 1024 lanes. [`Self::checksum]
/// represents the same state as a digest, which is ultimately used as the commitment. However,
/// it's not possible to go from a digest back to the accumulator state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LthashAccumulator([u16; LTHASH_ACCUMULATOR_LANES]);

impl LthashAccumulator {
    pub(crate) const fn zero() -> Self {
        Self([0; LTHASH_ACCUMULATOR_LANES])
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(|lane| lane.to_le_bytes()).collect()
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != LTHASH_ACCUMULATOR_LEN {
            return None;
        }
        let mut lanes = [0u16; LTHASH_ACCUMULATOR_LANES];
        for (lane, chunk) in lanes.iter_mut().zip(bytes.chunks_exact(2)) {
            *lane = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        Some(Self(lanes))
    }

    pub(crate) fn add(&mut self, data: impl AsRef<[u8]>) {
        let lanes = Self::expand(data.as_ref());
        for (lane, value) in self.0.iter_mut().zip(lanes) {
            *lane = lane.wrapping_add(value);
        }
    }

    pub(crate) fn subtract(&mut self, data: impl AsRef<[u8]>) {
        let lanes = Self::expand(data.as_ref());
        for (lane, value) in self.0.iter_mut().zip(lanes) {
            *lane = lane.wrapping_sub(value);
        }
    }

    pub(crate) fn checksum(&self) -> B256 {
        let mut bytes = [0; LTHASH_ACCUMULATOR_LEN];
        for (i, lane) in self.0.iter().enumerate() {
            let lane = lane.to_le_bytes();
            bytes[i * 2] = lane[0];
            bytes[i * 2 + 1] = lane[1];
        }
        B256::from(*blake3::hash(&bytes).as_bytes())
    }

    fn expand(data: &[u8]) -> [u16; LTHASH_ACCUMULATOR_LANES] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);

        let mut bytes = [0; LTHASH_ACCUMULATOR_LEN];
        hasher.finalize_xof().fill(&mut bytes);

        let mut lanes = [0; LTHASH_ACCUMULATOR_LANES];
        for (i, chunk) in bytes.chunks_exact(2).enumerate() {
            lanes[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        lanes
    }
}

pub(crate) fn lthash_account_element(
    hashed_address: B256,
    account: Account,
) -> Option<[u8; LTHASH_ACCOUNT_ELEMENT_LEN]> {
    if account.is_empty() {
        return None;
    }

    let mut element = [0u8; LTHASH_ACCOUNT_ELEMENT_LEN];
    element[0] = LTHASH_ACCOUNT_DOMAIN;
    element[1..33].copy_from_slice(hashed_address.as_slice());
    element[33..41].copy_from_slice(&account.nonce.to_be_bytes());
    element[41..73].copy_from_slice(&account.balance.to_be_bytes::<32>());
    element[73..105].copy_from_slice(account.bytecode_hash.unwrap_or(KECCAK_EMPTY).as_slice());
    Some(element)
}

pub(crate) fn lthash_storage_element(
    hashed_address: B256,
    hashed_slot: B256,
    value: StorageValue,
) -> Option<[u8; LTHASH_STORAGE_ELEMENT_LEN]> {
    if value.is_zero() {
        return None;
    }

    let mut element = [0u8; LTHASH_STORAGE_ELEMENT_LEN];
    element[0] = LTHASH_STORAGE_DOMAIN;
    element[1..33].copy_from_slice(hashed_address.as_slice());
    element[33..65].copy_from_slice(hashed_slot.as_slice());
    element[65..97].copy_from_slice(&value.to_be_bytes::<32>());
    Some(element)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::account;

    #[test]
    fn accumulator_bytes_round_trip() {
        let mut accumulator = LthashAccumulator::zero();
        accumulator.add(lthash_account_element(B256::repeat_byte(0x33), account(5, 50)).unwrap());

        let bytes = accumulator.to_bytes();
        assert_eq!(bytes.len(), LTHASH_ACCUMULATOR_LEN);
        assert_eq!(LthashAccumulator::from_bytes(&bytes).unwrap(), accumulator);

        assert!(LthashAccumulator::from_bytes(&bytes[1..]).is_none());
        assert!(LthashAccumulator::from_bytes(&[]).is_none());
    }
}
