//! Synthetic contract accounts for cold-call benchmarks.
//!
//! A dump stores only the parameters of a contract range; the importer expands it.
//! Contract `i` lives at the last 20 bytes of `keccak256(seed || uint64_be(i))`, the
//! state-bloat fast derivation, so fixtures can compute targets onchain. Its code
//! returns that hash as one word, then pads to `size` bytes with pseudo-random filler,
//! so every contract has distinct code and a caller can depend on what it loaded.

use alloy_primitives::{Address, B256, Bytes, keccak256};
use eyre::ensure;

/// Header flag of a contract-range block.
pub(crate) const CONTRACTS_FLAG: u16 = 1;

/// Largest deployable code (EIP-170).
pub const MAX_CONTRACT_SIZE: u64 = 24_576;

/// Length of the executed prefix: `PUSH32 <tag> PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN`.
pub(crate) const CONTRACT_PREFIX_LEN: u64 = 39;

/// Default seed of synthetic contract addresses: `keccak256("tempo-state-bloat-contracts")`.
pub fn default_contract_seed() -> B256 {
    keccak256(b"tempo-state-bloat-contracts")
}

/// A range of synthetic contracts in a dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractRange {
    /// Address derivation seed.
    pub seed: B256,
    /// Number of contracts, indices `0..count`.
    pub count: u64,
    /// Code size of every contract in bytes.
    pub size: u64,
}

impl ContractRange {
    /// Validate the range parameters.
    pub fn validate(&self) -> eyre::Result<()> {
        ensure!(self.count > 0, "contract count must be greater than 0");
        ensure!(
            (CONTRACT_PREFIX_LEN..=MAX_CONTRACT_SIZE).contains(&self.size),
            "contract size must be between {CONTRACT_PREFIX_LEN} and {MAX_CONTRACT_SIZE} bytes"
        );
        Ok(())
    }

    /// Encode as one 64-byte dump entry: `[seed:32][count:8][size:8][zero:16]`.
    pub(crate) fn encode(&self) -> [u8; 64] {
        let mut entry = [0u8; 64];
        entry[..32].copy_from_slice(self.seed.as_slice());
        entry[32..40].copy_from_slice(&self.count.to_be_bytes());
        entry[40..48].copy_from_slice(&self.size.to_be_bytes());
        entry
    }

    /// Decode a dump entry written by [`Self::encode`].
    pub(crate) fn decode(entry: &[u8; 64]) -> eyre::Result<Self> {
        ensure!(entry[48..] == [0u8; 16], "unsupported contract range entry");
        let range = Self {
            seed: B256::from_slice(&entry[..32]),
            count: u64::from_be_bytes(entry[32..40].try_into()?),
            size: u64::from_be_bytes(entry[40..48].try_into()?),
        };
        range.validate()?;
        Ok(range)
    }

    /// The hash contract `index` derives from: its address preimage and returned word.
    pub fn tag(&self, index: u64) -> B256 {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(self.seed.as_slice());
        buf[32..].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }

    /// Address of contract `index`.
    pub fn address(&self, index: u64) -> Address {
        Address::from_word(self.tag(index))
    }

    /// Code of contract `index`.
    pub fn code(&self, index: u64) -> Bytes {
        let tag = self.tag(index);
        let size = self.size as usize;
        let mut code = Vec::with_capacity(size);
        code.push(0x7f); // PUSH32
        code.extend_from_slice(tag.as_slice());
        code.extend_from_slice(&[0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
        // The filler never runs; splitmix64 keeps it distinct without hashing every word.
        let mut state = u64::from_be_bytes(tag[..8].try_into().expect("8 bytes"));
        while code.len() < size {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let take = (size - code.len()).min(8);
            code.extend_from_slice(&z.to_le_bytes()[..take]);
        }
        code.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_distinct_sized_and_return_their_tag() {
        let range = ContractRange {
            seed: default_contract_seed(),
            count: 3,
            size: MAX_CONTRACT_SIZE,
        };
        let codes: Vec<_> = (0..3).map(|i| range.code(i)).collect();
        for (i, code) in codes.iter().enumerate() {
            assert_eq!(code.len() as u64, MAX_CONTRACT_SIZE);
            assert_eq!(code[0], 0x7f);
            assert_eq!(&code[1..33], range.tag(i as u64).as_slice());
            assert_eq!(&code[33..39], &[0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
        }
        assert_ne!(keccak256(&codes[0]), keccak256(&codes[1]));
        assert_eq!(range.code(1), codes[1]);
        assert_eq!(range.address(0), Address::from_word(range.tag(0)));
    }

    #[test]
    fn range_round_trips_and_validates() {
        let range = ContractRange {
            seed: B256::repeat_byte(7),
            count: 10,
            size: 100,
        };
        assert_eq!(ContractRange::decode(&range.encode()).unwrap(), range);
        let mut bad = range.encode();
        bad[63] = 1;
        assert!(ContractRange::decode(&bad).is_err());
        for (count, size) in [(0, 100), (1, 38), (1, MAX_CONTRACT_SIZE + 1)] {
            let invalid = ContractRange {
                count,
                size,
                ..range
            };
            assert!(ContractRange::decode(&invalid.encode()).is_err());
        }
    }
}
