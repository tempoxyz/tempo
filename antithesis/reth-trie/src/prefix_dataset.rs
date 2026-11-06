//! Prefix-indexed Keccak preimages for trie addresses and slots.

use alloy_primitives::{keccak256, Address, B256, U256};
use eyre::{ensure, Result};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serializer};
use std::{
    fs,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::OnceLock,
};

const MAGIC: &[u8; 8] = b"TRIEKEY1";
static KEYS: OnceLock<KeySpace> = OnceLock::new();
static DATASET: OnceLock<Option<PathBuf>> = OnceLock::new();
static INDICES: OnceLock<KeySpace> = OnceLock::new();
#[derive(Debug)]
pub(crate) struct KeySpace {
    bits: u8,
    addresses: Vec<u64>,
    slots: Vec<u64>,
}

fn address_from(candidate: u64) -> Address {
    Address::from_word(B256::from(U256::from(candidate)))
}

fn prefix(hash: B256, bits: u8) -> usize {
    let bytes = hash.as_slice();
    let mut prefix = 0usize;
    for byte in &bytes[..(bits / 8) as usize] {
        prefix = (prefix << 8) | usize::from(*byte);
    }
    if !bits.is_multiple_of(8) {
        prefix = (prefix << 4) | usize::from(bytes[(bits / 8) as usize] >> 4);
    }
    prefix
}

impl KeySpace {
    fn from_tables(bits: u8, addresses: Vec<u64>, slots: Vec<u64>) -> Result<Self> {
        ensure!(
            (4..=28).contains(&bits) && bits.is_multiple_of(4),
            "prefix bits must be a multiple of four in 4..=28"
        );
        let count = 1usize << bits;
        ensure!(addresses.len() == count && slots.len() == count, "incorrect prefix table length");
        // Check small tables eagerly; validating all 2^24 entries on every
        // planner invocation would dwarf the actual execution. Large Nix
        // outputs are immutable; lookups verify each entry before use.
        if bits <= 16 {
            ensure!(
                addresses
                    .iter()
                    .enumerate()
                    .all(|(i, value)| prefix(keccak256(address_from(*value)), bits) == i),
                "invalid address prefix table"
            );
            ensure!(
                slots
                    .iter()
                    .enumerate()
                    .all(|(i, value)| prefix(keccak256(B256::from(U256::from(*value))), bits) == i),
                "invalid slot prefix table"
            );
        }
        Ok(Self { bits, addresses, slots })
    }

    pub(crate) fn read(path: &Path) -> Result<Self> {
        let file = fs::File::open(path)?;
        let size = file.metadata()?.len();
        let mut reader = BufReader::new(file);
        let mut header = [0u8; 9];
        reader.read_exact(&mut header)?;
        ensure!(&header[..8] == MAGIC, "invalid prefix dataset header");
        let bits = header[8];
        ensure!(
            (4..=28).contains(&bits) && bits.is_multiple_of(4),
            "prefix bits must be a multiple of four in 4..=28"
        );
        let count = 1usize << bits;
        ensure!(size == (9 + 16 * count) as u64, "invalid prefix dataset size");
        let mut read_table = || -> Result<Vec<u64>> {
            let mut table = Vec::with_capacity(count);
            let mut word = [0u8; 8];
            for _ in 0..count {
                reader.read_exact(&mut word)?;
                table.push(u64::from_le_bytes(word));
            }
            Ok(table)
        };
        let addresses = read_table()?;
        let slots = read_table()?;
        Self::from_tables(bits, addresses, slots)
    }

    fn address(&self, index: u64) -> Result<Address> {
        let candidate = *self
            .addresses
            .get(usize::try_from(index)?)
            .ok_or_else(|| eyre::eyre!("address index outside prefix table"))?;
        let address = address_from(candidate);
        ensure!(
            prefix(keccak256(address), self.bits) == index as usize,
            "invalid address prefix table"
        );
        Ok(address)
    }

    fn slot(&self, index: u64) -> Result<U256> {
        let candidate = *self
            .slots
            .get(usize::try_from(index)?)
            .ok_or_else(|| eyre::eyre!("slot index outside prefix table"))?;
        let slot = U256::from(candidate);
        ensure!(
            prefix(keccak256(B256::from(slot)), self.bits) == index as usize,
            "invalid slot prefix table"
        );
        Ok(slot)
    }
}

pub(crate) fn init(path: Option<&Path>) -> Result<()> {
    let bits = if let Some(path) = path {
        let mut file = fs::File::open(path)?;
        let mut header = [0u8; 9];
        file.read_exact(&mut header)?;
        ensure!(&header[..8] == MAGIC, "invalid prefix dataset header");
        let bits = header[8];
        ensure!((4..=28).contains(&bits) && bits.is_multiple_of(4), "invalid prefix dataset bits");
        ensure!(file.metadata()?.len() == 9 + 16 * (1u64 << bits), "invalid prefix dataset size");
        bits
    } else {
        0
    };
    INDICES
        .set(KeySpace { bits, addresses: Vec::new(), slots: Vec::new() })
        .map_err(|_| eyre::eyre!("prefix dataset already initialized"))?;
    DATASET
        .set(path.map(Path::to_path_buf))
        .map_err(|_| eyre::eyre!("prefix dataset already initialized"))?;
    if path.is_none() {
        load()?;
    }
    Ok(())
}

pub(crate) fn load() -> Result<()> {
    if KEYS.get().is_none() {
        let keys = match DATASET.get().expect("prefix dataset initialized at process entry") {
            Some(path) => KeySpace::read(path)?,
            None => KeySpace { bits: 0, addresses: Vec::new(), slots: Vec::new() },
        };
        KEYS.set(keys).map_err(|_| eyre::eyre!("prefix dataset already loaded"))?;
    }
    Ok(())
}

pub(crate) fn check_bits(bits: u8) -> Result<()> {
    ensure!((4..=28).contains(&bits) && bits.is_multiple_of(4), "invalid prefix_bits");
    // Without a packaged table, direct local runs retain the old integer keys.
    let loaded = INDICES.get().expect("prefix dataset initialized at process entry").bits;
    ensure!(loaded == 0 || loaded == bits, "prefix_bits={bits} differs from dataset={loaded}");
    Ok(())
}

fn keys() -> &'static KeySpace {
    KEYS.get().expect("prefix dataset loaded before key lookup")
}

pub(crate) fn random_address(rng: &mut impl Rng) -> Address {
    let keys = keys();
    if keys.bits == 0 {
        address_from(u64::from(rng.random::<u32>()))
    } else {
        keys.address(rng.random_range(0..keys.addresses.len() as u64)).expect("valid index")
    }
}

pub(crate) fn random_slot(rng: &mut impl Rng) -> U256 {
    let keys = keys();
    if keys.bits == 0 {
        U256::from(rng.random::<u32>())
    } else {
        keys.slot(rng.random_range(0..keys.slots.len() as u64)).expect("valid index")
    }
}

pub(crate) mod address {
    use super::*;
    pub(crate) fn serialize<S: Serializer>(
        value: &Address,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let candidate = u64::try_from(U256::from_be_bytes(value.into_word().0))
            .map_err(serde::ser::Error::custom)?;
        let keys = keys();
        let index = if keys.bits == 0 {
            candidate
        } else {
            let index = prefix(keccak256(*value), keys.bits);
            if keys.addresses[index] != candidate {
                return Err(serde::ser::Error::custom("address absent from prefix dataset"));
            }
            index as u64
        };
        serializer.serialize_u64(index)
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Address, D::Error> {
        let index = u64::deserialize(deserializer)?;
        let keys = keys();
        if keys.bits == 0 {
            Ok(address_from(index))
        } else {
            keys.address(index).map_err(serde::de::Error::custom)
        }
    }
}

pub(crate) mod slot {
    use super::*;
    pub(crate) fn serialize<S: Serializer>(
        value: &U256,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let candidate = u64::try_from(*value).map_err(serde::ser::Error::custom)?;
        let keys = keys();
        let index = if keys.bits == 0 {
            candidate
        } else {
            let index = prefix(keccak256(B256::from(*value)), keys.bits);
            if keys.slots[index] != candidate {
                return Err(serde::ser::Error::custom("slot absent from prefix dataset"));
            }
            index as u64
        };
        serializer.serialize_u64(index)
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<U256, D::Error> {
        let index = u64::deserialize(deserializer)?;
        let keys = keys();
        if keys.bits == 0 {
            Ok(U256::from(index))
        } else {
            keys.slot(index).map_err(serde::de::Error::custom)
        }
    }
}

pub(crate) mod addresses {
    use super::*;
    pub(crate) fn serialize<S: Serializer>(
        values: &[Address],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            seq.serialize_element(&AddressIndex(value))?;
        }
        seq.end()
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<Address>, D::Error> {
        let indices = Vec::<u64>::deserialize(deserializer)?;
        indices
            .into_iter()
            .map(|index| {
                if keys().bits == 0 {
                    Ok(address_from(index))
                } else {
                    keys().address(index).map_err(serde::de::Error::custom)
                }
            })
            .collect()
    }
    struct AddressIndex<'a>(&'a Address);
    impl serde::Serialize for AddressIndex<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
            address::serialize(self.0, serializer)
        }
    }
}
