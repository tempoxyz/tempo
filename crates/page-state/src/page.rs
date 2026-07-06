use alloy_primitives::{Address, B256, U256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const PAGE_SIZE_WORDS: usize = 128;
pub const PAGE_SIZE_BYTES: usize = 4096;
pub const PAGE_INDEX_BITS: usize = 249;
pub const PAGE_DOMAIN: &[u8] = b"tempo/page/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PageCodecError {
    #[error("buffer too short")]
    TooShort,
    #[error("trailing bytes in page codec")]
    TrailingBytes,
    #[error("page word count exceeds 128")]
    TooManyWords,
    #[error("page word offset {0} is outside 0..128")]
    OffsetOutOfRange(u8),
    #[error("page words are not strictly sorted")]
    Unsorted,
    #[error("page codec contains a zero-valued word")]
    ZeroWord,
    #[error("invalid page tree node tag {0}")]
    InvalidNodeTag(u8),
    #[error("invalid node path length {0}")]
    InvalidPathLength(u16),
}

/// Upper 249 bits of a storage slot (`slot >> 7`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PageIndex(U256);

impl PageIndex {
    pub const fn new(index: U256) -> Self {
        Self(index)
    }

    pub fn of_slot(slot: U256) -> Self {
        Self(slot >> 7)
    }

    pub const fn into_inner(self) -> U256 {
        self.0
    }

    /// Returns the page-index bit at `depth`, most-significant bit first.
    pub fn bit(&self, depth: usize) -> bool {
        assert!(depth < PAGE_INDEX_BITS, "page-index depth out of range");
        let bytes = self.0.to_be_bytes::<32>();
        let bit_offset = 256 - PAGE_INDEX_BITS + depth;
        let byte = bytes[bit_offset / 8];
        let mask = 1u8 << (7 - (bit_offset % 8));
        byte & mask != 0
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0.to_be_bytes::<32>()
    }
}

impl From<U256> for PageIndex {
    fn from(value: U256) -> Self {
        Self::new(value)
    }
}

impl From<PageIndex> for U256 {
    fn from(value: PageIndex) -> Self {
        value.0
    }
}

pub fn page_offset(slot: U256) -> u8 {
    (slot & U256::from(0x7f_u8)).to::<u8>()
}

/// Sparse page representation. Zero values are omitted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    words: BTreeMap<u8, U256>,
}

impl Page {
    pub fn set_word(&mut self, offset: u8, value: U256) {
        assert!(
            usize::from(offset) < PAGE_SIZE_WORDS,
            "page offset out of range"
        );
        if value.is_zero() {
            self.words.remove(&offset);
        } else {
            self.words.insert(offset, value);
        }
    }

    pub fn word(&self, offset: u8) -> U256 {
        assert!(
            usize::from(offset) < PAGE_SIZE_WORDS,
            "page offset out of range"
        );
        self.words.get(&offset).copied().unwrap_or_default()
    }

    pub fn words(&self) -> &BTreeMap<u8, U256> {
        &self.words
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    pub fn to_dense(&self) -> Box<[u8; PAGE_SIZE_BYTES]> {
        let mut dense = Box::new([0u8; PAGE_SIZE_BYTES]);
        for (&offset, &word) in &self.words {
            let start = usize::from(offset) * 32;
            dense[start..start + 32].copy_from_slice(&word.to_be_bytes::<32>());
        }
        dense
    }

    pub fn hash(&self, address: Address, index: PageIndex) -> B256 {
        let dense = self.to_dense();
        let mut hasher = blake3::Hasher::new();
        hasher.update(PAGE_DOMAIN);
        hasher.update(address.as_slice());
        hasher.update(&index.to_be_bytes());
        hasher.update(dense.as_ref());
        B256::from_slice(hasher.finalize().as_bytes())
    }

    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.words.len() <= PAGE_SIZE_WORDS);
        let mut out = Vec::with_capacity(2 + self.words.len() * 33);
        out.extend_from_slice(&(self.words.len() as u16).to_be_bytes());
        for (&offset, &word) in &self.words {
            out.push(offset);
            out.extend_from_slice(&word.to_be_bytes::<32>());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, PageCodecError> {
        let Some(count_bytes) = buf.get(..2) else {
            return Err(PageCodecError::TooShort);
        };
        let count = u16::from_be_bytes([count_bytes[0], count_bytes[1]]) as usize;
        if count > PAGE_SIZE_WORDS {
            return Err(PageCodecError::TooManyWords);
        }
        let expected = 2 + count * 33;
        if buf.len() < expected {
            return Err(PageCodecError::TooShort);
        }
        if buf.len() != expected {
            return Err(PageCodecError::TrailingBytes);
        }

        let mut words = BTreeMap::new();
        let mut pos = 2;
        let mut previous = None;
        for _ in 0..count {
            let offset = buf[pos];
            pos += 1;
            if usize::from(offset) >= PAGE_SIZE_WORDS {
                return Err(PageCodecError::OffsetOutOfRange(offset));
            }
            if previous.is_some_and(|prev| offset <= prev) {
                return Err(PageCodecError::Unsorted);
            }
            let mut word = [0u8; 32];
            word.copy_from_slice(&buf[pos..pos + 32]);
            pos += 32;
            let word = U256::from_be_bytes(word);
            if word.is_zero() {
                return Err(PageCodecError::ZeroWord);
            }
            words.insert(offset, word);
            previous = Some(offset);
        }
        Ok(Self { words })
    }
}

impl FromIterator<(u8, U256)> for Page {
    fn from_iter<T: IntoIterator<Item = (u8, U256)>>(iter: T) -> Self {
        let mut page = Self::default();
        for (offset, word) in iter {
            page.set_word(offset, word);
        }
        page
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn page_codec_roundtrip(entries in prop::collection::btree_map(0u8..128, any::<[u8; 32]>(), 0..128)) {
            let mut page = Page::default();
            for (offset, bytes) in entries {
                let word = U256::from_be_bytes(bytes);
                page.set_word(offset, word);
            }
            let decoded = Page::decode(&page.encode()).unwrap();
            prop_assert_eq!(decoded, page);
        }

        #[test]
        fn page_index_roundtrips_slot_partition(slot in any::<[u8; 32]>()) {
            let slot = U256::from_be_bytes(slot);
            let index = PageIndex::of_slot(slot);
            let offset = page_offset(slot);
            prop_assert_eq!((index.into_inner() << 7) + U256::from(offset), slot);
        }
    }
}
