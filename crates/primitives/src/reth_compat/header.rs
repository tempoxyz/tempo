use crate::TempoHeader;
use alloy_primitives::{B256, BlockNumber, U256};

impl reth_primitives_traits::InMemorySize for TempoHeader {
    fn size(&self) -> usize {
        let Self {
            inner,
            general_gas_limit,
            timestamp_millis_part,
            shared_gas_limit,
        } = self;
        inner.size()
            + general_gas_limit.size()
            + timestamp_millis_part.size()
            + shared_gas_limit.size()
    }
}

impl reth_primitives_traits::BlockHeader for TempoHeader {}

impl reth_primitives_traits::header::HeaderMut for TempoHeader {
    fn set_parent_hash(&mut self, hash: B256) {
        self.inner.set_parent_hash(hash);
    }

    fn set_block_number(&mut self, number: BlockNumber) {
        self.inner.set_block_number(number);
    }

    fn set_timestamp(&mut self, timestamp: u64) {
        self.inner.set_timestamp(timestamp);
    }

    fn set_state_root(&mut self, state_root: B256) {
        self.inner.set_state_root(state_root);
    }

    fn set_difficulty(&mut self, difficulty: U256) {
        self.inner.set_difficulty(difficulty);
    }
}

#[cfg(feature = "reth-codec")]
mod codec {
    use crate::TempoHeader;

    impl reth_db_api::table::Compress for TempoHeader {
        type Compressed = alloc::vec::Vec<u8>;

        fn compress_to_buf<B: alloy_primitives::bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
            let _ = reth_codecs::Compact::to_compact(self, buf);
        }
    }

    impl reth_db_api::table::Decompress for TempoHeader {
        fn decompress(value: &[u8]) -> Result<Self, reth_codecs::DecompressError> {
            let (obj, _) = reth_codecs::Compact::from_compact(value, value.len());
            Ok(obj)
        }
    }
}
