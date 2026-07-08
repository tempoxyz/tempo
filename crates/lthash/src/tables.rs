//! Database tables for the lthash prototype.

use alloy_primitives::B256;
use reth_db_api::{TableSet, TableType, TableViewer, table::TableInfo, tables};
use std::fmt;

tables! {
    /// Lthash accumulator of each persisted block, keyed by block number.
    ///
    /// The value is the block hash followed by the accumulator bytes; see
    /// [`encode_accumulator_row`]. Keying by number makes rows self-overwriting when a
    /// reorg crosses the persisted height; the stored hash is checked on read.
    table LthashAccumulators {
        type Key = u64;
        type Value = Vec<u8>;
    }
}

/// Encodes a [`LthashAccumulators`] value: block hash then accumulator bytes.
pub fn encode_accumulator_row(block_hash: B256, accumulator: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(32 + accumulator.len());
    value.extend_from_slice(block_hash.as_slice());
    value.extend_from_slice(accumulator);
    value
}

/// Decodes a [`LthashAccumulators`] value into the block hash and accumulator bytes.
pub fn decode_accumulator_row(value: &[u8]) -> Option<(B256, &[u8])> {
    if value.len() <= 32 {
        return None;
    }
    let (hash, accumulator) = value.split_at(32);
    Some((B256::from_slice(hash), accumulator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::LthashAccumulator;

    #[test]
    fn accumulator_row_round_trip() {
        let hash = B256::repeat_byte(0x44);
        let accumulator = LthashAccumulator::zero().to_bytes();

        let row = encode_accumulator_row(hash, &accumulator);
        let (decoded_hash, decoded) = decode_accumulator_row(&row).unwrap();
        assert_eq!(decoded_hash, hash);
        assert_eq!(decoded, accumulator.as_slice());

        assert!(decode_accumulator_row(&row[..32]).is_none());
        assert!(decode_accumulator_row(&[]).is_none());
    }
}
