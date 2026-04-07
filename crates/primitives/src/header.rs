use alloy_consensus::{BlockHeader, Header, Sealable};
use alloy_primitives::{Address, B64, B256, BlockNumber, Bloom, Bytes, U256, keccak256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// Tempo block header.
///
/// Encoded as `rlp([general_gas_limit, shared_gas_limit, timestamp_millis_part, inner])` meaning that any new
/// fields added to the inner header will only affect the first list element.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub struct TempoHeader {
    /// Non-payment gas limit for the block.
    #[cfg_attr(
        feature = "serde",
        serde(with = "alloy_serde::quantity", rename = "mainBlockGeneralGasLimit")
    )]
    pub general_gas_limit: u64,

    /// Shared gas limit allocated for the subblocks section of the block.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub shared_gas_limit: u64,

    /// Sub-second (milliseconds) portion of the timestamp.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub timestamp_millis_part: u64,

    /// Inner Ethereum [`Header`].
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub inner: Header,
}

impl TempoHeader {
    /// Returns the timestamp in milliseconds.
    pub fn timestamp_millis(&self) -> u64 {
        self.inner
            .timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timestamp_millis_part)
    }
}

impl AsRef<Self> for TempoHeader {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl BlockHeader for TempoHeader {
    fn parent_hash(&self) -> B256 {
        self.inner.parent_hash()
    }

    fn ommers_hash(&self) -> B256 {
        self.inner.ommers_hash()
    }

    fn beneficiary(&self) -> Address {
        self.inner.beneficiary()
    }

    fn state_root(&self) -> B256 {
        self.inner.state_root()
    }

    fn transactions_root(&self) -> B256 {
        self.inner.transactions_root()
    }

    fn receipts_root(&self) -> B256 {
        self.inner.receipts_root()
    }

    fn withdrawals_root(&self) -> Option<B256> {
        self.inner.withdrawals_root()
    }

    fn logs_bloom(&self) -> Bloom {
        self.inner.logs_bloom()
    }

    fn difficulty(&self) -> U256 {
        self.inner.difficulty()
    }

    fn number(&self) -> BlockNumber {
        self.inner.number()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_used(&self) -> u64 {
        self.inner.gas_used()
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn mix_hash(&self) -> Option<B256> {
        self.inner.mix_hash()
    }

    fn nonce(&self) -> Option<B64> {
        self.inner.nonce()
    }

    fn base_fee_per_gas(&self) -> Option<u64> {
        self.inner.base_fee_per_gas()
    }

    fn blob_gas_used(&self) -> Option<u64> {
        self.inner.blob_gas_used()
    }

    fn excess_blob_gas(&self) -> Option<u64> {
        self.inner.excess_blob_gas()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }

    fn requests_hash(&self) -> Option<B256> {
        self.inner.requests_hash()
    }

    fn extra_data(&self) -> &Bytes {
        self.inner.extra_data()
    }
}

impl Sealable for TempoHeader {
    fn hash_slow(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{b256, hex};
    use reth_codecs::Compact;

    /// Ensures backwards compatibility of the compact bitflag.
    ///
    /// If this fails because unused bits dropped to zero, new fields should be added via an
    /// extension type (e.g. `Option<TempoHeaderExt>`) rather than directly to [`TempoHeader`].
    ///
    /// See reth's `HeaderExt` pattern:
    /// <https://github.com/paradigmxyz/reth-core/blob/0476d1bc4b71f3c3b080622be297edd91ee4e70c/crates/codecs/src/alloy/header.rs>
    #[test]
    fn tempo_header_has_unused_compact_bits() {
        assert_ne!(
            TempoHeader::bitflag_unused_bits(),
            0,
            "TempoHeader compact bitflag has no unused bits left — use an extension type"
        );
    }

    #[test]
    fn tempo_header_compact_roundtrip() {
        let header = TempoHeader {
            general_gas_limit: 30_000_000,
            shared_gas_limit: 10_000_000,
            timestamp_millis_part: 500,
            inner: Header {
                parent_hash: B256::ZERO,
                ommers_hash: b256!("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
                beneficiary: Address::ZERO,
                state_root: b256!("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
                transactions_root: b256!("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
                receipts_root: b256!("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
                logs_bloom: Bloom::ZERO,
                difficulty: U256::ZERO,
                number: 1000,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1_700_000_000,
                extra_data: Bytes::new(),
                mix_hash: B256::ZERO,
                nonce: B64::ZERO,
                base_fee_per_gas: Some(7),
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            },
        };

        let expected = hex!("340201c9c38098968001f40021200800000000000000000000000000000000000000000000000000000000000000001dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347000000000000000000000000000000000000000056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42156e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42156e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e801c9c3806553f10000000000000000000000000000000000000000000000000000000000000000000107");

        let mut buf = vec![];
        let len = header.to_compact(&mut buf);
        assert_eq!(buf, expected, "compact encoding changed — this breaks backwards compatibility");
        assert_eq!(len, expected.len());

        let (decoded, _) = TempoHeader::from_compact(&expected, expected.len());
        assert_eq!(decoded, header);
    }
}
