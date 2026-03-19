use alloy_consensus::{BlockHeader, Header, Sealable};
use alloy_primitives::{Address, B64, B256, BlockNumber, Bloom, Bytes, U256, keccak256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// Consensus context metadata for a Tempo block.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub struct TempoConsensusContext {
    pub epoch: u64,
    pub view: u64,
    pub proposer: B256,
    pub parent_view: u64,
}

/// Tempo block header.
///
/// RLP-encoded as `[general_gas_limit, shared_gas_limit, timestamp_millis_part, inner,
/// consensus_context?]`. The `consensus_context` is trailing and omitted for pre-fork blocks.
///
/// RLP is implemented manually because `consensus_context` must be trailing (optional) while
/// `inner: Header` must be the last field for `reth_codecs::Compact`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[rlp(trailing)]
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

    /// Consensus metadata for the block. `None` for pre-fork blocks.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub consensus_context: Option<TempoConsensusContext>,
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

/// Trailing fields grouped into a dedicated struct to maximize the use of bits
/// in a type's bitfields. We add to this prior to occupying another slot in
/// `TempoHeaderCompact`
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
struct TempoHeaderCompactTrailing {
    consensus_context: TempoConsensusContext,
}

/// Private helper for Reth's Compat encoding where the last type
/// must be `Header` as an unknown variable length field.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
struct TempoHeaderCompact {
    /// Non-payment gas limit for the block.
    pub general_gas_limit: u64,
    /// Shared gas limit allocated for the subblocks section of the block.
    pub shared_gas_limit: u64,
    /// Sub-second (milliseconds) portion of the timestamp.
    pub timestamp_millis_part: u64,
    /// Consensus metadata for the block. `None` for pre-fork blocks.
    pub trailing: Option<TempoHeaderCompactTrailing>,
    /// Inner Ethereum [`Header`].
    pub inner: Header,
}

impl reth_codecs::Compact for TempoHeader {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
    {
        let trailing = self
            .consensus_context
            .map(|consensus_context| TempoHeaderCompactTrailing { consensus_context });

        let header = TempoHeaderCompact {
            general_gas_limit: self.general_gas_limit,
            shared_gas_limit: self.shared_gas_limit,
            timestamp_millis_part: self.timestamp_millis_part,
            trailing,
            inner: self.inner.clone(),
        };

        header.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (header_compat, buf) = TempoHeaderCompact::from_compact(buf, len);
        let header = TempoHeader {
            general_gas_limit: header_compat.general_gas_limit,
            shared_gas_limit: header_compat.shared_gas_limit,
            timestamp_millis_part: header_compat.timestamp_millis_part,
            consensus_context: header_compat.trailing.map(|f| f.consensus_context),
            inner: header_compat.inner.clone(),
        };

        (header, buf)
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

#[cfg(all(test, feature = "reth-codec"))]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{address, b256, bytes, hex};
    use alloy_rlp::Decodable;
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
            TempoHeaderCompact::bitflag_unused_bits(),
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
            consensus_context: None,
            inner: Header {
                parent_hash: b256!(
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                ommers_hash: b256!(
                    "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                ),
                beneficiary: address!("0x000000000000000000000000000000000000beef"),
                state_root: b256!(
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                transactions_root: b256!(
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                ),
                receipts_root: b256!(
                    "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                ),
                logs_bloom: Bloom::with_last_byte(0xff),
                difficulty: U256::from(1u64),
                number: 1000,
                gas_limit: 30_000_000,
                gas_used: 15_000_000,
                timestamp: 1_700_000_000,
                extra_data: bytes!("deadbeef"),
                mix_hash: b256!(
                    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                ),
                nonce: B64::from(42u64),
                base_fee_per_gas: Some(7),
                withdrawals_root: Some(b256!(
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                )),
                blob_gas_used: Some(131072),
                excess_blob_gas: Some(65536),
                parent_beacon_block_root: Some(b256!(
                    "0x2222222222222222222222222222222222222222222222222222222222222222"
                )),
                requests_hash: Some(b256!(
                    "0x3333333333333333333333333333333333333333333333333333333333333333"
                )),
            },
        };

        let expected = hex!(
            "340201c9c38098968001f403a1a1f8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347000000000000000000000000000000000000beefbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff0103e801c9c380e4e1c06553f100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee2a01070302000003010000222222222222222222222222222222222222222222222222222222222222222221013333333333333333333333333333333333333333333333333333333333333333deadbeef"
        );

        let mut buf = vec![];
        let len = header.to_compact(&mut buf);
        assert_eq!(
            buf, expected,
            "compact encoding changed — this breaks backwards compatibility"
        );
        assert_eq!(len, expected.len());

        let (decoded, _) = TempoHeader::from_compact(&expected, expected.len());
        assert_eq!(decoded, header);
    }

    /// Presto block 1 — a real mainnet header without consensus context (T4 not active).
    fn presto_block_1() -> TempoHeader {
        TempoHeader {
            general_gas_limit: 0xd693a40,
            shared_gas_limit: 0x2faf080,
            timestamp_millis_part: 0x2c5,
            consensus_context: None,
            inner: Header {
                parent_hash: b256!(
                    "49d7ec7085e77bf5a403d0fcb4cfc42a4084a89dfff60477579c5e09c9e03c54"
                ),
                ommers_hash: b256!(
                    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
                ),
                state_root: b256!(
                    "83408974323f63ab969b23f0fe1dba30d7ee5dc5c524a975bae38187eaa2c7f6"
                ),
                transactions_root: b256!(
                    "6cbfac2d2b694b71b37538fe5bcc8450fc4bdab1c3c2119a450e333a724d1b44"
                ),
                receipts_root: b256!(
                    "b64408da6b8fe39ab764af88ece1e8cca1c35fd988db57806e99138c629365a0"
                ),
                withdrawals_root: Some(b256!(
                    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                )),
                parent_beacon_block_root: Some(B256::ZERO),
                requests_hash: Some(b256!(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                )),
                number: 1,
                gas_limit: 0x1dcd6500,
                gas_used: 0,
                timestamp: 0x696aa4c7,
                base_fee_per_gas: Some(0x2540be400),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                beneficiary: Address::ZERO,
                ..Default::default()
            },
        }
    }

    #[test]
    fn presto_block_1_hash_backwards_compat() {
        let header = presto_block_1();
        let hash = header.hash_slow();

        // Presto block 1 on-chain hash. If this changes, RLP encoding has broken.
        let expected = "0x76e86f9739fbe17669b01b24e976ac214742c4b1bbc6ae0c083a87e43a5e9b0f";
        assert_eq!(format!("{hash:#x}"), expected);
    }

    #[test]
    fn presto_block_1_rlp_roundtrip() {
        let header = presto_block_1();
        let encoded = alloy_rlp::encode(&header);
        let decoded = TempoHeader::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(header, decoded);
    }

    #[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
    struct TestPreT4TempoHeader {
        pub general_gas_limit: u64,
        pub shared_gas_limit: u64,
        pub timestamp_millis_part: u64,
        pub inner: Header,
    }

    #[test]
    fn presto_block_1_compact_roundtrip() {
        use reth_codecs::Compact;

        let header = presto_block_1();
        let pre_t4_header = TestPreT4TempoHeader {
            general_gas_limit: header.general_gas_limit,
            shared_gas_limit: header.shared_gas_limit,
            timestamp_millis_part: header.timestamp_millis_part,
            inner: header.inner.clone(),
        };

        let mut header_buf = vec![];
        let mut pre_t4_header_buf = vec![];

        let header_len = header.to_compact(&mut header_buf);
        let pre_t4_len = pre_t4_header.to_compact(&mut pre_t4_header_buf);

        assert_eq!(header_len, pre_t4_len);
        assert_eq!(header_buf, pre_t4_header_buf);
    }
}
