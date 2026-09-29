use crate::{TempoConsensusContext, TempoHeader};
use alloy_primitives::{B256, BlockNumber, Bytes, U256};

impl reth_primitives_traits::InMemorySize for TempoConsensusContext {
    fn size(&self) -> usize {
        self.epoch.size() + self.view.size() + self.proposer.size() + self.parent_view.size()
    }
}

impl reth_primitives_traits::InMemorySize for TempoHeader {
    fn size(&self) -> usize {
        let Self {
            inner,
            general_gas_limit,
            timestamp_millis_part,
            shared_gas_limit,
            consensus_context,
        } = self;
        inner.size()
            + general_gas_limit.size()
            + timestamp_millis_part.size()
            + shared_gas_limit.size()
            + consensus_context.size()
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

    fn set_mix_hash(&mut self, mix_hash: B256) {
        self.inner.set_mix_hash(mix_hash);
    }

    fn set_extra_data(&mut self, extra_data: Bytes) {
        self.inner.set_extra_data(extra_data);
    }

    fn set_parent_beacon_block_root(&mut self, parent_beacon_block_root: Option<B256>) {
        self.inner
            .set_parent_beacon_block_root(parent_beacon_block_root);
    }
}

#[cfg(feature = "reth-codec")]
mod codec {
    use crate::{TempoConsensusContext, TempoHeader};
    use alloy_consensus::Header;
    use reth_codecs::Compact;

    /// Trailing fields grouped into a dedicated struct to maximize the use of bits
    /// in a type's bitfields. We add to this prior to occupying another slot in
    /// `TempoHeaderCompact`
    #[derive(Clone, Debug, Default, Eq, Hash, PartialEq, reth_codecs::Compact)]
    #[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
    #[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
    struct TempoHeaderTrailingCompact {
        consensus_context: Option<TempoConsensusContext>,
    }

    /// Private helper for Reth's Compat encoding where the last type
    /// must be `Header` as an unknown variable length field.
    #[derive(Clone, Debug, Default, Eq, Hash, PartialEq, reth_codecs::Compact)]
    #[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
    #[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
    struct TempoHeaderCompact {
        /// Non-payment gas limit for the block.
        pub general_gas_limit: u64,
        /// Shared gas limit allocated for the subblocks section of the block.
        pub shared_gas_limit: u64,
        /// Sub-second (milliseconds) portion of the timestamp.
        pub timestamp_millis_part: u64,
        /// Added trailing options
        pub trailing: Option<TempoHeaderTrailingCompact>,
        /// Inner Ethereum [`Header`].
        pub inner: Header,
    }

    impl reth_codecs::Compact for TempoHeader {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
        {
            // Retain the existing presence bits for context-bearing database records.
            let trailing = Some(TempoHeaderTrailingCompact {
                consensus_context: Some(self.consensus_context),
            });

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
            let header = header_compat
                .try_into()
                .expect("missing consensus context in compact header");
            (header, buf)
        }
    }

    impl reth_db_api::table::Compress for TempoHeader {
        type Compressed = alloc::vec::Vec<u8>;

        fn compress_to_buf<B: alloy_primitives::bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
            let _ = reth_codecs::Compact::to_compact(self, buf);
        }
    }

    impl reth_db_api::table::Decompress for TempoHeader {
        fn decompress(value: &[u8]) -> Result<Self, reth_codecs::DecompressError> {
            let (header, _) = TempoHeaderCompact::from_compact(value, value.len());
            header.try_into()
        }
    }

    impl TryFrom<TempoHeaderCompact> for TempoHeader {
        type Error = reth_codecs::DecompressError;

        fn try_from(header: TempoHeaderCompact) -> Result<Self, Self::Error> {
            let consensus_context = header
                .trailing
                .and_then(|fields| fields.consensus_context)
                .ok_or_else(|| {
                    reth_codecs::DecompressError::new(alloy_rlp::Error::Custom(
                        "missing consensus context in compact header",
                    ))
                })?;
            Ok(Self {
                general_gas_limit: header.general_gas_limit,
                shared_gas_limit: header.shared_gas_limit,
                timestamp_millis_part: header.timestamp_millis_part,
                consensus_context,
                inner: header.inner,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloy_consensus::Sealable;
        use alloy_primitives::{Address, B256, Bloom, U256, address, b256, bytes, hex};
        use alloy_rlp::Decodable;
        use reth_codecs::{Compact, Decompress};

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
                "TempoHeaderCompact bitflag has no unused bits left — use an extension type"
            );
        }

        #[test]
        fn tempo_header_trailing_has_unused_compact_bits() {
            assert_ne!(
                TempoHeaderTrailingCompact::bitflag_unused_bits(),
                0,
                "TempoHeaderTrailingCompact bitflag has no unused bits left — use another extension type"
            );
        }

        #[test]
        fn tempo_header_compact_roundtrip() {
            let header = TempoHeader {
                general_gas_limit: 30_000_000,
                shared_gas_limit: 10_000_000,
                timestamp_millis_part: 500,
                consensus_context: Default::default(),
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
                    nonce: alloy_primitives::B64::from(42u64),
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
                    block_access_list_hash: None,
                    slot_number: None,
                },
            };

            let expected = hex!(
                "340201c9c38098968001f403a1a1f8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347000000000000000000000000000000000000beefbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff0103e801c9c380e4e1c06553f100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee2a01070302000003010000222222222222222222222222222222222222222222222222222222222222222221013333333333333333333333333333333333333333333333333333333333333333deadbeef"
            );

            let mut buf = vec![];
            let len = header.to_compact(&mut buf);
            assert_ne!(buf, expected);
            assert!(TempoHeader::decompress(&expected).is_err());
            let (decoded, _) = TempoHeader::from_compact(&buf, len);
            assert_eq!(decoded, header);
        }

        /// Presto block 1's fields, with the newly required zero consensus context.
        fn presto_block_1() -> TempoHeader {
            TempoHeader {
                general_gas_limit: 0xd693a40,
                shared_gas_limit: 0x2faf080,
                timestamp_millis_part: 0x2c5,
                consensus_context: Default::default(),
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
        fn adding_context_changes_pre_activation_header_hash() {
            let header = presto_block_1();
            let hash = header.hash_slow();

            // Adding context to a historical header changes its on-chain hash.
            let expected = "0x76e86f9739fbe17669b01b24e976ac214742c4b1bbc6ae0c083a87e43a5e9b0f";
            assert_ne!(format!("{hash:#x}"), expected);
        }

        #[test]
        fn presto_block_1_rlp_roundtrip() {
            let header = presto_block_1();
            let encoded = alloy_rlp::encode(&header);
            let decoded = TempoHeader::decode(&mut encoded.as_slice()).unwrap();
            assert_eq!(header, decoded);
        }

        #[derive(reth_codecs::Compact, alloy_rlp::RlpEncodable)]
        struct TestPreT4TempoHeader {
            pub general_gas_limit: u64,
            pub shared_gas_limit: u64,
            pub timestamp_millis_part: u64,
            pub inner: Header,
        }

        #[test]
        fn pre_activation_headers_without_context_are_rejected() {
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

            assert_ne!(header_len, pre_t4_len);
            assert_ne!(header_buf, pre_t4_header_buf);
            assert!(TempoHeader::decompress(&pre_t4_header_buf).is_err());
            let encoded = alloy_rlp::encode(pre_t4_header);
            assert!(TempoHeader::decode(&mut encoded.as_slice()).is_err());
        }

        #[test]
        fn context_bearing_compact_encoding_is_unchanged() {
            let header = TempoHeader {
                consensus_context: TempoConsensusContext {
                    epoch: 1,
                    view: 5,
                    parent_view: 4,
                    proposer: crate::ed25519::PublicKey::from_seed(42),
                },
                ..presto_block_1()
            };
            let legacy = TempoHeaderCompact {
                general_gas_limit: header.general_gas_limit,
                shared_gas_limit: header.shared_gas_limit,
                timestamp_millis_part: header.timestamp_millis_part,
                trailing: Some(TempoHeaderTrailingCompact {
                    consensus_context: Some(header.consensus_context),
                }),
                inner: header.inner.clone(),
            };
            let mut expected = Vec::new();
            legacy.to_compact(&mut expected);
            let mut actual = Vec::new();
            header.to_compact(&mut actual);
            assert_eq!(actual, expected);
            assert_eq!(TempoHeader::decompress(&expected).unwrap(), header);

            let mut missing_context = legacy;
            missing_context.trailing.as_mut().unwrap().consensus_context = None;
            let mut encoded = Vec::new();
            missing_context.to_compact(&mut encoded);
            assert!(TempoHeader::decompress(&encoded).is_err());
        }
    }
}
