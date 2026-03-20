use alloy_consensus::{BlockHeader, Header, Sealable};
use alloy_primitives::{Address, B64, B256, BlockNumber, Bloom, Bytes, U256, keccak256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};

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
    pub leader: B256,
    pub parent_view: u64,
}

#[cfg(feature = "serde-bincode-compat")]
impl reth_primitives_traits::serde_bincode_compat::RlpBincode for TempoConsensusContext {}

/// Tempo block header.
///
/// RLP-encoded as `[general_gas_limit, shared_gas_limit, timestamp_millis_part, inner,
/// consensus_context?]`. The `consensus_context` is trailing and omitted for pre-fork blocks.
///
/// RLP is implemented manually because `consensus_context` must be trailing (optional) while
/// `inner: Header` must be the last field for `reth_codecs::Compact`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
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

    /// Consensus metadata for the block. `None` for pre-fork blocks.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub consensus_context: Option<TempoConsensusContext>,

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

impl Encodable for TempoHeader {
    fn encode(&self, out: &mut dyn alloy_primitives::bytes::BufMut) {
        let payload_length = self.rlp_payload_length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
        self.general_gas_limit.encode(out);
        self.shared_gas_limit.encode(out);
        self.timestamp_millis_part.encode(out);
        self.inner.encode(out);
        if let Some(ctx) = &self.consensus_context {
            ctx.encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        payload_length + alloy_rlp::length_of_length(payload_length)
    }
}

impl TempoHeader {
    fn rlp_payload_length(&self) -> usize {
        let mut len = self.general_gas_limit.length()
            + self.shared_gas_limit.length()
            + self.timestamp_millis_part.length()
            + self.inner.length();
        if let Some(ctx) = &self.consensus_context {
            len += ctx.length();
        }
        len
    }
}

impl Decodable for TempoHeader {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let remaining = buf.len();
        let general_gas_limit = u64::decode(buf)?;
        let shared_gas_limit = u64::decode(buf)?;
        let timestamp_millis_part = u64::decode(buf)?;
        let inner = Header::decode(buf)?;
        let consensus_context = if remaining - buf.len() < header.payload_length {
            Some(TempoConsensusContext::decode(buf)?)
        } else {
            None
        };
        Ok(Self {
            general_gas_limit,
            shared_gas_limit,
            timestamp_millis_part,
            consensus_context,
            inner,
        })
    }
}

#[cfg(feature = "serde-bincode-compat")]
impl reth_primitives_traits::serde_bincode_compat::RlpBincode for TempoHeader {}

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

#[cfg(feature = "reth")]
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
            + core::mem::size_of_val(consensus_context)
    }
}

impl Sealable for TempoHeader {
    fn hash_slow(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

#[cfg(feature = "reth")]
impl reth_primitives_traits::BlockHeader for TempoHeader {}

#[cfg(feature = "reth")]
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
impl reth_db_api::table::Compress for TempoHeader {
    type Compressed = alloc::vec::Vec<u8>;

    fn compress_to_buf<B: alloy_primitives::bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let _ = reth_codecs::Compact::to_compact(self, buf);
    }
}

#[cfg(feature = "reth-codec")]
impl reth_db_api::table::Decompress for TempoHeader {
    fn decompress(value: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        let (obj, _) = reth_codecs::Compact::from_compact(value, value.len());
        Ok(obj)
    }
}
