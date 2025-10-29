use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_rlp::{BufMut, Decodable, Encodable, RlpDecodable, RlpEncodable};
use alloy_rpc_types_eth::TransactionTrait;
use reth_primitives_traits::{Recovered, crypto::RecoveryError};
use tempo_primitives::TempoTxEnvelope;

/// Magic byte for the subblock signature hash.
const SUBBLOCK_SIGNATURE_HASH_MAGIC_BYTE: u8 = 0x77;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubBlockVersion {
    /// Subblock version 1.
    V1 = 1,
}

impl From<SubBlockVersion> for u8 {
    fn from(value: SubBlockVersion) -> Self {
        value as Self
    }
}

impl TryFrom<u8> for SubBlockVersion {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(value),
        }
    }
}

impl Encodable for SubBlockVersion {
    fn encode(&self, out: &mut dyn BufMut) {
        u8::from(*self).encode(out);
    }

    fn length(&self) -> usize {
        u8::from(*self).length()
    }
}

impl Decodable for SubBlockVersion {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        u8::decode(buf)?
            .try_into()
            .map_err(|_| alloy_rlp::Error::Custom("invalid subblock version"))
    }
}

#[derive(Debug, Clone)]
pub struct SubBlock {
    /// Version of the subblock.
    pub version: SubBlockVersion,
    /// Transactions included in the subblock.
    pub transactions: Vec<TempoTxEnvelope>,
    /// Hash of the parent block. This subblock can only be included as
    /// part of the block building on top of the specified parent.
    pub parent_hash: B256,
}

impl SubBlock {
    /// Returns the hash for the signature.
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::new();
        buf.put_u8(SUBBLOCK_SIGNATURE_HASH_MAGIC_BYTE);
        self.rlp_encode_fields(&mut buf);
        keccak256(&buf)
    }

    /// Returns the total gas occupied by the subblock.
    pub fn occupied_gas(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.gas_limit()).sum()
    }

    fn rlp_encode_fields(&self, out: &mut dyn BufMut) {
        self.version.encode(out);
        self.transactions.encode(out);
        self.parent_hash.encode(out);
    }

    fn rlp_encoded_fields_length(&self) -> usize {
        self.version.length() + self.transactions.length() + self.parent_hash.length()
    }

    fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            version: Decodable::decode(buf)?,
            transactions: Decodable::decode(buf)?,
            parent_hash: Decodable::decode(buf)?,
        })
    }
}

/// A subblock with a signature.
#[derive(Debug, Clone, derive_more::Deref, derive_more::DerefMut)]
pub struct SignedSubBlock {
    /// The subblock.
    #[deref]
    #[deref_mut]
    pub inner: SubBlock,
    /// The signature of the subblock.
    pub signature: Bytes,
}

impl SignedSubBlock {
    /// Attempts to recover the senders and convert the subblock into a [`RecoveredSubBlock`].
    ///
    /// Note that the validator is assumed to be pre-validated to match the submitted signature.
    pub fn try_into_recovered(self, validator: B256) -> Result<RecoveredSubBlock, RecoveryError> {
        let senders =
            reth_primitives_traits::transaction::recover::recover_signers(&self.transactions)?;

        Ok(RecoveredSubBlock {
            inner: self,
            senders,
            validator,
        })
    }

    fn rlp_encode_fields(&self, out: &mut dyn BufMut) {
        self.inner.rlp_encode_fields(out);
        self.signature.encode(out);
    }

    fn rlp_encoded_fields_length(&self) -> usize {
        self.inner.rlp_encoded_fields_length() + self.signature.length()
    }

    fn rlp_header(&self) -> alloy_rlp::Header {
        alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_encoded_fields_length(),
        }
    }

    fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            inner: SubBlock::rlp_decode_fields(buf)?,
            signature: Decodable::decode(buf)?,
        })
    }
}

impl Encodable for SignedSubBlock {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_header().encode(out);
        self.rlp_encode_fields(out);
    }

    fn length(&self) -> usize {
        self.rlp_header().length_with_payload()
    }
}

impl Decodable for SignedSubBlock {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let remaining = buf.len();

        let this = Self::rlp_decode_fields(buf)?;

        if buf.len() + header.payload_length != remaining {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        Ok(this)
    }
}

/// A subblock with recovered senders.
#[derive(Debug, Clone, RlpEncodable, RlpDecodable, derive_more::Deref, derive_more::DerefMut)]
pub struct RecoveredSubBlock {
    /// Inner subblock.
    #[deref]
    #[deref_mut]
    inner: SignedSubBlock,

    /// The senders of the transactions.
    senders: Vec<Address>,

    /// The validator that submitted the subblock.
    validator: B256,
}

impl RecoveredSubBlock {
    /// Returns an iterator over `Recovered<&Transaction>`
    #[inline]
    pub fn transactions_recovered(&self) -> impl Iterator<Item = Recovered<&TempoTxEnvelope>> + '_ {
        self.senders
            .iter()
            .zip(self.inner.transactions.iter())
            .map(|(sender, tx)| Recovered::new_unchecked(tx, *sender))
    }

    /// Returns the validator that submitted the subblock.
    pub fn validator(&self) -> B256 {
        self.validator
    }

    /// Returns the metadata for the subblock.
    pub fn metadata(&self) -> SubBlockMetadata {
        SubBlockMetadata {
            validator: self.validator(),
            signature: self.signature.clone(),
        }
    }
}

/// Metadata for an included subblock.
#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct SubBlockMetadata {
    /// Validator that submitted the subblock.
    pub validator: B256,
    /// Signature of the subblock.
    pub signature: Bytes,
}
