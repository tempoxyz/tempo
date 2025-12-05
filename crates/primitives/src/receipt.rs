use alloy_consensus::{Eip658Value, ReceiptWithBloom, TxReceipt, TxType};
use alloy_eips::{
    Decodable2718, Encodable2718, Typed2718,
    eip2718::{
        EIP1559_TX_TYPE_ID, EIP2930_TX_TYPE_ID, EIP7702_TX_TYPE_ID, Eip2718Error, Eip2718Result,
        IsTyped2718, LEGACY_TX_TYPE_ID,
    },
};
use alloy_primitives::{Bloom, Log};
use alloy_rlp::{BufMut, Decodable, Encodable};
use std::fmt::Debug;

use crate::{FEE_TOKEN_TX_TYPE_ID, TEMPO_TX_TYPE_ID, TempoReceipt, TempoTxType};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type"))]
pub enum TempoReceiptEnvelope<L = Log> {
    /// Receipt envelope with no type flag.
    #[cfg_attr(feature = "serde", serde(rename = "0x0", alias = "0x00"))]
    Legacy(ReceiptWithBloom<TempoReceipt<L>>),
    /// Receipt envelope with type flag 1, containing a [EIP-2930] receipt.
    ///
    /// [EIP-2930]: https://eips.ethereum.org/EIPS/eip-2930
    #[cfg_attr(feature = "serde", serde(rename = "0x1", alias = "0x01"))]
    Eip2930(ReceiptWithBloom<TempoReceipt<L>>),
    /// Receipt envelope with type flag 2, containing a [EIP-1559] receipt.
    ///
    /// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
    #[cfg_attr(feature = "serde", serde(rename = "0x2", alias = "0x02"))]
    Eip1559(ReceiptWithBloom<TempoReceipt<L>>),
    /// Receipt envelope with type flag 4, containing a [EIP-7702] receipt.
    ///
    /// [EIP-7702]: https://eips.ethereum.org/EIPS/eip-7702
    #[cfg_attr(feature = "serde", serde(rename = "0x4", alias = "0x04"))]
    Eip7702(ReceiptWithBloom<TempoReceipt<L>>),
    /// Receipt envelope with type flag 0x76, containing a Tempo transactoin receipt.
    #[cfg_attr(feature = "serde", serde(rename = "0x76", alias = "0x76"))]
    AA(ReceiptWithBloom<TempoReceipt<L>>),
    /// Receipt envelope with type flag 0x77, containing a Tempo fee token transaction receipt.
    #[cfg_attr(feature = "serde", serde(rename = "0x77", alias = "0x77"))]
    FeeToken(ReceiptWithBloom<TempoReceipt<L>>),
}

impl TempoReceiptEnvelope {
    /// Get the length of the inner receipt in the 2718 encoding.
    fn inner_length(&self) -> usize {
        self.as_receipt_with_bloom().length()
    }
}

impl<L> TempoReceiptEnvelope<L> {
    fn as_receipt(&self) -> &TempoReceipt<L> {
        &match self {
            Self::Legacy(receipt) => receipt,
            Self::Eip2930(receipt) => receipt,
            Self::Eip1559(receipt) => receipt,
            Self::Eip7702(receipt) => receipt,
            Self::AA(receipt) => receipt,
            Self::FeeToken(receipt) => receipt,
        }
        .receipt
    }

    fn into_receipt(self) -> TempoReceipt<L> {
        match self {
            Self::Legacy(receipt) => receipt,
            Self::Eip2930(receipt) => receipt,
            Self::Eip1559(receipt) => receipt,
            Self::Eip7702(receipt) => receipt,
            Self::AA(receipt) => receipt,
            Self::FeeToken(receipt) => receipt,
        }
        .receipt
    }

    fn as_receipt_with_bloom(&self) -> &ReceiptWithBloom<TempoReceipt<L>> {
        match self {
            Self::Legacy(receipt) => receipt,
            Self::Eip2930(receipt) => receipt,
            Self::Eip1559(receipt) => receipt,
            Self::Eip7702(receipt) => receipt,
            Self::AA(receipt) => receipt,
            Self::FeeToken(receipt) => receipt,
        }
    }
}

impl<L> From<TempoReceipt<L>> for TempoReceiptEnvelope<L>
where
    L: Send + Sync + Clone + Debug + Eq + AsRef<Log>,
{
    fn from(value: TempoReceipt<L>) -> Self {
        let tx_type = value.tx_type;
        let receipt = value.into_with_bloom().map_receipt(Into::into);
        match tx_type {
            TempoTxType::Legacy => Self::Legacy(receipt),
            TempoTxType::Eip2930 => Self::Eip2930(receipt),
            TempoTxType::Eip1559 => Self::Eip1559(receipt),
            TempoTxType::Eip7702 => Self::Eip7702(receipt),
            TempoTxType::AA => Self::AA(receipt),
            TempoTxType::FeeToken => Self::FeeToken(receipt),
        }
    }
}

impl<T> TxReceipt for TempoReceiptEnvelope<T>
where
    T: Clone + Debug + PartialEq + Eq + Send + Sync,
{
    type Log = T;

    fn status_or_post_state(&self) -> Eip658Value {
        self.as_receipt().success.into()
    }

    fn status(&self) -> bool {
        self.as_receipt().success
    }

    /// Return the receipt's bloom.
    fn bloom(&self) -> Bloom {
        self.as_receipt_with_bloom().logs_bloom
    }

    fn bloom_cheap(&self) -> Option<Bloom> {
        Some(self.bloom())
    }

    /// Returns the cumulative gas used at this receipt.
    fn cumulative_gas_used(&self) -> u64 {
        self.as_receipt().cumulative_gas_used
    }

    /// Return the receipt logs.
    fn logs(&self) -> &[T] {
        &self.as_receipt().logs
    }

    fn into_logs(self) -> Vec<Self::Log>
    where
        Self::Log: Clone,
    {
        self.into_receipt().logs
    }
}

impl<L> Typed2718 for TempoReceiptEnvelope<L> {
    fn ty(&self) -> u8 {
        match self {
            Self::Legacy(_) => LEGACY_TX_TYPE_ID,
            Self::Eip2930(_) => EIP2930_TX_TYPE_ID,
            Self::Eip1559(_) => EIP1559_TX_TYPE_ID,
            Self::Eip7702(_) => EIP7702_TX_TYPE_ID,
            Self::AA(_) => TEMPO_TX_TYPE_ID,
            Self::FeeToken(_) => FEE_TOKEN_TX_TYPE_ID,
        }
    }
}

impl<L> IsTyped2718 for TempoReceiptEnvelope<L> {
    fn is_type(type_id: u8) -> bool {
        <TxType as IsTyped2718>::is_type(type_id)
    }
}

impl Encodable2718 for TempoReceiptEnvelope {
    fn encode_2718_len(&self) -> usize {
        self.inner_length() + !self.is_legacy() as usize
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        match self.type_flag() {
            None => {}
            Some(ty) => out.put_u8(ty),
        }
        self.as_receipt_with_bloom().encode(out);
    }
}

impl Decodable2718 for TempoReceiptEnvelope {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        let receipt = Decodable::decode(buf)?;
        match ty
            .try_into()
            .map_err(|_| alloy_rlp::Error::Custom("Unexpected type"))?
        {
            TempoTxType::Eip2930 => Ok(Self::Eip2930(receipt)),
            TempoTxType::Eip1559 => Ok(Self::Eip1559(receipt)),
            TempoTxType::Eip7702 => Ok(Self::Eip7702(receipt)),
            TempoTxType::AA => Ok(Self::AA(receipt)),
            TempoTxType::FeeToken => Ok(Self::FeeToken(receipt)),
            TempoTxType::Legacy => Err(Eip2718Error::UnexpectedType(0)),
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Eip2718Result<Self> {
        Ok(Self::Legacy(Decodable::decode(buf)?))
    }
}
