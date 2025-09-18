use crate::TxFeeToken;
use alloy_consensus::{TxEip1559, TxEip2930, TxEip7702, TxLegacy};

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(
    from = "serde_from::MaybeTempoTypedTransaction",
    into = "serde_from::TempoTypedTransaction",
    bound = ""
)]
pub enum TempoTypedTransaction {
    /// Legacy transaction (type 0x00)
    #[serde(rename = "0x00", alias = "0x0")]
    Legacy(TxLegacy),
    /// EIP-2930 access list transaction (type 0x01)
    #[serde(rename = "0x01", alias = "0x1")]
    Eip2930(TxEip2930),
    /// EIP-1559 dynamic fee transaction (type 0x02)
    #[serde(rename = "0x02", alias = "0x2")]
    Eip1559(TxEip1559),
    /// EIP-7702 authorization list transaction (type 0x04)
    #[serde(rename = "0x04", alias = "0x4")]
    Eip7702(TxEip7702),
    /// Tempo fee token transaction (type 0x77)
    #[serde(rename = "0x77", alias = "0x77")]
    FeeToken(TxFeeToken),
}

#[cfg(feature = "serde")]
mod serde_from {
    //! NB: Why do we need this?
    //!
    //! Because the tag may be missing, we need an abstraction over tagged (with
    //! type) and untagged (always legacy). This is
    //! [`MaybeTempoTypedTransaction`].
    //!
    //! The tagged variant is [`TempoTypedTransaction`], which always has a
    //! type tag.
    //!
    //! We serialize via [`TempoTypedTransaction`] and deserialize via
    //! [`MaybeTempoTypedTransaction`].
    use super::*;

    #[derive(Debug, serde::Deserialize)]
    #[serde(untagged)]
    pub(crate) enum MaybeTempoTypedTransaction {
        Tagged(TempoTypedTransaction),
        Untagged(TxLegacy),
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(tag = "type")]
    pub(crate) enum TempoTypedTransaction {
        /// Legacy transaction
        #[serde(rename = "0x00", alias = "0x0")]
        Legacy(TxLegacy),
        /// EIP-2930 transaction
        #[serde(rename = "0x01", alias = "0x1")]
        Eip2930(TxEip2930),
        /// EIP-1559 transaction
        #[serde(rename = "0x02", alias = "0x2")]
        Eip1559(TxEip1559),
        /// EIP-7702 transaction
        #[serde(rename = "0x04", alias = "0x4")]
        Eip7702(TxEip7702),
        /// Tempo fee token transaction (type 0x77)
        #[serde(rename = "0x77", alias = "0x77")]
        FeeToken(TxFeeToken),
    }

    impl From<MaybeTempoTypedTransaction> for super::TempoTypedTransaction {
        fn from(value: MaybeTempoTypedTransaction) -> Self {
            match value {
                MaybeTempoTypedTransaction::Tagged(tagged) => tagged.into(),
                MaybeTempoTypedTransaction::Untagged(tx) => Self::Legacy(tx),
            }
        }
    }

    impl From<super::TempoTypedTransaction> for TempoTypedTransaction {
        fn from(value: super::TempoTypedTransaction) -> Self {
            match value {
                super::TempoTypedTransaction::Legacy(signed) => Self::Legacy(signed),
                super::TempoTypedTransaction::Eip2930(signed) => Self::Eip2930(signed),
                super::TempoTypedTransaction::Eip1559(signed) => Self::Eip1559(signed),
                super::TempoTypedTransaction::Eip7702(signed) => Self::Eip7702(signed),
                super::TempoTypedTransaction::FeeToken(tx) => Self::FeeToken(tx),
            }
        }
    }

    impl From<TempoTypedTransaction> for super::TempoTypedTransaction {
        fn from(value: TempoTypedTransaction) -> Self {
            match value {
                TempoTypedTransaction::Legacy(signed) => Self::Legacy(signed),
                TempoTypedTransaction::Eip2930(signed) => Self::Eip2930(signed),
                TempoTypedTransaction::Eip1559(signed) => Self::Eip1559(signed),
                TempoTypedTransaction::Eip7702(signed) => Self::Eip7702(signed),
                TempoTypedTransaction::FeeToken(tx) => Self::FeeToken(tx),
            }
        }
    }
}
