use crate::TxFeeToken;
use alloy_consensus::{TxEip1559, TxEip2930, TxEip7702, TxLegacy};

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(
    from = "serde_from::MaybeTaggedTypedTransaction<Eip4844>",
    into = "serde_from::TaggedTypedTransaction<Eip4844>",
    bound = "Eip4844: Clone + serde::Serialize + serde::de::DeserializeOwned"
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
