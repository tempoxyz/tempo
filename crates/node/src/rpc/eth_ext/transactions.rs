use crate::rpc::pagination::FieldName;
use alloy_primitives::Address;
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use tempo_primitives::{TempoTxEnvelope, TempoTxType};

pub type Transaction = alloy_rpc_types_eth::Transaction<TempoTxEnvelope>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionsFilter {
    /// Filter by sender address (from)
    from: Option<Address>,
    /// Filter by recipient address (to)
    to: Option<Address>,
    /// Transaction type
    #[serde(rename = "type")]
    type_: Option<TempoTxType>,
}

impl FieldName for Transaction {
    fn field_plural_camel_case() -> &'static str {
        "transactions"
    }
}
