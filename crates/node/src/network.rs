use crate::rpc::TempoTransactionRequest;
use alloy::consensus::{ReceiptWithBloom, TypedTransaction};
use alloy_network::Network;
use tempo_primitives::{TempoReceipt, TempoTxEnvelope, TempoTxType};

/// The Tempo specific configuration of [`Network`] schema and consensus primitives.
#[derive(Debug, Clone, Copy)]
pub struct TempoNetwork;

impl Network for TempoNetwork {
    type TxType = TempoTxType;
    type TxEnvelope = TempoTxEnvelope;
    type UnsignedTx = TypedTransaction;
    type ReceiptEnvelope = TempoReceipt;
    type Header = alloy::consensus::Header;
    type TransactionRequest = TempoTransactionRequest;
    type TransactionResponse = alloy_rpc_types_eth::Transaction<TempoTxEnvelope>;
    type ReceiptResponse = alloy_rpc_types_eth::TransactionReceipt<
        ReceiptWithBloom<TempoReceipt<alloy_rpc_types_eth::Log>>,
    >;
    type HeaderResponse = alloy_rpc_types_eth::Header;
    type BlockResponse =
        alloy_rpc_types_eth::Block<alloy_rpc_types_eth::Transaction<TempoTxEnvelope>>;
}
