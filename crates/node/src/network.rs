use crate::rpc::TempoTransactionRequest;
use alloy::{
    consensus::{ReceiptWithBloom, TxType, TypedTransaction},
    rpc::types::AccessList,
};
use alloy_network::{
    BuildResult, Network, NetworkWallet, TransactionBuilder, TransactionBuilderError,
    UnbuiltTransactionError,
};
use alloy_primitives::{Address, Bytes, ChainId, TxKind, U256};
use std::{error, fmt, fmt::Formatter};
use tempo_primitives::{
    TempoReceipt, TempoTxEnvelope, TempoTxType, transaction::TempoTypedTransaction,
};

/// The Tempo specific configuration of [`Network`] schema and consensus primitives.
#[derive(Debug, Clone, Copy)]
pub struct TempoNetwork;

impl Network for TempoNetwork {
    type TxType = TempoTxType;
    type TxEnvelope = TempoTxEnvelope;
    type UnsignedTx = TempoTypedTransaction;
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

impl TransactionBuilder<TempoNetwork> for TempoTransactionRequest {
    fn chain_id(&self) -> Option<ChainId> {
        self.inner.chain_id()
    }

    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.inner.set_chain_id(chain_id)
    }

    fn nonce(&self) -> Option<u64> {
        TransactionBuilder::nonce(&self.inner)
    }

    fn set_nonce(&mut self, nonce: u64) {
        self.inner.set_nonce(nonce)
    }

    fn take_nonce(&mut self) -> Option<u64> {
        self.inner.take_nonce()
    }

    fn input(&self) -> Option<&Bytes> {
        TransactionBuilder::input(&self.inner)
    }

    fn set_input<T: Into<Bytes>>(&mut self, input: T) {
        TransactionBuilder::set_input(&mut self.inner, input)
    }

    fn from(&self) -> Option<Address> {
        TransactionBuilder::from(&self.inner)
    }

    fn set_from(&mut self, from: Address) {
        TransactionBuilder::set_from(&mut self.inner, from)
    }

    fn kind(&self) -> Option<TxKind> {
        self.inner.kind()
    }

    fn clear_kind(&mut self) {
        self.inner.clear_kind()
    }

    fn set_kind(&mut self, kind: TxKind) {
        self.inner.set_kind(kind)
    }

    fn value(&self) -> Option<U256> {
        TransactionBuilder::value(&self.inner)
    }

    fn set_value(&mut self, value: U256) {
        self.inner.set_value(value)
    }

    fn gas_price(&self) -> Option<u128> {
        TransactionBuilder::gas_price(&self.inner)
    }

    fn set_gas_price(&mut self, gas_price: u128) {
        TransactionBuilder::set_gas_price(&mut self.inner, gas_price)
    }

    fn max_fee_per_gas(&self) -> Option<u128> {
        TransactionBuilder::max_fee_per_gas(&self.inner)
    }

    fn set_max_fee_per_gas(&mut self, max_fee_per_gas: u128) {
        TransactionBuilder::set_max_fee_per_gas(&mut self.inner, max_fee_per_gas)
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        TransactionBuilder::max_priority_fee_per_gas(&self.inner)
    }

    fn set_max_priority_fee_per_gas(&mut self, max_priority_fee_per_gas: u128) {
        TransactionBuilder::set_max_priority_fee_per_gas(&mut self.inner, max_priority_fee_per_gas)
    }

    fn gas_limit(&self) -> Option<u64> {
        TransactionBuilder::gas_limit(&self.inner)
    }

    fn set_gas_limit(&mut self, gas_limit: u64) {
        TransactionBuilder::set_gas_limit(&mut self.inner, gas_limit)
    }

    fn access_list(&self) -> Option<&AccessList> {
        TransactionBuilder::access_list(&self.inner)
    }

    fn set_access_list(&mut self, access_list: AccessList) {
        TransactionBuilder::set_access_list(&mut self.inner, access_list)
    }

    fn complete_type(&self, ty: TempoTxType) -> Result<(), Vec<&'static str>> {
        TransactionBuilder::complete_type(
            &self.inner,
            into_tx_type_checked(ty).unwrap_or(TxType::Eip7702),
        )
    }

    fn can_submit(&self) -> bool {
        self.inner.can_submit()
    }

    fn can_build(&self) -> bool {
        self.inner.can_build()
    }

    fn output_tx_type(&self) -> TempoTxType {
        self.output_tx_type_checked().unwrap()
    }

    fn output_tx_type_checked(&self) -> Option<TempoTxType> {
        if self.fee_token.is_some() {
            return Some(TempoTxType::FeeToken);
        }

        into_tempo_tx_type_checked(self.inner.output_tx_type_checked()?)
    }

    fn prep_for_submission(&mut self) {
        self.inner.prep_for_submission()
    }

    fn build_unsigned(self) -> BuildResult<TempoTypedTransaction, TempoNetwork> {
        if let Err((tx_type, missing)) = self.inner.missing_keys() {
            return Err(TransactionBuilderError::InvalidTransactionRequest(
                into_tempo_tx_type_checked(tx_type).unwrap(),
                missing,
            )
            .into_unbuilt(self));
        }

        if self.fee_token.is_some() {
            Ok(self
                .build_fee_token()
                .expect("checked by missing_keys and above condition")
                .into())
        } else {
            if let Some(TxType::Eip4844) = self.inner.buildable_type() {
                return Err(UnbuiltTransactionError {
                    request: self,
                    error: TransactionBuilderError::Custom(Box::new(
                        UnsupportedTransactionTypeEip4844,
                    )),
                });
            }

            let inner = self
                .inner
                .build_typed_tx()
                .expect("checked by missing_keys");

            Ok(into_tempo_typed_tx_checked(inner).expect("checked by above condition"))
        }
    }

    async fn build<W: NetworkWallet<TempoNetwork>>(
        self,
        wallet: &W,
    ) -> Result<TempoTxEnvelope, TransactionBuilderError<TempoNetwork>> {
        Ok(wallet.sign_request(self).await?)
    }
}

fn into_tempo_tx_type_checked(value: TxType) -> Option<TempoTxType> {
    Some(match value {
        TxType::Legacy => TempoTxType::Legacy,
        TxType::Eip2930 => TempoTxType::Eip2930,
        TxType::Eip1559 => TempoTxType::Eip1559,
        TxType::Eip4844 => return None,
        TxType::Eip7702 => TempoTxType::Eip7702,
    })
}

fn into_tx_type_checked(value: TempoTxType) -> Option<TxType> {
    Some(match value {
        TempoTxType::Legacy => TxType::Legacy,
        TempoTxType::Eip2930 => TxType::Eip2930,
        TempoTxType::Eip1559 => TxType::Eip1559,
        TempoTxType::Eip7702 => TxType::Eip7702,
        TempoTxType::FeeToken => return None,
    })
}

fn into_tempo_typed_tx_checked(value: TypedTransaction) -> Option<TempoTypedTransaction> {
    Some(match value {
        TypedTransaction::Legacy(tx) => TempoTypedTransaction::Legacy(tx),
        TypedTransaction::Eip2930(tx) => TempoTypedTransaction::Eip2930(tx),
        TypedTransaction::Eip1559(tx) => TempoTypedTransaction::Eip1559(tx),
        TypedTransaction::Eip4844(_) => return None,
        TypedTransaction::Eip7702(tx) => TempoTypedTransaction::Eip7702(tx),
    })
}

#[derive(Debug)]
pub struct UnsupportedTransactionTypeEip4844;

impl fmt::Display for UnsupportedTransactionTypeEip4844 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Unsupported transaction type EIP-4844")
    }
}

impl error::Error for UnsupportedTransactionTypeEip4844 {}
