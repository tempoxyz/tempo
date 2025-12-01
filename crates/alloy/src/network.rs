use std::fmt::Debug;

use crate::rpc::{TempoHeaderResponse, TempoTransactionReceipt, TempoTransactionRequest};
use alloy_consensus::{SignableTransaction, TxType, error::UnsupportedTransactionType};

use alloy_network::{
    BuildResult, Ethereum, EthereumWallet, IntoWallet, Network, NetworkWallet, TransactionBuilder,
    TransactionBuilderError, UnbuiltTransactionError,
};
use alloy_primitives::{Address, Bytes, ChainId, TxKind, U256};
use alloy_provider::fillers::{
    ChainIdFiller, GasFiller, JoinFill, NonceFiller, RecommendedFillers,
};
use alloy_rpc_types_eth::AccessList;
use alloy_signer_local::PrivateKeySigner;
use tempo_primitives::{
    TempoHeader, TempoReceipt, TempoTxEnvelope, TempoTxType, transaction::TempoTypedTransaction,
};

pub type TempoFillers<N> = JoinFill<GasFiller, JoinFill<N, ChainIdFiller>>;

/// The Tempo specific configuration of [`Network`] schema and consensus primitives.
#[derive(Default, Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TempoNetwork;

impl Network for TempoNetwork {
    type TxType = TempoTxType;
    type TxEnvelope = TempoTxEnvelope;
    type UnsignedTx = TempoTypedTransaction;
    type ReceiptEnvelope = TempoReceipt;
    type Header = TempoHeader;
    type TransactionRequest = TempoTransactionRequest;
    type TransactionResponse = alloy_rpc_types_eth::Transaction<TempoTxEnvelope>;
    type ReceiptResponse = TempoTransactionReceipt;
    type HeaderResponse = TempoHeaderResponse;
    type BlockResponse = alloy_rpc_types_eth::Block<
        alloy_rpc_types_eth::Transaction<TempoTxEnvelope>,
        Self::HeaderResponse,
    >;
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
        match ty {
            TempoTxType::FeeToken => self.complete_fee_token(),
            ty => self.inner.complete_type(
                ty.try_into()
                    .expect("should not be reachable with fee token tx"),
            ),
        }
    }

    fn can_submit(&self) -> bool {
        self.inner.can_submit()
    }

    fn can_build(&self) -> bool {
        self.inner.can_build()
    }

    fn output_tx_type(&self) -> TempoTxType {
        if !self.calls.is_empty() || self.nonce_key.is_some() {
            TempoTxType::AA
        } else if self.fee_token.is_some() {
            TempoTxType::FeeToken
        } else {
            match self.inner.output_tx_type() {
                TxType::Legacy => TempoTxType::Legacy,
                TxType::Eip2930 => TempoTxType::Eip2930,
                TxType::Eip1559 => TempoTxType::Eip1559,
                // EIP-4844 transactions are not supported on Tempo
                TxType::Eip4844 => TempoTxType::Legacy,
                TxType::Eip7702 => TempoTxType::Eip7702,
            }
        }
    }

    fn output_tx_type_checked(&self) -> Option<TempoTxType> {
        match self.output_tx_type() {
            TempoTxType::AA => Some(TempoTxType::AA).filter(|_| self.can_build_aa()),
            TempoTxType::FeeToken => {
                Some(TempoTxType::FeeToken).filter(|_| self.can_build_fee_token())
            }
            TempoTxType::Legacy
            | TempoTxType::Eip2930
            | TempoTxType::Eip1559
            | TempoTxType::Eip7702 => self.inner.output_tx_type_checked()?.try_into().ok(),
        }
    }

    fn prep_for_submission(&mut self) {
        self.inner.prep_for_submission()
    }

    fn build_unsigned(self) -> BuildResult<TempoTypedTransaction, TempoNetwork> {
        match self.output_tx_type() {
            TempoTxType::AA => match self.complete_aa() {
                Ok(..) => Ok(self.build_aa().expect("checked by above condition").into()),
                Err(missing) => Err(TransactionBuilderError::InvalidTransactionRequest(
                    TempoTxType::AA,
                    missing,
                )
                .into_unbuilt(self)),
            },
            TempoTxType::FeeToken => match self.complete_fee_token() {
                Ok(..) => Ok(self
                    .build_fee_token()
                    .expect("checked by above condition")
                    .into()),
                Err(missing) => Err(TransactionBuilderError::InvalidTransactionRequest(
                    TempoTxType::FeeToken,
                    missing,
                )
                .into_unbuilt(self)),
            },
            _ => {
                if let Err((tx_type, missing)) = self.inner.missing_keys() {
                    return Err(match tx_type.try_into() {
                        Ok(tx_type) => {
                            TransactionBuilderError::InvalidTransactionRequest(tx_type, missing)
                        }
                        Err(err) => TransactionBuilderError::from(err),
                    }
                    .into_unbuilt(self));
                }

                if let Some(TxType::Eip4844) = self.inner.buildable_type() {
                    return Err(UnbuiltTransactionError {
                        request: self,
                        error: TransactionBuilderError::Custom(Box::new(
                            UnsupportedTransactionType::new(TxType::Eip4844),
                        )),
                    });
                }

                let inner = self
                    .inner
                    .build_typed_tx()
                    .expect("checked by missing_keys");

                Ok(inner.try_into().expect("checked by above condition"))
            }
        }
    }

    async fn build<W: NetworkWallet<TempoNetwork>>(
        self,
        wallet: &W,
    ) -> Result<TempoTxEnvelope, TransactionBuilderError<TempoNetwork>> {
        Ok(wallet.sign_request(self).await?)
    }
}

impl TempoTransactionRequest {
    fn can_build_aa(&self) -> bool {
        (!self.calls.is_empty() || self.inner.to.is_some())
            && self.inner.nonce.is_some()
            && self.inner.gas.is_some()
            && self.inner.max_fee_per_gas.is_some()
            && self.inner.max_priority_fee_per_gas.is_some()
    }

    fn can_build_fee_token(&self) -> bool {
        self.fee_token.is_some()
            && self.inner.nonce.is_some()
            && self.inner.gas.is_some()
            && self.inner.max_fee_per_gas.is_some()
            && self.inner.max_priority_fee_per_gas.is_some()
            && (self
                .inner
                .authorization_list
                .as_ref()
                .map(Vec::is_empty)
                .unwrap_or(true)
                || matches!(self.inner.to, Some(TxKind::Call(..))))
    }

    fn complete_aa(&self) -> Result<(), Vec<&'static str>> {
        let mut fields = Vec::new();

        if self.calls.is_empty() && self.inner.to.is_none() {
            fields.push("calls or to");
        }
        if self.inner.nonce.is_none() {
            fields.push("nonce");
        }
        if self.inner.gas.is_none() {
            fields.push("gas");
        }
        if self.inner.max_fee_per_gas.is_none() {
            fields.push("max_fee_per_gas");
        }
        if self.inner.max_priority_fee_per_gas.is_none() {
            fields.push("max_priority_fee_per_gas");
        }

        if fields.is_empty() {
            Ok(())
        } else {
            Err(fields)
        }
    }

    fn complete_fee_token(&self) -> Result<(), Vec<&'static str>> {
        let mut fields = Vec::new();

        if self.fee_token.is_none() {
            fields.push("fee_token");
        }
        if self.inner.gas.is_none() {
            fields.push("gas");
        }
        if self.inner.max_fee_per_gas.is_none() {
            fields.push("max_fee_per_gas");
        }
        if self.inner.max_priority_fee_per_gas.is_none() {
            fields.push("max_priority_fee_per_gas");
        }
        if !self
            .inner
            .authorization_list
            .as_ref()
            .map(Vec::is_empty)
            .unwrap_or(true)
            && !matches!(self.inner.to, Some(TxKind::Call(..)))
        {
            fields.push("to");
        }

        if fields.is_empty() {
            Ok(())
        } else {
            Err(fields)
        }
    }
}

impl RecommendedFillers for TempoNetwork {
    type RecommendedFillers = TempoFillers<NonceFiller>;

    fn recommended_fillers() -> Self::RecommendedFillers {
        Default::default()
    }
}

impl NetworkWallet<TempoNetwork> for EthereumWallet {
    fn default_signer_address(&self) -> Address {
        NetworkWallet::<Ethereum>::default_signer_address(self)
    }

    fn has_signer_for(&self, address: &Address) -> bool {
        NetworkWallet::<Ethereum>::has_signer_for(self, address)
    }

    fn signer_addresses(&self) -> impl Iterator<Item = Address> {
        NetworkWallet::<Ethereum>::signer_addresses(self)
    }

    #[doc(alias = "sign_tx_from")]
    async fn sign_transaction_from(
        &self,
        sender: Address,
        tx: TempoTypedTransaction,
    ) -> alloy_signer::Result<TempoTxEnvelope> {
        let signer = self.signer_by_address(sender).ok_or_else(|| {
            alloy_signer::Error::other(format!("Missing signing credential for {sender}"))
        })?;
        match tx {
            TempoTypedTransaction::Legacy(mut t) => {
                let sig = signer.sign_transaction(&mut t).await?;
                Ok(t.into_signed(sig).into())
            }
            TempoTypedTransaction::Eip2930(mut t) => {
                let sig = signer.sign_transaction(&mut t).await?;
                Ok(t.into_signed(sig).into())
            }
            TempoTypedTransaction::Eip1559(mut t) => {
                let sig = signer.sign_transaction(&mut t).await?;
                Ok(t.into_signed(sig).into())
            }
            TempoTypedTransaction::Eip7702(mut t) => {
                let sig = signer.sign_transaction(&mut t).await?;
                Ok(t.into_signed(sig).into())
            }
            TempoTypedTransaction::FeeToken(mut t) => {
                let sig = signer.sign_transaction(&mut t).await?;
                Ok(t.into_signed(sig).into())
            }
            TempoTypedTransaction::AA(mut t) => {
                let sig = signer.sign_transaction(&mut t).await?;
                Ok(t.into_signed(sig.into()).into())
            }
        }
    }
}

impl IntoWallet<TempoNetwork> for PrivateKeySigner {
    type NetworkWallet = EthereumWallet;

    fn into_wallet(self) -> Self::NetworkWallet {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{TxEip1559, TxEip2930, TxEip7702, TxLegacy};
    use alloy_eips::eip7702::SignedAuthorization;
    use alloy_primitives::B256;
    use alloy_rpc_types_eth::{AccessListItem, Authorization, TransactionRequest};
    use tempo_primitives::TxFeeToken;

    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(Address::repeat_byte(0xDE))),
                gas_price: Some(1234),
                nonce: Some(57),
                gas: Some(123456),
                ..Default::default()
            },
            ..Default::default()
        },
        TempoTypedTransaction::Legacy(TxLegacy {
            to: TxKind::Call(Address::repeat_byte(0xDE)),
            gas_price: 1234,
            nonce: 57,
            gas_limit: 123456,
            ..Default::default()
        });
        "Legacy"
    )]
    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(Address::repeat_byte(0xDE))),
                max_fee_per_gas: Some(1234),
                max_priority_fee_per_gas: Some(987),
                nonce: Some(57),
                gas: Some(123456),
                ..Default::default()
            },
            ..Default::default()
        },
        TempoTypedTransaction::Eip1559(TxEip1559 {
            to: TxKind::Call(Address::repeat_byte(0xDE)),
            max_fee_per_gas: 1234,
            max_priority_fee_per_gas: 987,
            nonce: 57,
            gas_limit: 123456,
            chain_id: 1,
            ..Default::default()
        });
        "EIP-1559"
    )]
    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(Address::repeat_byte(0xDE))),
                gas_price: Some(1234),
                nonce: Some(57),
                gas: Some(123456),
                access_list: Some(AccessList(vec![AccessListItem {
                    address: Address::from([3u8; 20]),
                    storage_keys: vec![B256::from([4u8; 32])],
                }])),
                ..Default::default()
            },
            ..Default::default()
        },
        TempoTypedTransaction::Eip2930(TxEip2930 {
            to: TxKind::Call(Address::repeat_byte(0xDE)),
            gas_price: 1234,
            nonce: 57,
            gas_limit: 123456,
            chain_id: 1,
            access_list: AccessList(vec![AccessListItem {
                address: Address::from([3u8; 20]),
                storage_keys: vec![B256::from([4u8; 32])],
            }]),
            ..Default::default()
        });
        "EIP-2930"
    )]
    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(Address::repeat_byte(0xDE))),
                max_fee_per_gas: Some(1234),
                max_priority_fee_per_gas: Some(987),
                nonce: Some(57),
                gas: Some(123456),
                authorization_list: Some(vec![SignedAuthorization::new_unchecked(
                    Authorization {
                        chain_id: U256::from(1337),
                        address: Address::ZERO,
                        nonce: 0
                    },
                    0,
                    U256::ZERO,
                    U256::ZERO,
                )]),
                ..Default::default()
            },
            ..Default::default()
        },
        TempoTypedTransaction::Eip7702(TxEip7702 {
            to: Address::repeat_byte(0xDE),
            max_fee_per_gas: 1234,
            max_priority_fee_per_gas: 987,
            nonce: 57,
            gas_limit: 123456,
            chain_id: 1,
            authorization_list: vec![SignedAuthorization::new_unchecked(
                Authorization {
                    chain_id: U256::from(1337),
                    address: Address::ZERO,
                    nonce: 0
                },
                0,
                U256::ZERO,
                U256::ZERO,
            )],
            ..Default::default()
        });
        "EIP-7702"
    )]
    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(Address::repeat_byte(0xDE))),
                max_fee_per_gas: Some(1234),
                max_priority_fee_per_gas: Some(987),
                nonce: Some(57),
                gas: Some(123456),
                ..Default::default()
            },
            fee_token: Some(Address::repeat_byte(0xFA)),
            ..Default::default()
        },
        TempoTypedTransaction::FeeToken(TxFeeToken {
            to: TxKind::Call(Address::repeat_byte(0xDE)),
            max_fee_per_gas: 1234,
            max_priority_fee_per_gas: 987,
            nonce: 57,
            gas_limit: 123456,
            fee_token: Some(Address::repeat_byte(0xFA)),
            chain_id: 1,
            ..Default::default()
        });
        "Fee token of call kind"
    )]
    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Create),
                max_fee_per_gas: Some(987),
                max_priority_fee_per_gas: Some(987),
                nonce: Some(57),
                gas: Some(123456),
                ..Default::default()
            },
            fee_token: Some(Address::repeat_byte(0xFA)),
            ..Default::default()
        },
        TempoTypedTransaction::FeeToken(TxFeeToken {
            to: TxKind::Create,
            max_fee_per_gas: 987,
            max_priority_fee_per_gas: 987,
            nonce: 57,
            gas_limit: 123456,
            chain_id: 1,
            fee_token: Some(Address::repeat_byte(0xFA)),
            ..Default::default()
        });
        "Fee token of create kind"
    )]
    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(Address::repeat_byte(0xDE))),
                max_fee_per_gas: Some(987),
                max_priority_fee_per_gas: Some(987),
                nonce: Some(57),
                gas: Some(123456),
                authorization_list: Some(vec![SignedAuthorization::new_unchecked(
                    Authorization {
                        chain_id: U256::from(1337),
                        address: Address::ZERO,
                        nonce: 0
                    },
                    0,
                    U256::ZERO,
                    U256::ZERO,
                )]),
                ..Default::default()
            },
            fee_token: Some(Address::repeat_byte(0xFA)),
            ..Default::default()
        },
        TempoTypedTransaction::FeeToken(TxFeeToken {
            to: TxKind::Call(Address::repeat_byte(0xDE)),
            max_fee_per_gas: 987,
            max_priority_fee_per_gas: 987,
            nonce: 57,
            gas_limit: 123456,
            chain_id: 1,
            fee_token: Some(Address::repeat_byte(0xFA)),
            authorization_list: vec![SignedAuthorization::new_unchecked(
                Authorization {
                    chain_id: U256::from(1337),
                    address: Address::ZERO,
                    nonce: 0
                },
                0,
                U256::ZERO,
                U256::ZERO,
            )],
            ..Default::default()
        });
        "Fee token of call kind with authorization list"
    )]
    fn test_transaction_builds_successfully(
        request: TempoTransactionRequest,
        expected_transaction: TempoTypedTransaction,
    ) {
        let actual_transaction = request
            .build_unsigned()
            .expect("required fields should be filled out");

        assert_eq!(actual_transaction, expected_transaction);
    }

    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(Address::repeat_byte(0xDE))),
                max_priority_fee_per_gas: Some(987),
                nonce: Some(57),
                gas: Some(123456),
                ..Default::default()
            },
            ..Default::default()
        },
        "Failed to build transaction: EIP-1559 transaction can't be built due to missing keys: [\"max_fee_per_gas\"]";
        "EIP-1559 missing max fee"
    )]
    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Call(Address::repeat_byte(0xDE))),
                max_priority_fee_per_gas: Some(987),
                nonce: Some(57),
                gas: Some(123456),
                ..Default::default()
            },
            fee_token: Some(Address::repeat_byte(0xFA)),
            ..Default::default()
        },
        "Failed to build transaction: FeeToken transaction can't be built due to missing keys: [\"max_fee_per_gas\"]";
        "Fee token missing max fee"
    )]
    #[test_case::test_case(
        TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(TxKind::Create),
                max_fee_per_gas: Some(987),
                max_priority_fee_per_gas: Some(987),
                nonce: Some(57),
                gas: Some(123456),
                authorization_list: Some(vec![SignedAuthorization::new_unchecked(
                    Authorization {
                        chain_id: U256::from(1337),
                        address: Address::ZERO,
                        nonce: 0
                    },
                    0,
                    U256::ZERO,
                    U256::ZERO,
                )]),
                ..Default::default()
            },
            fee_token: Some(Address::repeat_byte(0xFA)),
            ..Default::default()
        },
        "Failed to build transaction: FeeToken transaction can't be built due to missing keys: [\"to\"]";
        "Fee token of create kind with authorization list"
    )]
    fn test_transaction_fails_to_build(request: TempoTransactionRequest, expected_error: &str) {
        let actual_error = request
            .build_unsigned()
            .expect_err("some required fields should be missing")
            .to_string();

        assert_eq!(actual_error, expected_error);
    }
}
