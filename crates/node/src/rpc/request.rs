use alloy::{
    consensus::{
        EthereumTxEnvelope, Signed, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy,
        error::ValueError,
    },
    rpc::types::TransactionTrait,
};
use alloy_network::TxSigner;
use alloy_primitives::{Address, Signature};
use alloy_rpc_types_eth::TransactionRequest;
use reth_evm::revm::context::{BlockEnv, CfgEnv};
use reth_rpc_convert::{
    EthTxEnvError, SignTxRequestError, SignableTxRequest, TryIntoSimTx, transaction::TryIntoTxEnv,
};
use serde::{Deserialize, Serialize};
use tempo_primitives::{TempoTxEnvelope, TxFeeToken, transaction::TempoTypedTransaction};
use tempo_revm::TempoTxEnv;

/// An Ethereum [`TransactionRequest`] with an optional `fee_token`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename = "camelCase")]
pub struct TempoTransactionRequest {
    #[serde(flatten)]
    pub inner: TransactionRequest,
    pub fee_token: Option<Address>,
}

impl TempoTransactionRequest {
    pub fn build_fee_token(self) -> Result<TxFeeToken, ValueError<Self>> {
        let Some(to) = self.inner.to else {
            return Err(ValueError::new(
                self,
                "Missing 'to' field for FeeToken transaction.",
            ));
        };
        let Some(nonce) = self.inner.nonce else {
            return Err(ValueError::new(
                self,
                "Missing 'nonce' field for FeeToken transaction.",
            ));
        };
        let Some(gas_limit) = self.inner.gas else {
            return Err(ValueError::new(
                self,
                "Missing 'gas_limit' field for FeeToken transaction.",
            ));
        };
        let Some(max_fee_per_gas) = self.inner.max_fee_per_gas else {
            return Err(ValueError::new(
                self,
                "Missing 'max_fee_per_gas' field for FeeToken transaction.",
            ));
        };
        let Some(max_priority_fee_per_gas) = self.inner.max_priority_fee_per_gas else {
            return Err(ValueError::new(
                self,
                "Missing 'max_priority_fee_per_gas' field for FeeToken transaction.",
            ));
        };

        Ok(TxFeeToken {
            chain_id: self.inner.chain_id.unwrap_or(1),
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to,
            fee_token: self.fee_token,
            value: self.inner.value.unwrap_or_default(),
            input: self.inner.input.into_input().unwrap_or_default(),
            access_list: self.inner.access_list.unwrap_or_default(),
            authorization_list: self.inner.authorization_list.unwrap_or_default(),
        })
    }
}

impl TryIntoSimTx<TempoTxEnvelope> for TempoTransactionRequest {
    fn try_into_sim_tx(self) -> Result<TempoTxEnvelope, ValueError<Self>> {
        if self.fee_token.is_some() {
            let tx = self.build_fee_token()?;

            // Create an empty signature for the transaction.
            let signature = Signature::new(Default::default(), Default::default(), false);

            Ok(tx.into_signed(signature).into())
        } else {
            let inner =
                TryIntoSimTx::<EthereumTxEnvelope<TxEip4844>>::try_into_sim_tx(self.inner.clone())
                    .map_err(|e| {
                        e.map(|inner| Self {
                            inner,
                            fee_token: self.fee_token,
                        })
                    })?;

            Ok(TryFrom::<EthereumTxEnvelope<TxEip4844>>::try_from(inner)
                .map_err(|e: ValueError<EthereumTxEnvelope<TxEip4844>>| e.map(|_inner| self))?)
        }
    }
}

impl TryIntoTxEnv<TempoTxEnv> for TempoTransactionRequest {
    type Err = EthTxEnvError;

    fn try_into_tx_env<Spec>(
        self,
        cfg_env: &CfgEnv<Spec>,
        block_env: &BlockEnv,
    ) -> Result<TempoTxEnv, Self::Err> {
        Ok(TempoTxEnv {
            inner: self.inner.try_into_tx_env(cfg_env, block_env)?,
            fee_token: self.fee_token,
            is_system_tx: false,
        })
    }
}

impl SignableTxRequest<TempoTxEnvelope> for TempoTransactionRequest {
    async fn try_build_and_sign(
        self,
        signer: impl TxSigner<Signature> + Send,
    ) -> Result<TempoTxEnvelope, SignTxRequestError> {
        SignableTxRequest::<TempoTxEnvelope>::try_build_and_sign(self.inner, signer).await
    }
}

impl AsRef<TransactionRequest> for TempoTransactionRequest {
    fn as_ref(&self) -> &TransactionRequest {
        &self.inner
    }
}

impl AsMut<TransactionRequest> for TempoTransactionRequest {
    fn as_mut(&mut self) -> &mut TransactionRequest {
        &mut self.inner
    }
}

impl From<TransactionRequest> for TempoTransactionRequest {
    fn from(value: TransactionRequest) -> Self {
        Self {
            inner: value,
            fee_token: None,
        }
    }
}

impl From<TempoTransactionRequest> for TransactionRequest {
    fn from(value: TempoTransactionRequest) -> Self {
        value.inner
    }
}

impl From<TempoTxEnvelope> for TempoTransactionRequest {
    fn from(value: TempoTxEnvelope) -> Self {
        match value {
            TempoTxEnvelope::Legacy(tx) => tx.into(),
            TempoTxEnvelope::Eip2930(tx) => tx.into(),
            TempoTxEnvelope::Eip1559(tx) => tx.into(),
            TempoTxEnvelope::Eip7702(tx) => tx.into(),
            TempoTxEnvelope::FeeToken(tx) => tx.into(),
        }
    }
}

trait FeeToken {
    fn fee_token(&self) -> Option<Address>;
}

impl FeeToken for TxFeeToken {
    fn fee_token(&self) -> Option<Address> {
        self.fee_token
    }
}

impl FeeToken for TxEip7702 {
    fn fee_token(&self) -> Option<Address> {
        None
    }
}

impl FeeToken for TxEip1559 {
    fn fee_token(&self) -> Option<Address> {
        None
    }
}

impl FeeToken for TxEip2930 {
    fn fee_token(&self) -> Option<Address> {
        None
    }
}

impl FeeToken for TxLegacy {
    fn fee_token(&self) -> Option<Address> {
        None
    }
}

impl<T: TransactionTrait + FeeToken> From<Signed<T>> for TempoTransactionRequest {
    fn from(value: Signed<T>) -> Self {
        Self {
            fee_token: value.tx().fee_token(),
            inner: TransactionRequest::from_transaction(value),
        }
    }
}

impl From<TempoTypedTransaction> for TempoTransactionRequest {
    fn from(value: TempoTypedTransaction) -> Self {
        match value {
            TempoTypedTransaction::Legacy(tx) => Self {
                inner: tx.into(),
                fee_token: None,
            },
            TempoTypedTransaction::Eip2930(tx) => Self {
                inner: tx.into(),
                fee_token: None,
            },
            TempoTypedTransaction::Eip1559(tx) => Self {
                inner: tx.into(),
                fee_token: None,
            },
            TempoTypedTransaction::Eip7702(tx) => Self {
                inner: tx.into(),
                fee_token: None,
            },
            TempoTypedTransaction::FeeToken(tx) => Self {
                fee_token: tx.fee_token,
                inner: TransactionRequest::from_transaction(tx),
            },
        }
    }
}
