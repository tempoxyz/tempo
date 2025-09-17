use alloy::consensus::{EthereumTxEnvelope, Transaction, TxEip4844, TxEip7702, error::ValueError};
use alloy_network::TxSigner;
use alloy_primitives::{Address, Signature};
use alloy_rpc_types_eth::TransactionRequest;
use reth_evm::revm::context::{BlockEnv, CfgEnv};
use reth_rpc_convert::{
    EthTxEnvError, SignTxRequestError, SignableTxRequest, TryIntoSimTx, transaction::TryIntoTxEnv,
};
use serde::{Deserialize, Serialize};
use tempo_primitives::{TempoTxEnvelope, TxFeeToken};
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
        let tx: TxEip7702 =
            self.inner
                .build_7702()
                .map_err(|inner: ValueError<TransactionRequest>| {
                    ValueError::new(
                        Self {
                            inner: inner.into_value(),
                            fee_token: self.fee_token,
                        },
                        "Missing transaction fields",
                    )
                })?;

        Ok(TxFeeToken {
            chain_id: tx.chain_id().unwrap_or(1),
            nonce: tx.nonce(),
            gas_limit: tx.gas_limit(),
            max_fee_per_gas: tx.max_fee_per_gas(),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            to: tx.kind(),
            value: tx.value(),
            input: tx.input().clone(),
            fee_token: self.fee_token,
            access_list: tx.access_list().cloned().unwrap_or_default(),
            authorization_list: tx
                .authorization_list()
                .map(|v| v.to_vec())
                .unwrap_or_default(),
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
