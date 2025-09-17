use alloy::consensus::{EthereumTxEnvelope, TxEip4844, error::ValueError};
use alloy_primitives::{Address, private::derive_more};
use alloy_rpc_types_eth::TransactionRequest;
use reth_evm::revm::context::{BlockEnv, CfgEnv};
use reth_rpc_convert::{EthTxEnvError, SignableTxRequest, TryIntoSimTx, transaction::TryIntoTxEnv};
use serde::{Deserialize, Serialize};
use tempo_primitives::TempoTxEnvelope;
use tempo_revm::TempoTxEnv;

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    derive_more::From,
    derive_more::AsRef,
    derive_more::AsMut,
    Serialize,
    Deserialize,
)]
#[serde(rename = "camelCase")]
pub struct TempoTransactionRequest {
    #[serde(flatten)]
    pub inner: TransactionRequest,
    pub fee_token: Option<Address>,
}

impl TryIntoSimTx<TempoTxEnvelope> for TempoTransactionRequest {
    fn try_into_sim_tx(self) -> Result<TempoTxEnvelope, ValueError<Self>> {
        let tx_req = self.inner.clone();
        let inner = TryIntoSimTx::<EthereumTxEnvelope<TxEip4844>>::try_into_sim_tx(self.inner)
            .map_err(|e| {
                e.map(|inner| TempoTransactionRequest {
                    inner,
                    fee_token: self.fee_token,
                })
            })?;

        Ok(
            TryFrom::<EthereumTxEnvelope<TxEip4844>>::try_from(inner).map_err(
                |e: ValueError<EthereumTxEnvelope<TxEip4844>>| {
                    e.map(|_inner| TempoTransactionRequest {
                        inner: tx_req,
                        fee_token: self.fee_token,
                    })
                },
            )?,
        )
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
        signer: impl alloy_network::TxSigner<alloy_primitives::Signature> + Send,
    ) -> Result<TempoTxEnvelope, reth_rpc_convert::SignTxRequestError> {
        SignableTxRequest::<TempoTxEnvelope>::try_build_and_sign(self.inner, signer)
            .await
            .and_then(|tx| {
                tx.try_into()
                    .map_err(|_| reth_rpc_convert::SignTxRequestError::InvalidTransactionRequest)
            })
    }
}
