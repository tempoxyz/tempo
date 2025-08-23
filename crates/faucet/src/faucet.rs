use crate::faucet::FaucetError::ParseUrlError;
use alloy::{
    consensus::{TxEnvelope, transaction::SignerRecoverable},
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::ProviderBuilder,
    rpc::types::{TransactionInput, TransactionRequest},
    sol_types::SolCall,
};
use alloy::consensus::crypto::RecoveryError;
use alloy::providers::SendableTxErr;
use alloy::transports::{RpcError, TransportErrorKind};
use async_trait::async_trait;
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::error::INTERNAL_ERROR_CODE
};
use jsonrpsee::types::error::INVALID_REQUEST_CODE;
use reth::rpc::result::rpc_err;
use reth::transaction_pool::{TransactionOrigin, TransactionPool};
use reth::transaction_pool::error::PoolError;
use tempo_precompiles::contracts::ITIP20;
use tempo_transaction_pool::transaction::TempoPooledTransaction;

#[rpc(server, namespace = "tempo")]
pub trait TempoFaucetExtApi {
    #[method(name = "fundAddress")]
    async fn fund_address(&self, address: Address) -> RpcResult<B256>;
}

pub struct TempoFaucetExt<Pool> {
    pool: Pool,
    signer: EthereumWallet,
    tip20_address: Address,
    funding_amount: U256,
}

impl<Pool> TempoFaucetExt<Pool> {
    pub fn new(
        pool: Pool,
        signer: EthereumWallet,
        tip20_address: Address,
        funding_amount: U256,
    ) -> Self {
        Self {
            pool,
            signer,
            tip20_address,
            funding_amount,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FaucetError {
    #[error(transparent)]
    ParseUrlError(#[from] url::ParseError),
    #[error(transparent)]
    FillError(#[from] RpcError<TransportErrorKind>),
    #[error(transparent)]
    ConversionError(#[from] SendableTxErr<TransactionRequest>),
    #[error(transparent)]
    SignatureRecoveryError(#[from] RecoveryError),
    #[error(transparent)]
    TxPoolError(#[from] PoolError),
}

impl From<FaucetError> for jsonrpsee::types::ErrorObject<'static> {
    fn from(err: FaucetError) -> Self {
        match err {
            FaucetError::ParseUrlError(e) => rpc_err(INTERNAL_ERROR_CODE, e.to_string(), None),
            FaucetError::FillError(e) => rpc_err(INTERNAL_ERROR_CODE, e.to_string(), None),
            FaucetError::ConversionError(e) => rpc_err(INTERNAL_ERROR_CODE, e.to_string(), None),
            FaucetError::SignatureRecoveryError(e) => rpc_err(INTERNAL_ERROR_CODE, e.to_string(), None),
            FaucetError::TxPoolError(e) => rpc_err(INVALID_REQUEST_CODE, e.to_string(), None),
        }
    }
}

#[async_trait]
impl<Pool> TempoFaucetExtApiServer for TempoFaucetExt<Pool>
where
    Pool: TransactionPool<Transaction = TempoPooledTransaction> + Clone + 'static,
{
    async fn fund_address(&self, address: Address) -> RpcResult<B256> {
        let url = "http://localhost:8545".parse().map_err(|e| ParseUrlError(e))?;
        let provider = ProviderBuilder::new()
            .wallet(&self.signer)
            .connect_http(url);

        let transfer_call_data = ITIP20::transferCall {
            to: address,
            amount: self.funding_amount,
        }
        .abi_encode();

        let request = TransactionRequest::default()
            .to(self.tip20_address)
            .input(TransactionInput::from(transfer_call_data));

        let filled_tx = provider
            .fill(request)
            .await
            .map_err(|e| FaucetError::FillError(e))?;

        let tx: TxEnvelope = filled_tx
            .try_into_envelope()
            .map_err(|e| FaucetError::ConversionError(e))?;

        let tx_hash = *tx.hash();

        let tx = tx
            .try_into_recovered()
            .map_err(|e| FaucetError::SignatureRecoveryError(e))?;

        self.pool
            .add_consensus_transaction(tx.convert(), TransactionOrigin::Local)
            .await
            .map_err(FaucetError::TxPoolError)?;

        Ok(tx_hash)
    }
}
