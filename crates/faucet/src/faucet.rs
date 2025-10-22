use alloy::{
    consensus::{
        TxEnvelope, crypto::RecoveryError, error::ValueError, transaction::SignerRecoverable,
    },
    network::Ethereum,
    primitives::{Address, B256, U256},
    providers::{
        Provider,
        fillers::{FillProvider, TxFiller},
    },
    transports::{RpcError, TransportErrorKind},
};
use async_trait::async_trait;
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::error::{INTERNAL_ERROR_CODE, INVALID_REQUEST_CODE},
};
use reth_rpc_server_types::result::rpc_err;
use reth_transaction_pool::{TransactionOrigin, TransactionPool, error::PoolError};
use std::error::Error;
use tempo_precompiles::tip20::bindings::ITIP20;
use tempo_transaction_pool::transaction::TempoPooledTransaction;

#[rpc(server, namespace = "tempo")]
pub trait TempoFaucetExtApi {
    #[method(name = "fundAddress")]
    async fn fund_address(&self, address: Address) -> RpcResult<Vec<B256>>;
}

pub struct TempoFaucetExt<Pool, P, F>
where
    P: Provider,
    F: TxFiller<Ethereum>,
{
    pool: Pool,
    faucet_token_addresses: Vec<Address>,
    funding_amount: U256,
    provider: FillProvider<F, P, Ethereum>,
}

impl<Pool, P, F> TempoFaucetExt<Pool, P, F>
where
    P: Provider,
    F: TxFiller<Ethereum>,
{
    pub fn new(
        pool: Pool,
        faucet_token_addresses: Vec<Address>,
        funding_amount: U256,
        provider: FillProvider<F, P, Ethereum>,
    ) -> Self {
        Self {
            pool,
            faucet_token_addresses,
            funding_amount,
            provider,
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
    ConversionError(#[from] Box<dyn Error + Send + Sync + 'static>),
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
            FaucetError::SignatureRecoveryError(e) => {
                rpc_err(INTERNAL_ERROR_CODE, e.to_string(), None)
            }
            FaucetError::TxPoolError(e) => rpc_err(INVALID_REQUEST_CODE, e.to_string(), None),
        }
    }
}

#[async_trait]
impl<Pool, P, F> TempoFaucetExtApiServer for TempoFaucetExt<Pool, P, F>
where
    Pool: TransactionPool<Transaction = TempoPooledTransaction> + Clone + 'static,
    P: Provider + Clone + 'static,
    F: TxFiller<Ethereum> + Send + Sync + 'static,
{
    async fn fund_address(&self, address: Address) -> RpcResult<Vec<B256>> {
        let requests = self.faucet_token_addresses.iter().map(|token_address| {
            ITIP20::new(*token_address, &self.provider)
                .transfer(address, self.funding_amount)
                .into_transaction_request()
        });

        let mut tx_hashes = Vec::new();

        for request in requests {
            let filled_tx = self
                .provider
                .fill(request)
                .await
                .map_err(FaucetError::FillError)?;

            let tx: TxEnvelope = filled_tx
                .try_into_envelope()
                .map_err(|e| FaucetError::ConversionError(Box::new(e)))?;

            let tx_hash = *tx.hash();

            let tx = tx
                .try_into_recovered()
                .map_err(FaucetError::SignatureRecoveryError)?
                .try_convert::<_, ValueError<TxEnvelope>>()
                .map_err(|e| FaucetError::ConversionError(Box::new(e)))?;

            self.pool
                .add_consensus_transaction(tx, TransactionOrigin::Local)
                .await
                .map_err(FaucetError::TxPoolError)?;

            tx_hashes.push(tx_hash);
        }

        Ok(tx_hashes)
    }
}
