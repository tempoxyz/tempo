use crate::faucet::FaucetError::ParseUrlError;
use alloy::{
    consensus::{TxEnvelope, transaction::SignerRecoverable},
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::ProviderBuilder,
    rpc::types::{TransactionInput, TransactionRequest},
    sol_types::SolCall,
};
use async_trait::async_trait;
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::{
        ErrorObjectOwned,
        error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG},
    },
};
use reth::transaction_pool::{TransactionOrigin, TransactionPool};
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

pub enum FaucetError {
    ParseUrlError,
    FillError,
    ConversionError,
    TxPoolError,
}

impl From<FaucetError> for ErrorObjectOwned {
    fn from(err: FaucetError) -> Self {
        let message = match err {
            ParseUrlError => "failed to parse the provider url",
            FaucetError::FillError => "failed to fill the transaction details",
            FaucetError::ConversionError => "failed to convert the transaction",
            FaucetError::TxPoolError => "failed to add transaction into the pool",
        };

        ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, Some(message))
    }
}

#[async_trait]
impl<Pool> TempoFaucetExtApiServer for TempoFaucetExt<Pool>
where
    Pool: TransactionPool<Transaction = TempoPooledTransaction> + Clone + 'static,
{
    async fn fund_address(&self, address: Address) -> RpcResult<B256> {
        let url = "http://localhost:8545".parse().map_err(|_| ParseUrlError)?;
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
            .map_err(|_| FaucetError::FillError)?;

        let tx: TxEnvelope = filled_tx
            .try_into_envelope()
            .map_err(|_| FaucetError::ConversionError)?;

        let tx_hash = *tx.hash();

        let tx = tx
            .try_into_recovered()
            .map_err(|_| FaucetError::ConversionError)?;

        self.pool
            .add_consensus_transaction(tx.convert(), TransactionOrigin::Local)
            .await
            .map_err(|_| FaucetError::TxPoolError)?;

        Ok(tx_hash)
    }
}
