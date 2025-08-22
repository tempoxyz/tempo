use alloy::{
    primitives::{Address, U256, B256},
    network::EthereumWallet,
    providers::ProviderBuilder,
    sol_types::SolCall,
};
use alloy::consensus::TxEnvelope;
use async_trait::async_trait;
use reth::transaction_pool::{TransactionOrigin, TransactionPool};
use jsonrpsee::{
    core::{RpcResult, Error as RpcError},
    proc_macros::rpc,
    types::ErrorCode,
};
use reth::core::primitives::SignedTransaction;
use reth::rpc::types::{TransactionInput, TransactionRequest};
use tempo_precompiles::contracts::ITIP20;
use tempo_transaction_pool::transaction::TempoPooledTransaction;

#[cfg_attr(not(test), rpc(server, namespace = "tempo"))]
#[cfg_attr(test, rpc(server, client, namespace = "tempo"))]
pub trait TempoFaucetExtApi {
    #[method(name="fundAddress")]
    async fn fund_address(&self, address: Address) -> RpcResult<B256>;
}

pub struct TempoFaucetExt<Pool> {
    pool: Pool,
    signer: EthereumWallet,
    tip20_address: Address,
}

impl <Pool> TempoFaucetExt<Pool>{
    pub fn new(pool: Pool, signer: EthereumWallet, tip20_address: Address) -> Self {
        Self { pool, signer, tip20_address }
    }
}

#[cfg(not(test))]
#[async_trait]
impl<Pool> TempoFaucetExtApiServer for TempoFaucetExt<Pool>
where
    Pool: TransactionPool<Transaction = TempoPooledTransaction> + Clone + 'static,
{
    async fn fund_address(&self, address: Address) -> RpcResult<B256> {
        let url = "http://localhost:8545".parse().unwrap();
        let provider = ProviderBuilder::new()
            .wallet(&self.signer)
            .connect_http(url);

        let transfer_call_data = ITIP20::transferCall {
            to: address,
            amount: U256::from(10000000000u64),
        }.abi_encode();

        let request= TransactionRequest::default()
            .to(self.tip20_address)
            .input(TransactionInput::from(transfer_call_data));

        let tx: TxEnvelope = provider.fill(request).await.unwrap().try_into_envelope().unwrap();
        let tx_hash = *tx.hash();

        let tx = tx.try_into_recovered().unwrap();

        self.pool
            .add_consensus_transaction(
                tx.convert(),
                TransactionOrigin::Local,
            )
            .await
            .unwrap();

        Ok(tx_hash)
    }
}