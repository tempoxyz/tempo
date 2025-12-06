use alloy::{
    primitives::{Address, B256, U256},
    providers::{
        DynProvider, Provider,
        fillers::{FillProvider, TxFiller},
    },
};
use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::error::INTERNAL_ERROR_CODE};
use reth_rpc_server_types::result::rpc_err;
use tempo_precompiles::tip20::ITIP20;

#[rpc(server, namespace = "tempo")]
pub trait TempoFaucetExtApi {
    #[method(name = "fundAddress")]
    async fn fund_address(&self, address: Address) -> RpcResult<Vec<B256>>;
}

pub struct TempoFaucetExt {
    faucet_token_addresses: Vec<Address>,
    funding_amount: U256,
    provider: DynProvider,
}

impl TempoFaucetExt {
    pub fn new(
        faucet_token_addresses: Vec<Address>,
        funding_amount: U256,
        provider: FillProvider<impl TxFiller + 'static, impl Provider + 'static>,
    ) -> Self {
        Self {
            faucet_token_addresses,
            funding_amount,
            provider: provider.erased(),
        }
    }
}

#[async_trait]
impl TempoFaucetExtApiServer for TempoFaucetExt {
    async fn fund_address(&self, address: Address) -> RpcResult<Vec<B256>> {
        let mut tx_hashes = Vec::new();
        for token in &self.faucet_token_addresses {
            let tx_hash = *ITIP20::new(*token, &self.provider)
                .mint(address, self.funding_amount)
                .send()
                .await
                .map_err(|err| rpc_err(INTERNAL_ERROR_CODE, err.to_string(), None))?
                .tx_hash();

            tx_hashes.push(tx_hash);
        }

        Ok(tx_hashes)
    }
}
