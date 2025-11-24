use crate::rpc::amm::pools::PoolsResponse;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;
use tempo_alloy::rpc::pagination::PaginationParams;

pub mod pools;
pub use pools::{Pool, PoolsFilters};

#[rpc(server, namespace = "amm")]
pub trait TempoAmmApi {
    /// Gets paginated liquidity pools from the Fee AMM on Tempo.
    ///
    /// Each pool is directional (userToken → validatorToken) with fixed swap rates for fee swaps (0.997) and rebalance swaps (0.9985).
    ///
    /// Uses cursor-based pagination for stable iteration through pools.
    #[method(name = "getLiquidityPools")]
    async fn pools(&self, params: PaginationParams<PoolsFilters>) -> RpcResult<PoolsResponse>;
}

/// The JSON-RPC handlers for the `amm_` namespace.
#[derive(Debug, Clone, Default)]
pub struct TempoAmm<EthApi> {
    eth_api: EthApi,
}

impl<EthApi> TempoAmm<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self { eth_api }
    }
}

#[async_trait::async_trait]
impl<EthApi: RpcNodeCore> TempoAmmApiServer for TempoAmm<EthApi> {
    async fn pools(&self, _params: PaginationParams<PoolsFilters>) -> RpcResult<PoolsResponse> {
        Err(internal_rpc_err("unimplemented"))
    }
}

impl<EthApi: RpcNodeCore> TempoAmm<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
