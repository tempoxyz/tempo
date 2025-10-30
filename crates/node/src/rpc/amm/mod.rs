pub use pools::{Pool, PoolsFilters};

use crate::rpc::dex::{PaginationParams, types::PaginationResponse};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;

pub mod pools;

#[rpc(server, namespace = "amm")]
pub trait TempoAmmApi {
    #[method(name = "getPools")]
    async fn pools(
        &self,
        params: PaginationParams<PoolsFilters>,
    ) -> RpcResult<PaginationResponse<Pool>>;
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
    async fn pools(
        &self,
        _params: PaginationParams<PoolsFilters>,
    ) -> RpcResult<PaginationResponse<Pool>> {
        Err(internal_rpc_err("unimplemented"))
    }
}

impl<EthApi: RpcNodeCore> TempoAmm<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
