pub use types::{
    FilterRange, Order, OrdersFilters, OrdersParams, OrdersResponse, OrdersSort, OrdersSortOrder,
};

use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;

pub mod types;

#[rpc(server, namespace = "dex")]
pub trait TempoDexApi {
    #[method(name = "getOrders")]
    async fn orders(&self, params: Vec<OrdersParams>) -> RpcResult<OrdersResponse>;
}

/// The JSON-RPC handlers for the `dex_` namespace.
#[derive(Debug, Clone, Default)]
pub struct TempoDex<EthApi> {
    eth_api: EthApi,
}

impl<EthApi> TempoDex<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self { eth_api }
    }
}

#[async_trait::async_trait]
impl<EthApi: RpcNodeCore> TempoDexApiServer for TempoDex<EthApi> {
    async fn orders(&self, _params: Vec<OrdersParams>) -> RpcResult<OrdersResponse> {
        Err(internal_rpc_err("unimplemented"))
    }
}

impl<EthApi: RpcNodeCore> TempoDex<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
