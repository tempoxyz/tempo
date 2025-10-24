pub use books::{Orderbook, OrderbooksFilter, OrderbooksParam, OrderbooksResponse};
pub use types::{
    FilterRange, Order, OrdersFilters, OrdersResponse, OrdersSort, OrdersSortOrder,
    PaginationParams,
};

use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;

mod books;
pub mod types;

#[rpc(server, namespace = "dex")]
pub trait TempoDexApi {
    #[method(name = "getOrders")]
    async fn orders(
        &self,
        params: Vec<PaginationParams<OrdersFilters>>,
    ) -> RpcResult<OrdersResponse>;

    #[method(name = "getOrderbooks")]
    async fn orderbooks(
        &self,
        params: Vec<PaginationParams<OrderbooksFilter>>,
    ) -> RpcResult<OrderbooksResponse>;
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
    async fn orders(
        &self,
        _params: Vec<PaginationParams<OrdersFilters>>,
    ) -> RpcResult<OrdersResponse> {
        Err(internal_rpc_err("unimplemented"))
    }

    async fn orderbooks(
        &self,
        _params: Vec<PaginationParams<OrderbooksFilter>>,
    ) -> RpcResult<OrderbooksResponse> {
        Err(internal_rpc_err("unimplemented"))
    }
}

impl<EthApi: RpcNodeCore> TempoDex<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
