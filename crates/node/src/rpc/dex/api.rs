use crate::rpc::dex::{
    Order, Orderbook, OrderbooksFilter, OrdersFilters, PaginationParams, types::PaginationResponse,
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// RPC api for the `dex_` namespace
#[rpc(server, namespace = "dex")]
pub trait TempoDexApi {
    /// Gets paginated orders from the Stablecoin Exchange orderbook.
    ///
    /// Uses cursor-based pagination for stable iteration through orders as the orderbook changes.
    #[method(name = "getOrders")]
    async fn orders(
        &self,
        params: PaginationParams<OrdersFilters>,
    ) -> RpcResult<PaginationResponse<Order>>;

    /// Gets paginated orderbooks from the Stablecoin Exchange on Tempo.
    ///
    /// Uses cursor-based pagination for stable iteration through orderbooks.
    #[method(name = "getOrderbooks")]
    async fn orderbooks(
        &self,
        params: PaginationParams<OrderbooksFilter>,
    ) -> RpcResult<PaginationResponse<Orderbook>>;
}
