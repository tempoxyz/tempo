pub use types::{
    FilterRange, Order, OrdersFilters, OrdersParams, OrdersResponse, OrdersSort, OrdersSortOrder,
};

use jsonrpsee::{core::RpcResult, proc_macros::rpc};

pub mod types;

#[rpc(server, namespace = "dex")]
pub trait TempoDexApi {
    #[method(name = "getOrders")]
    async fn orders(&self, params: Vec<OrdersParams>) -> RpcResult<OrdersResponse>;
}
