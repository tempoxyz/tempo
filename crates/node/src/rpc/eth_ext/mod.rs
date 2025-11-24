use crate::rpc::eth_ext::transactions::TransactionsResponse;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;
use tempo_alloy::rpc::pagination::PaginationParams;

pub mod transactions;
pub use transactions::TransactionsFilter;

#[rpc(server, namespace = "eth")]
pub trait TempoEthExtApi {
    /// Gets paginated transactions on Tempo with flexible filtering and sorting.
    ///
    /// Uses cursor-based pagination for stable iteration through transactions.
    #[method(name = "getTransactions")]
    async fn transactions(
        &self,
        params: PaginationParams<TransactionsFilter>,
    ) -> RpcResult<TransactionsResponse>;
}

/// The JSON-RPC handlers for the `dex_` namespace.
#[derive(Debug, Clone, Default)]
pub struct TempoEthExt<EthApi> {
    eth_api: EthApi,
}

impl<EthApi> TempoEthExt<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self { eth_api }
    }
}

#[async_trait::async_trait]
impl<EthApi: RpcNodeCore> TempoEthExtApiServer for TempoEthExt<EthApi> {
    async fn transactions(
        &self,
        _params: PaginationParams<TransactionsFilter>,
    ) -> RpcResult<TransactionsResponse> {
        Err(internal_rpc_err("unimplemented"))
    }
}

impl<EthApi: RpcNodeCore> TempoEthExt<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
