use crate::rpc::eth_ext::transactions::TransactionsResponse;
use alloy_primitives::{B256, Bytes};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;
use reth_rpc_eth_types::utils::recover_raw_transaction;
use reth_transaction_pool::{PoolPooledTx, PoolTransaction, TransactionOrigin, TransactionPool};
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

    /// Submits a raw transaction to the pool with `Private` origin so that it is not propagated
    /// to other peers. Otherwise behaves identically to `eth_sendRawTransaction`.
    #[method(name = "sendRawTransactionPrivate")]
    async fn send_raw_transaction_private(&self, tx: Bytes) -> RpcResult<B256>;
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

    async fn send_raw_transaction_private(&self, tx: Bytes) -> RpcResult<B256> {
        let recovered = recover_raw_transaction::<PoolPooledTx<EthApi::Pool>>(&tx)
            .map_err(|e| internal_rpc_err(e.to_string()))?;

        let pool_transaction =
            <EthApi::Pool as TransactionPool>::Transaction::from_pooled(recovered);

        let outcome = self
            .eth_api
            .pool()
            .add_transaction(TransactionOrigin::Private, pool_transaction)
            .await
            .map_err(|e| internal_rpc_err(e.to_string()))?;

        Ok(outcome.hash)
    }
}

impl<EthApi: RpcNodeCore> TempoEthExt<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
