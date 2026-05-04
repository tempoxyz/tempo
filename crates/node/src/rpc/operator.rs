use alloy_rpc_types_admin::PeerInfo;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_network_api::{NetworkInfo, Peers};
use reth_rpc::AdminApi;
use reth_rpc_api::servers::AdminApiServer as _;
use reth_transaction_pool::TransactionPool;

#[rpc(server, namespace = "operator")]
pub trait TempoOperatorApi {
    /// Returns the node's connected execution peers.
    #[method(name = "peers")]
    async fn peers(&self) -> RpcResult<Vec<PeerInfo>>;
}

/// Tempo-specific operator RPCs that can be enabled without exposing the full `admin_` namespace.
#[derive(Debug)]
pub struct TempoOperatorRpc<N, ChainSpec, Pool> {
    admin_api: AdminApi<N, ChainSpec, Pool>,
}

impl<N, ChainSpec, Pool> TempoOperatorRpc<N, ChainSpec, Pool> {
    pub const fn new(admin_api: AdminApi<N, ChainSpec, Pool>) -> Self {
        Self { admin_api }
    }
}

#[async_trait::async_trait]
impl<N, ChainSpec, Pool> TempoOperatorApiServer for TempoOperatorRpc<N, ChainSpec, Pool>
where
    N: NetworkInfo + Peers + 'static,
    ChainSpec: EthChainSpec + EthereumHardforks + Send + Sync + 'static,
    Pool: TransactionPool + 'static,
{
    async fn peers(&self) -> RpcResult<Vec<PeerInfo>> {
        self.admin_api.peers().await
    }
}
