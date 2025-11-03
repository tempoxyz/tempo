pub use addresses::{AddressesFilters, PolicyAddress};

use crate::rpc::policy::addresses::{AddressesParams, AddressesResponse};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;

pub mod addresses;

#[rpc(server, namespace = "policy")]
pub trait TempoPolicyApi {
    /// Gets paginated addresses in a transfer policy on Tempo.
    ///
    /// Returns addresses that are authorized or restricted based on the policy type (whitelist or blacklist).
    ///
    /// Uses cursor-based pagination for stable iteration through addresses.
    #[method(name = "getAddresses")]
    async fn addresses(&self, params: AddressesParams) -> RpcResult<AddressesResponse>;
}

/// The JSON-RPC handlers for the `policy_` namespace.
#[derive(Debug, Clone, Default)]
pub struct TempoPolicy<EthApi> {
    eth_api: EthApi,
}

impl<EthApi> TempoPolicy<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self { eth_api }
    }
}

#[async_trait::async_trait]
impl<EthApi: RpcNodeCore> TempoPolicyApiServer for TempoPolicy<EthApi> {
    async fn addresses(&self, _params: AddressesParams) -> RpcResult<AddressesResponse> {
        Err(internal_rpc_err("unimplemented"))
    }
}

impl<EthApi: RpcNodeCore> TempoPolicy<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
