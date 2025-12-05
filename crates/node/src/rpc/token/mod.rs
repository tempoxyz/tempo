use crate::rpc::token::{
    role_history::{RoleHistoryFilters, RoleHistoryResponse},
    tokens::{TokensFilters, TokensResponse},
    tokens_by_address::{TokensByAddressParams, TokensByAddressResponse},
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;
use tempo_alloy::rpc::pagination::PaginationParams;

pub mod role_history;
pub mod tokens;
pub mod tokens_by_address;

#[rpc(server, namespace = "token")]
pub trait TempoTokenApi {
    /// Gets paginated role change history for TIP-20 tokens on Tempo.
    ///
    /// Tracks role grants and revocations from the RoleMembershipUpdated event for audit trails and
    /// compliance monitoring.
    ///
    /// Uses cursor-based pagination for stable iteration through role changes.
    #[method(name = "getRoleHistory")]
    async fn role_history(
        &self,
        params: PaginationParams<RoleHistoryFilters>,
    ) -> RpcResult<RoleHistoryResponse>;

    /// Gets paginated TIP-20 tokens on Tempo.
    ///
    /// Uses cursor-based pagination for stable iteration through tokens.
    #[method(name = "getTokens")]
    async fn tokens(&self, params: PaginationParams<TokensFilters>) -> RpcResult<TokensResponse>;

    /// Gets paginated TIP-20 tokens associated with an account address on Tempo.
    ///
    /// Returns tokens where the account has a balance or specific roles.
    ///
    /// Uses cursor-based pagination for stable iteration through tokens.
    #[method(name = "getTokensByAddress")]
    async fn tokens_by_address(
        &self,
        params: TokensByAddressParams,
    ) -> RpcResult<TokensByAddressResponse>;
}

/// The JSON-RPC handlers for the `token_` namespace.
#[derive(Debug, Clone, Default)]
pub struct TempoToken<EthApi> {
    eth_api: EthApi,
}

impl<EthApi> TempoToken<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self { eth_api }
    }
}

#[async_trait::async_trait]
impl<EthApi: RpcNodeCore> TempoTokenApiServer for TempoToken<EthApi> {
    async fn role_history(
        &self,
        _params: PaginationParams<RoleHistoryFilters>,
    ) -> RpcResult<RoleHistoryResponse> {
        Err(internal_rpc_err("unimplemented"))
    }

    async fn tokens(&self, _params: PaginationParams<TokensFilters>) -> RpcResult<TokensResponse> {
        Err(internal_rpc_err("unimplemented"))
    }

    async fn tokens_by_address(
        &self,
        _params: TokensByAddressParams,
    ) -> RpcResult<TokensByAddressResponse> {
        Err(internal_rpc_err("unimplemented"))
    }
}

impl<EthApi: RpcNodeCore> TempoToken<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
