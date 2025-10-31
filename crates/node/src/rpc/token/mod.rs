use crate::rpc::{
    pagination::{PaginationParams, PaginationResponse},
    token::{
        role_history::{RoleChange, RoleHistoryFilters},
        tokens::{Token, TokensFilters},
        tokens_by_address::{AccountToken, TokensByAddressParams},
    },
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;

pub mod role_history;
pub mod tokens;
pub mod tokens_by_address;

#[rpc(server, namespace = "token")]
pub trait TempoTokenApi {
    #[method(name = "getRoleHistory")]
    async fn role_history(
        &self,
        params: PaginationParams<RoleHistoryFilters>,
    ) -> RpcResult<PaginationResponse<RoleChange>>;

    #[method(name = "getTokens")]
    async fn tokens(
        &self,
        params: PaginationParams<TokensFilters>,
    ) -> RpcResult<PaginationResponse<Token>>;

    #[method(name = "getTokensByAddress")]
    async fn tokens_by_address(
        &self,
        params: TokensByAddressParams,
    ) -> RpcResult<PaginationResponse<AccountToken>>;
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
    ) -> RpcResult<PaginationResponse<RoleChange>> {
        Err(internal_rpc_err("unimplemented"))
    }

    async fn tokens(
        &self,
        _params: PaginationParams<TokensFilters>,
    ) -> RpcResult<PaginationResponse<Token>> {
        Err(internal_rpc_err("unimplemented"))
    }

    async fn tokens_by_address(
        &self,
        _params: TokensByAddressParams,
    ) -> RpcResult<PaginationResponse<AccountToken>> {
        Err(internal_rpc_err("unimplemented"))
    }
}

impl<EthApi: RpcNodeCore> TempoToken<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
