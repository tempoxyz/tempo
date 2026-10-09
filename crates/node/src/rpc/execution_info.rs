//! Identity and callable-method discovery for a private RPC endpoint.

use alloy_primitives::B256;
use jsonrpsee::{
    RpcModule,
    core::server::{MethodCallback, Methods},
    types::ErrorObjectOwned,
};
use reth_rpc_builder::TransportRpcModules;
pub use tempo_metabinary::handshake::{
    EXECUTION_INFO_METHOD, EXECUTION_INFO_PROTOCOL_VERSION, ExecutionInfo,
};

fn info_module(
    methods: Methods,
    chain_id: u64,
    genesis_hash: B256,
    read_only: bool,
) -> Result<RpcModule<ExecutionInfo>, jsonrpsee::core::RegisterMethodError> {
    let mut names = methods
        .method_names()
        .filter(|name| {
            matches!(
                methods.method(name),
                Some(MethodCallback::Sync(_) | MethodCallback::Async(_))
            )
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.push(EXECUTION_INFO_METHOD.to_owned());
    names.sort_unstable();
    names.dedup();

    let mut module = RpcModule::new(ExecutionInfo {
        protocol_version: EXECUTION_INFO_PROTOCOL_VERSION,
        process_id: std::process::id(),
        chain_id: alloy_primitives::U64::from(chain_id),
        genesis_hash,
        read_only,
        methods: names,
    });
    module.register_method(EXECUTION_INFO_METHOD, |_, info, _| {
        Ok::<_, ErrorObjectOwned>(info.clone())
    })?;
    Ok(module)
}

/// Install discovery separately for each configured transport, preserving its namespace policy.
///
/// Call after adding RPC extensions. Repeated calls refresh the snapshot without changing other
/// callbacks or exposing methods configured on a different transport.
pub fn install_execution_info(
    modules: &mut TransportRpcModules,
    chain_id: u64,
    genesis_hash: B256,
    read_only: bool,
) -> Result<(), jsonrpsee::core::RegisterMethodError> {
    modules.remove_method_from_configured(EXECUTION_INFO_METHOD);
    if let Some(methods) = modules.http_methods(|_| true) {
        modules.merge_http(info_module(methods, chain_id, genesis_hash, read_only)?)?;
    }
    if let Some(methods) = modules.ws_methods(|_| true) {
        modules.merge_ws(info_module(methods, chain_id, genesis_hash, read_only)?)?;
    }
    if let Some(methods) = modules.ipc_methods(|_| true) {
        modules.merge_ipc(info_module(methods, chain_id, genesis_hash, read_only)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::rpc_params;

    #[tokio::test]
    async fn discovery_preserves_transport_policy_and_refreshes_extensions() {
        let mut http = RpcModule::new(());
        http.register_method("eth_chainId", |_, _, _| "0x1")
            .unwrap();
        let mut ws = RpcModule::new(());
        ws.register_method("debug_traceBlockByNumber", |_, _, _| ())
            .unwrap();
        ws.register_subscription(
            "eth_subscribe",
            "eth_subscription",
            "eth_unsubscribe",
            |_, _, _, _| async {},
        )
        .unwrap();
        let mut modules = TransportRpcModules::default().with_http(http).with_ws(ws);
        install_execution_info(&mut modules, 1, B256::ZERO, false).unwrap();

        let http_info: ExecutionInfo = modules
            .http_methods(|_| true)
            .unwrap()
            .call(EXECUTION_INFO_METHOD, rpc_params![])
            .await
            .unwrap();
        assert_eq!(http_info.methods, ["eth_chainId", EXECUTION_INFO_METHOD]);
        assert_eq!(http_info.chain_id, alloy_primitives::U64::from(1));
        assert!(!http_info.read_only);
        assert_eq!(http_info.process_id, std::process::id());
        let ws_info: ExecutionInfo = modules
            .ws_methods(|_| true)
            .unwrap()
            .call(EXECUTION_INFO_METHOD, rpc_params![])
            .await
            .unwrap();
        assert_eq!(
            ws_info.methods,
            ["debug_traceBlockByNumber", EXECUTION_INFO_METHOD]
        );

        let mut extension = RpcModule::new(());
        extension
            .register_method("tempo_example", |_, _, _| ())
            .unwrap();
        modules.merge_http(extension).unwrap();
        install_execution_info(&mut modules, 1, B256::ZERO, false).unwrap();
        let refreshed: ExecutionInfo = modules
            .http_methods(|_| true)
            .unwrap()
            .call(EXECUTION_INFO_METHOD, rpc_params![])
            .await
            .unwrap();
        assert_eq!(
            refreshed.methods,
            ["eth_chainId", "tempo_example", EXECUTION_INFO_METHOD]
        );
    }
}
