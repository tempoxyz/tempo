use alloy::providers::{Provider, ProviderBuilder};
use reth_rpc_builder::RpcModuleSelection;

use crate::utils::TestNodeBuilder;

#[tokio::test(flavor = "multi_thread")]
async fn test_operator_peers_without_admin_namespace() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .build_http_only_with_api("operator".parse::<RpcModuleSelection>().unwrap())
        .await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url);

    let peers: serde_json::Value = provider.raw_request("operator_peers".into(), ()).await?;
    assert!(peers.is_array(), "operator_peers should return an array");

    let err = provider
        .raw_request::<_, serde_json::Value>("admin_peers".into(), ())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("Method not found"),
        "expected admin_peers to remain disabled, got: {err}"
    );

    Ok(())
}
