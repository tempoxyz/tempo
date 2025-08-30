//! Test utility functions for integration tests.
//!
//! This module provides helper functions for setting up and managing test environments,
//! including test token creation and node setup for integration testing.

use alloy::{
    primitives::Address, providers::Provider, sol_types::SolEvent, transports::http::reqwest::Url,
};
use reth_ethereum::tasks::TaskManager;
use reth_node_api::FullNodeComponents;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle, rpc::RethRpcAddOns};
use reth_node_core::args::RpcServerArgs;
use reth_rpc_builder::RpcModuleSelection;
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::node::TempoNode;
use tempo_precompiles::{
    TIP20_FACTORY_ADDRESS,
    contracts::{
        ITIP20::ITIP20Instance, ITIP20Factory, tip20::ISSUER_ROLE, token_id_to_address,
        types::IRolesAuth,
    },
};

/// Creates a test TIP20 token with issuer role granted to the caller
pub(crate) async fn setup_test_token<P>(
    provider: P,
    caller: Address,
) -> eyre::Result<ITIP20Instance<impl Clone + Provider>>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken(
            "Test".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            caller,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    let event = ITIP20Factory::TokenCreated::decode_log(&receipt.logs()[0].inner).unwrap();

    let token_addr = token_id_to_address(event.tokenId.to());
    let token = ITIP20Instance::new(token_addr, provider.clone());
    let roles = IRolesAuth::new(*token.address(), provider);

    roles
        .grantRole(*ISSUER_ROLE, caller)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(token)
}

/// Node source for integration testing
pub(crate) enum NodeSource {
    ExternalRpc(Url),
    LocalNode(String),
}

/// Type alias for a local test node and task manager
pub(crate) type LocalTestNode = (Box<dyn TestNodeHandle>, TaskManager);

/// Trait wrapper around NodeHandle to simplify function return types
pub(crate) trait TestNodeHandle: Send {}

/// Generic [`TestNodeHandle`] implementation for NodeHandle
impl<Node, AddOns> TestNodeHandle for NodeHandle<Node, AddOns>
where
    Node: FullNodeComponents,
    AddOns: RethRpcAddOns<Node>,
{
}

/// Set up a test node from the provided source configuration
pub(crate) async fn setup_test_node(
    source: NodeSource,
) -> eyre::Result<(Url, Option<LocalTestNode>)> {
    match source {
        NodeSource::ExternalRpc(url) => Ok((url, None)),
        NodeSource::LocalNode(genesis_content) => {
            let tasks = TaskManager::current();
            let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(&genesis_content)?);

            let node_config = NodeConfig::new(Arc::new(chain_spec))
                .with_unused_ports()
                .dev()
                .with_rpc(
                    RpcServerArgs::default()
                        .with_unused_ports()
                        .with_http()
                        .with_http_api(RpcModuleSelection::All),
                );

            let node_handle = NodeBuilder::new(node_config.clone())
                .testing_node(tasks.executor())
                .node(TempoNode::default())
                .launch_with_debug_capabilities()
                .await?;

            let http_url = node_handle
                .node
                .rpc_server_handle()
                .http_url()
                .unwrap()
                .parse()
                .unwrap();

            Ok((http_url, Some((Box::new(node_handle), tasks))))
        }
    }
}
