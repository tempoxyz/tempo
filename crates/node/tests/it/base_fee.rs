use alloy::{
    network::ReceiptResponse,
    primitives::{BlockNumber, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use alloy_eips::BlockNumberOrTag;
use alloy_rpc_types_eth::TransactionRequest;
use reth_chainspec::{BaseFeeParams, BaseFeeParamsKind, ChainSpec};
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::node::TempoNode;

#[tokio::test(flavor = "multi_thread")]
async fn test_base_fee() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();

    let spec = ChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);
    let chain_spec = TempoChainSpec { inner: spec };
    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url = node
        .rpc_server_handle()
        .http_url()
        .unwrap()
        .parse()
        .unwrap();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Get initial block to check base fee
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .expect("Could not get latest block");

    let base_fee = block
        .header
        .base_fee_per_gas
        .expect("Could not get basefee");
    assert_eq!(base_fee, 0);

    // TODO: submit tx to exceed gas_target

    // TODO: ensure base fees stays 0

    // TODO: check fee history and ensure fee stays at 0

    Ok(())
}
