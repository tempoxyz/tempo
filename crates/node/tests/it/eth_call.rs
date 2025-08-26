use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol_types::SolCall,
    transports::http::reqwest::Url,
};
use alloy_rpc_types_eth::TransactionInput;
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::node::TempoNode;
use tempo_precompiles::contracts::ITIP20::transferCall;

use crate::utils::setup_test_token;

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();
    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let mut node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
        .with_rpc(RpcServerArgs::default().with_unused_ports().with_http());
    node_config.txpool.minimal_protocol_basefee = 0;

    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(executor.clone())
        .node(TempoNode::default())
        .launch_with_debug_capabilities()
        .await?;

    let http_url: Url = node
        .rpc_server_handle()
        .http_url()
        .unwrap()
        .parse()
        .unwrap();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    // Setup test token
    let token = setup_test_token(provider.clone(), caller).await?;

    // First, mint some tokens to the caller for testing
    let mint_amount = U256::random();
    token
        .mint(caller, mint_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    let recipient = Address::random();
    let calldata = token.transfer(recipient, mint_amount).calldata().clone();
    let tx = TransactionRequest::default()
        .to(*token.address())
        .gas_price(0)
        .input(TransactionInput::new(calldata));

    let res = provider.call(tx).await?;
    let success = transferCall::abi_decode_returns(&res)?;
    assert!(success);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_trace_call() -> eyre::Result<()> {
    todo!()
}
