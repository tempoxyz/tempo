use alloy::{
    network::ReceiptResponse,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use alloy_rpc_types_eth::TransactionRequest;
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::node::{TEMPO_BASE_FEE, TempoNode};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{IFeeManager, ITIP20},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_in_stable() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();

    let chain_spec = TempoChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);
    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_unused_ports()
        .dev()
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

    // Ensure the native account balance is 0
    assert_eq!(provider.get_balance(caller).await?, U256::ZERO);

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_token_address = fee_manager.userTokens(caller).call().await?;

    // Get the balance of the fee token before the tx
    let fee_token = ITIP20::new(fee_token_address, provider.clone());
    let initial_balance = fee_token.balanceOf(caller).call().await?;

    let tx = TransactionRequest::default()
        .from(caller)
        .to(caller)
        .gas_price(TEMPO_BASE_FEE as u128);

    let pending_tx = provider.send_transaction(tx).await?;
    let receipt = pending_tx.get_receipt().await?;

    // Assert that the fee token balance has decreased by gas spent
    let balance_after = fee_token.balanceOf(caller).call().await?;

    let cost = receipt.effective_gas_price() * receipt.gas_used as u128;
    assert_eq!(balance_after, initial_balance - U256::from(cost));

    Ok(())
}
