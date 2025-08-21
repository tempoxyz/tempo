use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use reth_chainspec::ChainSpec;
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use std::sync::Arc;
use tempo_node::node::TempoNode;
use tempo_precompiles::{
    TIP20_FACTORY_ADDRESS,
    contracts::{ITIP20, ITIP20Factory, token_id_to_address},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_create_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let tasks = TaskManager::current();
    let executor = tasks.executor();

    let chain_spec = ChainSpec::from_genesis(serde_json::from_str(include_str!(
        "../assets/test-genesis.json"
    ))?);

    let node_config = NodeConfig::test()
        .with_chain(Arc::new(chain_spec))
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

    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    factory
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

    let token_id = factory.tokenIdCounter().call().await?;
    let token_addr = token_id_to_address(token_id.to::<u64>());
    let token = ITIP20::new(token_addr, provider.clone());

    let caller_initial_balance = token.balanceOf(caller).call().await?;
    let recipient = Address::random();
    let recipient_initial_balance = token.balanceOf(recipient).call().await?;
    let transfer_amount = U256::random();

    assert_eq!(provider.get_balance(caller).await?, U256::ZERO);
    token
        .transfer(recipient, transfer_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    let caller_balance_after = token.balanceOf(caller).call().await?;
    let recipient_balance_after = token.balanceOf(recipient).call().await?;

    assert_eq!(
        caller_balance_after,
        caller_initial_balance - transfer_amount
    );
    assert_eq!(
        recipient_balance_after,
        recipient_initial_balance + transfer_amount
    );

    Ok(())
}
