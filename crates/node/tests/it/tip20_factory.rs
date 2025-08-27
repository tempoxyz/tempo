use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol_types::SolEvent,
    transports::http::reqwest::Url,
};
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::node::{TEMPO_BASE_FEE, TempoNode};
use tempo_precompiles::{
    TIP20_FACTORY_ADDRESS,
    contracts::{ITIP20, ITIP20Factory, token_id_to_address},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_create_token() -> eyre::Result<()> {
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

    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());

    let initial_token_id = factory.tokenIdCounter().call().await?;
    let name = "Test".to_string();
    let symbol = "TEST".to_string();
    let currency = "USD".to_string();

    // Ensure the native account balance is 0
    assert_eq!(provider.get_balance(caller).await?, U256::ZERO);
    let receipt = factory
        .createToken(
            "Test".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            caller,
        )
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let event = ITIP20Factory::TokenCreated::decode_log(&receipt.logs()[0].inner).unwrap();
    assert_eq!(event.tokenId, initial_token_id);
    assert_eq!(event.address, TIP20_FACTORY_ADDRESS);
    assert_eq!(event.name, "Test");
    assert_eq!(event.symbol, "TEST");
    assert_eq!(event.currency, "USD");
    assert_eq!(event.admin, caller);

    let token_id = factory.tokenIdCounter().call().await?;
    assert_eq!(token_id, initial_token_id + U256::ONE);

    let token_addr = token_id_to_address(event.tokenId.to());
    let token = ITIP20::new(token_addr, provider);
    assert_eq!(token.name().call().await?, name);
    assert_eq!(token.symbol().call().await?, symbol);
    assert_eq!(token.decimals().call().await?, 6);
    assert_eq!(token.currency().call().await?, currency);
    assert_eq!(token.supplyCap().call().await?, U256::MAX);
    assert_eq!(token.transferPolicyId().call().await?, 1);

    Ok(())
}
