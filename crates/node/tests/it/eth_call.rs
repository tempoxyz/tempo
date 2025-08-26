use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder, ext::TraceApi},
    rpc::types::{Filter, TransactionRequest},
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol_types::{SolCall, SolEvent},
    transports::http::reqwest::Url,
};
use alloy_rpc_types_eth::TransactionInput;
use reth_ethereum::tasks::TaskManager;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_node::node::{TEMPO_BASE_FEE, TempoNode};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        IFeeManager,
        ITIP20::{self, transferCall},
        storage::slots::mapping_slot,
        tip20,
    },
};

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

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_token = fee_manager.userTokens(caller).call().await?;

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

    let trace_res = provider.trace_call(&tx).await?;

    let success = transferCall::abi_decode_returns(&trace_res.output)?;
    assert!(success);

    let state_diff = trace_res.state_diff.expect("Could not get state diff");
    let caller_diff = state_diff.get(&caller).expect("Could not get caller diff");
    assert!(caller_diff.nonce.is_changed());
    assert!(caller_diff.balance.is_unchanged());
    assert!(caller_diff.code.is_unchanged());
    assert!(caller_diff.storage.is_empty());

    let token_diff = state_diff
        .get(token.address())
        .expect("Could not get token diff");

    assert!(token_diff.balance.is_unchanged());
    assert!(token_diff.code.is_unchanged());
    assert!(token_diff.nonce.is_unchanged());

    let token_storage_diff = token_diff.storage.clone();
    // Assert sender token balance has changed
    let slot = mapping_slot(caller, tip20::slots::BALANCES);
    let sender_balance = token_storage_diff
        .get(&B256::from(slot))
        .expect("Could not get recipient balance delta");
    assert!(sender_balance.is_changed());

    // Assert recipient token balance is changed
    let slot = mapping_slot(recipient, tip20::slots::BALANCES);
    let recipient_balance = token_storage_diff
        .get(&B256::from(slot))
        .expect("Could not get recipient balance delta");
    assert!(recipient_balance.is_changed());

    let fee_token_diff = state_diff
        .get(&fee_token)
        .expect("Could not get fee token diff");
    assert!(fee_token_diff.balance.is_unchanged());
    assert!(fee_token_diff.code.is_unchanged());
    assert!(fee_token_diff.nonce.is_unchanged());

    let fee_token_storage_diff = token_diff.storage.clone();
    // Assert sender fee token balance is changed
    let slot = mapping_slot(caller, tip20::slots::BALANCES);
    let sender_balance = fee_token_storage_diff
        .get(&B256::from(slot))
        .expect("Could not get recipient balance delta");
    assert!(sender_balance.is_changed());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_get_logs() -> eyre::Result<()> {
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

    let mint_amount = U256::random();
    let mint_receipt = token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let recipient = Address::random();
    token
        .transfer(recipient, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;

    let filter = Filter::new()
        .address(*token.address())
        .from_block(mint_receipt.block_number.unwrap());
    let logs = provider.get_logs(&filter).await?;
    assert_eq!(logs.len(), 3);

    // NOTE: this currently reflects the event emission from the reference contract. Double check
    // this is the expected behavior
    let transfer_event = ITIP20::Transfer::decode_log(&logs[0].inner)?;
    assert_eq!(transfer_event.from, Address::ZERO);
    assert_eq!(transfer_event.to, caller);
    assert_eq!(transfer_event.amount, mint_amount);

    let mint_event = ITIP20::Mint::decode_log(&logs[1].inner)?;
    assert_eq!(mint_event.to, caller);
    assert_eq!(mint_event.amount, mint_amount);

    let transfer_event = ITIP20::Transfer::decode_log(&logs[2].inner)?;
    assert_eq!(transfer_event.from, caller);
    assert_eq!(transfer_event.to, recipient);
    assert_eq!(transfer_event.amount, mint_amount);

    Ok(())
}
