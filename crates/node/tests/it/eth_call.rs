use crate::utils::{NodeSource, setup_test_node, setup_test_token};
use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder, ext::TraceApi},
    rpc::types::{
        Filter, TransactionRequest,
        trace::parity::{ChangedType, Delta},
    },
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol_types::{SolCall, SolEvent},
};
use alloy_rpc_types_eth::TransactionInput;
use reth_evm::revm::interpreter::instructions::utility::IntoU256;
use std::env;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::contracts::{
    ITIP20::{self, transferCall},
    storage::slots::mapping_slot,
    tip20,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_call() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _node_handle) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test token
    let token = setup_test_token(provider.clone(), caller).await?;

    // First, mint some tokens to the caller for testing
    let mint_amount = U256::random();
    token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(30000)
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

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _node_handle) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test token
    let token = setup_test_token(provider.clone(), caller).await?;

    // First, mint some tokens to the caller for testing
    let mint_amount = U256::random();
    token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(30000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let recipient = Address::random();
    let calldata = token.transfer(recipient, mint_amount).calldata().clone();
    let tx = TransactionRequest::default()
        .from(caller)
        .to(*token.address())
        .input(TransactionInput::new(calldata));

    let res = provider.call(tx.clone()).await?;
    let success = transferCall::abi_decode_returns(&res)?;
    assert!(success);

    let trace_res = provider.trace_call(&tx).state_diff().await?;

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

    let Delta::Changed(ChangedType { from, to }) = sender_balance else {
        panic!("Unexpected delta");
    };
    assert_eq!(from.into_u256(), mint_amount);
    assert_eq!(to.into_u256(), U256::ZERO);

    // Assert recipient token balance is changed
    let slot = mapping_slot(recipient, tip20::slots::BALANCES);
    let recipient_balance = token_storage_diff
        .get(&B256::from(slot))
        .expect("Could not get recipient balance delta");
    assert!(recipient_balance.is_changed());

    let Delta::Changed(ChangedType { from, to }) = recipient_balance else {
        panic!("Unexpected delta");
    };
    assert_eq!(from.into_u256(), U256::ZERO);
    assert_eq!(to.into_u256(), mint_amount);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_get_logs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _node_handle) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Setup test token
    let token = setup_test_token(provider.clone(), caller).await?;

    let mint_amount = U256::random();
    let mint_receipt = token
        .mint(caller, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(30000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let recipient = Address::random();
    token
        .transfer(recipient, mint_amount)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas(30000)
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

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_estimate_gas() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _node_handle) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let token = setup_test_token(provider.clone(), caller).await?;
    let calldata = token.mint(caller, U256::from(1000)).calldata().clone();
    let tx = TransactionRequest::default()
        .to(*token.address())
        .input(calldata.into());

    let gas = provider.estimate_gas(tx.clone()).await?;
    // gas estimation is calldata dependent, but should be consistent with same calldata
    assert_eq!(gas, 22919);

    // ensure we can successfully send the tx with that gas
    let receipt = provider
        .send_transaction(tx.gas_limit(gas))
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.gas_used <= gas);

    Ok(())
}
