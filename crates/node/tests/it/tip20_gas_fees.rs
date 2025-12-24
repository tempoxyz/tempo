use alloy::{
    network::ReceiptResponse,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    sol_types::SolEvent,
};
use alloy_network::TransactionBuilder;
use alloy_primitives::Bytes;
use alloy_rpc_types_eth::TransactionRequest;
use std::env;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_contracts::precompiles::{IFeeManager, ITIP20};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tempo_primitives::transaction::calc_gas_balance_spending;

use crate::utils::TestNodeBuilder;

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_in_stable() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Ensure the native account balance is 0
    let balance = provider.get_account_info(caller).await?.balance;
    assert_eq!(balance, U256::ZERO);

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_token_address = fee_manager.userTokens(caller).call().await?;

    // Get the balance of the fee token before the tx
    let fee_token = ITIP20::new(fee_token_address, provider.clone());
    let initial_balance = fee_token.balanceOf(caller).call().await?;

    let tx = TransactionRequest::default().from(caller).to(caller);

    let pending_tx = provider.send_transaction(tx).await?;
    let tx_hash = pending_tx.watch().await?;
    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;

    // Assert that the fee token balance has decreased by gas spent
    let balance_after = fee_token.balanceOf(caller).call().await?;

    let cost = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price());
    assert_eq!(balance_after, initial_balance - U256::from(cost));

    assert!(receipt.status());
    assert_eq!(receipt.logs().len(), 1);
    let transfer = ITIP20::Transfer::decode_log(&receipt.logs()[0].inner)?;
    assert_eq!(transfer.from, caller);
    assert_eq!(transfer.to, TIP_FEE_MANAGER_ADDRESS);
    assert_eq!(transfer.amount, U256::from(cost));
    assert_eq!(receipt.fee_token, Some(fee_token_address));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_default_fee_token() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    // Create new random wallet
    let new_wallet = PrivateKeySigner::random();
    let new_address = new_wallet.address();

    // Transfer pathUSD to the new wallet
    let path_usd = ITIP20::new(PATH_USD_ADDRESS, provider.clone());
    let transfer_amount = U256::from(1_000_000u64);
    path_usd
        .transfer(new_address, transfer_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Create provider with the new wallet
    let new_provider = ProviderBuilder::new()
        .wallet(new_wallet)
        .connect_http(http_url);

    // Ensure the native account balance is 0
    let balance = new_provider.get_account_info(new_address).await?.balance;
    assert_eq!(balance, U256::ZERO);

    // Ensure the fee token is not set for the user
    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_token_address = fee_manager.userTokens(new_address).call().await?;
    assert_eq!(fee_token_address, Address::ZERO);

    // Get the balance of the fee token before the tx
    let initial_balance = path_usd.balanceOf(new_address).call().await?;

    let tx = TransactionRequest::default().from(new_address).to(caller);
    let pending_tx = new_provider.send_transaction(tx).await?;
    let tx_hash = pending_tx.watch().await?;
    let receipt = new_provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;

    // Assert that the fee token balance has decreased by gas spent
    let balance_after = path_usd.balanceOf(new_address).call().await?;
    let cost = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price());
    assert_eq!(balance_after, initial_balance - U256::from(cost));

    assert!(receipt.status());
    assert_eq!(receipt.logs().len(), 1);
    let transfer = ITIP20::Transfer::decode_log(&receipt.logs()[0].inner)?;
    assert_eq!(transfer.from, new_address);
    assert_eq!(transfer.to, TIP_FEE_MANAGER_ADDRESS);
    assert_eq!(transfer.amount, U256::from(cost));
    assert_eq!(receipt.fee_token, Some(PATH_USD_ADDRESS));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_transfer_logs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Ensure the native account balance is 0
    let balance = provider.get_account_info(caller).await?.balance;
    assert_eq!(balance, U256::ZERO);

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_token_address = fee_manager.userTokens(caller).call().await?;

    // Get the balance of the fee token before the tx
    let fee_token = ITIP20::new(fee_token_address, provider.clone());
    let initial_balance = fee_token.balanceOf(caller).call().await?;

    let tx = TransactionRequest::default()
        .into_create()
        .input(Bytes::from_static(&[0xef]).into())
        .gas_limit(100000);
    let pending_tx = provider.send_transaction(tx).await?;
    let tx_hash = pending_tx.watch().await?;
    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;

    // Assert that the fee token balance has decreased by gas spent
    let balance_after = fee_token.balanceOf(caller).call().await?;

    let cost = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price());
    assert_eq!(balance_after, initial_balance - U256::from(cost));

    assert!(!receipt.status());
    assert_eq!(receipt.logs().len(), 1);
    let transfer = ITIP20::Transfer::decode_log(&receipt.logs()[0].inner)?;
    assert_eq!(transfer.from, caller);
    assert_eq!(transfer.to, TIP_FEE_MANAGER_ADDRESS);
    assert_eq!(transfer.amount, U256::from(cost));
    assert_eq!(receipt.fee_token, Some(fee_token_address));

    Ok(())
}
