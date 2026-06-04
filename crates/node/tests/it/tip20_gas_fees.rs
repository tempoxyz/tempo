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
use tempo_chainspec::constants::gas::{TEMPO_T1_BASE_FEE, TEMPO_T6_DISCOUNTED_PAYMENT_GAS_PRICE};
use tempo_contracts::precompiles::{IFeeManager, ITIP20};
use tempo_evm::SSTORE_SET_COST;
use tempo_precompiles::{PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tempo_primitives::transaction::calc_gas_balance_spending;

use crate::utils::{TestNodeBuilder, setup_test_token};

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
        .gas_limit(1_000_000);
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

#[tokio::test(flavor = "multi_thread")]
async fn test_tip1059_discounted_payment_receipts_and_fees() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_token_address = fee_manager.userTokens(caller).call().await?;
    let fee_token = ITIP20::new(fee_token_address, provider.clone());
    let token = setup_test_token(provider.clone(), caller).await?;
    let recipient = PrivateKeySigner::random().address();

    token
        .mint(caller, U256::from(1_000_000u64))
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    token
        .mint(recipient, U256::ONE)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let fee_balance_before = fee_token.balanceOf(caller).call().await?;
    let tx_hash = token
        .transfer(recipient, U256::from(1))
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(250_000)
        .send()
        .await?
        .watch()
        .await?;
    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;
    assert!(receipt.status());
    assert!(
        receipt.gas_used <= SSTORE_SET_COST,
        "existing-balance transfer must stay within TIP-1059 gas cap"
    );
    assert_eq!(
        receipt.effective_gas_price(),
        u128::from(TEMPO_T6_DISCOUNTED_PAYMENT_GAS_PRICE)
    );
    assert_eq!(
        fee_balance_before - fee_token.balanceOf(caller).call().await?,
        calc_gas_balance_spending(
            receipt.gas_used,
            u128::from(TEMPO_T6_DISCOUNTED_PAYMENT_GAS_PRICE)
        )
    );

    const PRIORITY_FEE: u128 = 3_000_000_000;
    let discounted_price_with_priority =
        u128::from(TEMPO_T6_DISCOUNTED_PAYMENT_GAS_PRICE) + PRIORITY_FEE;
    let fee_balance_before = fee_token.balanceOf(caller).call().await?;
    let tx_hash = token
        .transfer(recipient, U256::from(1))
        .max_fee_per_gas(TEMPO_T1_BASE_FEE as u128 + PRIORITY_FEE)
        .max_priority_fee_per_gas(PRIORITY_FEE)
        .gas(250_000)
        .send()
        .await?
        .watch()
        .await?;
    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;
    assert!(receipt.status());
    assert!(
        receipt.gas_used <= SSTORE_SET_COST,
        "existing-balance transfer with priority fee must stay within TIP-1059 gas cap"
    );
    assert_eq!(
        receipt.effective_gas_price(),
        discounted_price_with_priority
    );
    assert_eq!(
        fee_balance_before - fee_token.balanceOf(caller).call().await?,
        calc_gas_balance_spending(receipt.gas_used, discounted_price_with_priority)
    );

    let fee_balance_before = fee_token.balanceOf(caller).call().await?;
    let tx_hash = token
        .transfer(Address::random(), U256::from(1))
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .watch()
        .await?;
    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;
    assert!(receipt.status());
    assert!(
        receipt.gas_used > SSTORE_SET_COST,
        "new-recipient transfer must exceed TIP-1059 gas cap"
    );
    assert_eq!(receipt.effective_gas_price(), TEMPO_T1_BASE_FEE as u128);
    assert_eq!(
        fee_balance_before - fee_token.balanceOf(caller).call().await?,
        calc_gas_balance_spending(receipt.gas_used, TEMPO_T1_BASE_FEE as u128)
    );

    let fee_balance_before = fee_token.balanceOf(caller).call().await?;
    let tx_hash = token
        .mint(caller, U256::ONE)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .watch()
        .await?;
    let receipt = provider
        .raw_request::<_, TempoTransactionReceipt>("eth_getTransactionReceipt".into(), (tx_hash,))
        .await?;
    assert!(receipt.status());
    assert_eq!(receipt.effective_gas_price(), TEMPO_T1_BASE_FEE as u128);
    assert_eq!(
        fee_balance_before - fee_token.balanceOf(caller).call().await?,
        calc_gas_balance_spending(receipt.gas_used, TEMPO_T1_BASE_FEE as u128)
    );

    Ok(())
}
