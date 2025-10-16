use alloy::{
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::local::MnemonicBuilder,
};
use rand::Rng;
use std::{env, time::Duration};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::precompiles::ITIP20::ITIP20Instance;
use tempo_precompiles::{
    LINKING_USD_ADDRESS, STABLECOIN_EXCHANGE_ADDRESS,
    contracts::{
        address_to_token_id_unchecked,
        stablecoin_exchange::{MAX_TICK, MIN_TICK},
        token_id_to_address,
        types::{IStablecoinExchange, ITIP20},
    },
};

use crate::utils::{await_receipts, setup_test_token};

#[tokio::test(flavor = "multi_thread")]
async fn test_bids() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup node
    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let base = setup_test_token(provider.clone(), caller).await?;
    let quote = ITIP20Instance::new(token_id_to_address(0), provider.clone());

    let account_data: Vec<_> = (1..100)
        .map(|i| {
            let signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
                .index(i as u32)
                .unwrap()
                .build()
                .unwrap();
            let account = signer.address();
            (account, signer)
        })
        .collect();

    let mint_amount = U256::from(1000000000000u128);

    // Mint tokens to each account
    let mut pending = vec![];
    for (account, _) in &account_data {
        pending.push(quote.mint(*account, mint_amount).send().await?);
    }
    await_receipts(&mut pending).await?;

    // Create pair
    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());
    let tx = exchange.createPair(*base.address()).send().await?;
    tx.get_receipt().await?;

    let order_amount = 1000000000;

    // Approve tokens for exchange for each account
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let quote = ITIP20::new(*quote.address(), account_provider);
        pending.push(
            quote
                .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
                .send()
                .await?,
        );
    }
    await_receipts(&mut pending).await?;

    let mut order_ids = vec![];
    // Place bid orders for each account
    let mut pending_orders = vec![];
    let tick = 1;
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, account_provider);

        let call = exchange.place(*base.address(), order_amount, true, tick);
        order_ids.push(call.call().await?);

        let order_tx = call.send().await?;
        pending_orders.push(order_tx);
    }
    await_receipts(&mut pending_orders).await?;

    for (order_id, (account, _)) in order_ids.iter().zip(account_data) {
        let order = exchange.orders(*order_id).call().await?;
        assert_eq!(order.maker, account);
        assert!(order.isBid);
        assert_eq!(order.tick, tick);
        assert_eq!(order.amount, order_amount);
        assert_eq!(order.remaining, order_amount);
    }

    // // TODO: send tx to fill all orders but the last
    // // TODO: calc amount in
    // let amount_in = 1000;
    // let tx = exchange
    //     .sell(*base.address(), *quote.address(), amountIn, 0)
    //     .send()
    //     .await?;
    // tx.get_receipt().await?;
    //
    // for order_id in order_ids {
    //     // TODO: get each order and assert filled
    // }
    //
    // // TODO: assert last order paritially filled

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_asks() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup node
    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let base = setup_test_token(provider.clone(), caller).await?;
    let quote = ITIP20Instance::new(token_id_to_address(0), provider.clone());

    let account_data: Vec<_> = (1..100)
        .map(|i| {
            let signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
                .index(i as u32)
                .unwrap()
                .build()
                .unwrap();
            let account = signer.address();
            (account, signer)
        })
        .collect();

    let mint_amount = U256::from(1000000000000u128);

    // Mint tokens to each account
    let mut pending = vec![];
    for (account, _) in &account_data {
        pending.push(base.mint(*account, mint_amount).send().await?);
    }
    await_receipts(&mut pending).await?;

    // Create pair
    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());
    let tx = exchange.createPair(*base.address()).send().await?;
    tx.get_receipt().await?;

    let order_amount = 1000000000;

    // Approve tokens for exchange for each account
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let base = ITIP20::new(*quote.address(), account_provider);
        pending.push(
            base.approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
                .send()
                .await?,
        );
    }
    await_receipts(&mut pending).await?;

    let mut order_ids = vec![];
    let tick = 1;
    // Place ask orders for each account
    let mut pending_orders = vec![];
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, account_provider);

        let call = exchange.place(*base.address(), order_amount, false, tick);
        order_ids.push(call.call().await?);

        let order_tx = call.send().await?;
        pending_orders.push(order_tx);
    }
    await_receipts(&mut pending_orders).await?;

    for (order_id, (account, _)) in order_ids.iter().zip(account_data) {
        let order = exchange.orders(*order_id).call().await?;
        assert_eq!(order.maker, account);
        assert!(!order.isBid);
        assert_eq!(order.tick, tick);
        assert_eq!(order.amount, order_amount);
        assert_eq!(order.remaining, order_amount);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cancel_orders() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup node
    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let base = setup_test_token(provider.clone(), caller).await?;
    let quote = ITIP20Instance::new(token_id_to_address(0), provider.clone());

    let account_data: Vec<_> = (1..30)
        .map(|i| {
            let signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
                .index(i as u32)
                .unwrap()
                .build()
                .unwrap();
            let account = signer.address();
            (account, signer)
        })
        .collect();

    let mint_amount = U256::from(1000000000000u128);

    // Mint tokens to each account
    let mut pending = vec![];
    for (account, _) in &account_data {
        pending.push(quote.mint(*account, mint_amount).send().await?);
    }
    await_receipts(&mut pending).await?;

    // Create pair
    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());
    let tx = exchange.createPair(*base.address()).send().await?;
    tx.get_receipt().await?;

    let order_amount = 1000000000;

    // Approve tokens for exchange for each account
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let quote = ITIP20::new(*quote.address(), account_provider);
        pending.push(
            quote
                .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
                .send()
                .await?,
        );
    }
    await_receipts(&mut pending).await?;

    let mut order_ids = vec![];
    let mut rng = rand::rng();

    // Place bid orders for each account
    let mut pending = vec![];
    for (account, signer) in &account_data {
        let tick = rng.random_range(MIN_TICK..=MAX_TICK);
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, account_provider);

        let call = exchange.place(*base.address(), order_amount, true, tick);
        let order_id = call.call().await?;
        order_ids.push(call.call().await?);

        let order_tx = call.send().await?;
        order_tx.get_receipt().await?;

        let order = exchange.orders(order_id).call().await?;
        assert_eq!(order.maker, *account);
        assert!(order.isBid);
        assert_eq!(order.tick, tick);
        assert_eq!(order.amount, order_amount);
        assert_eq!(order.remaining, order_amount);

        pending.push(exchange.cancel(order_id).send().await?);
    }
    await_receipts(&mut pending).await?;

    // Assert that orders have been canceled
    for order_id in order_ids {
        let order = exchange.orders(order_id).call().await?;
        assert!(order.maker.is_zero());
    }

    Ok(())
}
