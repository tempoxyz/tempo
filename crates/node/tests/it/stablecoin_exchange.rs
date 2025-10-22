use alloy::{primitives::U256, providers::ProviderBuilder, signers::local::MnemonicBuilder};
use rand::Rng;
use std::env;
use tempo_contracts::precompiles::{
    IStablecoinExchange,
    ITIP20::{self, ITIP20Instance},
};
use tempo_precompiles::{
    STABLECOIN_EXCHANGE_ADDRESS,
    stablecoin_exchange::{MAX_TICK, MIN_TICK},
    tip20::token_id_to_address,
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

    let account_data: Vec<_> = (1..=10)
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

    let mut pending = vec![];
    pending.push(
        base.approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    // Mint tokens to each account
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

    let num_orders = account_data.len() as u128;
    // Place bid orders for each account
    let mut pending_orders = vec![];
    let tick = 1;
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, account_provider);

        let call = exchange.place(*base.address(), order_amount, true, tick);

        let order_tx = call.send().await?;
        pending_orders.push(order_tx);
    }
    await_receipts(&mut pending_orders).await?;

    for order_id in 1..=num_orders {
        let order = exchange.getOrder(order_id).call().await?;
        assert!(!order.maker.is_zero());
        assert!(order.isBid);
        assert_eq!(order.tick, tick);
        assert_eq!(order.amount, order_amount);
        assert_eq!(order.remaining, order_amount);
    }

    // Calculate fill amount to fill all `n-1` orders, partial fill last order
    let fill_amount = (num_orders * order_amount) - (order_amount / 2);

    let amount_in = exchange
        .quoteSwapExactAmountIn(*base.address(), *quote.address(), fill_amount)
        .call()
        .await?;

    // Mint base tokens to the seller for amount in
    let pending = base.mint(caller, U256::from(amount_in)).send().await?;
    pending.get_receipt().await?;

    //  Execute swap and assert orders are filled
    let tx = exchange
        .swapExactAmountIn(*base.address(), *quote.address(), amount_in, 0)
        .send()
        .await?;
    tx.get_receipt().await?;

    for order_id in 1..num_orders {
        let err = exchange
            .getOrder(order_id)
            .call()
            .await
            .expect_err("Expected error");

        // Assert order does not exist
        assert!(err.to_string().contains("0x5dcaf2d7"));
    }

    // Assert the last order is partially filled
    let level = exchange
        .getPriceLevel(*base.address(), tick, true)
        .call()
        .await?;

    assert_eq!(level.head, num_orders);
    assert_eq!(level.tail, num_orders);
    assert!(level.totalLiquidity < order_amount);

    let order = exchange.getOrder(num_orders).call().await?;
    assert_eq!(order.next, 0);
    assert_eq!(level.totalLiquidity, order.remaining);

    // Assert exchange balance for makers
    for (account, _) in account_data.iter().take(account_data.len() - 1) {
        let balance = exchange.balanceOf(*account, *base.address()).call().await?;
        assert_eq!(balance, order_amount);
    }

    let (last_account, _) = account_data.last().unwrap();
    let balance = exchange
        .balanceOf(*last_account, *base.address())
        .call()
        .await?;
    assert_eq!(balance, order_amount - order.remaining);

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

    let account_data: Vec<_> = (1..=3)
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

    let mut pending = vec![];

    // Mint tokens to each account
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
        let base = ITIP20::new(*base.address(), account_provider);
        pending.push(
            base.approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
                .send()
                .await?,
        );
    }
    await_receipts(&mut pending).await?;

    let num_orders = account_data.len() as u128;
    // Place ask orders for each account
    let mut pending_orders = vec![];
    let tick = 1;
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, account_provider);

        let call = exchange.place(*base.address(), order_amount, false, tick);

        let order_tx = call.send().await?;
        pending_orders.push(order_tx);
    }
    await_receipts(&mut pending_orders).await?;

    for order_id in 1..=num_orders {
        let order = exchange.getOrder(order_id).call().await?;
        assert!(!order.maker.is_zero());
        assert!(!order.isBid);
        assert_eq!(order.tick, tick);
        assert_eq!(order.amount, order_amount);
        assert_eq!(order.remaining, order_amount);
    }

    // Calculate fill amount to fill all `n-1` orders, partial fill last order
    let fill_amount = (num_orders * order_amount) - (order_amount / 2);

    let amount_in = exchange
        .quoteSwapExactAmountOut(*quote.address(), *base.address(), fill_amount)
        .call()
        .await?;

    // Mint quote tokens to the buyer for amount in
    let pending = quote.mint(caller, U256::from(amount_in)).send().await?;
    pending.get_receipt().await?;

    // Approve quote tokens for the buy operation
    let pending = quote
        .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
        .send()
        .await?;
    pending.get_receipt().await?;

    //  Execute swap and assert orders are filled
    let tx = exchange
        .swapExactAmountOut(*quote.address(), *base.address(), fill_amount, u128::MAX)
        .send()
        .await?;
    tx.get_receipt().await?;

    for order_id in 1..num_orders {
        let err = exchange
            .getOrder(order_id)
            .call()
            .await
            .expect_err("Expected error");

        // Assert order does not exist
        assert!(err.to_string().contains("0x5dcaf2d7"));
    }

    // Assert the last order is partially filled
    let level = exchange
        .getPriceLevel(*base.address(), tick, false)
        .call()
        .await?;

    assert_eq!(level.head, num_orders);
    assert_eq!(level.tail, num_orders);
    assert!(level.totalLiquidity < order_amount);

    let order = exchange.getOrder(num_orders).call().await?;
    assert_eq!(order.next, 0);
    assert_eq!(level.totalLiquidity, order.remaining);

    // Assert exchange balance for makers
    // For ask orders, makers receive quote tokens based on price
    let price = (100000 + tick as i32) as u128; // tick_to_price formula: PRICE_SCALE + tick
    let expected_quote_per_order = (order_amount * price) / 100000;

    for (account, _) in account_data.iter().take(account_data.len() - 1) {
        let balance = exchange
            .balanceOf(*account, *quote.address())
            .call()
            .await?;
        assert_eq!(balance, expected_quote_per_order);
    }

    let (last_account, _) = account_data.last().unwrap();
    let balance = exchange
        .balanceOf(*last_account, *quote.address())
        .call()
        .await?;
    let filled_amount = order_amount - order.remaining;
    let expected_last_quote = (filled_amount * price) / 100000;
    assert_eq!(balance, expected_last_quote);

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

    let account_data: Vec<_> = (1..=30)
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

        let order = exchange.getOrder(order_id).call().await?;
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
        let err = exchange
            .getOrder(order_id)
            .call()
            .await
            .expect_err("Expected error");

        // Assert order does not exist
        assert!(err.to_string().contains("0x5dcaf2d7"));
    }

    Ok(())
}
