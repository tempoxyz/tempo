use alloy::{
    primitives::U256, providers::ProviderBuilder, signers::local::MnemonicBuilder,
    sol_types::SolError,
};
use rand::Rng;
use std::env;
use tempo_contracts::precompiles::{
    IStablecoinExchange,
    ITIP20::{self, ITIP20Instance},
};
use tempo_precompiles::{
    STABLECOIN_EXCHANGE_ADDRESS,
    stablecoin_exchange::{MAX_TICK, MIN_TICK, calculate_min_order_amount},
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

#[tokio::test(flavor = "multi_thread")]
async fn test_multi_hop_swap() -> eyre::Result<()> {
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

    // Setup tokens: LinkingUSD (token_id=0) <- USDC (token_id=2) and LinkingUSD <- EURC (token_id=3)
    let linking_usd = ITIP20Instance::new(token_id_to_address(0), provider.clone());
    let usdc = setup_test_token(provider.clone(), caller).await?; // This will be token_id=2
    let eurc = setup_test_token(provider.clone(), caller).await?; // This will be token_id=3

    // Setup liquidity provider (Alice) and trader (Bob)
    let alice_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)
        .unwrap()
        .build()
        .unwrap();
    let alice = alice_signer.address();

    let bob_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(2)
        .unwrap()
        .build()
        .unwrap();
    let bob = bob_signer.address();

    let mint_amount = U256::from(10_000_000_000u128);
    let mut pending = vec![];

    // Mint tokens to Alice (liquidity provider)
    pending.push(usdc.mint(alice, mint_amount).send().await?);
    pending.push(eurc.mint(alice, mint_amount).send().await?);
    pending.push(linking_usd.mint(alice, mint_amount).send().await?);

    // Mint USDC to Bob (trader)
    pending.push(usdc.mint(bob, mint_amount).send().await?);

    await_receipts(&mut pending).await?;

    // Create pairs on the exchange
    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());
    let tx = exchange.createPair(*usdc.address()).send().await?;
    tx.get_receipt().await?;
    let tx = exchange.createPair(*eurc.address()).send().await?;
    tx.get_receipt().await?;

    // Alice approves exchange to spend her tokens
    let alice_provider = ProviderBuilder::new()
        .wallet(alice_signer.clone())
        .connect_http(http_url.clone());
    let alice_usdc = ITIP20::new(*usdc.address(), alice_provider.clone());
    let alice_eurc = ITIP20::new(*eurc.address(), alice_provider.clone());
    let alice_linking_usd = ITIP20::new(*linking_usd.address(), alice_provider.clone());

    let mut pending = vec![];
    pending.push(
        alice_usdc
            .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        alice_eurc
            .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        alice_linking_usd
            .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    // Alice places liquidity orders at tick 0 (1:1 price)
    let alice_exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, alice_provider);
    let liquidity_amount = 5_000_000_000u128;

    // For USDC -> LinkingUSD: need bid on USDC (buying USDC with LinkingUSD)
    let tx = alice_exchange
        .place(*usdc.address(), liquidity_amount, true, 0)
        .send()
        .await?;
    tx.get_receipt().await?;

    // For LinkingUSD -> EURC: need ask on EURC (selling EURC for LinkingUSD)
    let tx = alice_exchange
        .place(*eurc.address(), liquidity_amount, false, 0)
        .send()
        .await?;
    tx.get_receipt().await?;

    // Bob approves exchange to spend his USDC
    let bob_provider = ProviderBuilder::new()
        .wallet(bob_signer)
        .connect_http(http_url.clone());
    let bob_usdc = ITIP20::new(*usdc.address(), bob_provider.clone());
    let tx = bob_usdc
        .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
        .send()
        .await?;
    tx.get_receipt().await?;

    // Check Bob's balances before swap
    let bob_exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, bob_provider.clone());
    let bob_usdc_before = bob_usdc.balanceOf(bob).call().await?;
    let bob_eurc = ITIP20::new(*eurc.address(), bob_provider.clone());
    let bob_eurc_before = bob_eurc.balanceOf(bob).call().await?;
    let bob_linking_usd = ITIP20::new(*linking_usd.address(), bob_provider);
    let bob_linking_usd_wallet_before = bob_linking_usd.balanceOf(bob).call().await?;
    let bob_linking_usd_exchange_before = bob_exchange
        .balanceOf(bob, *linking_usd.address())
        .call()
        .await?;

    // Execute multi-hop swap: USDC -> LinkingUSD -> EURC
    let amount_in = 1_000_000_000u128;
    let amount_out = bob_exchange
        .quoteSwapExactAmountIn(*usdc.address(), *eurc.address(), amount_in)
        .call()
        .await?;

    let tx = bob_exchange
        .swapExactAmountIn(*usdc.address(), *eurc.address(), amount_in, 0)
        .send()
        .await?;
    tx.get_receipt().await?;

    // Check Bob's balances after swap
    let bob_usdc_after = bob_usdc.balanceOf(bob).call().await?;
    let bob_eurc_after = bob_eurc.balanceOf(bob).call().await?;
    let bob_linking_usd_wallet_after = bob_linking_usd.balanceOf(bob).call().await?;
    let bob_linking_usd_exchange_after = bob_exchange
        .balanceOf(bob, *linking_usd.address())
        .call()
        .await?;

    // Verify Bob spent USDC
    assert_eq!(
        bob_usdc_before - bob_usdc_after,
        U256::from(amount_in),
        "Bob should have spent exact amount_in USDC"
    );

    // Verify Bob received EURC
    assert_eq!(
        bob_eurc_after - bob_eurc_before,
        U256::from(amount_out),
        "Bob should have received amount_out EURC"
    );

    // Verify Bob has ZERO LinkingUSD (proving intermediate balances are transitory)
    assert_eq!(
        bob_linking_usd_wallet_before, bob_linking_usd_wallet_after,
        "Bob's LinkingUSD wallet balance should not change (transitory)"
    );
    assert!(
        bob_linking_usd_wallet_after.is_zero(),
        "Bob should have ZERO LinkingUSD in wallet (transitory)"
    );
    assert_eq!(
        bob_linking_usd_exchange_before, bob_linking_usd_exchange_after,
        "Bob's LinkingUSD exchange balance should not change (transitory)"
    );
    assert_eq!(
        bob_linking_usd_exchange_after, 0,
        "Bob should have ZERO LinkingUSD on exchange (transitory)"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_place_rejects_order_below_dust_limit() -> eyre::Result<()> {
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

    // Create pair
    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());
    let tx = exchange.createPair(*base.address()).send().await?;
    tx.get_receipt().await?;

    // Mint and approve tokens
    let mint_amount = U256::from(1000000000u128);
    let mut pending = vec![];
    pending.push(base.mint(caller, mint_amount).send().await?);
    pending.push(quote.mint(caller, mint_amount).send().await?);
    await_receipts(&mut pending).await?;

    let mut pending = vec![];
    pending.push(
        base.approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        quote
            .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    let expected_selector = format!(
        "0x{}",
        alloy::hex::encode(IStablecoinExchange::BelowMinimumOrderSize::SELECTOR)
    );

    // Try to place a bid order below dust limit (should fail)
    let min_order_amount = calculate_min_order_amount(6);
    let below_dust_amount = min_order_amount - 1;
    let result = exchange
        .place(*base.address(), below_dust_amount, true, 0)
        .call()
        .await;

    assert!(
        result.is_err(),
        "Expected bid order below dust limit to fail"
    );
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&expected_selector));

    // Try to place an ask order below dust limit (should also fail)
    let result = exchange
        .place(*base.address(), below_dust_amount, false, 0)
        .call()
        .await;

    assert!(
        result.is_err(),
        "Expected ask order below dust limit to fail"
    );
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&expected_selector));

    // Place an order at exactly the dust limit (should succeed)
    let tx = exchange
        .place(*base.address(), min_order_amount, true, 0)
        .send()
        .await?;
    tx.get_receipt().await?;

    // Place an order above the dust limit (should succeed)
    let above_dust_amount = min_order_amount + 1;
    let tx = exchange
        .place(*base.address(), above_dust_amount, false, 0)
        .send()
        .await?;
    tx.get_receipt().await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_place_flip_rejects_order_below_dust_limit() -> eyre::Result<()> {
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

    // Create pair
    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());
    let tx = exchange.createPair(*base.address()).send().await?;
    tx.get_receipt().await?;

    // Mint and approve tokens
    let mint_amount = U256::from(1000000000u128);
    let mut pending = vec![];
    pending.push(base.mint(caller, mint_amount).send().await?);
    pending.push(quote.mint(caller, mint_amount).send().await?);
    await_receipts(&mut pending).await?;

    let mut pending = vec![];
    pending.push(
        base.approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        quote
            .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    let expected_selector = format!(
        "0x{}",
        alloy::hex::encode(IStablecoinExchange::BelowMinimumOrderSize::SELECTOR)
    );

    // Try to place a flip bid order below dust limit (should fail)
    let min_order_amount = calculate_min_order_amount(6);
    let below_dust_amount = min_order_amount - 1;
    let result = exchange
        .placeFlip(*base.address(), below_dust_amount, true, 0, 10)
        .call()
        .await;

    assert!(
        result.is_err(),
        "Expected flip bid order below dust limit to fail"
    );
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&expected_selector));

    // Try to place a flip ask order below dust limit (should also fail)
    let result = exchange
        .placeFlip(*base.address(), below_dust_amount, false, 10, 0)
        .call()
        .await;

    assert!(
        result.is_err(),
        "Expected flip ask order below dust limit to fail"
    );
    let err = result.unwrap_err();
    assert!(err.to_string().contains(&expected_selector));

    // Place a flip order at exactly the dust limit (should succeed)
    let tx = exchange
        .placeFlip(*base.address(), min_order_amount, true, 0, 10)
        .send()
        .await?;
    tx.get_receipt().await?;

    // Place a flip order above the dust limit (should succeed)
    let above_dust_amount = min_order_amount + 1;
    let tx = exchange
        .placeFlip(*base.address(), above_dust_amount, false, 10, 0)
        .send()
        .await?;
    tx.get_receipt().await?;

    Ok(())
}
