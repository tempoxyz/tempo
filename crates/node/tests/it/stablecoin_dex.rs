use alloy::{
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
    sol_types::{SolCall, SolError},
};
use alloy_eips::BlockNumberOrTag;
use tempo_contracts::precompiles::{
    IStablecoinDEX,
    ITIP20::{self, ITIP20Instance},
    ITIP1060StorageCredits, STORAGE_CREDITS_ADDRESS,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, STABLECOIN_DEX_ADDRESS, stablecoin_dex::MIN_ORDER_AMOUNT,
};

use crate::utils::{TestNodeBuilder, await_receipts, setup_test_token};

fn calldata_intrinsic_gas(calldata: &[u8]) -> u64 {
    21_000
        + calldata
            .iter()
            .map(|byte| if *byte == 0 { 4 } else { 16 })
            .sum::<u64>()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bids() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup node
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let base = setup_test_token(provider.clone(), caller).await?;
    let quote = ITIP20Instance::new(PATH_USD_ADDRESS, provider.clone());

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
        base.approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    // Mint tokens to each account
    for (account, _) in &account_data {
        pending.push(quote.mint(*account, mint_amount).send().await?);
    }
    await_receipts(&mut pending).await?;

    // Pair is auto-created on first place() call
    let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    let order_amount = 1000000000;

    // Approve tokens for exchange for each account
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let quote = ITIP20::new(*quote.address(), account_provider);
        pending.push(
            quote
                .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
                .send()
                .await?,
        );
    }
    await_receipts(&mut pending).await?;

    let num_orders = account_data.len() as u128;
    // Place bid orders for each account
    let mut pending_orders = vec![];
    let tick = 10;
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, account_provider);

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
    assert_eq!(exchange.nextOrderId().call().await?, num_orders + 1);

    // Calculate fill amount to fill all `n-1` orders, partial fill last order
    let fill_amount = (num_orders * order_amount) - (order_amount / 2);

    let amount_in = exchange
        .quoteSwapExactAmountIn(*base.address(), *quote.address(), fill_amount)
        .call()
        .await?;

    // Mint base tokens to the seller for amount in
    let pending = base.mint(caller, U256::from(amount_in)).send().await?;
    pending.get_receipt().await?;

    // Execute swap and assert orders are filled
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
        .getTickLevel(*base.address(), tick, true)
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
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let base = setup_test_token(provider.clone(), caller).await?;
    let quote = ITIP20Instance::new(PATH_USD_ADDRESS, provider.clone());

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

    // Pair is auto-created on first place() call
    let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    let order_amount = 1000000000;

    // Approve tokens for exchange for each account
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let base = ITIP20::new(*base.address(), account_provider);
        pending.push(
            base.approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
                .send()
                .await?,
        );
    }
    await_receipts(&mut pending).await?;

    let num_orders = account_data.len() as u128;
    // Place ask orders for each account
    let mut pending_orders = vec![];
    let tick = 10;
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, account_provider);

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
    assert_eq!(exchange.nextOrderId().call().await?, num_orders + 1);

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
        .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
        .send()
        .await?;
    pending.get_receipt().await?;

    // Execute swap and assert orders are filled
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
        .getTickLevel(*base.address(), tick, false)
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
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let base = setup_test_token(provider.clone(), caller).await?;
    let quote = ITIP20Instance::new(PATH_USD_ADDRESS, provider.clone());

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

    // Mint tokens to each account
    let mut pending = vec![];
    for (account, _) in &account_data {
        pending.push(quote.mint(*account, mint_amount).send().await?);
    }
    await_receipts(&mut pending).await?;

    // Pair is auto-created on first place() call
    let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    let order_amount = 1000000000;

    // Approve tokens for exchange for each account
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let quote = ITIP20::new(*quote.address(), account_provider);
        pending.push(
            quote
                .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
                .send()
                .await?,
        );
    }
    await_receipts(&mut pending).await?;

    let num_orders = account_data.len() as u128;
    // Place bid orders for each account
    let mut pending_orders = vec![];
    let tick = 10;
    for (_, signer) in &account_data {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, account_provider);

        let call = exchange.place(*base.address(), order_amount, true, tick);
        let order_tx = call.send().await?;
        pending_orders.push(order_tx);
    }
    await_receipts(&mut pending_orders).await?;

    // Verify orders were created correctly
    for order_id in 1..=num_orders {
        let order = exchange.getOrder(order_id).call().await?;
        assert!(!order.maker.is_zero());
        assert!(order.isBid);
        assert_eq!(order.tick, tick);
        assert_eq!(order.amount, order_amount);
        assert_eq!(order.remaining, order_amount);
    }
    assert_eq!(exchange.nextOrderId().call().await?, num_orders + 1);

    // Cancel all orders
    for (order_id, (_, signer)) in (1..=num_orders).zip(&account_data) {
        let account_provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect_http(http_url.clone());
        let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, account_provider);

        let cancel_tx = exchange.cancel(order_id).send().await?;
        cancel_tx.get_receipt().await?;
    }

    // Assert that orders have been canceled
    for order_id in 1..=num_orders {
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
async fn test_dex_swap_restoring_dirty_slots_mints_unbacked_tip1060_credit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let base = setup_test_token(provider.clone(), caller).await?;
    let quote = ITIP20Instance::new(PATH_USD_ADDRESS, provider.clone());
    let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider.clone());
    let credits = ITIP1060StorageCredits::new(STORAGE_CREDITS_ADDRESS, provider.clone());

    let alice_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let alice = alice_signer.address();
    let alice_provider = ProviderBuilder::new()
        .wallet(alice_signer)
        .connect_http(http_url.clone());
    let alice_exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, alice_provider.clone());

    let bob_signer = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(2)?
        .build()?;
    let bob = bob_signer.address();
    let bob_provider = ProviderBuilder::new()
        .wallet(bob_signer)
        .connect_http(http_url.clone());
    let bob_exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, bob_provider.clone());

    let amount = MIN_ORDER_AMOUNT;
    let total_amount = amount * 2;
    let mut pending = vec![
        base.mint(alice, U256::from(total_amount)).send().await?,
        quote.mint(alice, U256::from(total_amount)).send().await?,
        quote.mint(bob, U256::from(amount)).send().await?,
    ];
    await_receipts(&mut pending).await?;

    let alice_base = ITIP20::new(*base.address(), alice_provider.clone());
    let alice_quote = ITIP20::new(*quote.address(), alice_provider);
    let bob_base = ITIP20::new(*base.address(), bob_provider.clone());
    let bob_quote = ITIP20::new(*quote.address(), bob_provider);

    let mut pending = vec![
        alice_base
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
        alice_quote
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
        bob_base
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
        bob_quote
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
    ];
    await_receipts(&mut pending).await?;

    exchange
        .createPair(*base.address())
        .send()
        .await?
        .get_receipt()
        .await?;

    alice_exchange
        .place(*base.address(), amount, false, 0)
        .send()
        .await?
        .get_receipt()
        .await?;
    alice_exchange
        .place(*base.address(), amount, true, 0)
        .send()
        .await?
        .get_receipt()
        .await?;

    let pre_balance = credits.balanceOf(STABLECOIN_DEX_ADDRESS).call().await?;
    assert_eq!(pre_balance, 1);
    let pre_deletion_backed_credits = exchange.storageCredits(alice).call().await?;
    assert_eq!(pre_deletion_backed_credits, 0);

    let amount_in = amount;
    let amount_out = bob_exchange
        .quoteSwapExactAmountIn(*quote.address(), *base.address(), amount_in)
        .call()
        .await?;
    assert!(amount_out > 0);

    let receipt = bob_exchange
        .swapExactAmountIn(*quote.address(), *base.address(), amount_in, 0)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "first swap should succeed");

    let block_number = receipt
        .block_number
        .expect("swap receipt should have a block number");
    let block = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number))
        .await?
        .expect("swap block should exist");
    let first_gas_used = block.header.inner.gas_used;
    let first_intrinsic_gas = calldata_intrinsic_gas(
        &IStablecoinDEX::swapExactAmountInCall {
            tokenIn: *quote.address(),
            tokenOut: *base.address(),
            amountIn: amount_in,
            minAmountOut: 0,
        }
        .abi_encode(),
    );

    let post_first_balance = credits.balanceOf(STABLECOIN_DEX_ADDRESS).call().await?;
    eprintln!(
        "regular sequence: pre={pre_balance} post_first={post_first_balance} first_delta={}",
        post_first_balance - pre_balance
    );

    let second_receipt = bob_exchange
        .swapExactAmountIn(*base.address(), *quote.address(), amount_out, 0)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(second_receipt.status(), "second swap should succeed");
    let second_block_number = second_receipt
        .block_number
        .expect("second swap receipt should have a block number");
    let second_block = provider
        .get_block_by_number(BlockNumberOrTag::Number(second_block_number))
        .await?
        .expect("second swap block should exist");
    let second_gas_used = second_block.header.inner.gas_used;
    let second_intrinsic_gas = calldata_intrinsic_gas(
        &IStablecoinDEX::swapExactAmountInCall {
            tokenIn: *base.address(),
            tokenOut: *quote.address(),
            amountIn: amount_out,
            minAmountOut: 0,
        }
        .abi_encode(),
    );
    let post_balance = credits.balanceOf(STABLECOIN_DEX_ADDRESS).call().await?;
    let post_deletion_backed_credits = exchange.storageCredits(alice).call().await?;
    eprintln!(
        "regular sequence: post_second={post_balance} second_delta={} total_delta={}",
        post_balance - post_first_balance,
        post_balance - pre_balance,
    );

    assert!(
        post_first_balance > pre_balance,
        "first swap should increase protocol storage credits"
    );

    let deletion_backed_credits =
        post_deletion_backed_credits.saturating_sub(pre_deletion_backed_credits);
    let deletion_backed_balance = pre_balance.saturating_add(deletion_backed_credits);
    let unbacked_credit_increase = post_balance.saturating_sub(deletion_backed_balance);
    let minimum_execution_gas = unbacked_credit_increase * 250_000;
    let gas_used = first_gas_used + second_gas_used;
    let intrinsic_gas = first_intrinsic_gas + second_intrinsic_gas;
    let execution_gas = gas_used.saturating_sub(intrinsic_gas);

    eprintln!(
        "delta={} deletion_backed_credits={deletion_backed_credits} unbacked={unbacked_credit_increase} first_gas={first_gas_used} second_gas={second_gas_used} gas_used={gas_used} intrinsic={intrinsic_gas} execution={execution_gas} minimum={minimum_execution_gas}",
        post_balance - pre_balance,
    );

    assert!(
        unbacked_credit_increase > 0,
        "DEX swaps should mint credits beyond deletion-backed balance"
    );
    assert!(
        execution_gas >= minimum_execution_gas,
        "TEMPO-STORAGE-CREDIT-BALANCE-BACKING unbacked_credit_increase={unbacked_credit_increase} \
         gas_used={gas_used} intrinsic_gas={intrinsic_gas} execution_gas={execution_gas} \
         minimum_execution_gas={minimum_execution_gas} pre_balance={pre_balance} \
         post_balance={post_balance} deletion_backed_credits={deletion_backed_credits}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_multi_hop_swap() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup node
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    // Setup tokens: pathUSD (token_id=0) <- USDC (token_id=2) and pathUSD <- EURC (token_id=3)
    let linking_usd = ITIP20Instance::new(PATH_USD_ADDRESS, provider.clone());
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
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        alice_eurc
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        alice_linking_usd
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    // Alice places liquidity orders at tick 0 (1:1 price)
    let alice_exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, alice_provider);
    let liquidity_amount = 5_000_000_000u128;

    // For USDC -> pathUSD: need bid on USDC (buying USDC with pathUSD)
    let tx = alice_exchange
        .place(*usdc.address(), liquidity_amount, true, 0)
        .send()
        .await?;
    tx.get_receipt().await?;

    // For pathUSD -> EURC: need ask on EURC (selling EURC for pathUSD)
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
        .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
        .send()
        .await?;
    tx.get_receipt().await?;

    // Check Bob's balances before swap
    let bob_exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, bob_provider.clone());
    let bob_usdc_before = bob_usdc.balanceOf(bob).call().await?;
    let bob_eurc = ITIP20::new(*eurc.address(), bob_provider.clone());
    let bob_eurc_before = bob_eurc.balanceOf(bob).call().await?;
    let bob_linking_usd = ITIP20::new(*linking_usd.address(), bob_provider);
    let bob_linking_usd_wallet_before = bob_linking_usd.balanceOf(bob).call().await?;
    let bob_linking_usd_exchange_before = bob_exchange
        .balanceOf(bob, *linking_usd.address())
        .call()
        .await?;

    // Execute multi-hop swap: USDC -> pathUSD -> EURC
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

    // Verify Bob's linking USD balance has not changed
    assert_eq!(
        bob_linking_usd_wallet_before, bob_linking_usd_wallet_after,
        "Bob's pathUSD wallet balance should not change (transitory)"
    );

    assert_eq!(
        bob_linking_usd_wallet_before - bob_linking_usd_wallet_after,
        U256::ZERO,
        "Bob should have ZERO pathUSD in wallet (transitory)"
    );

    assert_eq!(
        bob_linking_usd_exchange_before, bob_linking_usd_exchange_after,
        "Bob's pathUSD exchange balance should not change (transitory)"
    );
    assert_eq!(
        bob_linking_usd_exchange_after, 0,
        "Bob should have ZERO pathUSD on exchange (transitory)"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_place_rejects_order_below_dust_limit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Setup node
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let base = setup_test_token(provider.clone(), caller).await?;
    let quote = ITIP20Instance::new(PATH_USD_ADDRESS, provider.clone());

    // Pair is auto-created on first place() call
    let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    // Mint and approve tokens
    let mint_amount = U256::from(1000000000u128);
    let mut pending = vec![];
    pending.push(base.mint(caller, mint_amount).send().await?);
    pending.push(quote.mint(caller, mint_amount).send().await?);
    await_receipts(&mut pending).await?;

    let mut pending = vec![];
    pending.push(
        base.approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        quote
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    let expected_selector = format!(
        "0x{}",
        alloy::hex::encode(IStablecoinDEX::BelowMinimumOrderSize::SELECTOR)
    );

    // Try to place a bid order below dust limit (should fail)
    let min_order_amount = MIN_ORDER_AMOUNT;
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
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let base = setup_test_token(provider.clone(), caller).await?;
    let quote = ITIP20Instance::new(PATH_USD_ADDRESS, provider.clone());

    // Pair is auto-created on first place() call
    let exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    // Mint and approve tokens
    let mint_amount = U256::from(1000000000u128);
    let mut pending = vec![];
    pending.push(base.mint(caller, mint_amount).send().await?);
    pending.push(quote.mint(caller, mint_amount).send().await?);
    await_receipts(&mut pending).await?;

    let mut pending = vec![];
    pending.push(
        base.approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    pending.push(
        quote
            .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
            .send()
            .await?,
    );
    await_receipts(&mut pending).await?;

    let expected_selector = format!(
        "0x{}",
        alloy::hex::encode(IStablecoinDEX::BelowMinimumOrderSize::SELECTOR)
    );

    // Try to place a flip bid order below dust limit (should fail)
    let min_order_amount = MIN_ORDER_AMOUNT;
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
