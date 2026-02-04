//! StablecoinDEX actions

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use rand::{random_range, seq::IndexedRandom};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::{
    IStablecoinDEX::IStablecoinDEXInstance, ITIP20::ITIP20Instance, STABLECOIN_DEX_ADDRESS,
};

use super::{ActionContext, select_random_user_token};

/// Valid ticks for order placement (matching invariant tests)
const TICKS: [i16; 10] = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

/// Place a regular bid or ask order
pub async fn place_order(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let exchange = IStablecoinDEXInstance::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    let token = select_random_user_token(ctx).ok_or_else(|| eyre::eyre!("No user tokens"))?;
    let tick = *TICKS.choose(&mut rand::rng()).unwrap();
    let is_bid = random_range(0..2) == 0;

    // Amount between min order size and reasonable max
    let amount: u128 = random_range(100_000_000..10_000_000_000);

    // Ensure sufficient balance
    let escrow_token = if is_bid { ctx.path_usd } else { token };
    let token_contract = ITIP20Instance::new(escrow_token, provider.clone());
    let balance = token_contract.balanceOf(caller).call().await?;

    if is_bid {
        let price = exchange.tickToPrice(tick).call().await?;
        let escrow_needed =
            U256::from(amount) * U256::from(price) / U256::from(100_000) + U256::from(1);
        if balance < escrow_needed {
            return Ok(());
        }
    } else if balance < U256::from(amount) {
        return Ok(());
    }

    let receipt = exchange
        .place(token, amount, is_bid, tick)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Store order ID for potential cancellation
    if let Some(event) =
        receipt.decoded_log::<tempo_contracts::precompiles::IStablecoinDEX::OrderPlaced>()
    {
        ctx.orders.write().await.push(event.orderId);
    }

    Ok(())
}

/// Place a flip order (bid that flips to ask when price crosses)
pub async fn place_flip_order(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let exchange = IStablecoinDEXInstance::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    let token = select_random_user_token(ctx).ok_or_else(|| eyre::eyre!("No user tokens"))?;

    // For flip orders, flipTick must be > tick for bids, < tick for asks
    let is_bid = random_range(0..2) == 0;
    let tick_idx = random_range(0..TICKS.len() - 2);

    let (tick, flip_tick) = if is_bid {
        (TICKS[tick_idx], TICKS[tick_idx + 2])
    } else {
        (TICKS[tick_idx + 2], TICKS[tick_idx])
    };

    let amount: u128 = random_range(100_000_000..5_000_000_000);

    // Ensure sufficient balance for both escrow and potential flip
    let path_usd_balance = ITIP20Instance::new(ctx.path_usd, provider.clone())
        .balanceOf(caller)
        .call()
        .await?;
    let token_balance = ITIP20Instance::new(token, provider.clone())
        .balanceOf(caller)
        .call()
        .await?;

    if is_bid {
        let price = exchange.tickToPrice(tick).call().await?;
        let escrow_needed =
            U256::from(amount) * U256::from(price) / U256::from(100_000) + U256::from(1);
        if path_usd_balance < escrow_needed {
            return Ok(());
        }
    } else if token_balance < U256::from(amount) {
        return Ok(());
    }

    let receipt = exchange
        .placeFlip(token, amount, is_bid, tick, flip_tick)
        .send()
        .await?
        .get_receipt()
        .await?;

    if let Some(event) =
        receipt.decoded_log::<tempo_contracts::precompiles::IStablecoinDEX::OrderPlaced>()
    {
        ctx.orders.write().await.push(event.orderId);
    }

    Ok(())
}

/// Cancel an existing order
pub async fn cancel_order(
    ctx: &ActionContext,
    _caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let exchange = IStablecoinDEXInstance::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    // Try to get an order to cancel
    let orders = ctx.orders.read().await;
    if orders.is_empty() {
        return Ok(());
    }

    // Pick a random order
    let order_id = *orders.choose(&mut rand::rng()).unwrap();
    drop(orders);

    // Try to cancel - may fail if already cancelled or not ours
    match exchange.cancel(order_id).send().await {
        Ok(pending) => {
            let _ = pending.get_receipt().await;
            // Remove from our list
            ctx.orders.write().await.retain(|&id| id != order_id);
        }
        Err(_) => {
            // Order may not exist or not be ours - that's okay
        }
    }

    Ok(())
}

/// Execute a swap
pub async fn swap(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let exchange = IStablecoinDEXInstance::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    // Pick token in and out
    let user_token = select_random_user_token(ctx).ok_or_else(|| eyre::eyre!("No user tokens"))?;

    // Randomly choose direction
    let (token_in, token_out) = if random_range(0..2) == 0 {
        (ctx.path_usd, user_token)
    } else {
        (user_token, ctx.path_usd)
    };

    let token_in_contract = ITIP20Instance::new(token_in, provider.clone());
    let balance = token_in_contract.balanceOf(caller).call().await?;

    if balance == U256::ZERO {
        return Ok(());
    }

    // Swap 1-5% of balance
    let max_swap = (balance / U256::from(20)).max(U256::from(1_000_000));
    let amount_in: u128 = random_range(1_000_000..(max_swap.try_into().unwrap_or(10_000_000_000)));

    // Use swapExactAmountIn with 0 min output (accept any slippage for testing)
    match exchange
        .swapExactAmountIn(token_in, token_out, amount_in, 0)
        .send()
        .await
    {
        Ok(pending) => {
            let _ = pending.get_receipt().await;
        }
        Err(_) => {
            // May fail due to insufficient liquidity
        }
    }

    Ok(())
}

/// Withdraw from DEX internal balance
pub async fn withdraw(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let exchange = IStablecoinDEXInstance::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    let token = select_random_user_token(ctx).unwrap_or(ctx.path_usd);

    let internal_balance = exchange.balanceOf(caller, token).call().await?;
    if internal_balance == 0 {
        return Ok(());
    }

    let amount: u128 = random_range(1..(internal_balance / 2).max(1));

    exchange
        .withdraw(token, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(())
}

/// Deposit to DEX internal balance via direct transfer
///
/// The DEX doesn't have an explicit deposit function - internal balance increases
/// when orders are placed and then cancelled, or when swaps occur.
/// This action performs a swap to build up internal balance.
pub async fn deposit(
    ctx: &ActionContext,
    _caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    // The DEX builds internal balance through trading operations
    // We'll just do a small swap to exercise the code path
    let exchange = IStablecoinDEXInstance::new(STABLECOIN_DEX_ADDRESS, provider.clone());

    let user_token = select_random_user_token(ctx).ok_or_else(|| eyre::eyre!("No user tokens"))?;

    // Do a small swap to exercise the balance transfer path
    let _ = exchange
        .swapExactAmountIn(ctx.path_usd, user_token, 1_000_000, 0)
        .send()
        .await;

    Ok(())
}
