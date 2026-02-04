//! FeeAMM/FeeManager actions

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use rand::{random_range, seq::IndexedRandom};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::{
    IFeeManager::IFeeManagerInstance, ITIP20::ITIP20Instance, ITIPFeeAMM::ITIPFeeAMMInstance,
};
use tempo_precompiles::TIP_FEE_MANAGER_ADDRESS;

use super::{ActionContext, random_amount, select_random_user_token};

/// Minimum liquidity constant from FeeAMM
const MIN_LIQUIDITY: u128 = 1000;

/// Mint LP tokens to a FeeAMM pool
pub async fn mint(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    if ctx.user_tokens.len() < 2 {
        return Ok(());
    }

    let amm = ITIPFeeAMMInstance::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Pick two different tokens
    let indices: Vec<usize> = (0..ctx.user_tokens.len()).collect();
    let selected: Vec<&usize> = indices.choose_multiple(&mut rand::rng(), 2).collect();
    let user_token = ctx.user_tokens[*selected[0]];
    let validator_token = ctx.user_tokens[*selected[1]];

    // Check validator token balance
    let token_contract = ITIP20Instance::new(validator_token, provider.clone());
    let balance = token_contract.balanceOf(caller).call().await?;

    if balance < U256::from(MIN_LIQUIDITY * 2) {
        return Ok(());
    }

    let max_deposit = (balance / U256::from(50)).max(U256::from(MIN_LIQUIDITY * 2));
    let amount = random_amount(
        MIN_LIQUIDITY * 2,
        max_deposit.try_into().unwrap_or(1_000_000_000),
    );

    amm.mint(user_token, validator_token, amount, caller)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(())
}

/// Burn LP tokens from a FeeAMM pool
pub async fn burn(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    if ctx.user_tokens.len() < 2 {
        return Ok(());
    }

    let amm = ITIPFeeAMMInstance::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Pick two different tokens
    let indices: Vec<usize> = (0..ctx.user_tokens.len()).collect();
    let selected: Vec<&usize> = indices.choose_multiple(&mut rand::rng(), 2).collect();
    let user_token = ctx.user_tokens[*selected[0]];
    let validator_token = ctx.user_tokens[*selected[1]];

    // Check LP balance
    let pool_id = amm.getPoolId(user_token, validator_token).call().await?;
    let lp_balance = amm.liquidityBalances(pool_id, caller).call().await?;

    if lp_balance == U256::ZERO {
        return Ok(());
    }

    // Burn 10-50% of LP balance
    let max_burn = (lp_balance / U256::from(2)).max(U256::from(1));
    let min_burn = (lp_balance / U256::from(10)).max(U256::from(1));
    let amount = random_amount(
        min_burn.try_into().unwrap_or(1),
        max_burn.try_into().unwrap_or(1_000_000_000),
    );

    match amm
        .burn(user_token, validator_token, amount, caller)
        .send()
        .await
    {
        Ok(pending) => {
            let _ = pending.get_receipt().await;
        }
        Err(_) => {
            // May fail if burning would leave less than MIN_LIQUIDITY
        }
    }

    Ok(())
}

/// Execute a rebalance swap on FeeAMM
pub async fn rebalance_swap(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    if ctx.user_tokens.len() < 2 {
        return Ok(());
    }

    let amm = ITIPFeeAMMInstance::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // Pick two different tokens
    let indices: Vec<usize> = (0..ctx.user_tokens.len()).collect();
    let selected: Vec<&usize> = indices.choose_multiple(&mut rand::rng(), 2).collect();
    let user_token = ctx.user_tokens[*selected[0]];
    let validator_token = ctx.user_tokens[*selected[1]];

    // Check pool has reserves
    let pool = amm.getPool(user_token, validator_token).call().await?;
    if pool.reserveUserToken == 0 {
        return Ok(());
    }

    // Check validator token balance (we pay validator tokens to receive user tokens)
    let token_contract = ITIP20Instance::new(validator_token, provider.clone());
    let balance = token_contract.balanceOf(caller).call().await?;

    if balance == U256::ZERO {
        return Ok(());
    }

    // Rebalance a small amount
    let max_out = pool.reserveUserToken / 10;
    if max_out == 0 {
        return Ok(());
    }

    let amount_out = U256::from(random_range(1000u128..(max_out as u128).max(1001)));

    match amm
        .rebalanceSwap(user_token, validator_token, amount_out, caller)
        .send()
        .await
    {
        Ok(pending) => {
            let _ = pending.get_receipt().await;
        }
        Err(_) => {
            // May fail due to insufficient reserves or balance
        }
    }

    Ok(())
}

/// Distribute collected fees to a validator
pub async fn distribute_fees(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let amm = IFeeManagerInstance::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    let token = select_random_user_token(ctx).unwrap_or(ctx.path_usd);

    // Check if there are collected fees
    let collected = amm.collectedFees(caller, token).call().await?;
    if collected == U256::ZERO {
        return Ok(());
    }

    amm.distributeFees(caller, token)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(())
}
