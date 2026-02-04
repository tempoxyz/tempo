//! TIP20 token actions

use alloy::{
    primitives::{Address, B256, U256},
    providers::DynProvider,
};
use rand::random_range;
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::ITIP20::ITIP20Instance;

use super::{
    ActionContext, random_amount, select_random_recipient, select_random_token,
    select_random_user_token,
};

/// Execute a TIP20 transfer
pub async fn transfer(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
    all_signers: &[Address],
) -> eyre::Result<()> {
    let token_addr = select_random_token(ctx);
    let token = ITIP20Instance::new(token_addr, provider.clone());

    let recipient = select_random_recipient(caller, all_signers);
    let balance = token.balanceOf(caller).call().await?;

    if balance == U256::ZERO {
        return Ok(()); // Skip if no balance
    }

    // Transfer 1-10% of balance
    let max_amount = (balance / U256::from(10)).max(U256::from(1));
    let amount = random_amount(1, max_amount.try_into().unwrap_or(1_000_000_000));

    // Randomly use memo variant
    if random_range(0..2) == 0 {
        let memo = B256::random();
        token
            .transferWithMemo(recipient, amount, memo)
            .send()
            .await?
            .get_receipt()
            .await?;
    } else {
        token
            .transfer(recipient, amount)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    Ok(())
}

/// Execute a TIP20 transferFrom
pub async fn transfer_from(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
    all_signers: &[Address],
) -> eyre::Result<()> {
    let token_addr = select_random_token(ctx);
    let token = ITIP20Instance::new(token_addr, provider.clone());

    // Pick a random owner (someone who has approved us)
    let owner = select_random_recipient(caller, all_signers);
    let recipient = select_random_recipient(caller, all_signers);

    let allowance = token.allowance(owner, caller).call().await?;
    let balance = token.balanceOf(owner).call().await?;

    let max_transferable = allowance.min(balance);
    if max_transferable == U256::ZERO {
        return Ok(()); // Skip if no allowance or balance
    }

    let amount = random_amount(
        1,
        (max_transferable / U256::from(10))
            .max(U256::from(1))
            .try_into()
            .unwrap_or(1_000_000),
    );

    // Randomly use memo variant
    if random_range(0..2) == 0 {
        let memo = B256::random();
        token
            .transferFromWithMemo(owner, recipient, amount, memo)
            .send()
            .await?
            .get_receipt()
            .await?;
    } else {
        token
            .transferFrom(owner, recipient, amount)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    Ok(())
}

/// Execute a TIP20 approve
pub async fn approve(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
    all_signers: &[Address],
) -> eyre::Result<()> {
    let token_addr = select_random_token(ctx);
    let token = ITIP20Instance::new(token_addr, provider.clone());

    let spender = select_random_recipient(caller, all_signers);

    // Randomly approve different amounts
    let amount = match random_range(0..3) {
        0 => U256::MAX, // Infinite approval
        1 => random_amount(1_000_000, 1_000_000_000_000),
        _ => U256::ZERO, // Revoke
    };

    token
        .approve(spender, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(())
}

/// Execute a TIP20 mint (admin only)
pub async fn mint(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    // Only admin can mint
    if caller != ctx.admin {
        return Ok(());
    }

    let token_addr = select_random_user_token(ctx).unwrap_or(ctx.path_usd);
    let token = ITIP20Instance::new(token_addr, provider.clone());

    let amount = random_amount(1_000_000, 10_000_000_000);
    let recipient = caller; // Mint to self

    // Randomly use memo variant
    if random_range(0..2) == 0 {
        let memo = B256::random();
        token
            .mintWithMemo(recipient, amount, memo)
            .send()
            .await?
            .get_receipt()
            .await?;
    } else {
        token
            .mint(recipient, amount)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    Ok(())
}

/// Execute a TIP20 burn
pub async fn burn(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let token_addr = select_random_token(ctx);
    let token = ITIP20Instance::new(token_addr, provider.clone());

    let balance = token.balanceOf(caller).call().await?;
    if balance == U256::ZERO {
        return Ok(());
    }

    // Burn 1-5% of balance
    let max_burn = (balance / U256::from(20)).max(U256::from(1));
    let amount = random_amount(1, max_burn.try_into().unwrap_or(1_000_000));

    // Randomly use memo variant
    if random_range(0..2) == 0 {
        let memo = B256::random();
        token
            .burnWithMemo(amount, memo)
            .send()
            .await?
            .get_receipt()
            .await?;
    } else {
        token.burn(amount).send().await?.get_receipt().await?;
    }

    Ok(())
}

/// Execute a reward distribution
pub async fn distribute_reward(
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    let token_addr = select_random_user_token(ctx).unwrap_or(ctx.path_usd);
    let token = ITIP20Instance::new(token_addr, provider.clone());

    let balance = token.balanceOf(caller).call().await?;
    if balance == U256::ZERO {
        return Ok(());
    }

    let amount = random_amount(
        1_000,
        (balance / U256::from(100))
            .max(U256::from(1_000))
            .try_into()
            .unwrap_or(1_000_000),
    );

    // Try to distribute reward (may fail if no opted-in supply)
    match token.distributeReward(amount).send().await {
        Ok(pending) => {
            let _ = pending.get_receipt().await;
        }
        Err(_) => {
            // Expected if no opted-in supply
        }
    }

    Ok(())
}
