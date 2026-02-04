//! Action generators for comprehensive Tempo coverage.
//!
//! Each action corresponds to operations tested in the invariant tests.

mod dex;
mod fee_amm;
mod nonce;
mod policy;
mod tip20;
mod token_factory;

use std::sync::{Arc, atomic::AtomicU64};

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
};
use rand::{random_range, seq::IndexedRandom};
use tempo_alloy::TempoNetwork;

/// Context shared across all actions
pub struct ActionContext {
    /// PathUSD token address
    pub path_usd: Address,
    /// User tokens created for testing
    pub user_tokens: Vec<Address>,
    /// Policy IDs created for testing
    pub policy_ids: Vec<u64>,
    /// Placed order IDs (for cancellation)
    pub orders: Arc<tokio::sync::RwLock<Vec<u128>>>,
    /// Counter for unique token salts
    pub token_salt_counter: Arc<AtomicU64>,
    /// Admin address (first signer)
    pub admin: Address,
}

/// Types of actions that can be executed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    // TIP20 actions
    Tip20Transfer,
    Tip20TransferFrom,
    Tip20Approve,
    Tip20Mint,
    Tip20Burn,
    Tip20DistributeReward,

    // DEX actions
    DexPlace,
    DexPlaceFlip,
    DexCancel,
    DexSwap,
    DexWithdraw,
    DexDeposit,

    // FeeAMM actions
    AmmMint,
    AmmBurn,
    AmmRebalance,
    AmmDistributeFees,

    // Nonce actions
    NonceIncrement,

    // Token factory actions
    TokenCreate,

    // Policy actions
    PolicyModify,
}

/// Pick a random action based on cumulative weights
pub fn pick_random_action(
    cumulative_weights: &[(ActionType, u32)],
    total_weight: u32,
) -> ActionType {
    let r = random_range(0..total_weight);
    for (action, cumulative) in cumulative_weights {
        if r < *cumulative {
            return *action;
        }
    }
    // Fallback
    cumulative_weights
        .last()
        .map(|(a, _)| *a)
        .unwrap_or(ActionType::Tip20Transfer)
}

/// Execute a single action
pub async fn execute_action(
    action: ActionType,
    ctx: &ActionContext,
    caller: Address,
    provider: &DynProvider<TempoNetwork>,
    all_signers: &[Address],
) -> eyre::Result<()> {
    match action {
        // TIP20 actions
        ActionType::Tip20Transfer => tip20::transfer(ctx, caller, provider, all_signers).await,
        ActionType::Tip20TransferFrom => {
            tip20::transfer_from(ctx, caller, provider, all_signers).await
        }
        ActionType::Tip20Approve => tip20::approve(ctx, caller, provider, all_signers).await,
        ActionType::Tip20Mint => tip20::mint(ctx, caller, provider).await,
        ActionType::Tip20Burn => tip20::burn(ctx, caller, provider).await,
        ActionType::Tip20DistributeReward => tip20::distribute_reward(ctx, caller, provider).await,

        // DEX actions
        ActionType::DexPlace => dex::place_order(ctx, caller, provider).await,
        ActionType::DexPlaceFlip => dex::place_flip_order(ctx, caller, provider).await,
        ActionType::DexCancel => dex::cancel_order(ctx, caller, provider).await,
        ActionType::DexSwap => dex::swap(ctx, caller, provider).await,
        ActionType::DexWithdraw => dex::withdraw(ctx, caller, provider).await,
        ActionType::DexDeposit => dex::deposit(ctx, caller, provider).await,

        // FeeAMM actions
        ActionType::AmmMint => fee_amm::mint(ctx, caller, provider).await,
        ActionType::AmmBurn => fee_amm::burn(ctx, caller, provider).await,
        ActionType::AmmRebalance => fee_amm::rebalance_swap(ctx, caller, provider).await,
        ActionType::AmmDistributeFees => fee_amm::distribute_fees(ctx, caller, provider).await,

        // Nonce actions
        ActionType::NonceIncrement => nonce::increment_nonce(ctx, caller, provider).await,

        // Token factory actions
        ActionType::TokenCreate => token_factory::create_token(ctx, caller, provider).await,

        // Policy actions
        ActionType::PolicyModify => policy::modify_policy(ctx, caller, provider, all_signers).await,
    }
}

/// Helper to select a random token from available tokens
pub fn select_random_token(ctx: &ActionContext) -> Address {
    let all_tokens: Vec<Address> = std::iter::once(ctx.path_usd)
        .chain(ctx.user_tokens.iter().copied())
        .collect();
    *all_tokens.choose(&mut rand::rng()).unwrap_or(&ctx.path_usd)
}

/// Helper to select a random user token (excluding pathUSD)
pub fn select_random_user_token(ctx: &ActionContext) -> Option<Address> {
    if ctx.user_tokens.is_empty() {
        None
    } else {
        Some(*ctx.user_tokens.choose(&mut rand::rng()).unwrap())
    }
}

/// Helper to select a random recipient excluding the caller
pub fn select_random_recipient(caller: Address, all_signers: &[Address]) -> Address {
    let candidates: Vec<_> = all_signers
        .iter()
        .filter(|a| **a != caller)
        .copied()
        .collect();
    if candidates.is_empty() {
        caller
    } else {
        *candidates.choose(&mut rand::rng()).unwrap()
    }
}

/// Helper to generate a random amount
pub fn random_amount(min: u128, max: u128) -> U256 {
    U256::from(random_range(min..max))
}
