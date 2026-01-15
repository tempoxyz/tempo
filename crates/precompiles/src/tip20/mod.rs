//! TIP20 Token module.
//!
//! This module contains the TIP20 token implementation including:
//! - `tip20`: Core ERC20-like token interface
//! - `roles_auth`: Role-based access control interface
//! - `rewards`: Reward distribution and claiming interface

pub mod dispatch;
pub mod rewards;
pub mod roles;
pub mod token;

use crate::{error::Result, storage::Mapping};
use alloy::primitives::{Address, B256, U256, keccak256};
use std::sync::LazyLock;
use tempo_precompiles_macros::{Storable, abi, contract};

pub use roles::*;
pub use token::*;

#[contract(abi, dispatch)]
pub struct TIP20Token {
    // RolesAuth
    roles: Mapping<Address, Mapping<B256, bool>>,
    role_admins: Mapping<B256, B256>,

    // TIP20 Metadata
    name: String,
    symbol: String,
    currency: String,
    domain_separator: B256,
    quote_token: Address,
    next_quote_token: Address,
    transfer_policy_id: u64,

    // TIP20 Token
    total_supply: U256,
    balances: Mapping<Address, U256>,
    allowances: Mapping<Address, Mapping<Address, U256>>,
    nonces: Mapping<Address, U256>,
    paused: bool,
    supply_cap: U256,
    salts: Mapping<B256, bool>,

    // TIP20 Rewards
    global_reward_per_token: U256,
    opted_in_supply: u128,
    user_reward_info: Mapping<Address, UserRewardInfo>,
}

#[abi(dispatch)]
#[rustfmt::skip]
pub mod abi {
    use super::*;

    pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
    pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"UNPAUSE_ROLE"));
    pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"ISSUER_ROLE"));
    pub static BURN_BLOCKED_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"BURN_BLOCKED_ROLE"));

    pub trait IToken {
        // View functions
        fn name(&self) -> Result<String>;
        fn symbol(&self) -> Result<String>;
        fn decimals(&self) -> Result<u8>;
        fn total_supply(&self) -> Result<U256>;
        fn quote_token(&self) -> Result<Address>;
        fn next_quote_token(&self) -> Result<Address>;
        fn balance_of(&self, account: Address) -> Result<U256>;
        fn allowance(&self, owner: Address, spender: Address) -> Result<U256>;
        fn currency(&self) -> Result<String>;
        fn supply_cap(&self) -> Result<U256>;
        fn paused(&self) -> Result<bool>;
        fn transfer_policy_id(&self) -> Result<u64>;

        // Mutating functions
        fn transfer(&mut self, to: Address, amount: U256) -> Result<bool>;
        fn approve(&mut self, spender: Address, amount: U256) -> Result<bool>;
        fn transfer_from(&mut self, from: Address, to: Address, amount: U256) -> Result<bool>;
        fn mint(&mut self, to: Address, amount: U256) -> Result<()>;
        fn burn(&mut self, amount: U256) -> Result<()>;
        fn burn_blocked(&mut self, from: Address, amount: U256) -> Result<()>;
        fn mint_with_memo(&mut self, to: Address, amount: U256, memo: B256) -> Result<()>;
        fn burn_with_memo(&mut self, amount: U256, memo: B256) -> Result<()>;
        fn transfer_with_memo(&mut self, to: Address, amount: U256, memo: B256) -> Result<()>;
        fn transfer_from_with_memo(&mut self, from: Address, to: Address, amount: U256, memo: B256 ) -> Result<bool>;
        fn change_transfer_policy_id(&mut self, new_policy_id: u64) -> Result<()>;
        fn set_supply_cap(&mut self, new_supply_cap: U256) -> Result<()>;
        fn pause(&mut self) -> Result<()>;
        fn unpause(&mut self) -> Result<()>;
        fn set_next_quote_token(&mut self, new_quote_token: Address) -> Result<()>;
        fn complete_quote_token_update(&mut self) -> Result<()>;
    }

    pub trait IRolesAuth {
        fn has_role(&self, account: Address, role: B256) -> Result<bool>;
        fn get_role_admin(&self, role: B256) -> Result<B256>;
        fn grant_role(&mut self, role: B256, account: Address) -> Result<()>;
        fn revoke_role(&mut self, role: B256, account: Address) -> Result<()>;
        fn renounce_role(&mut self, role: B256) -> Result<()>;
        fn set_role_admin(&mut self, role: B256, admin_role: B256) -> Result<()>;
    }

    #[derive(Debug, Clone, PartialEq, Eq, Storable)]
    pub struct UserRewardInfo {
        pub reward_recipient: Address,
        pub reward_per_token: U256,
        pub reward_balance: U256,
    }

    pub trait IRewards {
        fn distribute_reward(&mut self, amount: U256) -> Result<()>;
        fn set_reward_recipient(&mut self, recipient: Address) -> Result<()>;
        fn claim_rewards(&mut self) -> Result<U256>;
        fn opted_in_supply(&self) -> Result<u128>;
        fn global_reward_per_token(&self) -> Result<U256>;
        fn user_reward_info(&self, account: Address) -> Result<UserRewardInfo>;
        fn get_pending_rewards(&self, account: Address) -> Result<u128>;
    }

    pub enum Error {
        // TIP20 errors
        InsufficientBalance { available: U256, required: U256, token: Address, },
        InsufficientAllowance,
        SupplyCapExceeded,
        InvalidSupplyCap,
        InvalidPayload,
        StringTooLong,
        PolicyForbids,
        InvalidRecipient,
        ContractPaused,
        InvalidCurrency,
        InvalidQuoteToken,
        TransfersDisabled,
        InvalidAmount,
        NoOptedInSupply,
        ProtectedAddress,
        InvalidToken,
        Uninitialized,
        InvalidTransferPolicyId,
        // RolesAuth errors
        Unauthorized,
    }

    pub enum Event {
        // TIP20 events
        Transfer { #[indexed] from: Address, #[indexed] to: Address, amount: U256 },
        Approval { #[indexed] owner: Address, #[indexed] spender: Address, amount: U256 },
        Mint { #[indexed] to: Address, amount: U256 },
        Burn { #[indexed] from: Address, amount: U256 },
        BurnBlocked { #[indexed] from: Address, amount: U256 },
        TransferWithMemo { #[indexed] from: Address, #[indexed] to: Address, amount: U256, #[indexed] memo: B256 },
        TransferPolicyUpdate { #[indexed] updater: Address, #[indexed] new_policy_id: u64 },
        SupplyCapUpdate { #[indexed] updater: Address, #[indexed] new_supply_cap: U256 },
        PauseStateUpdate { #[indexed] updater: Address, is_paused: bool },
        NextQuoteTokenSet { #[indexed] updater: Address, #[indexed] next_quote_token: Address },
        QuoteTokenUpdate { #[indexed] updater: Address, #[indexed] new_quote_token: Address },

        // RolesAuth events
        RoleMembershipUpdated { #[indexed] role: B256, #[indexed] account: Address, #[indexed] sender: Address, has_role: bool },
        RoleAdminUpdated { #[indexed] role: B256, #[indexed] new_admin_role: B256, #[indexed] sender: Address },

        // Rewards events
        RewardDistributed { #[indexed] funder: Address, amount: U256 },
        RewardRecipientSet { #[indexed] holder: Address, #[indexed] recipient: Address },
    }
}

pub use abi::UserRewardInfo;

// Backward-compatibility type aliases
pub type TIP20Error = abi::Error;
pub type TIP20Event = abi::Event;
pub type RolesAuthError = abi::Error;
pub type RolesAuthEvent = abi::Event;

// Re-export individual error/event variants for convenience
pub use abi::{
    InvalidCurrency, PolicyForbids, RoleAdminUpdated, RoleMembershipUpdated, Unauthorized,
};

// Backward-compatibility trait/interface aliases
pub use IAbi as ITIP20;
pub use IAbi as IRewards;
pub use IAbi as IRolesAuth;
