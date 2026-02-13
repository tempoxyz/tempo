use tempo_precompiles_macros::abi;

/// Role-based access control interface.
#[abi]
#[rustfmt::skip]
pub mod IRolesAuth {
    #[cfg(feature = "precompiles")]
    use crate::error::Result;

    use alloy::primitives::{Address, B256};

    pub trait Interface {
        fn has_role(&self, account: Address, role: B256) -> Result<bool>;
        fn get_role_admin(&self, role: B256) -> Result<B256>;
        #[msg_sender]
        fn grant_role(&mut self, role: B256, account: Address) -> Result<()>;
        #[msg_sender]
        fn revoke_role(&mut self, role: B256, account: Address) -> Result<()>;
        #[msg_sender]
        fn renounce_role(&mut self, role: B256) -> Result<()>;
        #[msg_sender]
        fn set_role_admin(&mut self, role: B256, admin_role: B256) -> Result<()>;
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        Unauthorized,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
        RoleMembershipUpdated { #[indexed] role: B256, #[indexed] account: Address, #[indexed] sender: Address, has_role: bool },
        RoleAdminUpdated { #[indexed] role: B256, #[indexed] new_admin_role: B256, #[indexed] sender: Address },
    }
}

#[abi]
#[rustfmt::skip]
pub mod ITIP20 {
    #[cfg(feature = "precompiles")]
    use crate::error::Result;

    use std::sync::LazyLock;
    use alloy::primitives::{Address, U256, B256, keccak256};

    /// Decimal precision for TIP-20 tokens
    #[getter = "decimals"]
    pub const TIP20_DECIMALS: u8 = 6;

    /// This role identifier grants permission to pause the token contract.
    pub static PAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"PAUSE_ROLE"));
    /// This role identifier grants permission to unpause the token contract.
    pub static UNPAUSE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"UNPAUSE_ROLE"));
    /// This role identifier grants permission to mint and burn tokens.
    pub static ISSUER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"ISSUER_ROLE"));
    /// This role identifier grants permission to burn tokens from blocked accounts.
    pub static BURN_BLOCKED_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"BURN_BLOCKED_ROLE"));

    #[derive(Debug, Clone, PartialEq, Eq, Storable)]
    pub struct UserRewardInfo {
        pub reward_recipient: Address,
        pub reward_per_token: U256,
        pub reward_balance: U256,
    }

    pub trait IToken {
        #[getter]
        fn name(&self) -> Result<String>;
        #[getter]
        fn symbol(&self) -> Result<String>;
        #[getter]
        fn total_supply(&self) -> Result<U256>;
        #[getter]
        fn quote_token(&self) -> Result<Address>;
        #[getter]
        fn next_quote_token(&self) -> Result<Address>;
        #[getter = "balances"]
        fn balance_of(&self, account: Address) -> Result<U256>;
        #[msg_sender]
        fn transfer(&mut self, to: Address, amount: U256) -> Result<bool>;
        #[msg_sender]
        fn approve(&mut self, spender: Address, amount: U256) -> Result<bool>;
        #[getter = "allowances"]
        fn allowance(&self, owner: Address, spender: Address) -> Result<U256>;
        #[msg_sender]
        fn transfer_from(&mut self, from: Address, to: Address, amount: U256) -> Result<bool>;
        #[msg_sender]
        fn mint(&mut self, to: Address, amount: U256) -> Result<()>;
        #[msg_sender]
        fn burn(&mut self, amount: U256) -> Result<()>;

        #[getter]
        fn currency(&self) -> Result<String>;
        #[getter]
        fn supply_cap(&self) -> Result<U256>;
        #[getter]
        fn paused(&self) -> Result<bool>;
        #[getter]
        fn transfer_policy_id(&self) -> Result<u64>;
        #[msg_sender]
        fn burn_blocked(&mut self, from: Address, amount: U256) -> Result<()>;
        #[msg_sender]
        fn mint_with_memo(&mut self, to: Address, amount: U256, memo: B256) -> Result<()>;
        #[msg_sender]
        fn burn_with_memo(&mut self, amount: U256, memo: B256) -> Result<()>;
        #[msg_sender]
        fn transfer_with_memo(&mut self, to: Address, amount: U256, memo: B256) -> Result<()>;
        #[msg_sender]
        fn transfer_from_with_memo(&mut self, from: Address, to: Address, amount: U256, memo: B256) -> Result<bool>;

        #[msg_sender]
        fn change_transfer_policy_id(&mut self, new_policy_id: u64) -> Result<()>;
        #[msg_sender]
        fn set_supply_cap(&mut self, new_supply_cap: U256) -> Result<()>;
        #[msg_sender]
        fn pause(&mut self) -> Result<()>;
        #[msg_sender]
        fn unpause(&mut self) -> Result<()>;
        #[msg_sender]
        fn set_next_quote_token(&mut self, new_quote_token: Address) -> Result<()>;
        #[msg_sender]
        fn complete_quote_token_update(&mut self) -> Result<()>;
    }

    pub trait IRewards {
        #[msg_sender]
        fn distribute_reward(&mut self, amount: U256) -> Result<()>;
        #[msg_sender]
        fn set_reward_recipient(&mut self, recipient: Address) -> Result<()>;
        #[msg_sender]
        fn claim_rewards(&mut self) -> Result<U256>;
        #[getter]
        fn opted_in_supply(&self) -> Result<u128>;
        #[getter]
        fn global_reward_per_token(&self) -> Result<U256>;
        #[getter]
        fn user_reward_info(&self, account: Address) -> Result<UserRewardInfo>;
        fn get_pending_rewards(&self, account: Address) -> Result<u128>;
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        InsufficientBalance { available: U256, required: U256, token: Address },
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
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
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
        RewardDistributed { #[indexed] funder: Address, amount: U256 },
        RewardRecipientSet { #[indexed] holder: Address, #[indexed] recipient: Address },
    }
}

pub use IRolesAuth::{Error as RolesAuthError, Event as RolesAuthEvent};
pub use ITIP20::{Error as TIP20Error, Event as TIP20Event};
