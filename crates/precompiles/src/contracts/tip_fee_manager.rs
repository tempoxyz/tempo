//! TIP Fee Manager ABI definitions.
//!
//! This module defines two separate interfaces that together form the TIP Fee Manager:
//! - `IFeeManager`: Fee management functions (user/validator token preferences, fee distribution)
//! - `IFeeAMM`: AMM functions (pool management, liquidity operations, swaps)
//!
//! The `TipFeeManager` contract uses `#[contract(abi = [IFeeManager, IFeeAMM], dispatch)]`
//! to compose both modules into a unified `Calls` enum for precompile routing.

use tempo_precompiles_macros::abi;

/// Fee Manager interface for managing gas fee collection and distribution.
#[abi]
#[rustfmt::skip]
pub mod IFeeManager {
    use alloy::primitives::{Address, U256};

    #[cfg(feature = "precompiles")]
    use crate::error::Result;

    pub trait Interface {
        // View functions
        #[getter]
        fn user_tokens(&self, user: Address) -> Result<Address>;
        fn validator_tokens(&self, validator: Address) -> Result<Address>;
        #[getter]
        fn collected_fees(&self, validator: Address, token: Address) -> Result<U256>;

        // State-changing functions
        #[msg_sender]
        fn set_user_token(&mut self, token: Address) -> Result<()>;
        #[msg_sender]
        fn set_validator_token(&mut self, token: Address) -> Result<()>;
        fn distribute_fees(&mut self, validator: Address, token: Address) -> Result<()>;
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        OnlyValidator,
        OnlySystemContract,
        InvalidToken,
        PoolDoesNotExist,
        InsufficientFeeTokenBalance,
        CannotChangeWithinBlock,
        CannotChangeWithPendingFees,
        TokenPolicyForbids,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
        UserTokenSet { #[indexed] user: Address, #[indexed] token: Address },
        ValidatorTokenSet { #[indexed] validator: Address, #[indexed] token: Address },
        FeesDistributed { #[indexed] validator: Address, #[indexed] token: Address, amount: U256 },
    }
}

/// TIP Fee AMM interface for stablecoin pool management and swaps.
#[abi]
#[rustfmt::skip]
pub mod IFeeAMM {
    use alloy::primitives::{Address, B256, U256, uint};

    #[cfg(feature = "precompiles")]
    use crate::error::Result;

    // Structs
    #[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
    pub struct Pool {
        pub reserve_user_token: u128,
        pub reserve_validator_token: u128,
    }

    // Constants (auto-generates getter methods via macro)
    pub const M: U256 = uint!(9970_U256); // m = 0.9970 (scaled by 10000)
    pub const N: U256 = uint!(9985_U256);
    pub const SCALE: U256 = uint!(10000_U256);
    pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);

    pub trait Interface {
        // Pool management (view)
        fn get_pool_id(&self, user_token: Address, validator_token: Address) -> Result<B256>;
        fn get_pool(&self, user_token: Address, validator_token: Address) -> Result<Pool>;
        #[getter]
        fn pools(&self, pool_id: B256) -> Result<Pool>;

        // Liquidity balances (view)
        #[getter]
        fn total_supply(&self, pool_id: B256) -> Result<U256>;
        #[getter]
        fn liquidity_balances(&self, pool_id: B256, user: Address) -> Result<U256>;

        // Liquidity operations (mutate)
        #[msg_sender]
        fn mint(&mut self, user_token: Address, validator_token: Address, amount_validator_token: U256, to: Address) -> Result<U256>;
        #[msg_sender]
        fn burn(&mut self, user_token: Address, validator_token: Address, liquidity: U256, to: Address) -> Result<(U256, U256)>;

        // Swapping
        #[msg_sender]
        fn rebalance_swap(&mut self, user_token: Address, validator_token: Address, amount_out: U256, to: Address) -> Result<U256>;
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        IdenticalAddresses,
        InsufficientLiquidity,
        InsufficientReserves,
        InvalidAmount,
        DivisionByZero,
        InvalidSwapCalculation,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
        Mint { sender: Address, #[indexed] to: Address, #[indexed] user_token: Address, #[indexed] validator_token: Address, amount_validator_token: U256, liquidity: U256 },
        Burn { #[indexed] sender: Address, #[indexed] user_token: Address, #[indexed] validator_token: Address, amount_user_token: U256, amount_validator_token: U256, liquidity: U256, to: Address },
        RebalanceSwap { #[indexed] user_token: Address, #[indexed] validator_token: Address, #[indexed] swapper: Address, amount_in: U256, amount_out: U256 },
    }
}

// Re-export error types with aliases for compatibility
pub use IFeeAMM::Error as FeeAMMError;
pub use IFeeManager::Error as FeeManagerError;

// Re-export event types with aliases
pub use IFeeAMM::Event as FeeAMMEvent;
pub use IFeeManager::Event as FeeManagerEvent;
