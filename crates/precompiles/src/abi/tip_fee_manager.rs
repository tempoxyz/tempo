//! TIP Fee Manager bindings.

use tempo_precompiles_macros::abi;

#[abi(dispatch)]
#[rustfmt::skip]
pub mod IFeeManager {
    use alloy::primitives::{Address, B256, U256, uint};

    #[cfg(feature = "precompile")]
    use crate::error::Result;

    pub const FEE_BPS: u64 = 25; // 0.25% fee
    pub const BASIS_POINTS: u64 = 10000;
    pub const M: U256 = uint!(9970_U256); // m = 0.9970 (scaled by 10000)
    pub const N: U256 = uint!(9985_U256);
    pub const SCALE: U256 = uint!(10000_U256);
    pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);
    pub const MINIMUM_BALANCE: U256 = uint!(1_000_000_000_U256); // 1e9

    pub trait IFeeManager {
        fn user_tokens(&self, user: Address) -> Result<Address>;
        fn validator_tokens(&self, validator: Address) -> Result<Address>;
        fn collected_fees(&self, validator: Address, token: Address) -> Result<U256>;

        fn set_user_token(&mut self, token: Address) -> Result<()>;
        fn set_validator_token(&mut self, token: Address) -> Result<()>;
        fn distribute_fees(&mut self, validator: Address, token: Address) -> Result<()>;
    }

    pub trait IFeeAMM {
        fn get_pool_id(&self, user_token: Address, validator_token: Address) -> Result<B256>;
        fn get_pool(&self, user_token: Address, validator_token: Address) -> Result<Pool>;
        fn pools(&self, pool_id: B256) -> Result<Pool>;
        fn total_supply(&self, pool_id: B256) -> Result<U256>;
        fn liquidity_balances(&self, pool_id: B256, user: Address) -> Result<U256>;

        fn mint(&mut self, user_token: Address, validator_token: Address, amount_validator_token: U256, to: Address) -> Result<U256>;
        fn burn(&mut self, user_token: Address, validator_token: Address, liquidity: U256, to: Address) -> Result<(U256, U256)>;
        fn rebalance_swap(&mut self, user_token: Address, validator_token: Address, amount_out: U256, to: Address) -> Result<U256>;
    }

    // Structs
    #[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
    pub struct Pool {
        pub reserve_user_token: u128,
        pub reserve_validator_token: u128,
    }

    // Combined Error enum
    pub enum Error {
        // IFeeManager errors
        OnlyValidator,
        OnlySystemContract,
        InvalidToken,
        PoolDoesNotExist,
        InsufficientFeeTokenBalance,
        InternalError,
        CannotChangeWithinBlock,
        CannotChangeWithPendingFees,
        TokenPolicyForbids,
        // IFeeAMM errors
        IdenticalAddresses,
        InsufficientLiquidity,
        InsufficientReserves,
        InvalidAmount,
        DivisionByZero,
        InvalidSwapCalculation,
    }

    // Combined Event enum
    pub enum Event {
        // IFeeManager events
        UserTokenSet { #[indexed] user: Address, #[indexed] token: Address },
        ValidatorTokenSet { #[indexed] validator: Address, #[indexed] token: Address },
        FeesDistributed { #[indexed] validator: Address, #[indexed] token: Address, amount: U256 },
        // IFeeAMM events
        Mint { sender: Address, #[indexed] to: Address, #[indexed] user_token: Address, #[indexed] validator_token: Address, amount_validator_token: U256, liquidity: U256 },
        Burn { #[indexed] sender: Address, #[indexed] user_token: Address, #[indexed] validator_token: Address, amount_user_token: U256, amount_validator_token: U256, liquidity: U256, to: Address },
        RebalanceSwap { #[indexed] user_token: Address, #[indexed] validator_token: Address, #[indexed] swapper: Address, amount_in: U256, amount_out: U256 },
    }
}
