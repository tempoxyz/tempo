//! Stablecoin DEX bindings.

use tempo_precompiles_macros::abi;

#[abi(dispatch)]
#[rustfmt::skip]
pub mod IStablecoinDEX {
    use alloy::primitives::{Address, B256};

    #[cfg(feature = "precompile")]
    use crate::error::Result;

    // Constants
    pub const MIN_TICK: i16 = -2000;
    pub const MAX_TICK: i16 = 2000;
    pub const TICK_SPACING: i16 = 10;
    pub const PRICE_SCALE: u32 = 100_000;
    pub const MIN_PRICE: u32 = 98_000;
    pub const MAX_PRICE: u32 = 102_000;
    pub const MIN_ORDER_AMOUNT: u128 = 100_000_000;

    /// StablecoinDEX trait for managing orderbook based trading of stablecoins.
    ///
    /// The StablecoinDEX provides a limit orderbook system where users can:
    /// - Place limit orders (buy/sell) with specific price ticks
    /// - Place flip orders that automatically create opposite-side orders when filled
    /// - Execute swaps against existing liquidity
    /// - Manage internal balances for trading
    ///
    /// The exchange operates on pairs between base tokens and their designated quote tokens,
    /// using a tick-based pricing system for precise order matching.
    pub trait IStablecoinDEX {
        // Core Trading Functions
        fn create_pair(&mut self, base: Address) -> Result<B256>;
        fn place(&mut self, token: Address, amount: u128, is_bid: bool, tick: i16) -> Result<u128>;
        fn place_flip(&mut self, token: Address, amount: u128, is_bid: bool, tick: i16, flip_tick: i16) -> Result<u128>;
        fn cancel(&mut self, order_id: u128) -> Result<()>;
        fn cancel_stale_order(&mut self, order_id: u128) -> Result<()>;

        // Swap Functions
        fn swap_exact_amount_in(&mut self, token_in: Address, token_out: Address, amount_in: u128, min_amount_out: u128) -> Result<u128>;
        fn swap_exact_amount_out(&mut self, token_in: Address, token_out: Address, amount_out: u128, max_amount_in: u128) -> Result<u128>;
        fn quote_swap_exact_amount_in(&self, token_in: Address, token_out: Address, amount_in: u128) -> Result<u128>;
        fn quote_swap_exact_amount_out(&self, token_in: Address, token_out: Address, amount_out: u128) -> Result<u128>;

        // Balance Management
        fn balance_of(&self, user: Address, token: Address) -> Result<u128>;
        fn withdraw(&mut self, token: Address, amount: u128) -> Result<()>;

        // View Functions
        fn get_order(&self, order_id: u128) -> Result<Order>;
        fn get_tick_level(&self, base: Address, tick: i16, is_bid: bool) -> Result<PriceLevel>;
        fn pair_key(&self, token_a: Address, token_b: Address) -> Result<B256>;
        fn next_order_id(&self) -> Result<u128>;
        fn books(&self, pair_key: B256) -> Result<Orderbook>;

        // Price conversion functions
        fn tick_to_price(&self, tick: i16) -> Result<u32>;
        fn price_to_tick(&self, price: u32) -> Result<i16>;
    }

    // Structs
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Order {
        pub order_id: u128,
        pub maker: Address,
        pub book_key: B256,
        pub is_bid: bool,
        pub tick: i16,
        pub amount: u128,
        pub remaining: u128,
        pub prev: u128,
        pub next: u128,
        pub is_flip: bool,
        pub flip_tick: i16,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct PriceLevel {
        pub head: u128,
        pub tail: u128,
        pub total_liquidity: u128,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Orderbook {
        pub base: Address,
        pub quote: Address,
        pub best_bid_tick: i16,
        pub best_ask_tick: i16,
    }

    // Errors
    pub enum Error {
        Unauthorized,
        PairDoesNotExist,
        PairAlreadyExists,
        OrderDoesNotExist,
        IdenticalTokens,
        InvalidToken,
        TickOutOfBounds { tick: i16 },
        InvalidTick,
        InvalidFlipTick,
        InsufficientBalance,
        InsufficientLiquidity,
        InsufficientOutput,
        MaxInputExceeded,
        BelowMinimumOrderSize { amount: u128 },
        InvalidBaseToken,
        OrderNotStale,
    }

    // Events
    pub enum Event {
        PairCreated { #[indexed] key: B256, #[indexed] base: Address, #[indexed] quote: Address },
        OrderPlaced { #[indexed] order_id: u128, #[indexed] maker: Address, #[indexed] token: Address, amount: u128, is_bid: bool, tick: i16, is_flip_order: bool, flip_tick: i16 },
        OrderFilled { #[indexed] order_id: u128, #[indexed] maker: Address, #[indexed] taker: Address, amount_filled: u128, partial_fill: bool },
        OrderCancelled { #[indexed] order_id: u128 },
    }
}
