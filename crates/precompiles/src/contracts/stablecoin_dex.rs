use tempo_precompiles_macros::abi;

#[abi]
#[rustfmt::skip]
pub mod IStablecoinDEX {
    #[cfg(feature = "precompiles")]
    use crate::error::Result;

    use alloy::primitives::{Address, B256};

    // Constants from Solidity implementation
    pub const TICK_SPACING: i16 = 10;
    pub const MIN_TICK: i16 = -2000;
    pub const MAX_TICK: i16 = 2000;
    pub const PRICE_SCALE: u32 = 100_000;
    // PRICE_SCALE + MIN_TICK = 100_000 - 2000
    pub const MIN_PRICE: u32 = 98_000;
    // PRICE_SCALE + MAX_TICK = 100_000 + 2000
    pub const MAX_PRICE: u32 = 102_000;
    /// Minimum order size of $100 USD
    pub const MIN_ORDER_AMOUNT: u128 = 100_000_000;

    /// Represents an order in the stablecoin DEX orderbook.
    ///
    /// This struct matches the Solidity reference implementation in StablecoinDEX.sol.
    ///
    /// # Order Types
    /// - **Regular orders**: Orders with `is_flip = false`
    /// - **Flip orders**: Orders with `is_flip = true` that automatically create
    ///   a new order on the opposite side when fully filled
    ///
    /// # Order Lifecycle
    /// 1. Order is placed via `place()` or `placeFlip()` and immediately added to the orderbook
    /// 2. Orders can be filled (fully or partially) by swaps
    /// 3. Flip orders automatically create a new order on the opposite side when fully filled
    /// 4. Orders can be cancelled, removing them from the book and refunding escrow
    ///
    /// # Price-Time Priority
    /// Orders are sorted by price (tick), then by insertion time.
    /// The doubly linked list maintains insertion order - orders are added at the tail,
    /// so traversing from head to tail gives price-time priority.
    ///
    /// # Onchain Storage
    /// Orders are stored onchain in doubly linked lists organized by tick.
    /// Each tick maintains a FIFO queue of orders using `prev` and `next` pointers.
    #[derive(Debug, Clone, PartialEq, Eq, Storable)]
    pub struct Order {
        /// Unique identifier for this order
        pub order_id: u128,
        /// Address of the user who placed this order
        pub maker: Address,
        /// Orderbook key (identifies the trading pair)
        pub book_key: B256,
        /// Whether this is a bid (true) or ask (false) order
        pub is_bid: bool,
        /// Price tick
        pub tick: i16,
        /// Original order amount
        pub amount: u128,
        /// Remaining amount to be filled
        pub remaining: u128,
        /// Previous order ID in the doubly linked list (0 if head)
        pub prev: u128,
        /// Next order ID in the doubly linked list (0 if tail)
        pub next: u128,
        /// Whether this is a flip order
        pub is_flip: bool,
        /// Tick to flip to when fully filled (for flip orders, 0 for regular orders)
        /// For bid flips: flip_tick must be > tick
        /// For ask flips: flip_tick must be < tick
        pub flip_tick: i16,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Orderbook {
        /// Base token address
        pub base: Address,
        /// Quote token address
        pub quote: Address,
        /// Best bid tick for highest bid price
        pub best_bid_tick: i16,
        /// Best ask tick for lowest ask price
        pub best_ask_tick: i16,
    }


    #[derive(Debug, Clone, PartialEq, Eq)]
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
        PairCreated { #[indexed] key: B256, #[indexed] base: Address, #[indexed] quote: Address },
        OrderPlaced { #[indexed] order_id: u128, #[indexed] maker: Address, #[indexed] token: Address, amount: u128, is_bid: bool, tick: i16, is_flip_order: bool, flip_tick: i16 },
        OrderFilled { #[indexed] order_id: u128, #[indexed] maker: Address, #[indexed] taker: Address, amount_filled: u128, partial_fill: bool },
        OrderCancelled { #[indexed] order_id: u128 },
    }

    pub trait Interface {
        // View/pure functions
        /// Get user's balance for a specific token.
        #[getter = "balances"]
        fn balance_of(&self, user: Address, token: Address) -> Result<u128>;
        fn get_order(&self, order_id: u128) -> Result<Order>;
        fn get_tick_level(&self, base: Address, tick: i16, is_bid: bool) -> Result<(u128, u128, u128)>;
        fn pair_key(&self, token_a: Address, token_b: Address) -> Result<B256>;
        fn next_order_id(&self) -> Result<u128>;
        fn books(&self, pair_key: B256) -> Result<Orderbook>;
        fn tick_to_price(&self, tick: i16) -> Result<u32>;
        fn price_to_tick(&self, price: u32) -> Result<i16>;
        fn quote_swap_exact_amount_in(&self, token_in: Address, token_out: Address, amount_in: u128) -> Result<u128>;
        fn quote_swap_exact_amount_out(&self, token_in: Address, token_out: Address, amount_out: u128) -> Result<u128>;

        // Mutating functions
        fn create_pair(&mut self, base: Address) -> Result<B256>;
        #[msg_sender]
        fn place(&mut self, token: Address, amount: u128, is_bid: bool, tick: i16) -> Result<u128>;
        #[msg_sender]
        fn place_flip(&mut self, token: Address, amount: u128, is_bid: bool, tick: i16, flip_tick: i16) -> Result<u128>;
        #[msg_sender]
        fn cancel(&mut self, order_id: u128) -> Result<()>;
        fn cancel_stale_order(&mut self, order_id: u128) -> Result<()>;
        #[msg_sender]
        fn swap_exact_amount_in(&mut self, token_in: Address, token_out: Address, amount_in: u128, min_amount_out: u128) -> Result<u128>;
        #[msg_sender]
        fn swap_exact_amount_out(&mut self, token_in: Address, token_out: Address, amount_out: u128, max_amount_in: u128) -> Result<u128>;
        #[msg_sender]
        fn withdraw(&mut self, token: Address, amount: u128) -> Result<()>;
    }
}
