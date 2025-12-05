pub use IStablecoinExchange::{
    IStablecoinExchangeErrors as StablecoinExchangeError,
    IStablecoinExchangeEvents as StablecoinExchangeEvents,
};

use alloy::sol;

sol! {
    /// StablecoinExchange interface for managing order book based trading of stablecoins.
    ///
    /// The StablecoinExchange provides a limit order book system where users can:
    /// - Place limit orders (buy/sell) with specific price ticks
    /// - Place flip orders that automatically create opposite-side orders when filled
    /// - Execute swaps against existing liquidity
    /// - Manage internal balances for trading
    ///
    /// The exchange operates on pairs between base tokens and their designated quote tokens,
    /// using a tick-based pricing system for precise order matching.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    interface IStablecoinExchange {
        // Structs
        struct Order {
            uint128 orderId;
            address maker;
            bytes32 bookKey;
            bool isBid;
            int16 tick;
            uint128 amount;
            uint128 remaining;
            uint128 prev;
            uint128 next;
            bool isFlip;
            int16 flipTick;
        }

        struct PriceLevel {
            uint128 head;
            uint128 tail;
            uint128 totalLiquidity;
        }

        struct Orderbook {
            address base;
            address quote;
            int16 bestBidTick;
            int16 bestAskTick;
        }

        // Core Trading Functions
        function createPair(address base) external returns (bytes32 key);
        function place(address token, uint128 amount, bool isBid, int16 tick) external returns (uint128 orderId);
        function placeFlip(address token, uint128 amount, bool isBid, int16 tick, int16 flipTick) external returns (uint128 orderId);
        function cancel(uint128 orderId) external;
        function executeBlock() external;

        // Swap Functions
        function swapExactAmountIn(address tokenIn, address tokenOut, uint128 amountIn, uint128 minAmountOut) external returns (uint128 amountOut);
        function swapExactAmountOut(address tokenIn, address tokenOut, uint128 amountOut, uint128 maxAmountIn) external returns (uint128 amountIn);
        function quoteSwapExactAmountIn(address tokenIn, address tokenOut, uint128 amountIn) external view returns (uint128 amountOut);
        function quoteSwapExactAmountOut(address tokenIn, address tokenOut, uint128 amountOut) external view returns (uint128 amountIn);

        // Balance Management
        function balanceOf(address user, address token) external view returns (uint128);
        function withdraw(address token, uint128 amount) external;

        // View Functions
        function getOrder(uint128 orderId) external view returns (Order memory);

        function getTickLevel(address base, int16 tick, bool isBid) external view returns (uint128 head, uint128 tail, uint128 totalLiquidity);
        function pairKey(address tokenA, address tokenB) external pure returns (bytes32);
        function activeOrderId() external view returns (uint128);
        function pendingOrderId() external view returns (uint128);
        function books(bytes32 pairKey) external view returns (Orderbook memory);

        // Constants (exposed as view functions)
        function MIN_TICK() external pure returns (int16);
        function MAX_TICK() external pure returns (int16);
        function TICK_SPACING() external pure returns (int16);
        function PRICE_SCALE() external pure returns (uint32);
        function MIN_PRICE() external pure returns (uint32);
        function MAX_PRICE() external pure returns (uint32);

        // Price conversion functions
        function tickToPrice(int16 tick) external pure returns (uint32 price);
        function priceToTick(uint32 price) external pure returns (int16 tick);

        // Events
        event PairCreated(bytes32 indexed key, address indexed base, address indexed quote);
        event OrderPlaced(uint128 indexed orderId, address indexed maker, address indexed token, uint128 amount, bool isBid, int16 tick);
        event FlipOrderPlaced(uint128 indexed orderId, address indexed maker, address indexed token, uint128 amount, bool isBid, int16 tick, int16 flipTick);
        /// Pre-Allegretto: OrderFilled event without taker parameter
        event OrderFilled(uint128 indexed orderId, address indexed maker, uint128 amountFilled, bool partialFill);
        /// Post-Allegretto: OrderFilled event with taker parameter
        event OrderFilled(uint128 indexed orderId, address indexed maker, address indexed taker, uint128 amountFilled, bool partialFill);
        event OrderCancelled(uint128 indexed orderId);

        // Errors
        error Unauthorized();
        error PairDoesNotExist();
        error PairAlreadyExists();
        error OrderDoesNotExist();
        error IdenticalTokens();
        error InvalidToken();
        error TickOutOfBounds(int16 tick);
        error InvalidTick();
        error InvalidFlipTick();
        error InsufficientBalance();
        error InsufficientLiquidity();
        error InsufficientOutput();
        error MaxInputExceeded();
        error BelowMinimumOrderSize(uint128 amount);
        error InvalidBaseToken();
    }
}

impl StablecoinExchangeError {
    /// Creates an unauthorized access error.
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(IStablecoinExchange::Unauthorized {})
    }

    /// Creates an error when pair does not exist.
    pub const fn pair_does_not_exist() -> Self {
        Self::PairDoesNotExist(IStablecoinExchange::PairDoesNotExist {})
    }

    /// Creates an error when pair already exists.
    pub const fn pair_already_exists() -> Self {
        Self::PairAlreadyExists(IStablecoinExchange::PairAlreadyExists {})
    }

    /// Creates an error when order does not exist.
    pub const fn order_does_not_exist() -> Self {
        Self::OrderDoesNotExist(IStablecoinExchange::OrderDoesNotExist {})
    }

    /// Creates an error when trying to swap identical tokens.
    pub const fn identical_tokens() -> Self {
        Self::IdenticalTokens(IStablecoinExchange::IdenticalTokens {})
    }

    /// Creates an error when a token address is not a valid TIP20 token.
    pub const fn invalid_token() -> Self {
        Self::InvalidToken(IStablecoinExchange::InvalidToken {})
    }

    /// Creates an error for tick out of bounds.
    pub const fn tick_out_of_bounds(tick: i16) -> Self {
        Self::TickOutOfBounds(IStablecoinExchange::TickOutOfBounds { tick })
    }

    /// Creates an error for invalid flip tick.
    pub const fn invalid_flip_tick() -> Self {
        Self::InvalidFlipTick(IStablecoinExchange::InvalidFlipTick {})
    }

    /// Creates an error for invalid tick.
    pub const fn invalid_tick() -> Self {
        Self::InvalidTick(IStablecoinExchange::InvalidTick {})
    }

    /// Creates an error for insufficient balance.
    pub const fn insufficient_balance() -> Self {
        Self::InsufficientBalance(IStablecoinExchange::InsufficientBalance {})
    }

    /// Creates an error for insufficient liquidity.
    pub const fn insufficient_liquidity() -> Self {
        Self::InsufficientLiquidity(IStablecoinExchange::InsufficientLiquidity {})
    }

    /// Creates an error for insufficient output.
    pub const fn insufficient_output() -> Self {
        Self::InsufficientOutput(IStablecoinExchange::InsufficientOutput {})
    }

    /// Creates an error for max input exceeded.
    pub const fn max_input_exceeded() -> Self {
        Self::MaxInputExceeded(IStablecoinExchange::MaxInputExceeded {})
    }

    /// Creates an error for order amount below minimum.
    pub const fn below_minimum_order_size(amount: u128) -> Self {
        Self::BelowMinimumOrderSize(IStablecoinExchange::BelowMinimumOrderSize { amount })
    }

    /// Creates an error for invalid base token.
    pub const fn invalid_base_token() -> Self {
        Self::InvalidBaseToken(IStablecoinExchange::InvalidBaseToken {})
    }
}
