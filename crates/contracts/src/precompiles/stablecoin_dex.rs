pub use IStablecoinDEX::{
    IStablecoinDEXErrors as StablecoinDEXError, IStablecoinDEXEvents as StablecoinDEXEvents,
};

/// Minimum tick value for the orderbook price grid.
pub const MIN_TICK: i16 = -2000;
/// Maximum tick value for the orderbook price grid.
pub const MAX_TICK: i16 = 2000;
/// Price scale factor for tick-to-price conversions.
pub const PRICE_SCALE: u32 = 100_000;

crate::sol! {
    /// StablecoinDEX interface for managing orderbook based trading of stablecoins.
    ///
    /// The StablecoinDEX provides a limit orderbook system where users can:
    /// - Place limit orders (buy/sell) with specific price ticks
    /// - Place flip orders that automatically create opposite-side orders when filled
    /// - Execute swaps against existing liquidity
    /// - Manage internal balances for trading
    ///
    /// The exchange operates on pairs between base tokens and their designated quote tokens,
    /// using a tick-based pricing system for precise order matching.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IStablecoinDEX {
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
        function cancelStaleOrder(uint128 orderId) external;

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
        function nextOrderId() external view returns (uint128);
        function books(bytes32 pairKey) external view returns (Orderbook memory);

        // Constants (exposed as view functions)
        function MIN_TICK() external pure returns (int16);
        function MAX_TICK() external pure returns (int16);
        function TICK_SPACING() external pure returns (int16);
        function PRICE_SCALE() external pure returns (uint32);
        function MIN_ORDER_AMOUNT() external pure returns (uint128);
        function MIN_PRICE() external pure returns (uint32);
        function MAX_PRICE() external pure returns (uint32);

        // Price conversion functions
        function tickToPrice(int16 tick) external pure returns (uint32 price);
        function priceToTick(uint32 price) external pure returns (int16 tick);

        // Events
        event PairCreated(bytes32 indexed key, address indexed base, address indexed quote);
        event OrderPlaced(uint128 indexed orderId, address indexed maker, address indexed token, uint128 amount, bool isBid, int16 tick, bool isFlipOrder, int16 flipTick);
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
        error OrderNotStale();
    }
}
