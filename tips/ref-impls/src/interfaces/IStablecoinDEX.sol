// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

interface IStablecoinDEX {

    // Structs for return types

    /// @notice Represents a price level in the orderbook with a doubly-linked list of orders
    /// @dev Orders are maintained in FIFO order at each tick level
    struct TickLevel {
        /// Order ID of the first order at this tick (0 if empty)
        uint128 head;
        /// Order ID of the last order at this tick (0 if empty)
        uint128 tail;
        /// Total liquidity available at this tick level
        uint128 totalLiquidity;
    }

    /// @notice Order data structure for tracking limit orders
    struct Order {
        /// Order ID
        uint128 orderId;
        /// Address of order maker
        address maker;
        /// Orderbook key
        bytes32 bookKey;
        /// Bid or ask indicator
        bool isBid;
        /// Price tick
        int16 tick;
        /// Original order amount
        uint128 amount;
        /// Remaining amount to fill
        uint128 remaining;
        /// Previous order ID in FIFO queue
        uint128 prev;
        /// Next order ID in FIFO queue
        uint128 next;
        /// Boolean indicating if order is flipOrder
        bool isFlip;
        /// Flip order tick to place new order at once current order fills
        int16 flipTick;
    }

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

    event OrderCancelled(uint128 indexed orderId);
    event OrderFilled(
        uint128 indexed orderId,
        address indexed maker,
        address indexed taker,
        uint128 amountFilled,
        bool partialFill
    );
    event OrderPlaced(
        uint128 indexed orderId,
        address indexed maker,
        address indexed token,
        uint128 amount,
        bool isBid,
        int16 tick,
        bool isFlipOrder,
        int16 flipTick
    );
    event PairCreated(bytes32 indexed key, address indexed base, address indexed quote);

    function MAX_PRICE() external view returns (uint32);

    function MAX_TICK() external view returns (int16);

    function MIN_PRICE() external view returns (uint32);

    function MIN_TICK() external view returns (int16);

    function TICK_SPACING() external view returns (int16);

    function PRICE_SCALE() external view returns (uint32);

    function MIN_ORDER_AMOUNT() external view returns (uint128);

    function nextOrderId() external view returns (uint128);

    function balanceOf(address user, address token) external view returns (uint128);

    function books(bytes32 pairKey)
        external
        view
        returns (address base, address quote, int16 bestBidTick, int16 bestAskTick);

    function cancel(uint128 orderId) external;

    function cancelStaleOrder(uint128 orderId) external;

    function createPair(address base) external returns (bytes32 key);

    function getTickLevel(
        address base,
        int16 tick,
        bool isBid
    )
        external
        view
        returns (uint128 head, uint128 tail, uint128 totalLiquidity);

    function getOrder(uint128 orderId) external view returns (Order memory);

    function pairKey(address tokenA, address tokenB) external pure returns (bytes32 key);

    function place(
        address token,
        uint128 amount,
        bool isBid,
        int16 tick
    )
        external
        returns (uint128 orderId);

    function placeFlip(
        address token,
        uint128 amount,
        bool isBid,
        int16 tick,
        int16 flipTick
    )
        external
        returns (uint128 orderId);

    function priceToTick(uint32 price) external pure returns (int16 tick);

    function quoteSwapExactAmountIn(
        address tokenIn,
        address tokenOut,
        uint128 amountIn
    )
        external
        view
        returns (uint128 amountOut);

    function quoteSwapExactAmountOut(
        address tokenIn,
        address tokenOut,
        uint128 amountOut
    )
        external
        view
        returns (uint128 amountIn);

    function swapExactAmountIn(
        address tokenIn,
        address tokenOut,
        uint128 amountIn,
        uint128 minAmountOut
    )
        external
        returns (uint128 amountOut);

    function swapExactAmountOut(
        address tokenIn,
        address tokenOut,
        uint128 amountOut,
        uint128 maxAmountIn
    )
        external
        returns (uint128 amountIn);

    function tickToPrice(int16 tick) external pure returns (uint32 price);

    function withdraw(address token, uint128 amount) external;

}
