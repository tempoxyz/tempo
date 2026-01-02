// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20Factory } from "./TIP20Factory.sol";
import { TIP403Registry } from "./TIP403Registry.sol";
import { IStablecoinExchange } from "./interfaces/IStablecoinExchange.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";

contract StablecoinExchange is IStablecoinExchange {

    address internal constant FACTORY = 0x20Fc000000000000000000000000000000000000;
    TIP403Registry internal constant TIP403_REGISTRY =
        TIP403Registry(0x403c000000000000000000000000000000000000);

    /// @notice Minimum allowed tick
    int16 public constant MIN_TICK = -2000;

    /// @notice Maximum allowed tick
    int16 public constant MAX_TICK = 2000;

    /// @notice Allowed tick spacing for order placement (ticks must be divisible by this)
    int16 public constant TICK_SPACING = 10;

    /// @notice Price scaling factor (5 decimal places for 0.1 bps precision)
    uint32 public constant PRICE_SCALE = 100_000;

    /// @notice Minimum valid price (PRICE_SCALE + int16.min)
    uint32 public constant MIN_PRICE = 67_232;

    /// @notice Maximum valid price (PRICE_SCALE + int16.max)
    uint32 public constant MAX_PRICE = 132_767;

    /// @notice Minimum order amount (100 units with 6 decimals)
    uint128 public constant MIN_ORDER_AMOUNT = 100_000_000;

    /// @notice TIP20 token address prefix (12 bytes)
    bytes12 public constant TIP20_PREFIX = 0x20C000000000000000000000;

    /// @notice Orderbook for token pair with price-time priority
    /// @dev Uses tick-based pricing with bitmaps for price discovery
    /// @dev Order and TickLevel structs are inherited from IStablecoinExchange
    struct Orderbook {
        /// Base token address
        address base;
        /// Quote token address
        address quote;
        /// Bid orders by tick
        mapping(int16 => IStablecoinExchange.TickLevel) bids;
        /// Ask orders by tick
        mapping(int16 => IStablecoinExchange.TickLevel) asks;
        /// Best bid tick for highest bid price
        int16 bestBidTick;
        /// Best ask tick for lowest ask price
        int16 bestAskTick;
        /// Bid tick bitmaps for efficient price discovery
        mapping(int16 => uint256) bidBitmap;
        /// Ask tick bitmaps for efficient price discovery
        mapping(int16 => uint256) askBitmap;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// Mapping of pair key to orderbook
    mapping(bytes32 pairKey => Orderbook orderbook) public books;

    /// Mapping of order ID to order data
    mapping(uint128 orderId => IStablecoinExchange.Order order) internal orders;

    /// User balances
    mapping(address user => mapping(address token => uint128 balance)) internal balances;

    /// Next order ID to be assigned
    uint128 public nextOrderId = 1;

    /*//////////////////////////////////////////////////////////////
                              Functions
    //////////////////////////////////////////////////////////////*/

    /// @notice Convert relative tick to scaled price
    function tickToPrice(int16 tick) public pure returns (uint32 price) {
        return uint32(int32(PRICE_SCALE) + int32(tick));
    }

    /// @notice Convert scaled price to relative tick
    function priceToTick(uint32 price) public pure returns (int16 tick) {
        if (price < MIN_PRICE || price > MAX_PRICE) {
            // Calculate the tick to include in the error
            tick = int16(int32(price) - int32(PRICE_SCALE));
            revert IStablecoinExchange.TickOutOfBounds(tick);
        }
        return int16(int32(price) - int32(PRICE_SCALE));
    }

    /// @notice Set bit in bitmap to mark tick as active
    function _setTickBit(bytes32 bookKey, int16 tick, bool isBid) internal {
        Orderbook storage book = books[bookKey];
        int16 wordIndex = tick >> 8;
        uint8 bitIndex = uint8(int8(tick));
        uint256 mask = (uint256(1) << bitIndex);
        if (isBid) {
            book.bidBitmap[wordIndex] |= mask;
        } else {
            book.askBitmap[wordIndex] |= mask;
        }
    }

    /// @notice Clear bit in bitmap to mark tick as inactive
    function _clearTickBit(bytes32 bookKey, int16 tick, bool isBid) internal {
        Orderbook storage book = books[bookKey];
        int16 wordIndex = tick >> 8;
        uint8 bitIndex = uint8(int8(tick));
        uint256 mask = ~(uint256(1) << bitIndex);
        if (isBid) {
            book.bidBitmap[wordIndex] &= mask;
        } else {
            book.askBitmap[wordIndex] &= mask;
        }
    }

    /// @notice Check if an account is authorized by a token's transfer policy
    /// @param token The token to check the policy of
    /// @param account The account to check authorization for
    /// @return True if both the account and this contract are authorized
    function _checkTransferPolicy(address token, address account) internal view returns (bool) {
        uint64 policyId = ITIP20(token).transferPolicyId();
        return TIP403_REGISTRY.isAuthorized(policyId, account)
            && TIP403_REGISTRY.isAuthorized(policyId, address(this));
    }

    /// @notice Generate deterministic key for ordered (base, quote) token pair
    /// @return key pair key
    /// @dev The first argument MUST be the base token and the second the quote token.
    function pairKey(address base, address quote) public pure returns (bytes32 key) {
        key = keccak256(abi.encodePacked(base, quote));
    }

    /// @notice Creates a new trading pair between base and quote tokens
    /// @param base Base token address
    /// @return key The orderbook key for the created pair
    /// @dev Automatically sets tick bounds to ±2% from the peg price of 1.0
    function createPair(address base) external returns (bytes32 key) {
        // Validate that base is a TIP20 token
        if (!TIP20Factory(FACTORY).isTIP20(base)) {
            revert ITIP20.InvalidBaseToken();
        }

        address quote = address(ITIP20(base).quoteToken());
        // Only USD-denominated tokens are supported, and their quotes must also be USD
        if (keccak256(bytes(ITIP20(base).currency())) != keccak256(bytes("USD"))) {
            revert ITIP20.InvalidCurrency();
        }
        if (keccak256(bytes(ITIP20(quote).currency())) != keccak256(bytes("USD"))) {
            revert ITIP20.InvalidCurrency();
        }

        key = pairKey(base, quote);

        // Create new orderbook for pair
        Orderbook storage book = books[key];
        if (book.base != address(0)) {
            revert IStablecoinExchange.PairAlreadyExists();
        }
        book.base = base;
        book.quote = quote;

        book.bestBidTick = type(int16).min;
        book.bestAskTick = type(int16).max;

        emit PairCreated(key, base, quote);
    }

    /// @notice Internal function to place order and immediately add to orderbook
    /// @param base Base token address
    /// @param quote Quote token address
    /// @param amount Order amount in base token
    /// @param isBid True for buy orders, false for sell orders
    /// @param tick Price tick for the order
    /// @param isFlip Whether this is a flip order
    /// @param flipTick Target tick for flip (ignored if not flip order)
    /// @return orderId The assigned order ID
    function _placeOrder(
        address base,
        address quote,
        uint128 amount,
        address maker,
        bool isBid,
        int16 tick,
        bool isFlip,
        int16 flipTick,
        bool revertOnTransferFail
    ) internal returns (uint128 orderId) {
        bytes32 key = pairKey(base, quote);
        Orderbook storage book = books[key];

        if (book.base == address(0)) {
            revert IStablecoinExchange.PairDoesNotExist();
        }

        if (tick < MIN_TICK || tick > MAX_TICK) {
            revert IStablecoinExchange.TickOutOfBounds(tick);
        }
        if (tick % TICK_SPACING != 0) revert IStablecoinExchange.InvalidTick();

        if (amount < MIN_ORDER_AMOUNT) {
            revert IStablecoinExchange.BelowMinimumOrderSize(amount);
        }

        if (isFlip) {
            if (flipTick < MIN_TICK || flipTick > MAX_TICK) {
                revert IStablecoinExchange.InvalidFlipTick();
            }
            if (flipTick % TICK_SPACING != 0) {
                revert IStablecoinExchange.InvalidFlipTick();
            }

            if (isBid) {
                if (flipTick <= tick) {
                    revert IStablecoinExchange.InvalidFlipTick();
                }
            } else {
                if (flipTick >= tick) {
                    revert IStablecoinExchange.InvalidFlipTick();
                }
            }
        }
        {
            // Calculate escrow amount and token
            uint128 escrowAmount;
            address escrowToken;
            if (isBid) {
                // For bids, escrow quote tokens based on price
                escrowToken = quote;
                uint32 price = tickToPrice(tick);
                escrowAmount = uint128((uint256(amount) * uint256(price)) / uint256(PRICE_SCALE));
            } else {
                // For asks, escrow base tokens
                escrowToken = base;
                escrowAmount = amount;
            }

            // Check if maker and DEX are authorized by both tokens' transfer policies
            if (!_checkTransferPolicy(base, maker) || !_checkTransferPolicy(quote, maker)) {
                if (revertOnTransferFail) {
                    revert ITIP20.PolicyForbids();
                } else {
                    return 0;
                }
            }

            // Check if the user has a balance, transfer the rest
            uint128 userBalance = balances[maker][escrowToken];
            if (userBalance >= escrowAmount) {
                balances[maker][escrowToken] -= escrowAmount;
            } else if (revertOnTransferFail) {
                balances[maker][escrowToken] = 0;
                ITIP20(escrowToken).transferFrom(maker, address(this), escrowAmount - userBalance);
            } else {
                // For flip orders (revertOnTransferFail = false), only use internal balance
                return 0;
            }
        }
        orderId = nextOrderId;
        ++nextOrderId;

        orders[orderId] = IStablecoinExchange.Order({
            orderId: orderId,
            maker: maker,
            bookKey: key,
            isBid: isBid,
            tick: tick,
            amount: amount,
            remaining: amount,
            prev: 0,
            next: 0,
            isFlip: isFlip,
            flipTick: flipTick
        });

        // Immediately link order into the active orderbook
        _commitOrderToBook(orderId, key, tick, isBid, amount);

        emit OrderPlaced(orderId, maker, base, amount, isBid, tick);
        return orderId;
    }

    /// @notice Link an order into the active orderbook
    /// @param orderId The order ID to link
    /// @param bookKey The orderbook key
    /// @param tick The tick level
    /// @param isBid Whether this is a bid order
    /// @param amount The order amount (for liquidity tracking)
    function _commitOrderToBook(
        uint128 orderId,
        bytes32 bookKey,
        int16 tick,
        bool isBid,
        uint128 amount
    ) internal {
        Orderbook storage book = books[bookKey];
        IStablecoinExchange.TickLevel storage level = isBid ? book.bids[tick] : book.asks[tick];

        uint128 prevTail = level.tail;
        if (prevTail == 0) {
            level.head = orderId;
            level.tail = orderId;
            _setTickBit(bookKey, tick, isBid);

            // Update best bid/ask when new tick becomes active
            if (isBid) {
                if (tick > book.bestBidTick) {
                    book.bestBidTick = tick;
                }
            } else {
                if (tick < book.bestAskTick) {
                    book.bestAskTick = tick;
                }
            }
        } else {
            orders[prevTail].next = orderId;
            orders[orderId].prev = prevTail;
            level.tail = orderId;
        }

        // Increment total liquidity for this tick level
        level.totalLiquidity += amount;
    }

    /// @notice Place a limit order on the orderbook
    /// @param token Token address (system determines base/quote pairing)
    /// @param amount Order amount in base token
    /// @param isBid True for buy orders, false for sell orders
    /// @param tick Price tick for the order
    /// @return orderId The assigned order ID
    function place(address token, uint128 amount, bool isBid, int16 tick)
        external
        returns (uint128 orderId)
    {
        address quote = address(ITIP20(token).quoteToken());
        orderId = _placeOrder(token, quote, amount, msg.sender, isBid, tick, false, 0, true);
    }

    /// @notice Place a flip order that auto-flips when filled
    /// @param token Token address
    /// @param amount Order amount in base token
    /// @param isBid True for bid (buy), false for ask (sell)
    /// @param tick Price tick for the order
    /// @param flipTick Target tick to flip to when order is filled
    /// @return orderId The assigned order ID
    function placeFlip(address token, uint128 amount, bool isBid, int16 tick, int16 flipTick)
        external
        returns (uint128 orderId)
    {
        address quote = address(ITIP20(token).quoteToken());
        orderId = _placeOrder(token, quote, amount, msg.sender, isBid, tick, true, flipTick, true);
        emit FlipOrderPlaced(orderId, msg.sender, token, amount, isBid, tick, flipTick);
    }

    function cancel(uint128 orderId) external {
        IStablecoinExchange.Order storage order = orders[orderId];
        if (order.maker == address(0)) {
            revert IStablecoinExchange.OrderDoesNotExist();
        }
        if (order.maker != msg.sender) {
            revert IStablecoinExchange.Unauthorized();
        }

        _cancelOrder(orderId, order);
    }

    /// @notice Cancel an order where the maker is forbidden by TIP-403 policy
    /// @dev Allows anyone to clean up stale orders from blacklisted makers
    /// @param orderId The order ID to cancel
    function cancelStaleOrder(uint128 orderId) external {
        IStablecoinExchange.Order storage order = orders[orderId];
        if (order.maker == address(0)) {
            revert IStablecoinExchange.OrderDoesNotExist();
        }

        Orderbook storage book = books[order.bookKey];
        address token = order.isBid ? book.quote : book.base;

        // Check if maker is forbidden by the token's transfer policy
        uint64 policyId = ITIP20(token).transferPolicyId();
        if (TIP403_REGISTRY.isAuthorized(policyId, order.maker)) {
            revert IStablecoinExchange.OrderNotStale();
        }

        _cancelOrder(orderId, order);
    }

    /// @notice Internal function to cancel an order and refund escrow
    /// @dev Caller must validate authorization before calling
    /// @param orderId The order ID to cancel
    /// @param order Storage reference to the order
    function _cancelOrder(uint128 orderId, IStablecoinExchange.Order storage order) internal {
        Orderbook storage book = books[order.bookKey];
        address token = order.isBid ? book.quote : book.base;
        bool isBid = order.isBid;
        IStablecoinExchange.TickLevel storage level =
            isBid ? book.bids[order.tick] : book.asks[order.tick];

        if (order.prev != 0) {
            orders[order.prev].next = order.next;
        } else {
            level.head = order.next;
        }

        if (order.next != 0) {
            orders[order.next].prev = order.prev;
        } else {
            level.tail = order.prev;
        }

        // Decrement total liquidity
        level.totalLiquidity -= order.remaining;

        if (level.head == 0) {
            _clearTickBit(order.bookKey, order.tick, isBid);
        }

        // Credit escrow amount to user's withdrawable balance
        uint128 escrowAmount;
        if (order.isBid) {
            // For bids, escrow quote tokens based on price
            uint32 price = tickToPrice(order.tick);
            escrowAmount =
                uint128((uint256(order.remaining) * uint256(price)) / uint256(PRICE_SCALE));
        } else {
            // For asks, escrow base tokens
            escrowAmount = order.remaining;
        }
        balances[order.maker][token] += escrowAmount;

        delete orders[orderId];

        emit OrderCancelled(orderId);
    }

    /// @notice Withdraw tokens from exchange balance
    /// @param token Token address to withdraw
    /// @param amount Amount to withdraw
    function withdraw(address token, uint128 amount) external {
        uint128 balance = balances[msg.sender][token];
        if (balance < amount) revert IStablecoinExchange.InsufficientBalance();
        balances[msg.sender][token] -= amount;

        ITIP20(token).transfer(msg.sender, amount);
    }

    /// @notice Get user's token balance on the exchange
    /// @param user User address
    /// @param token Token address
    /// @return User's balance for the token
    function balanceOf(address user, address token) external view returns (uint128) {
        return balances[user][token];
    }

    /// @notice Get tick level information
    /// @param base Base token in pair
    /// @param tick Price tick
    /// @param isBid boolean to indicate bid/ask
    /// @return head First order ID tick
    /// @return tail Last order ID tick
    /// @return totalLiquidity Total liquidity at tick
    function getTickLevel(address base, int16 tick, bool isBid)
        external
        view
        returns (uint128 head, uint128 tail, uint128 totalLiquidity)
    {
        address quote = address(ITIP20(base).quoteToken());
        bytes32 key = pairKey(base, quote);
        Orderbook storage book = books[key];
        IStablecoinExchange.TickLevel memory level = isBid ? book.bids[tick] : book.asks[tick];
        return (level.head, level.tail, level.totalLiquidity);
    }

    /// @notice Get order information by order ID
    /// @param orderId The order ID to query
    /// @return order The order data
    function getOrder(uint128 orderId)
        external
        view
        returns (IStablecoinExchange.Order memory order)
    {
        IStablecoinExchange.Order storage o = orders[orderId];
        if (o.maker == address(0)) {
            revert IStablecoinExchange.OrderDoesNotExist();
        }
        return o;
    }

    /// @notice Quote swapping tokens for exact amount out (supports multi-hop routing)
    /// @param tokenIn Token to spend
    /// @param tokenOut Token to buy
    /// @param amountOut Amount of tokenOut to buy
    /// @return amountIn Amount of tokenIn needed
    function quoteSwapExactAmountOut(address tokenIn, address tokenOut, uint128 amountOut)
        external
        view
        returns (uint128 amountIn)
    {
        (bytes32[] memory route, bool[] memory directions) = findTradePath(tokenIn, tokenOut);

        // Work backwards from output to calculate input needed
        uint128 amount = amountOut;
        for (uint256 i = route.length; i > 0; i--) {
            bytes32 key = route[i - 1];
            bool baseForQuote = directions[i - 1];
            Orderbook storage book = books[key];
            amount = _quoteExactOut(key, book, baseForQuote, amount);
        }

        amountIn = amount;
    }

    /// @notice Fill an order and handle cleanup when fully filled
    /// @param orderId The order ID to fill
    /// @param fillAmount The amount to fill
    /// @return nextOrderAtTick The next order ID to process (0 if no more liquidity at this tick)
    function _fillOrder(uint128 orderId, uint128 fillAmount)
        internal
        returns (uint128 nextOrderAtTick)
    {
        // NOTE: This can be much more optimized but since this is only a reference contract, readability was prioritized
        IStablecoinExchange.Order storage order = orders[orderId];
        Orderbook storage book = books[order.bookKey];
        bool isBid = order.isBid;
        IStablecoinExchange.TickLevel storage level =
            isBid ? book.bids[order.tick] : book.asks[order.tick];

        // Fill the order
        order.remaining -= fillAmount;
        level.totalLiquidity -= fillAmount;

        emit OrderFilled(orderId, order.maker, msg.sender, fillAmount, order.remaining > 0);

        // Credit maker with appropriate tokens
        if (isBid) {
            // Bid order: maker gets base tokens (exact amount)
            balances[order.maker][book.base] += fillAmount;
        } else {
            // Ask order: maker gets quote tokens - round UP to favor maker
            uint32 price = tickToPrice(order.tick);
            uint128 quoteAmount =
                uint128((uint256(fillAmount) * uint256(price) + PRICE_SCALE - 1) / PRICE_SCALE);
            balances[order.maker][book.quote] += quoteAmount;
        }

        if (order.remaining == 0) {
            // Order fully filled
            nextOrderAtTick = order.next;

            // Remove from linked list
            if (order.prev != 0) {
                orders[order.prev].next = order.next;
            } else {
                level.head = order.next;
            }

            if (order.next != 0) {
                orders[order.next].prev = order.prev;
            } else {
                level.tail = order.prev;
            }

            // If flip order, place order at flip tick on opposite side
            if (order.isFlip) {
                _placeOrder(
                    book.base,
                    book.quote,
                    order.amount,
                    order.maker,
                    !order.isBid,
                    order.flipTick,
                    true,
                    order.tick,
                    false
                );
            }

            delete orders[orderId];

            // Check if tick is exhausted and return 0 if so
            if (level.head == 0) {
                _clearTickBit(order.bookKey, order.tick, isBid);
                return 0;
            }
        } else {
            // Order partially filled, continue with same order
            nextOrderAtTick = orderId;
        }
    }

    /// @notice Decrement user's internal balance or transfer from external wallet
    /// @param user The user to transfer from
    /// @param token The token to transfer
    /// @param amount The amount to transfer
    function _decrementBalanceOrTransferFrom(address user, address token, uint128 amount) internal {
        // Check if user is authorized by the token's transfer policy before using internal balance
        uint64 policyId = ITIP20(token).transferPolicyId();
        if (
            !TIP403_REGISTRY.isAuthorized(policyId, user)
                || !TIP403_REGISTRY.isAuthorized(policyId, address(this))
        ) {
            revert ITIP20.PolicyForbids();
        }

        uint128 userBalance = balances[user][token];
        if (userBalance >= amount) {
            balances[user][token] -= amount;
        } else {
            balances[user][token] = 0;
            uint128 remaining = amount - userBalance;
            ITIP20(token).transferFrom(user, address(this), remaining);
        }
    }

    /// @notice Swap tokens for exact amount out (supports multi-hop routing)
    /// @param tokenIn Token to spend
    /// @param tokenOut Token to buy
    /// @param amountOut Amount of tokenOut to buy
    /// @param maxAmountIn Maximum amount of tokenIn to spend
    /// @return amountIn Actual amount of tokenIn spent
    function swapExactAmountOut(
        address tokenIn,
        address tokenOut,
        uint128 amountOut,
        uint128 maxAmountIn
    ) external returns (uint128 amountIn) {
        (bytes32[] memory route, bool[] memory directions) = findTradePath(tokenIn, tokenOut);

        // Work backwards from output to calculate input needed - intermediate amounts are TRANSITORY
        uint128 amount = amountOut;
        for (uint256 i = route.length; i > 0; i--) {
            bytes32 key = route[i - 1];
            bool baseForQuote = directions[i - 1];
            Orderbook storage book = books[key];
            amount = _fillOrdersExactOut(key, book, baseForQuote, amount);
        }

        amountIn = amount;
        if (amountIn > maxAmountIn) {
            revert IStablecoinExchange.MaxInputExceeded();
        }

        _decrementBalanceOrTransferFrom(msg.sender, tokenIn, amountIn);
        ITIP20(tokenOut).transfer(msg.sender, amountOut);
    }

    /// @notice Quote the proceeds from swapping a specific amount of tokens (supports multi-hop routing)
    /// @param tokenIn Token to sell
    /// @param tokenOut Token to receive
    /// @param amountIn Amount of tokenIn to sell
    /// @return amountOut Amount of tokenOut to receive
    function quoteSwapExactAmountIn(address tokenIn, address tokenOut, uint128 amountIn)
        external
        view
        returns (uint128 amountOut)
    {
        (bytes32[] memory route, bool[] memory directions) = findTradePath(tokenIn, tokenOut);

        // Work forwards from input to calculate output
        uint128 amount = amountIn;
        for (uint256 i = 0; i < route.length; i++) {
            bytes32 key = route[i];
            bool baseForQuote = directions[i];
            Orderbook storage book = books[key];
            amount = _quoteExactIn(key, book, baseForQuote, amount);
        }

        amountOut = amount;
    }

    /// @notice Swap tokens for exact amount in (supports multi-hop routing)
    /// @param tokenIn Token to sell
    /// @param tokenOut Token to receive
    /// @param amountIn Amount of tokenIn to sell
    /// @param minAmountOut Minimum amount of tokenOut to receive
    /// @return amountOut Actual amount of tokenOut received
    function swapExactAmountIn(
        address tokenIn,
        address tokenOut,
        uint128 amountIn,
        uint128 minAmountOut
    ) external returns (uint128 amountOut) {
        (bytes32[] memory route, bool[] memory directions) = findTradePath(tokenIn, tokenOut);

        // Work forwards from input to calculate output - intermediate amounts are TRANSITORY
        uint128 amount = amountIn;
        for (uint256 i = 0; i < route.length; i++) {
            bytes32 key = route[i];
            bool baseForQuote = directions[i];
            Orderbook storage book = books[key];
            amount = _fillOrdersExactIn(key, book, baseForQuote, amount);
        }

        amountOut = amount;
        if (amountOut < minAmountOut) {
            revert IStablecoinExchange.InsufficientOutput();
        }

        _decrementBalanceOrTransferFrom(msg.sender, tokenIn, amountIn);
        ITIP20(tokenOut).transfer(msg.sender, amountOut);
    }

    /// @notice Fill orders for exact output amount
    /// @param key Orderbook key
    /// @param book Orderbook storage reference
    /// @param baseForQuote True if spending base for quote, false if spending quote for base
    /// @param amountOut Exact amount of output tokens desired
    /// @return amountIn Actual amount of input tokens spent
    function _fillOrdersExactOut(
        bytes32 key,
        Orderbook storage book,
        bool baseForQuote,
        uint128 amountOut
    ) internal returns (uint128 amountIn) {
        uint128 remainingOut = amountOut;

        if (baseForQuote) {
            int16 currentTick = book.bestBidTick;
            // If there is no liquidity, revert
            if (currentTick == type(int16).min) {
                revert IStablecoinExchange.InsufficientLiquidity();
            }

            IStablecoinExchange.TickLevel storage level = book.bids[currentTick];
            uint128 orderId = level.head;

            while (remainingOut > 0) {
                // Get the price at the current tick and fetch the current order from storage
                uint32 price = tickToPrice(currentTick);
                IStablecoinExchange.Order memory currentOrder = orders[orderId];

                // For bids: round UP baseNeeded and add 1 to ensure full order consumption.
                // This guards against ceil(floor(x) * inverse) < x rounding edge cases.
                uint128 baseNeeded =
                    uint128((uint256(remainingOut) * PRICE_SCALE + price - 1) / price) + 1;
                uint128 fillAmount;

                // Calculate how much quote to receive for fillAmount of base
                if (baseNeeded > currentOrder.remaining) {
                    fillAmount = currentOrder.remaining;
                    remainingOut -= (fillAmount * price) / PRICE_SCALE;
                } else {
                    fillAmount = baseNeeded;
                    remainingOut = 0;
                }
                amountIn += fillAmount;

                // Fill the order and get next order
                orderId = _fillOrder(orderId, fillAmount);

                if (remainingOut == 0) {
                    return amountIn;
                }

                // If tick is exhausted, move to next tick
                if (orderId == 0) {
                    bool initialized;
                    (currentTick, initialized) = nextInitializedBidTick(key, currentTick);
                    if (!initialized) {
                        revert IStablecoinExchange.InsufficientLiquidity();
                    }

                    level = book.bids[currentTick];
                    book.bestBidTick = currentTick;
                    orderId = level.head;
                }
            }
        } else {
            // quote for base
            int16 currentTick = book.bestAskTick;
            // If there is no liquidity, revert
            if (currentTick == type(int16).max) {
                revert IStablecoinExchange.InsufficientLiquidity();
            }

            IStablecoinExchange.TickLevel storage level = book.asks[currentTick];
            uint128 orderId = level.head;

            while (remainingOut > 0) {
                uint32 price = tickToPrice(currentTick);
                IStablecoinExchange.Order memory currentOrder = orders[orderId];

                uint128 fillAmount;

                if (remainingOut > currentOrder.remaining) {
                    fillAmount = currentOrder.remaining;
                    remainingOut -= fillAmount;
                } else {
                    fillAmount = remainingOut;
                    remainingOut = 0;
                }

                // Calculate how much quote taker pays (maker receives) - round UP to favor maker
                uint128 quoteIn =
                    uint128((uint256(fillAmount) * uint256(price) + PRICE_SCALE - 1) / PRICE_SCALE);
                amountIn += quoteIn;

                // Fill the order and get next order
                orderId = _fillOrder(orderId, fillAmount);

                if (remainingOut == 0) {
                    return amountIn;
                }

                // If tick is exhausted, move to next tick
                if (orderId == 0) {
                    bool initialized;
                    (currentTick, initialized) = nextInitializedAskTick(key, currentTick);
                    if (!initialized) {
                        revert IStablecoinExchange.InsufficientLiquidity();
                    }

                    level = book.asks[currentTick];
                    book.bestAskTick = currentTick;
                    orderId = level.head;
                }
            }
        }
    }

    /// @notice Fill orders for exact input amount
    /// @param key Orderbook key
    /// @param book Orderbook storage reference
    /// @param baseForQuote True if spending base for quote, false if spending quote for base
    /// @param amountIn Exact amount of input tokens to spend
    /// @return amountOut Actual amount of output tokens received
    function _fillOrdersExactIn(
        bytes32 key,
        Orderbook storage book,
        bool baseForQuote,
        uint128 amountIn
    ) internal returns (uint128 amountOut) {
        uint128 remainingIn = amountIn;

        if (baseForQuote) {
            int16 currentTick = book.bestBidTick;
            // If there is no liquidity, revert
            if (currentTick == type(int16).min) {
                revert IStablecoinExchange.InsufficientLiquidity();
            }

            IStablecoinExchange.TickLevel storage level = book.bids[currentTick];
            uint128 orderId = level.head;

            while (remainingIn > 0) {
                uint32 price = tickToPrice(currentTick);
                IStablecoinExchange.Order memory currentOrder = orders[orderId];

                uint128 fillAmount;

                if (remainingIn > currentOrder.remaining) {
                    fillAmount = currentOrder.remaining;
                    remainingIn -= fillAmount;
                } else {
                    fillAmount = remainingIn;
                    remainingIn = 0;
                }

                // Calculate how much quote to receive for fillAmount of base
                uint128 quoteOut = (fillAmount * price) / PRICE_SCALE;
                amountOut += quoteOut;

                // Fill the order and get next order
                orderId = _fillOrder(orderId, fillAmount);

                if (remainingIn == 0) {
                    return amountOut;
                }

                // If tick is exhausted (orderId == 0), move to next tick
                if (orderId == 0) {
                    bool initialized;
                    (currentTick, initialized) = nextInitializedBidTick(key, currentTick);
                    if (!initialized) {
                        revert IStablecoinExchange.InsufficientLiquidity();
                    }

                    level = book.bids[currentTick];
                    book.bestBidTick = currentTick;
                    orderId = level.head;
                }
            }
        } else {
            // quote for base
            int16 currentTick = book.bestAskTick;
            // If there is no liquidity, revert
            if (currentTick == type(int16).max) {
                revert IStablecoinExchange.InsufficientLiquidity();
            }

            IStablecoinExchange.TickLevel storage level = book.asks[currentTick];
            uint128 orderId = level.head;

            while (remainingIn > 0) {
                uint32 price = tickToPrice(currentTick);
                IStablecoinExchange.Order memory currentOrder = orders[orderId];

                // For asks, calculate how much base we can get for remainingIn quote
                uint128 baseOut = (remainingIn * PRICE_SCALE) / price;
                uint128 fillAmount;

                // Calculate quote consumed = what maker receives - round UP to favor maker
                if (baseOut > currentOrder.remaining) {
                    fillAmount = currentOrder.remaining;
                    remainingIn -= uint128(
                        (uint256(fillAmount) * uint256(price) + PRICE_SCALE - 1) / PRICE_SCALE
                    );
                } else {
                    fillAmount = baseOut;
                    remainingIn = 0;
                }
                amountOut += fillAmount;

                // Fill the order and get next order
                orderId = _fillOrder(orderId, fillAmount);

                if (remainingIn == 0) {
                    return amountOut;
                }

                // If tick is exhausted (orderId == 0), move to next tick
                if (orderId == 0) {
                    bool initialized;
                    (currentTick, initialized) = nextInitializedAskTick(key, currentTick);
                    if (!initialized) {
                        revert IStablecoinExchange.InsufficientLiquidity();
                    }

                    level = book.asks[currentTick];
                    book.bestAskTick = currentTick;
                    orderId = level.head;
                }
            }
        }
    }

    /// @notice Quote exact output amount
    /// @param book Orderbook storage reference
    /// @param baseForQuote True if spending base for quote, false if spending quote for base
    /// @param amountOut Exact amount of output tokens desired
    /// @return amountIn Amount of input tokens needed
    function _quoteExactOut(
        bytes32 key,
        Orderbook storage book,
        bool baseForQuote,
        uint128 amountOut
    ) internal view returns (uint128 amountIn) {
        uint128 remainingOut = amountOut;

        if (baseForQuote) {
            int16 currentTick = book.bestBidTick;
            if (currentTick == type(int16).min) {
                revert IStablecoinExchange.InsufficientLiquidity();
            }

            while (remainingOut > 0) {
                IStablecoinExchange.TickLevel storage level = book.bids[currentTick];

                uint32 price = tickToPrice(currentTick);

                // Round UP + 1 to match execution. Note: if multiple orders are crossed
                // within this tick, execution may charge slightly more (+1 per order boundary).
                uint128 baseNeeded =
                    uint128((uint256(remainingOut) * PRICE_SCALE + price - 1) / price) + 1;
                uint128 fillAmount;

                if (baseNeeded > level.totalLiquidity) {
                    fillAmount = level.totalLiquidity;
                    remainingOut -= (fillAmount * price) / PRICE_SCALE;
                } else {
                    fillAmount = baseNeeded;
                    remainingOut = 0;
                }

                amountIn += fillAmount;

                if (fillAmount == level.totalLiquidity) {
                    // Move to next tick if we exhaust this level
                    bool initialized;
                    (currentTick, initialized) = nextInitializedBidTick(key, currentTick);
                    if (!initialized && remainingOut > 0) {
                        revert IStablecoinExchange.InsufficientLiquidity();
                    }
                }
            }
        } else {
            int16 currentTick = book.bestAskTick;
            if (currentTick == type(int16).max) {
                revert IStablecoinExchange.InsufficientLiquidity();
            }

            while (remainingOut > 0) {
                IStablecoinExchange.TickLevel storage level = book.asks[currentTick];
                uint32 price = tickToPrice(currentTick);

                uint128 fillAmount;

                if (remainingOut > level.totalLiquidity) {
                    fillAmount = level.totalLiquidity;
                    remainingOut -= fillAmount;
                } else {
                    fillAmount = remainingOut;
                    remainingOut = 0;
                }

                // Taker pays quote, maker receives quote - round UP to favor maker
                uint128 quoteIn =
                    uint128((uint256(fillAmount) * uint256(price) + PRICE_SCALE - 1) / PRICE_SCALE);
                amountIn += quoteIn;

                if (fillAmount == level.totalLiquidity) {
                    // Move to next tick if we exhaust this level
                    bool initialized;
                    (currentTick, initialized) = nextInitializedAskTick(key, currentTick);
                    if (!initialized && remainingOut > 0) {
                        revert IStablecoinExchange.InsufficientLiquidity();
                    }
                }
            }
        }
    }

    /// @notice Quote exact input amount
    /// @param book Orderbook storage reference
    /// @param baseForQuote True if spending base for quote, false if spending quote for base
    /// @param amountIn Exact amount of input tokens to spend
    /// @return amountOut Amount of output tokens received
    function _quoteExactIn(bytes32 key, Orderbook storage book, bool baseForQuote, uint128 amountIn)
        internal
        view
        returns (uint128 amountOut)
    {
        uint128 remainingIn = amountIn;

        if (baseForQuote) {
            int16 currentTick = book.bestBidTick;
            if (currentTick == type(int16).min) {
                revert IStablecoinExchange.InsufficientLiquidity();
            }

            while (remainingIn > 0) {
                IStablecoinExchange.TickLevel storage level = book.bids[currentTick];
                uint32 price = tickToPrice(currentTick);

                uint128 fillAmount;

                if (remainingIn > level.totalLiquidity) {
                    fillAmount = level.totalLiquidity;
                    remainingIn -= fillAmount;
                } else {
                    fillAmount = remainingIn;
                    remainingIn = 0;
                }

                amountOut += (fillAmount * price) / PRICE_SCALE;

                if (fillAmount == level.totalLiquidity) {
                    // Move to next tick if we exhaust this level
                    bool initialized;
                    (currentTick, initialized) = nextInitializedBidTick(key, currentTick);
                    if (!initialized && remainingIn > 0) {
                        revert IStablecoinExchange.InsufficientLiquidity();
                    }
                }
            }
        } else {
            int16 currentTick = book.bestAskTick;
            if (currentTick == type(int16).max) {
                revert IStablecoinExchange.InsufficientLiquidity();
            }

            while (remainingIn > 0) {
                IStablecoinExchange.TickLevel storage level = book.asks[currentTick];
                uint32 price = tickToPrice(currentTick);

                // Calculate how much base we can get for remainingIn quote
                uint128 baseOut = (remainingIn * PRICE_SCALE) / price;
                uint128 fillAmount;

                // Quote consumed = what maker receives - round UP to favor maker
                if (baseOut > level.totalLiquidity) {
                    fillAmount = level.totalLiquidity;
                    remainingIn -= uint128(
                        (uint256(fillAmount) * uint256(price) + PRICE_SCALE - 1) / PRICE_SCALE
                    );
                } else {
                    fillAmount = baseOut;
                    remainingIn = 0;
                }
                amountOut += fillAmount;

                if (fillAmount == level.totalLiquidity) {
                    // Move to next tick if we exhaust this level
                    bool initialized;
                    (currentTick, initialized) = nextInitializedAskTick(key, currentTick);
                    if (!initialized && remainingIn > 0) {
                        revert IStablecoinExchange.InsufficientLiquidity();
                    }
                }
            }
        }
    }

    /// @notice Find next initialized ask tick higher than current tick
    function nextInitializedAskTick(bytes32 bookKey, int16 tick)
        internal
        view
        returns (int16 nextTick, bool initialized)
    {
        Orderbook storage book = books[bookKey];
        nextTick = tick + 1;
        while (nextTick <= MAX_TICK) {
            int16 wordIndex = nextTick >> 8;
            uint8 bitIndex = uint8(int8(nextTick));
            if ((book.askBitmap[wordIndex] >> bitIndex) & 1 != 0) {
                return (nextTick, true);
            }
            ++nextTick;
        }
        return (nextTick, false);
    }

    /// @notice Find next initialized bid tick lower than current tick
    function nextInitializedBidTick(bytes32 bookKey, int16 tick)
        internal
        view
        returns (int16 nextTick, bool initialized)
    {
        Orderbook storage book = books[bookKey];
        nextTick = tick - 1;
        while (nextTick >= MIN_TICK) {
            int16 wordIndex = nextTick >> 8;
            uint8 bitIndex = uint8(int8(nextTick));
            if ((book.bidBitmap[wordIndex] >> bitIndex) & 1 != 0) {
                return (nextTick, true);
            }
            --nextTick;
        }
        return (nextTick, false);
    }

    /*//////////////////////////////////////////////////////////////
                        MULTI-HOP ROUTING
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if an address is a TIP20 token by verifying its prefix
    /// @param token The address to check
    /// @return True if the address has the TIP20 prefix
    function isTIP20(address token) internal pure returns (bool) {
        bytes12 tokenPrefix;
        assembly {
            tokenPrefix := shl(96, token)
        }
        return tokenPrefix == TIP20_PREFIX;
    }

    /// @notice Find trade path between two tokens using LCA (Lowest Common Ancestor) algorithm
    /// @param tokenIn Input token address
    /// @param tokenOut Output token address
    /// @return route Array of (bookKey, baseForQuote) tuples representing the trade path
    function findTradePath(address tokenIn, address tokenOut)
        internal
        view
        returns (bytes32[] memory, bool[] memory)
    {
        if (tokenIn == tokenOut) revert IStablecoinExchange.IdenticalTokens();

        // Validate that both tokens are TIP20 tokens
        if (!isTIP20(tokenIn)) revert IStablecoinExchange.InvalidToken();
        if (!isTIP20(tokenOut)) revert IStablecoinExchange.InvalidToken();

        // Check if direct or reverse pair exists
        address inQuote = address(ITIP20(tokenIn).quoteToken());
        address outQuote = address(ITIP20(tokenOut).quoteToken());

        if (inQuote == tokenOut || outQuote == tokenIn) {
            address[] memory directPath = new address[](2);
            directPath[0] = tokenIn;
            directPath[1] = tokenOut;
            return validateAndBuildRoute(directPath);
        }

        // Multi-hop: Find LCA and build path
        address[] memory pathIn = findPathToRoot(tokenIn);
        address[] memory pathOut = findPathToRoot(tokenOut);

        // Find the lowest common ancestor (LCA)
        address lca = address(0);
        for (uint256 i = 0; i < pathIn.length; i++) {
            for (uint256 j = 0; j < pathOut.length; j++) {
                if (pathIn[i] == pathOut[j]) {
                    lca = pathIn[i];
                    break;
                }
            }
            if (lca != address(0)) break;
        }

        if (lca == address(0)) revert IStablecoinExchange.PairDoesNotExist();

        // Build the trade path: tokenIn -> ... -> LCA -> ... -> tokenOut
        uint256 pathInLength = 0;
        for (uint256 i = 0; i < pathIn.length; i++) {
            pathInLength++;
            if (pathIn[i] == lca) break;
        }

        uint256 pathOutLength = 0;
        for (uint256 i = 0; i < pathOut.length; i++) {
            if (pathOut[i] == lca) break;
            pathOutLength++;
        }

        address[] memory tradePath = new address[](pathInLength + pathOutLength);

        // Add path from tokenIn up to and including LCA
        for (uint256 i = 0; i < pathInLength; i++) {
            tradePath[i] = pathIn[i];
        }

        // Add path from LCA down to tokenOut (excluding LCA itself, in reverse)
        for (uint256 i = 0; i < pathOutLength; i++) {
            tradePath[pathInLength + i] = pathOut[pathOutLength - 1 - i];
        }

        return validateAndBuildRoute(tradePath);
    }

    /// @notice Validates that all pairs in the path exist and returns book keys with direction info
    /// @param path Array of token addresses representing the trade path
    /// @return bookKeys Array of orderbook keys for each hop
    /// @return baseForQuote Array of direction indicators (true if selling base for quote)
    function validateAndBuildRoute(address[] memory path)
        internal
        view
        returns (bytes32[] memory bookKeys, bool[] memory baseForQuote)
    {
        if (path.length < 2) revert IStablecoinExchange.PairDoesNotExist();

        bookKeys = new bytes32[](path.length - 1);
        baseForQuote = new bool[](path.length - 1);

        // Track whether we are currently moving "up" the quote tree (child -> parent)
        // or "down" (parent -> child). We start with the natural direction from
        // `tokenIn` towards the LCA and flip once when we cross the LCA so that
        // at most one hop has to check both orientations.
        bool isBaseForQuote = true;

        for (uint256 i = 0; i < path.length - 1; i++) {
            address hopTokenIn = path[i];
            address hopTokenOut = path[i + 1];

            address base;
            address quote;
            // Determine which token is base and which is quote using the current
            // TIP-20 quoteToken relationships. While we are "going up" the tree,
            // we expect hopTokenIn.quoteToken() == hopTokenOut; once this no longer
            // holds, we flip to "going down" and expect hopTokenOut.quoteToken() == hopTokenIn
            // for all remaining hops. This guarantees at most one hop checks both.
            // First, try the "upward" direction (child -> parent) while we are goingUp.
            if (isBaseForQuote && address(ITIP20(hopTokenIn).quoteToken()) == hopTokenOut) {
                // hopTokenIn quotes hopTokenOut => base = hopTokenIn, quote = hopTokenOut
                base = hopTokenIn;
                quote = hopTokenOut;
            } else {
                // Upward match failed or we've already flipped; we now only accept
                // the "downward" direction (parent -> child).
                if (isBaseForQuote) {
                    // Flip direction at most once when we cross the LCA
                    isBaseForQuote = false;
                }

                // This check may not be strictly needed given how path is constructed
                if (address(ITIP20(hopTokenOut).quoteToken()) == hopTokenIn) {
                    // hopTokenOut quotes hopTokenIn => base = hopTokenOut, quote = hopTokenIn
                    base = hopTokenOut;
                    quote = hopTokenIn;
                } else {
                    revert IStablecoinExchange.PairDoesNotExist();
                }
            }

            bytes32 bookKey = pairKey(base, quote);
            Orderbook storage orderbook = books[bookKey];

            // Validate pair exists
            if (orderbook.base == address(0)) {
                revert IStablecoinExchange.PairDoesNotExist();
            }

            bookKeys[i] = bookKey;
            baseForQuote[i] = isBaseForQuote;
        }

        return (bookKeys, baseForQuote);
    }

    /// @notice Find the path from a token to the root (PathUSD)
    /// @param token Starting token address
    /// @return path Array of addresses starting with the token and ending with PathUSD
    function findPathToRoot(address token) internal view returns (address[] memory path) {
        // First, count the path length
        uint256 length = 1;
        address current = token;
        address pathUSD = 0x20C0000000000000000000000000000000000000;

        while (current != pathUSD) {
            current = address(ITIP20(current).quoteToken());
            length++;
        }

        // Now build the path
        path = new address[](length);
        current = token;
        for (uint256 i = 0; i < length; i++) {
            path[i] = current;
            if (current == pathUSD) break;
            current = address(ITIP20(current).quoteToken());
        }

        return path;
    }

}
