// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { LinkingUSD } from "./LinkingUSD.sol";
import { IStablecoinExchange } from "./interfaces/IStablecoinExchange.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";

contract StablecoinExchange is IStablecoinExchange {

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

    /// @notice Orderbook for token pair with price-time priority
    /// @dev Uses tick-based pricing with bitmaps for price discovery
    /// @dev Order and TickLevel structs are inherited from IStablecoinExchange
    struct Orderbook {
        /// Base token address
        address base;
        /// Quote token address
        address quote;
        /// Bid orders by tick
        mapping(int16 => TickLevel) bids;
        /// Ask orders by tick
        mapping(int16 => TickLevel) asks;
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
    mapping(uint128 orderId => Order order) internal orders;

    /// User balances
    mapping(address user => mapping(address token => uint128 balance)) internal balances;

    /// Last processed order ID
    uint128 public activeOrderId;
    /// Latest pending order ID
    uint128 public pendingOrderId;

    /*//////////////////////////////////////////////////////////////
                              Functions
    //////////////////////////////////////////////////////////////*/

    /// @notice Convert relative tick to scaled price
    function tickToPrice(int16 tick) public pure returns (uint32 price) {
        return uint32(int32(PRICE_SCALE) + int32(tick));
    }

    /// @notice Convert scaled price to relative tick
    function priceToTick(uint32 price) public pure returns (int16 tick) {
        require(price >= MIN_PRICE && price <= MAX_PRICE, "Price out of bounds");
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

    /// @notice Generate deterministic key for token pair
    /// @return key Deterministic pair key
    function pairKey(address tokenA, address tokenB) public pure returns (bytes32 key) {
        (tokenA, tokenB) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        key = keccak256(abi.encodePacked(tokenA, tokenB));
    }

    /// @notice Creates a new trading pair between base and quote tokens
    /// @param base Base token address
    /// @return key The orderbook key for the created pair
    /// @dev Automatically sets tick bounds to ±2% from the peg price of 1.0
    function createPair(address base) external returns (bytes32 key) {
        address quote = address(ITIP20(base).quoteToken());
        // Only USD-denominated tokens are supported, and their quotes must also be USD
        require(
            keccak256(bytes(ITIP20(base).currency())) == keccak256(bytes("USD"))
                && keccak256(bytes(ITIP20(quote).currency())) == keccak256(bytes("USD")),
            "ONLY_USD_PAIRS"
        );
        key = pairKey(base, quote);

        // Create new orderbook for pair
        Orderbook storage book = books[key];
        require(book.base == address(0), "PAIR_EXISTS");
        book.base = base;
        book.quote = quote;

        book.bestBidTick = type(int16).min;
        book.bestAskTick = type(int16).max;

        emit PairCreated(key, base, quote);
    }

    /// @notice Internal function to place order in pending queue
    /// @param base Base token address
    /// @param quote Quote token address
    /// @param amount Order amount in base token
    /// @param isBid True for buy orders, false for sell orders
    /// @param tick Price tick for the order
    /// @param isFlip Whether this is a flip order
    /// @param flipTick Target tick for flip (ignored if not flip order)
    /// @return orderId The assigned order ID
    /// @dev Orders are queued and processed at end of block
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

        require(book.base != address(0), "PAIR_NOT_EXISTS");

        require(tick >= MIN_TICK && tick <= MAX_TICK, "TICK_OUT_OF_BOUNDS");
        require(tick % TICK_SPACING == 0, "TICK_NOT_MULTIPLE_OF_SPACING");

        if (isFlip) {
            require(flipTick >= MIN_TICK && flipTick <= MAX_TICK, "FLIP_TICK_OUT_OF_BOUNDS");
            require(flipTick % TICK_SPACING == 0, "FLIP_TICK_NOT_MULTIPLE_OF_SPACING");

            if (isBid) {
                require(flipTick > tick, "FLIP_TICK_MUST_BE_GREATER_FOR_BID");
            } else {
                require(flipTick < tick, "FLIP_TICK_MUST_BE_LESS_FOR_ASK");
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

            // Check if the user has a balance, transfer the rest
            uint128 userBalance = balances[maker][escrowToken];
            if (userBalance >= escrowAmount) {
                balances[maker][escrowToken] -= escrowAmount;
            } else {
                balances[maker][escrowToken] = 0;
                if (revertOnTransferFail) {
                    ITIP20(escrowToken)
                        .transferFrom(maker, address(this), escrowAmount - userBalance);
                } else {
                    try ITIP20(escrowToken)
                        .transferFrom(maker, address(this), escrowAmount - userBalance) { }
                    catch {
                        return 0;
                    }
                }
            }
        }
        orderId = pendingOrderId + 1;
        ++pendingOrderId;

        orders[orderId] = Order({
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

        emit OrderPlaced(orderId, maker, base, amount, isBid, tick);
        return orderId;
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
        Order storage order = orders[orderId];
        require(order.maker != address(0), "ORDER_DOES_NOT_EXIST");
        require(order.maker == msg.sender, "UNAUTHORIZED");

        Orderbook storage book = books[order.bookKey];
        address token = order.isBid ? book.quote : book.base;

        // If the order is pending, delete it from storage without adjusting the orderbook
        if (orderId > activeOrderId) {
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
            return;
        } else {
            bool isBid = order.isBid;
            TickLevel storage level = isBid ? book.bids[order.tick] : book.asks[order.tick];

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
    }

    // TODO: it might be nice to create some ISystem Tx interface that is used
    // for contracts that are executed by the protocol at the end of the block.
    // This makes it easy to distinguish when the protocol is responsible for calling a function
    // TODO: natspec
    function executeBlock() external {
        if (msg.sender != address(0)) revert Unauthorized();

        uint128 orderId = activeOrderId;
        uint128 pendingId = pendingOrderId;

        for (orderId = orderId; orderId <= pendingId; orderId++) {
            Order storage order = orders[orderId];

            // If the order is already canceled, skip
            if (order.maker == address(0)) continue;

            Orderbook storage book = books[order.bookKey];
            bool isBid = order.isBid;
            TickLevel storage level = isBid ? book.bids[order.tick] : book.asks[order.tick];

            uint128 prevTail = level.tail;
            if (prevTail == 0) {
                level.head = orderId;
                level.tail = orderId;
                _setTickBit(order.bookKey, order.tick, isBid);

                // Update best bid/ask when new tick becomes active
                if (isBid) {
                    if (order.tick > book.bestBidTick) {
                        book.bestBidTick = order.tick;
                    }
                } else {
                    if (order.tick < book.bestAskTick) {
                        book.bestAskTick = order.tick;
                    }
                }
            } else {
                orders[prevTail].next = orderId;
                order.prev = prevTail;
                level.tail = orderId;
            }

            // Increment total liquidity for this tick level
            level.totalLiquidity += order.remaining;
        }

        // Update activeOrderId to last processed order
        activeOrderId = orderId - 1;
    }

    /// @notice Withdraw tokens from exchange balance
    /// @param token Token address to withdraw
    /// @param amount Amount to withdraw
    function withdraw(address token, uint128 amount) external {
        require(balances[msg.sender][token] >= amount, "INSUFFICIENT_BALANCE");
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
        TickLevel memory level = isBid ? book.bids[tick] : book.asks[tick];
        return (level.head, level.tail, level.totalLiquidity);
    }

    /// @notice Get order information by order ID
    /// @param orderId The order ID to query
    /// @return order The order data
    function getOrder(uint128 orderId) external view returns (Order memory order) {
        Order storage o = orders[orderId];
        require(o.maker != address(0), "ORDER_DOES_NOT_EXIST");
        require(orderId <= activeOrderId, "ORDER_NOT_ACTIVE");
        return o;
    }

    /// @notice Quote swapping tokens for exact amount out
    /// @param tokenIn Token to spend
    /// @param tokenOut Token to buy
    /// @param amountOut Amount of tokenOut to buy
    /// @return amountIn Amount of tokenIn needed
    function quoteSwapExactAmountOut(address tokenIn, address tokenOut, uint128 amountOut)
        external
        view
        returns (uint128 amountIn)
    {
        bytes32 key = pairKey(tokenIn, tokenOut);
        Orderbook storage book = books[key];
        require(book.base != address(0), "PAIR_NOT_EXISTS");

        bool baseForQuote = tokenIn == book.base;
        amountIn = _quoteExactOut(key, book, baseForQuote, amountOut);
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
        Order storage order = orders[orderId];
        Orderbook storage book = books[order.bookKey];
        bool isBid = order.isBid;
        TickLevel storage level = isBid ? book.bids[order.tick] : book.asks[order.tick];

        // Fill the order
        order.remaining -= fillAmount;
        level.totalLiquidity -= fillAmount;

        emit OrderFilled(orderId, order.maker, msg.sender, fillAmount, order.remaining > 0);

        // Credit maker with appropriate tokens
        if (isBid) {
            // Bid order: maker gets base tokens
            balances[order.maker][book.base] += fillAmount;
        } else {
            // Ask order: maker gets quote tokens
            uint32 price = tickToPrice(order.tick);
            uint128 quoteAmount = (fillAmount * price) / PRICE_SCALE;
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
        uint128 userBalance = balances[user][token];
        if (userBalance >= amount) {
            balances[user][token] -= amount;
        } else {
            balances[user][token] = 0;
            uint128 remaining = amount - userBalance;
            ITIP20(token).transferFrom(user, address(this), remaining);
        }
    }

    /// @notice Swap tokens for exact amount out
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
        bytes32 key = pairKey(tokenIn, tokenOut);
        Orderbook storage book = books[key];
        require(book.base != address(0), "PAIR_NOT_EXISTS");

        bool baseForQuote = tokenIn == book.base;
        amountIn = _fillOrdersExactOut(key, book, baseForQuote, amountOut);
        if (amountIn > maxAmountIn) {
            revert("MAX_IN_EXCEEDED");
        }

        _decrementBalanceOrTransferFrom(msg.sender, tokenIn, amountIn);
        ITIP20(tokenOut).transfer(msg.sender, amountOut);
    }

    /// @notice Quote the proceeds from swapping a specific amount of tokens
    /// @param tokenIn Token to sell
    /// @param tokenOut Token to receive
    /// @param amountIn Amount of tokenIn to sell
    /// @return amountOut Amount of tokenOut to receive
    function quoteSwapExactAmountIn(address tokenIn, address tokenOut, uint128 amountIn)
        external
        view
        returns (uint128 amountOut)
    {
        bytes32 key = pairKey(tokenIn, tokenOut);
        Orderbook storage book = books[key];
        require(book.base != address(0), "PAIR_NOT_EXISTS");

        bool baseForQuote = tokenIn == book.base;
        amountOut = _quoteExactIn(key, book, baseForQuote, amountIn);
    }

    /// @notice Swap tokens for exact amount in
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
        bytes32 key = pairKey(tokenIn, tokenOut);
        Orderbook storage book = books[key];
        require(book.base != address(0), "PAIR_NOT_EXISTS");

        bool baseForQuote = tokenIn == book.base;
        amountOut = _fillOrdersExactIn(key, book, baseForQuote, amountIn);
        if (amountOut < minAmountOut) {
            revert("INSUFFICIENT_OUTPUT");
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
                revert("INSUFFICIENT_LIQUIDITY");
            }

            TickLevel storage level = book.bids[currentTick];
            uint128 orderId = level.head;

            while (remainingOut > 0) {
                // Get the price at the current tick and fetch the current order from storage
                uint32 price = tickToPrice(currentTick);
                Order memory currentOrder = orders[orderId];

                // For bids, we want remainingOut quote tokens
                uint128 baseNeeded = (remainingOut * PRICE_SCALE) / price;
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
                        revert("INSUFFICIENT_LIQUIDITY");
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
                revert("INSUFFICIENT_LIQUIDITY");
            }

            TickLevel storage level = book.asks[currentTick];
            uint128 orderId = level.head;

            while (remainingOut > 0) {
                uint32 price = tickToPrice(currentTick);
                Order memory currentOrder = orders[orderId];

                uint128 fillAmount;

                if (remainingOut > currentOrder.remaining) {
                    fillAmount = currentOrder.remaining;
                    remainingOut -= fillAmount;
                } else {
                    fillAmount = remainingOut;
                    remainingOut = 0;
                }

                // Calculate how much quote to pay for fillAmount of base
                uint128 quoteIn = (fillAmount * price) / PRICE_SCALE;
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
                        revert("INSUFFICIENT_LIQUIDITY");
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
                revert("INSUFFICIENT_LIQUIDITY");
            }

            TickLevel storage level = book.bids[currentTick];
            uint128 orderId = level.head;

            while (remainingIn > 0) {
                uint32 price = tickToPrice(currentTick);
                Order memory currentOrder = orders[orderId];

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
                        revert("INSUFFICIENT_LIQUIDITY");
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
                revert("INSUFFICIENT_LIQUIDITY");
            }

            TickLevel storage level = book.asks[currentTick];
            uint128 orderId = level.head;

            while (remainingIn > 0) {
                uint32 price = tickToPrice(currentTick);
                Order memory currentOrder = orders[orderId];

                // For asks, calculate how much base we can get for remainingIn quote
                uint128 baseOut = (remainingIn * PRICE_SCALE) / price;
                uint128 fillAmount;

                // Calculate actual quote needed for fillAmount of base
                if (baseOut > currentOrder.remaining) {
                    fillAmount = currentOrder.remaining;
                    remainingIn -= (fillAmount * price) / PRICE_SCALE;
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
                        revert("INSUFFICIENT_LIQUIDITY");
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
                revert("INSUFFICIENT_LIQUIDITY");
            }

            while (remainingOut > 0) {
                TickLevel storage level = book.bids[currentTick];

                uint32 price = tickToPrice(currentTick);

                uint128 baseNeeded = (remainingOut * PRICE_SCALE) / price;
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
                        revert("INSUFFICIENT_LIQUIDITY");
                    }
                }
            }
        } else {
            int16 currentTick = book.bestAskTick;
            if (currentTick == type(int16).max) {
                revert("INSUFFICIENT_LIQUIDITY");
            }

            while (remainingOut > 0) {
                TickLevel storage level = book.asks[currentTick];
                uint32 price = tickToPrice(currentTick);

                uint128 fillAmount;

                if (remainingOut > level.totalLiquidity) {
                    fillAmount = level.totalLiquidity;
                    remainingOut -= fillAmount;
                } else {
                    fillAmount = remainingOut;
                    remainingOut = 0;
                }

                uint128 quoteIn = (fillAmount * price) / PRICE_SCALE;
                amountIn += quoteIn;

                if (fillAmount == level.totalLiquidity) {
                    // Move to next tick if we exhaust this level
                    bool initialized;
                    (currentTick, initialized) = nextInitializedAskTick(key, currentTick);
                    if (!initialized && remainingOut > 0) {
                        revert("INSUFFICIENT_LIQUIDITY");
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
                revert("INSUFFICIENT_LIQUIDITY");
            }

            while (remainingIn > 0) {
                TickLevel storage level = book.bids[currentTick];
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
                        revert("INSUFFICIENT_LIQUIDITY");
                    }
                }
            }
        } else {
            int16 currentTick = book.bestAskTick;
            if (currentTick == type(int16).max) {
                revert("INSUFFICIENT_LIQUIDITY");
            }

            while (remainingIn > 0) {
                TickLevel storage level = book.asks[currentTick];
                uint32 price = tickToPrice(currentTick);

                // Calculate how much base we can get for remainingIn quote
                uint128 baseOut = (remainingIn * PRICE_SCALE) / price;
                uint128 fillAmount;

                if (baseOut > level.totalLiquidity) {
                    fillAmount = level.totalLiquidity;
                    remainingIn -= (fillAmount * price) / PRICE_SCALE;
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
                        revert("INSUFFICIENT_LIQUIDITY");
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

}
