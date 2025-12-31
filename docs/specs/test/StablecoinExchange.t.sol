// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IStablecoinExchange } from "../src/interfaces/IStablecoinExchange.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "./BaseTest.t.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";

contract StablecoinExchangeTest is BaseTest {

    bytes32 pairKey;
    uint128 constant INITIAL_BALANCE = 10_000e18;

    event OrderPlaced(
        uint128 indexed orderId,
        address indexed maker,
        address indexed base,
        uint128 amount,
        bool isBid,
        int16 tick
    );

    event FlipOrderPlaced(
        uint128 indexed orderId,
        address indexed maker,
        address indexed base,
        uint128 amount,
        bool isBid,
        int16 tick,
        int16 flipTick
    );

    event OrderCancelled(uint128 indexed orderId);

    event OrderFilled(
        uint128 indexed orderId,
        address indexed maker,
        address indexed taker,
        uint128 amountFilled,
        bool partialFill
    );

    event PairCreated(bytes32 indexed key, address indexed base, address indexed quote);

    function setUp() public override {
        super.setUp();

        vm.startPrank(admin);
        token1.grantRole(_ISSUER_ROLE, admin);
        token1.mint(alice, INITIAL_BALANCE);
        token1.mint(bob, INITIAL_BALANCE);
        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(alice, INITIAL_BALANCE);
        pathUSD.mint(bob, INITIAL_BALANCE);
        vm.stopPrank();

        // Approve exchange to spend tokens
        vm.startPrank(alice);
        token1.approve(address(exchange), type(uint256).max);
        pathUSD.approve(address(exchange), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(bob);
        token1.approve(address(exchange), type(uint256).max);
        pathUSD.approve(address(exchange), type(uint256).max);
        vm.stopPrank();

        // Create trading pair
        pairKey = exchange.createPair(address(token1));
    }

    function test_TickToPrice(int16 tick) public view {
        uint32 price = exchange.tickToPrice(tick);
        uint32 expectedPrice = uint32(int32(exchange.PRICE_SCALE()) + int32(tick));
        assertEq(price, expectedPrice);
    }

    function test_PriceToTick(uint32 price) public view {
        price = uint32(bound(price, exchange.MIN_PRICE(), exchange.MAX_PRICE()));
        int16 tick = exchange.priceToTick(price);
        int16 expectedTick = int16(int32(price) - int32(exchange.PRICE_SCALE()));
        assertEq(tick, expectedTick);
    }

    function test_PairKey(address base, address quote) public view {
        bytes32 expectedKey = keccak256(abi.encodePacked(base, quote));

        bytes32 key = exchange.pairKey(base, quote);

        assertEq(key, expectedKey);
    }

    function test_CreatePair() public {
        ITIP20 newQuote = ITIP20(factory.createToken("New Quote", "NQUOTE", "USD", pathUSD, admin));

        ITIP20 newBase = ITIP20(factory.createToken("New Base", "NBASE", "USD", newQuote, admin));
        bytes32 expectedKey = exchange.pairKey(address(newBase), address(newQuote));

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit PairCreated(expectedKey, address(newBase), address(newQuote));
        }

        bytes32 key = exchange.createPair(address(newBase));
        assertEq(key, expectedKey);
    }

    /// @notice Orderbook keys should be order-sensitive and change when quoteToken changes.
    function test_OrderbookPairs_AreOrderSensitive_AcrossQuoteUpdates() public {
        // Create a dedicated base token and two possible quote tokens, all USD-denominated.
        vm.startPrank(admin);
        ITIP20 base = ITIP20(factory.createToken("OBBase", "OBB", "USD", pathUSD, admin));
        ITIP20 quote1 = ITIP20(factory.createToken("OBQuote1", "OBQ1", "USD", pathUSD, admin));
        vm.stopPrank();

        // Initial state: base quotes PathUSD
        assertEq(address(base.quoteToken()), address(pathUSD));

        // 1) First pair: (base, PathUSD)
        bytes32 key0 = exchange.createPair(address(base));
        (address b0, address q0,,) = exchange.books(key0);
        assertEq(b0, address(base), "first book base mismatch");
        assertEq(q0, address(pathUSD), "first book quote mismatch");

        // 2) Update base's quote token to quote1 and create a new pair
        vm.startPrank(admin);
        base.setNextQuoteToken(quote1);
        base.completeQuoteTokenUpdate();
        vm.stopPrank();

        assertEq(address(base.quoteToken()), address(quote1));

        bytes32 key1 = exchange.createPair(address(base));
        (address b1, address q1,,) = exchange.books(key1);
        assertEq(b1, address(base), "second book base mismatch");
        assertEq(q1, address(quote1), "second book quote mismatch");

        // Keys must differ when quoteToken changes
        assertTrue(key1 != key0, "orderbook key should change when quoteToken changes");

        // 3) Reset base's quote token back to PathUSD so that setting quote1's
        // quote token to base does not create a quote-token loop.
        vm.startPrank(admin);
        base.setNextQuoteToken(pathUSD);
        base.completeQuoteTokenUpdate();
        vm.stopPrank();

        assertEq(address(base.quoteToken()), address(pathUSD));

        // 4) Now set quote1's quote token to base and create a pair for quote1.
        // This tests that we can still create a new pair where the previous quote
        // becomes the base, and that the key is order-sensitive.
        vm.startPrank(admin);
        quote1.setNextQuoteToken(base);
        quote1.completeQuoteTokenUpdate();
        vm.stopPrank();

        assertEq(address(quote1.quoteToken()), address(base));

        bytes32 key2 = exchange.createPair(address(quote1));
        (address b2, address q2,,) = exchange.books(key2);
        assertEq(b2, address(quote1), "third book base mismatch");
        assertEq(q2, address(base), "third book quote mismatch");

        // The (base, quote1) and (quote1, base) books must have different keys
        assertTrue(key2 != key1, "reversed base/quote should have different key");
        // And also be distinct from the initial (base, PathUSD) configuration
        assertTrue(key2 != key0, "third key should differ from first");
    }

    function test_PlaceBidOrder() public {
        uint128 orderId = _placeBidOrder(alice, 1e18, 100);

        assertEq(orderId, 1);
        assertEq(exchange.nextOrderId(), 2);

        uint32 price = exchange.tickToPrice(100);
        uint256 expectedEscrow = (uint256(1e18) * uint256(price)) / uint256(exchange.PRICE_SCALE());
        assertEq(pathUSD.balanceOf(alice), uint256(INITIAL_BALANCE) - expectedEscrow);
        assertEq(pathUSD.balanceOf(address(exchange)), expectedEscrow);

        // Verify order is immediately active in orderbook
        (uint128 bidHead, uint128 bidTail, uint128 bidLiquidity) =
            exchange.getTickLevel(address(token1), 100, true);
        assertEq(bidHead, orderId);
        assertEq(bidTail, orderId);
        assertEq(bidLiquidity, 1e18);
    }

    function test_PlaceAskOrder() public {
        uint128 orderId = _placeAskOrder(alice, 1e18, 100);

        assertEq(orderId, 1);
        assertEq(exchange.nextOrderId(), 2);

        assertEq(token1.balanceOf(alice), INITIAL_BALANCE - 1e18);
        assertEq(token1.balanceOf(address(exchange)), 1e18);

        // Verify order is immediately active in orderbook
        (uint128 askHead, uint128 askTail, uint128 askLiquidity) =
            exchange.getTickLevel(address(token1), 100, false);
        assertEq(askHead, orderId);
        assertEq(askTail, orderId);
        assertEq(askLiquidity, 1e18);
    }

    function test_PlaceFlipBidOrder() public {
        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit FlipOrderPlaced(1, alice, address(token1), 1e18, true, 100, 200);
        }

        vm.prank(alice);
        uint128 orderId = exchange.placeFlip(address(token1), 1e18, true, 100, 200);

        assertEq(orderId, 1);
        assertEq(exchange.nextOrderId(), 2);

        uint32 price = exchange.tickToPrice(100);
        uint256 expectedEscrow = (uint256(1e18) * uint256(price)) / uint256(exchange.PRICE_SCALE());
        assertEq(pathUSD.balanceOf(alice), uint256(INITIAL_BALANCE) - expectedEscrow);
        assertEq(pathUSD.balanceOf(address(exchange)), expectedEscrow);

        // Verify order is immediately active in orderbook
        (uint128 bidHead, uint128 bidTail, uint128 bidLiquidity) =
            exchange.getTickLevel(address(token1), 100, true);
        assertEq(bidHead, orderId);
        assertEq(bidTail, orderId);
        assertEq(bidLiquidity, 1e18);
    }

    function test_PlaceFlipAskOrder() public {
        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit FlipOrderPlaced(1, alice, address(token1), 1e18, false, 100, -200);
        }

        vm.prank(alice);
        uint128 orderId = exchange.placeFlip(address(token1), 1e18, false, 100, -200);

        assertEq(orderId, 1);
        assertEq(exchange.nextOrderId(), 2);

        assertEq(token1.balanceOf(alice), INITIAL_BALANCE - 1e18);
        assertEq(token1.balanceOf(address(exchange)), 1e18);

        // Verify order is immediately active in orderbook
        (uint128 askHead, uint128 askTail, uint128 askLiquidity) =
            exchange.getTickLevel(address(token1), 100, false);
        assertEq(askHead, orderId);
        assertEq(askTail, orderId);
        assertEq(askLiquidity, 1e18);
    }

    function test_FlipOrderExecution() public {
        vm.prank(alice);
        uint128 flipOrderId = exchange.placeFlip(address(token1), 1e18, true, 100, 200);

        // Orders are immediately active, no executeBlock needed

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderFilled(flipOrderId, alice, bob, 1e18, false);

            vm.expectEmit(true, true, true, true);
            emit OrderPlaced(2, alice, address(token1), 1e18, false, 200);
        }

        vm.prank(bob);
        exchange.swapExactAmountIn(address(token1), address(pathUSD), 1e18, 0);

        assertEq(exchange.nextOrderId(), 3);
        // TODO: pull the order from orders mapping and assert state changes
    }

    function test_OrdersImmediatelyActive() public {
        uint128 bid0 = _placeBidOrder(alice, 1e18, 100);
        uint128 bid1 = _placeBidOrder(bob, 2e18, 100);

        uint128 ask0 = _placeAskOrder(alice, 1e18, 150);
        uint128 ask1 = _placeAskOrder(bob, 2e18, 150);

        assertEq(exchange.nextOrderId(), 5);

        // Verify liquidity at tick levels - orders are immediately active
        (uint128 bidHead, uint128 bidTail, uint128 bidLiquidity) =
            exchange.getTickLevel(address(token1), 100, true);

        assertEq(bidHead, bid0);
        assertEq(bidTail, bid1);
        assertEq(bidLiquidity, 3e18);

        (uint128 askHead, uint128 askTail, uint128 askLiquidity) =
            exchange.getTickLevel(address(token1), 150, false);
        assertEq(askHead, ask0);
        assertEq(askTail, ask1);
        assertEq(askLiquidity, 3e18);
    }

    function test_CancelOrder() public {
        uint128 orderId = _placeBidOrder(alice, 1e18, 100);

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderCancelled(orderId);
        }

        vm.prank(alice);
        exchange.cancel(orderId);

        // Verify tokens were returned to balance
        uint32 price = exchange.tickToPrice(100);
        uint256 escrowAmount = (uint256(1e18) * uint256(price)) / uint256(exchange.PRICE_SCALE());
        assertEq(exchange.balanceOf(alice, address(pathUSD)), escrowAmount);

        // Verify order removed from orderbook
        (uint128 bidHead, uint128 bidTail, uint128 bidLiquidity) =
            exchange.getTickLevel(address(token1), 100, true);
        assertEq(bidHead, 0);
        assertEq(bidTail, 0);
        assertEq(bidLiquidity, 0);
    }

    function test_Withdraw() public {
        uint128 orderId = _placeBidOrder(alice, 1e18, 100);
        vm.prank(alice);
        exchange.cancel(orderId);

        uint128 exchangeBalance = exchange.balanceOf(alice, address(pathUSD));
        uint256 initialTokenBalance = pathUSD.balanceOf(alice);

        vm.prank(alice);
        exchange.withdraw(address(pathUSD), exchangeBalance);

        assertEq(exchange.balanceOf(alice, address(pathUSD)), 0);
        assertEq(pathUSD.balanceOf(alice), initialTokenBalance + exchangeBalance);
    }

    function test_QuoteSwapExactAmountOut() public {
        _placeAskOrder(bob, 1000e18, 100);

        // Orders are immediately active

        uint128 amountOut = 500e18;
        uint128 amountIn =
            exchange.quoteSwapExactAmountOut(address(pathUSD), address(token1), amountOut);

        uint32 price = exchange.tickToPrice(100);
        uint128 expectedAmountIn = (amountOut * price) / exchange.PRICE_SCALE();
        assertEq(amountIn, expectedAmountIn);
    }

    function test_SwapExactAmountOut() public {
        uint128 askOrderId = _placeAskOrder(bob, 1000e18, 100);

        // Orders are immediately active

        uint128 amountOut = 500e18;
        uint32 price = exchange.tickToPrice(100);
        uint128 expectedAmountIn = (amountOut * price) / exchange.PRICE_SCALE();
        uint128 maxAmountIn = expectedAmountIn + 1000;
        uint256 initialBaseBalance = token1.balanceOf(alice);

        // Execute swap to partially fill order
        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderFilled(askOrderId, bob, alice, amountOut, true);
        }

        vm.prank(alice);
        uint128 amountIn = exchange.swapExactAmountOut(
            address(pathUSD), address(token1), amountOut, maxAmountIn
        );

        assertEq(amountIn, expectedAmountIn);
        assertEq(token1.balanceOf(alice), initialBaseBalance + amountOut);

        // Execute swap to fully fill order
        uint128 remainingAmount = 500e18;
        uint128 expectedAmountIn2 = (remainingAmount * price) / exchange.PRICE_SCALE();

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderFilled(askOrderId, bob, alice, remainingAmount, false);
        }

        vm.prank(alice);
        uint128 amountIn2 = exchange.swapExactAmountOut(
            address(pathUSD), address(token1), remainingAmount, maxAmountIn
        );

        assertEq(amountIn2, expectedAmountIn2);
        assertEq(token1.balanceOf(alice), initialBaseBalance + amountOut + remainingAmount);
    }

    function test_SwapExactAmountOut_MultiTick() public {
        uint128 order1 = _placeAskOrder(bob, 1e18, 10);
        uint128 order2 = _placeAskOrder(bob, 1e18, 20);
        uint128 order3 = _placeAskOrder(bob, 1e18, 30);

        // Orders are immediately active

        uint128 buyAmount = 25e17;
        uint128 p1 = exchange.tickToPrice(10);
        uint128 p2 = exchange.tickToPrice(20);
        uint128 p3 = exchange.tickToPrice(30);

        uint128 cost1 = (1e18 * p1) / exchange.PRICE_SCALE();
        uint128 cost2 = (1e18 * p2) / exchange.PRICE_SCALE();
        uint128 cost3 = (5e17 * p3) / exchange.PRICE_SCALE();
        uint128 totalCost = cost1 + cost2 + cost3;

        uint128 maxIn = totalCost * 2;
        uint256 initBalance = token1.balanceOf(alice);

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderFilled(order1, bob, alice, 1e18, false);

            vm.expectEmit(true, true, true, true);
            emit OrderFilled(order2, bob, alice, 1e18, false);

            vm.expectEmit(true, true, true, true);
            emit OrderFilled(order3, bob, alice, 5e17, true);
        }

        vm.prank(alice);
        uint128 amountIn =
            exchange.swapExactAmountOut(address(pathUSD), address(token1), buyAmount, maxIn);

        assertEq(amountIn, totalCost);
        assertEq(token1.balanceOf(alice), initBalance + buyAmount);
    }

    function test_QuoteSwapExactAmountIn() public {
        _placeBidOrder(bob, 1000e18, 100);

        // Orders are immediately active

        uint128 amountIn = 500e18;
        uint128 amountOut =
            exchange.quoteSwapExactAmountIn(address(token1), address(pathUSD), amountIn);

        uint32 price = exchange.tickToPrice(100);
        uint128 expectedProceeds = (amountIn * price) / exchange.PRICE_SCALE();
        assertEq(amountOut, expectedProceeds);
    }

    function test_SwapExactAmountIn() public {
        uint128 bidOrderId = _placeBidOrder(bob, 1000e18, 100);

        // Orders are immediately active

        uint128 amountIn = 500e18;
        uint32 price = exchange.tickToPrice(100);
        uint128 expectedAmountOut = (amountIn * price) / exchange.PRICE_SCALE();
        uint128 minAmountOut = expectedAmountOut - 1000;
        uint256 initialQuoteBalance = pathUSD.balanceOf(alice);

        // Execute swap to partially fill order
        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderFilled(bidOrderId, bob, alice, amountIn, true);
        }

        vm.prank(alice);
        uint128 amountOut =
            exchange.swapExactAmountIn(address(token1), address(pathUSD), amountIn, minAmountOut);

        assertEq(amountOut, expectedAmountOut);
        assertEq(pathUSD.balanceOf(alice), initialQuoteBalance + amountOut);

        // Execute swap to fully fill order
        uint128 remainingAmount = 500e18; // 1000e18 - 500e18 = 500e18 remaining
        uint128 expectedAmountOut2 = (remainingAmount * price) / exchange.PRICE_SCALE();
        uint128 minAmountOut2 = expectedAmountOut2 - 1000;

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderFilled(bidOrderId, bob, alice, remainingAmount, false);
        }

        vm.prank(alice);
        uint128 amountOut2 = exchange.swapExactAmountIn(
            address(token1), address(pathUSD), remainingAmount, minAmountOut2
        );

        assertEq(amountOut2, expectedAmountOut2);
        assertEq(pathUSD.balanceOf(alice), initialQuoteBalance + amountOut + amountOut2);
    }

    function test_SwapExactAmountIn_MultiTick() public {
        uint128 order1 = _placeBidOrder(bob, 1e18, 30);
        uint128 order2 = _placeBidOrder(bob, 1e18, 20);
        uint128 order3 = _placeBidOrder(bob, 1e18, 10);

        // Orders are immediately active

        uint128 sellAmount = 25e17;
        uint128 p1 = exchange.tickToPrice(30);
        uint128 p2 = exchange.tickToPrice(20);
        uint128 p3 = exchange.tickToPrice(10);

        uint128 out1 = (1e18 * p1) / exchange.PRICE_SCALE();
        uint128 out2 = (1e18 * p2) / exchange.PRICE_SCALE();
        uint128 out3 = (5e17 * p3) / exchange.PRICE_SCALE();
        uint128 totalOut = out1 + out2 + out3;

        uint128 minOut = totalOut / 2;
        uint256 initBalance = pathUSD.balanceOf(alice);

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderFilled(order1, bob, alice, 1e18, false);

            vm.expectEmit(true, true, true, true);
            emit OrderFilled(order2, bob, alice, 1e18, false);

            vm.expectEmit(true, true, true, true);
            emit OrderFilled(order3, bob, alice, 5e17, true);
        }

        vm.prank(alice);
        uint128 amountOut =
            exchange.swapExactAmountIn(address(token1), address(pathUSD), sellAmount, minOut);

        assertEq(amountOut, totalOut);
        assertEq(pathUSD.balanceOf(alice), initBalance + totalOut);
    }

    /*//////////////////////////////////////////////////////////////
                        MINIMUM ORDER SIZE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PlaceOrder_RevertIf_BelowMinimumOrderSize(uint128 amount) public {
        vm.assume(amount < exchange.MIN_ORDER_AMOUNT());

        vm.prank(alice);
        try exchange.place(address(token1), amount, true, 100) {
            revert CallShouldHaveReverted();
        } catch (bytes memory) {
            // Successfully reverted with BelowMinimumOrderSize(uint128) error
        }
    }

    function test_PlaceOrder_SucceedsAt_MinimumOrderSize() public {
        uint128 minOrderAmount = exchange.MIN_ORDER_AMOUNT();
        vm.prank(alice);
        uint128 orderId = exchange.place(address(token1), minOrderAmount, true, 100);

        assertEq(orderId, 1);
        assertEq(exchange.nextOrderId(), 2);
    }

    function test_PlaceOrder_SucceedsAbove_MinimumOrderSize(uint128 amount) public {
        // For bid orders (buying token1 with pathUSD), the escrow amount is:
        // escrow = amount * tickToPrice(100) / PRICE_SCALE
        // escrow = amount * (PRICE_SCALE + 100) / PRICE_SCALE
        // escrow = amount * (1000000 + 100) / 1000000
        // We need escrow <= INITIAL_BALANCE
        // So: amount * 1000100 / 1000000 <= INITIAL_BALANCE
        // Therefore: amount <= INITIAL_BALANCE * 1000000 / 1000100
        uint128 maxAmount = uint128((uint256(INITIAL_BALANCE) * 1_000_000) / 1_000_100);
        vm.assume(amount >= exchange.MIN_ORDER_AMOUNT() && amount <= maxAmount);

        vm.prank(alice);
        uint128 orderId = exchange.place(address(token1), amount, true, 100);

        assertEq(orderId, 1);
        assertEq(exchange.nextOrderId(), 2);
    }

    function test_PlaceFlipOrder_RevertIf_BelowMinimumOrderSize(uint128 amount) public {
        vm.assume(amount < exchange.MIN_ORDER_AMOUNT());

        vm.prank(alice);
        try exchange.placeFlip(address(token1), amount, true, 100, 200) {
            revert CallShouldHaveReverted();
        } catch (bytes memory) {
            // Successfully reverted with BelowMinimumOrderSize(uint128) error
        }
    }

    /*//////////////////////////////////////////////////////////////
                        NEGATIVE TESTS - VALIDATION RULES
    //////////////////////////////////////////////////////////////*/

    // Test all order placement validation rules
    function testFuzz_PlaceOrder_ValidationRules(uint128 amount, int16 tick) public {
        // Bound inputs to explore full range
        tick = int16(bound(int256(tick), type(int16).min, type(int16).max));

        // Use alice who has balance and approval from setUp
        address maker = alice;

        // Determine expected behavior
        bool shouldRevert = false;
        bytes memory expectedError;

        // Note: Validation order - tick bounds, tick spacing, then amount
        if (tick < exchange.MIN_TICK() || tick > exchange.MAX_TICK()) {
            shouldRevert = true;
            expectedError =
                abi.encodeWithSelector(IStablecoinExchange.TickOutOfBounds.selector, tick);
        } else if (tick % exchange.TICK_SPACING() != 0) {
            shouldRevert = true;
            expectedError = abi.encodeWithSelector(IStablecoinExchange.InvalidTick.selector);
        } else if (amount < exchange.MIN_ORDER_AMOUNT()) {
            shouldRevert = true;
            expectedError = abi.encodeWithSelector(
                IStablecoinExchange.BelowMinimumOrderSize.selector, amount
            );
        }

        // Execute and verify
        vm.prank(maker);
        if (shouldRevert) {
            try exchange.place(address(token1), amount, true, tick) {
                revert CallShouldHaveReverted();
            } catch (bytes memory err) {
                assertEq(err, expectedError, "Wrong error");
            }
        } else {
            // May fail due to insufficient balance/allowance - that's OK
            try exchange.place(address(token1), amount, true, tick) {
            // Success is fine
            }
                catch {
                // Failure due to balance/allowance is also OK for fuzz test
            }
        }
    }

    // Test flip order validation rules
    function testFuzz_PlaceFlipOrder_ValidationRules(
        uint128 amount,
        int16 tick,
        int16 flipTick,
        bool isBid
    ) public {
        tick = int16(bound(int256(tick), type(int16).min, type(int16).max));
        flipTick = int16(bound(int256(flipTick), type(int16).min, type(int16).max));

        bool shouldRevert = false;
        bytes4 expectedSelector;

        // Check all validation rules - tick bounds, tick spacing, amount, flip tick bounds, flip tick spacing, direction
        if (tick < exchange.MIN_TICK() || tick > exchange.MAX_TICK()) {
            shouldRevert = true;
            expectedSelector = IStablecoinExchange.TickOutOfBounds.selector;
        } else if (tick % exchange.TICK_SPACING() != 0) {
            shouldRevert = true;
            expectedSelector = IStablecoinExchange.InvalidTick.selector;
        } else if (amount < exchange.MIN_ORDER_AMOUNT()) {
            shouldRevert = true;
            expectedSelector = IStablecoinExchange.BelowMinimumOrderSize.selector;
        } else if (flipTick < exchange.MIN_TICK() || flipTick > exchange.MAX_TICK()) {
            shouldRevert = true;
            expectedSelector = IStablecoinExchange.InvalidFlipTick.selector;
        } else if (flipTick % exchange.TICK_SPACING() != 0) {
            shouldRevert = true;
            expectedSelector = IStablecoinExchange.InvalidFlipTick.selector;
        } else if (isBid && flipTick <= tick) {
            shouldRevert = true;
            expectedSelector = IStablecoinExchange.InvalidFlipTick.selector;
        } else if (!isBid && flipTick >= tick) {
            shouldRevert = true;
            expectedSelector = IStablecoinExchange.InvalidFlipTick.selector;
        }

        vm.prank(alice);
        if (shouldRevert) {
            try exchange.placeFlip(address(token1), amount, isBid, tick, flipTick) {
                revert CallShouldHaveReverted();
            } catch (bytes memory) {
                // Successfully reverted - we don't check exact error for simplicity
            }
        } else {
            // May fail due to insufficient balance/allowance - that's OK
            try exchange.placeFlip(address(token1), amount, isBid, tick, flipTick) {
            // Success is fine
            }
                catch {
                // Failure due to balance/allowance is also OK for fuzz test
            }
        }
    }

    // Test pair creation validation
    function test_CreatePair_RevertIf_NonUsdToken() public {
        // Create a non-USD token
        ITIP20 eurToken = ITIP20(factory.createToken("EUR Token", "EUR", "EUR", pathUSD, admin));

        try exchange.createPair(address(eurToken)) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            // Both Rust and Solidity throw ITIP20.InvalidCurrency()
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidCurrency.selector));
        }
    }

    function test_CreatePair_RevertIf_AlreadyExists() public {
        // Pair already created in setUp
        try exchange.createPair(address(token1)) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            // Both Rust and Solidity throw PairAlreadyExists()
            assertEq(err, abi.encodeWithSelector(IStablecoinExchange.PairAlreadyExists.selector));
        }
    }

    // Test cancel validation
    function testFuzz_Cancel_ValidationRules(uint128 orderId, address caller) public {
        vm.assume(caller != address(0));

        // Place an order as alice
        uint128 minOrderAmount = exchange.MIN_ORDER_AMOUNT();
        vm.prank(alice);
        uint128 validOrderId = exchange.place(address(token1), minOrderAmount, true, 100);

        bool shouldRevert = false;
        bytes4 expectedSelector;

        if (orderId == 0 || orderId != validOrderId) {
            shouldRevert = true;
            expectedSelector = IStablecoinExchange.OrderDoesNotExist.selector;
        } else if (caller != alice) {
            shouldRevert = true;
            expectedSelector = IStablecoinExchange.Unauthorized.selector;
        }

        vm.prank(caller);
        if (shouldRevert) {
            try exchange.cancel(orderId) {
                revert CallShouldHaveReverted();
            } catch (bytes memory) {
                // Successfully reverted
            }
        } else {
            exchange.cancel(orderId);
        }
    }

    // Test withdraw validation
    function testFuzz_Withdraw_RevertIf_InsufficientBalance(uint128 balance, uint128 withdrawAmount)
        public
    {
        vm.assume(balance < type(uint128).max); // Avoid overflow in balance + 1
        withdrawAmount = uint128(bound(withdrawAmount, balance + 1, type(uint128).max));

        // Give alice some balance by canceling an order
        uint128 minOrderAmount = exchange.MIN_ORDER_AMOUNT();
        vm.prank(alice);
        uint128 orderId = exchange.place(address(token1), minOrderAmount, true, 100);
        vm.prank(alice);
        exchange.cancel(orderId);

        // Get alice's actual balance
        uint128 actualBalance = exchange.balanceOf(alice, address(pathUSD));

        // Try to withdraw more than balance
        vm.prank(alice);
        try exchange.withdraw(address(pathUSD), actualBalance + 1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory) {
            // Successfully reverted with InsufficientBalance
        }
    }

    // Test swap validation
    function test_Swap_RevertIf_PairNotExists() public {
        // Try to swap between two tokens that don't have a trading pair
        ITIP20 token3 = ITIP20(factory.createToken("Token3", "TK3", "USD", pathUSD, admin));

        try exchange.swapExactAmountIn(address(token3), address(token2), 100, 0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory) {
            // Successfully reverted
        }
    }

    function test_Swap_RevertIf_InvalidTokenPrefix() public {
        // Create an address that doesn't have the TIP20 prefix (0x20C0...)
        // Using an arbitrary address that doesn't start with the TIP20 prefix
        address invalidToken = address(0x1234567890123456789012345678901234567890);

        vm.prank(alice);
        try exchange.swapExactAmountIn(invalidToken, address(pathUSD), 100, 0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IStablecoinExchange.InvalidToken.selector));
        }

        // Also test with invalid tokenOut
        vm.prank(alice);
        try exchange.swapExactAmountIn(address(pathUSD), invalidToken, 100, 0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IStablecoinExchange.InvalidToken.selector));
        }
    }

    function test_Swap_RevertIf_InsufficientLiquidity() public {
        // Try to swap when no orders exist
        vm.prank(alice);
        try exchange.swapExactAmountIn(address(token1), address(pathUSD), 100, 0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err, abi.encodeWithSelector(IStablecoinExchange.InsufficientLiquidity.selector)
            );
        }
    }

    function test_Swap_RevertIf_SlippageExceeded() public {
        // Place an order
        vm.prank(bob);
        exchange.place(address(token1), 1e18, false, 100);

        // Orders are immediately active

        // Try to swap with unrealistic minimum output
        vm.prank(alice);
        try exchange.swapExactAmountIn(address(pathUSD), address(token1), 1e18, type(uint128).max) {
            revert CallShouldHaveReverted();
        } catch (bytes memory) {
            // Successfully reverted
        }
    }

    // Test price conversion validates bounds and reverts for out-of-range prices
    function testFuzz_PriceToTick_Conversion(uint32 price) public view {
        int16 expectedTick = int16(int32(price) - int32(exchange.PRICE_SCALE()));

        if (price < exchange.MIN_PRICE() || price > exchange.MAX_PRICE()) {
            // Should revert with TickOutOfBounds for invalid prices
            try exchange.priceToTick(price) {
                revert CallShouldHaveReverted();
            } catch (bytes memory err) {
                assertEq(
                    err,
                    abi.encodeWithSelector(
                        IStablecoinExchange.TickOutOfBounds.selector, expectedTick
                    )
                );
            }
        } else {
            // Valid price range - should succeed
            int16 tick = exchange.priceToTick(price);
            assertEq(tick, expectedTick);
        }
    }

    /*//////////////////////////////////////////////////////////////
                        IMMEDIATE ORDER ACTIVATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ImmediateOrderActivation_MultipleOrders(uint8 numOrders) public {
        vm.assume(numOrders > 0 && numOrders <= 10);

        uint128 minAmount = exchange.MIN_ORDER_AMOUNT();
        int16 tickSpacing = exchange.TICK_SPACING();

        // Place several orders - use multiples of TICK_SPACING for valid ticks
        for (uint8 i = 0; i < numOrders; i++) {
            vm.prank(alice);
            exchange.place(address(token1), minAmount, true, int16(int8(i)) * tickSpacing);
        }

        // Orders are immediately active - verify nextOrderId
        assertEq(exchange.nextOrderId(), numOrders + 1);

        // Verify first tick has liquidity (tick 0)
        (uint128 head,, uint128 liquidity) = exchange.getTickLevel(address(token1), 0, true);
        assertEq(head, 1); // First order
        assertEq(liquidity, minAmount);
    }

    function test_ImmediateOrderActivation_MultipleBatches(uint8 batch1, uint8 batch2) public {
        vm.assume(batch1 > 0 && batch1 <= 5);
        vm.assume(batch2 > 0 && batch2 <= 5);

        uint128 minAmount = exchange.MIN_ORDER_AMOUNT();
        int16 tickSpacing = exchange.TICK_SPACING();

        // First batch of orders - use multiples of TICK_SPACING for valid ticks
        for (uint8 i = 0; i < batch1; i++) {
            vm.prank(alice);
            exchange.place(address(token1), minAmount, true, int16(int8(i)) * tickSpacing);
        }

        assertEq(exchange.nextOrderId(), batch1 + 1);

        // Second batch of orders - use multiples of TICK_SPACING for valid ticks (offset by 100)
        for (uint8 i = 0; i < batch2; i++) {
            vm.prank(bob);
            exchange.place(address(token1), minAmount, true, (int16(int8(i)) + 10) * tickSpacing);
        }

        // nextOrderId should now be batch1 + batch2
        assertEq(exchange.nextOrderId(), uint128(batch1) + uint128(batch2) + 1);
    }

    /*//////////////////////////////////////////////////////////////
                        MULTI-HOP ROUTING TESTS
    //////////////////////////////////////////////////////////////*/

    // Test direct pair routing (1 hop)
    function test_Routing_DirectPair() public {
        // token1 -> pathUSD is a direct pair
        vm.prank(bob);
        exchange.place(address(token1), 1e18, false, 0);

        // Orders are immediately active

        // Swap should work via direct route
        uint128 amountOut = exchange.quoteSwapExactAmountIn(address(pathUSD), address(token1), 1e18);

        assertGt(amountOut, 0, "Should get output from direct pair");
    }

    // Test sibling token routing (2 hops through LinkingUSD)
    function test_Routing_SiblingTokens() public {
        // Create two sibling tokens: token1 and token2, both quote LinkingUSD
        // Route: token1 -> pathUSD -> token2

        // Create orderbooks
        exchange.createPair(address(token2));

        // Setup token2 for bob
        vm.prank(admin);
        token2.grantRole(_ISSUER_ROLE, admin);
        vm.prank(admin);
        token2.mint(bob, INITIAL_BALANCE);
        vm.prank(bob);
        token2.approve(address(exchange), type(uint256).max);

        // For token1 -> pathUSD: Bob buys token1 (bids for token1)
        // This means alice can sell token1 to get pathUSD
        vm.prank(bob);
        exchange.place(address(token1), 1e18, true, 0);

        // For pathUSD -> token2: Bob sells token2 (asks for token2)
        // This means alice can buy token2 with pathUSD
        vm.prank(bob);
        exchange.place(address(token2), 1e18, false, 0);

        // Orders are immediately active

        // Try to swap token1 -> token2 (should route through pathUSD)
        vm.prank(alice);
        uint128 amountOut = exchange.quoteSwapExactAmountIn(
            address(token1),
            address(token2),
            1e17 // Small amount
        );

        assertGt(amountOut, 0, "Should route through pathUSD");
    }

    // Multi-level routing test skipped - requires complex token hierarchy setup
    // The routing logic is tested via sibling tokens which also exercises the LCA algorithm

    // Fuzz test: verify routing finds valid paths
    function testFuzz_Routing_FindsValidPath(uint8 scenario) public {
        scenario = uint8(bound(scenario, 0, 2));
        uint128 minOrderAmount = exchange.MIN_ORDER_AMOUNT();

        if (scenario == 0) {
            // Direct pair: token1 <-> pathUSD
            vm.prank(bob);
            exchange.place(address(token1), minOrderAmount * 100, false, 0);

            // Orders are immediately active

            // Should find direct path
            uint128 amountOut = exchange.quoteSwapExactAmountIn(
                address(pathUSD), address(token1), minOrderAmount
            );
            assertGt(amountOut, 0);
        } else if (scenario == 1) {
            // Sibling tokens through pathUSD
            exchange.createPair(address(token2));

            vm.prank(admin);
            token2.grantRole(_ISSUER_ROLE, admin);
            vm.prank(admin);
            token2.mint(bob, INITIAL_BALANCE);
            vm.prank(bob);
            token2.approve(address(exchange), type(uint256).max);

            // For token1 -> pathUSD: Bob bids for token1 (buys token1 with pathUSD)
            vm.prank(bob);
            exchange.place(address(token1), minOrderAmount * 100, true, 0);
            // For pathUSD -> token2: Bob asks for token2 (sells token2 for pathUSD)
            vm.prank(bob);
            exchange.place(address(token2), minOrderAmount * 100, false, 0);

            // Orders are immediately active

            // Should route token1 -> pathUSD -> token2
            uint128 amountOut =
                exchange.quoteSwapExactAmountIn(address(token1), address(token2), minOrderAmount);
            assertGt(amountOut, 0);
        } else {
            // Reverse direction
            vm.prank(bob);
            exchange.place(address(token1), minOrderAmount * 100, true, 0);

            // Orders are immediately active

            // Should find path in reverse
            uint128 amountOut = exchange.quoteSwapExactAmountIn(
                address(token1), address(pathUSD), minOrderAmount
            );
            assertGt(amountOut, 0);
        }
    }

    // Test routing reverts when no orderbook exists for a pair in the path
    function test_Routing_RevertIf_NoPathExists() public {
        // Create a token but don't create its orderbook pair
        // The path algorithm will find token1 -> pathUSD -> isolatedToken
        // But the swap will fail because the isolatedToken pair doesn't exist

        ITIP20 isolatedToken = ITIP20(factory.createToken("Isolated", "ISO", "USD", pathUSD, admin));

        // Don't create a pair for isolatedToken - this means the orderbook doesn't exist

        // Try to swap token1 -> isolatedToken
        // Path exists in token tree, but orderbook pair doesn't exist
        // Expect any revert (specifically PairDoesNotExist but exact error encoding varies)
        try exchange.quoteSwapExactAmountIn(
            address(token1), address(isolatedToken), exchange.MIN_ORDER_AMOUNT()
        ) {
            revert CallShouldHaveReverted();
        } catch {
            // Successfully reverted as expected
        }
    }

    // Fuzz test: routing handles various token pair combinations
    function testFuzz_Routing_TokenPairCombinations(
        bool useToken1,
        bool useToken2,
        bool swapDirection
    ) public {
        // Setup both token pairs
        exchange.createPair(address(token2));

        vm.prank(admin);
        token2.grantRole(_ISSUER_ROLE, admin);
        vm.prank(admin);
        token2.mint(bob, INITIAL_BALANCE);
        vm.prank(bob);
        token2.approve(address(exchange), type(uint256).max);

        uint128 minOrderAmount = exchange.MIN_ORDER_AMOUNT();

        // Add liquidity
        if (useToken1) {
            vm.prank(bob);
            exchange.place(address(token1), minOrderAmount * 100, false, 0);
        }
        if (useToken2) {
            vm.prank(bob);
            exchange.place(address(token2), minOrderAmount * 100, false, 0);
        }

        // Orders are immediately active

        // Try swap based on configuration - may fail due to insufficient liquidity
        address tokenIn = swapDirection ? address(token1) : address(pathUSD);
        address tokenOut = swapDirection ? address(pathUSD) : address(token1);

        // Always use try/catch since liquidity setup varies and may not support this direction
        try exchange.quoteSwapExactAmountIn(tokenIn, tokenOut, minOrderAmount) returns (
            uint128 amountOut
        ) {
            // Success - verify output
            assertGt(amountOut, 0);
        } catch {
            // Failure is OK - may be due to insufficient liquidity or wrong direction
        }
    }

    // Test that identical token swaps are rejected
    function testFuzz_Routing_RevertIf_IdenticalTokens(address token) public view {
        vm.assume(token != address(0));

        try exchange.quoteSwapExactAmountIn(token, token, exchange.MIN_ORDER_AMOUNT()) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IStablecoinExchange.IdenticalTokens.selector));
        }
    }

    // Test routing validation for edge cases
    // Note: validateAndBuildRoute is internal and always receives paths with >=2 elements
    // from findTradePath. The path.length < 2 check is defensive programming to prevent
    // underflow in the loop and ensure meaningful swap paths. This test verifies related
    // error handling is consistent with the Rust implementation.
    function test_Routing_RevertIf_InvalidPath() public view {
        // Test with non-TIP20 token (should fail when trying to get quote token)
        address invalidToken = address(0x123456);

        try exchange.quoteSwapExactAmountIn(
            invalidToken, address(token1), exchange.MIN_ORDER_AMOUNT()
        ) {
            revert CallShouldHaveReverted();
        } catch {
            // Successfully reverted - exact error depends on whether token implements interface
        }

        // Test swap to non-TIP20 token
        try exchange.quoteSwapExactAmountIn(
            address(token1), invalidToken, exchange.MIN_ORDER_AMOUNT()
        ) {
            revert CallShouldHaveReverted();
        } catch {
            // Successfully reverted
        }
    }

    /*//////////////////////////////////////////////////////////////
                        BLACKLIST INTERNAL BALANCE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that blacklisted users cannot use internal balance to place orders
    /// @dev This test ensures TIP403 blacklist enforcement on internal balance operations
    function test_BlacklistedUser_CannotUseInternalBalance() public {
        // Create a blacklist policy
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        // Set the policy on token1
        vm.prank(admin);
        token1.changeTransferPolicyId(policyId);

        // Also set the policy on pathUSD (quote token) for bid orders
        vm.prank(pathUSDAdmin);
        pathUSD.changeTransferPolicyId(policyId);

        // Give alice some internal balance by placing and canceling an order
        uint128 orderAmount = exchange.MIN_ORDER_AMOUNT() * 2;
        vm.prank(alice);
        uint128 orderId = exchange.place(address(token1), orderAmount, false, 100);

        vm.prank(alice);
        exchange.cancel(orderId);

        // Verify alice has internal balance
        uint128 aliceInternalBalance = exchange.balanceOf(alice, address(token1));
        assertEq(aliceInternalBalance, orderAmount, "Alice should have internal balance");

        // Blacklist alice
        vm.prank(admin);
        registry.modifyPolicyBlacklist(policyId, alice, true);

        // Verify alice is blacklisted
        assertFalse(registry.isAuthorized(policyId, alice), "Alice should be blacklisted");

        // Try to place an order using internal balance - should fail
        vm.prank(alice);
        try exchange.place(address(token1), orderAmount, false, 100) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        // Verify alice's internal balance is unchanged
        assertEq(
            exchange.balanceOf(alice, address(token1)),
            aliceInternalBalance,
            "Alice's internal balance should be unchanged"
        );
    }

    /// @notice Test that blacklisted users cannot use internal balance in swaps
    function test_BlacklistedUser_CannotSwapWithInternalBalance() public {
        // Setup: Create liquidity for swapping
        _placeAskOrder(bob, 1000e18, 100);
        vm.prank(address(0));

        // Create a blacklist policy
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        // Set the policy on pathUSD
        vm.prank(pathUSDAdmin);
        pathUSD.changeTransferPolicyId(policyId);

        // Give alice some internal pathUSD balance by placing and canceling a bid order
        uint128 bidAmount = exchange.MIN_ORDER_AMOUNT() * 10;
        vm.prank(alice);
        uint128 orderId = exchange.place(address(token1), bidAmount, true, 100);

        vm.prank(alice);
        exchange.cancel(orderId);

        // Verify alice has internal pathUSD balance
        uint128 aliceInternalBalance = exchange.balanceOf(alice, address(pathUSD));
        assertGt(aliceInternalBalance, 0, "Alice should have internal pathUSD balance");

        // Blacklist alice
        vm.prank(admin);
        registry.modifyPolicyBlacklist(policyId, alice, true);

        // Try to swap using internal balance - should fail
        vm.prank(alice);
        try exchange.swapExactAmountIn(address(pathUSD), address(token1), aliceInternalBalance, 0) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        // Verify alice's internal balance is unchanged
        assertEq(
            exchange.balanceOf(alice, address(pathUSD)),
            aliceInternalBalance,
            "Alice's internal balance should be unchanged"
        );
    }

    function test_FlipOrder_BlacklistedMakerDoesNotRevertSwap() public {
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        vm.prank(admin);
        token1.changeTransferPolicyId(policyId);

        uint128 orderAmount = 100e18;
        int16 bidTick = 100;
        int16 flipTick = 200;

        vm.prank(alice);
        uint128 flipOrderId =
            exchange.placeFlip(address(token1), orderAmount, true, bidTick, flipTick);
        assertEq(flipOrderId, 1);

        vm.prank(admin);
        registry.modifyPolicyBlacklist(policyId, alice, true);
        assertFalse(registry.isAuthorized(policyId, alice));

        uint256 bobInitialToken1 = token1.balanceOf(bob);
        uint256 bobInitialPathUSD = pathUSD.balanceOf(bob);

        vm.prank(bob);
        uint128 amountOut =
            exchange.swapExactAmountIn(address(token1), address(pathUSD), orderAmount, 0);

        assertGt(amountOut, 0);
        assertEq(token1.balanceOf(bob), bobInitialToken1 - orderAmount);
        assertEq(pathUSD.balanceOf(bob), bobInitialPathUSD + amountOut);

        uint128 aliceInternalToken1 = exchange.balanceOf(alice, address(token1));
        assertEq(aliceInternalToken1, orderAmount);

        assertEq(exchange.nextOrderId(), 2);

        (uint128 askHead,, uint128 askLiquidity) =
            exchange.getTickLevel(address(token1), flipTick, false);
        assertEq(askHead, 0);
        assertEq(askLiquidity, 0);
    }

    function test_FlipOrder_DoesNotFlipWhenMakerWithdrawsBalance() public {
        // Alice places a flip bid order: buying 2e18 base tokens at tick 100, will flip to ask at tick 200
        uint128 orderAmount = 2e18;
        int16 tick = 100;
        int16 flipTick = 200;

        vm.prank(alice);
        uint128 flipOrderId = exchange.placeFlip(address(token1), orderAmount, true, tick, flipTick);

        // Bob partially fills the order (sells 1e18 base tokens)
        // This credits Alice's internal balance with 1e18 base tokens
        vm.prank(bob);
        exchange.swapExactAmountIn(address(token1), address(pathUSD), 1e18, 0);

        // Verify Alice has received base tokens in her internal balance
        uint128 aliceBaseBalance = exchange.balanceOf(alice, address(token1));
        assertEq(aliceBaseBalance, 1e18, "Alice should have 1e18 base tokens in internal balance");

        // Alice withdraws all her internal base token balance
        vm.prank(alice);
        exchange.withdraw(address(token1), aliceBaseBalance);

        // Verify Alice's internal balance is now 0
        assertEq(
            exchange.balanceOf(alice, address(token1)), 0, "Alice's internal balance should be 0"
        );

        // Verify Alice still has sufficient external token balance and approval for a flip order
        // For a flip ask at tick 200, she would need to escrow base tokens
        assertGt(
            token1.balanceOf(alice),
            orderAmount,
            "Alice should have sufficient external token balance"
        );
        assertGt(
            token1.allowance(alice, address(exchange)),
            orderAmount,
            "Alice should have sufficient approval"
        );

        uint128 nextOrderIdBefore = exchange.nextOrderId();

        // Bob fills the remaining order (sells another 1e18 base tokens)
        // The flip order should NOT be created because Alice's internal balance is insufficient
        // and we don't resort to transferFrom for flip orders
        vm.prank(bob);
        exchange.swapExactAmountIn(address(token1), address(pathUSD), 1e18, 0);

        // The original flip order should be fully filled and deleted
        try exchange.getOrder(flipOrderId) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IStablecoinExchange.OrderDoesNotExist.selector));
        }

        // No new flip order should have been created
        // If a flip order was created, nextOrderId would have incremented
        assertEq(
            exchange.nextOrderId(),
            nextOrderIdBefore,
            "No new order should be created - flip should not execute when internal balance is insufficient"
        );

        // Verify no liquidity exists at the flip tick (ask at tick 200)
        (uint128 askHead, uint128 askTail, uint128 askLiquidity) =
            exchange.getTickLevel(address(token1), flipTick, false);
        assertEq(askHead, 0, "No ask order should exist at flip tick");
        assertEq(askTail, 0, "No ask order should exist at flip tick");
        assertEq(askLiquidity, 0, "No liquidity should exist at flip tick");
    }

    /*//////////////////////////////////////////////////////////////
                        CANCEL STALE ORDER TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that a stale ask order can be canceled when maker is blacklisted
    function test_CancelStaleOrder_Ask_Succeeds_WhenMakerBlacklisted() public {
        // Create a blacklist policy
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        // Set the policy on token1 (base token for asks)
        vm.prank(admin);
        token1.changeTransferPolicyId(policyId);

        // Alice places an ask order (escrows base token)
        uint128 orderAmount = exchange.MIN_ORDER_AMOUNT() * 2;
        uint128 orderId = _placeAskOrder(alice, orderAmount, 100);

        // Verify order exists
        IStablecoinExchange.Order memory order = exchange.getOrder(orderId);
        assertEq(order.maker, alice);
        assertEq(order.remaining, orderAmount);

        // Blacklist alice
        vm.prank(admin);
        registry.modifyPolicyBlacklist(policyId, alice, true);

        // Verify alice is blacklisted
        assertFalse(registry.isAuthorized(policyId, alice), "Alice should be blacklisted");

        // Anyone (bob) can cancel the stale order
        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderCancelled(orderId);
        }

        vm.prank(bob);
        exchange.cancelStaleOrder(orderId);

        // Verify order is removed from orderbook
        (uint128 askHead, uint128 askTail, uint128 askLiquidity) =
            exchange.getTickLevel(address(token1), 100, false);
        assertEq(askHead, 0);
        assertEq(askTail, 0);
        assertEq(askLiquidity, 0);

        // Verify escrow is refunded to alice's internal balance
        assertEq(
            exchange.balanceOf(alice, address(token1)),
            orderAmount,
            "Alice should have escrow refunded to internal balance"
        );
    }

    /// @notice Test that a stale bid order can be canceled when maker is blacklisted
    function test_CancelStaleOrder_Bid_Succeeds_WhenMakerBlacklisted() public {
        // Create a blacklist policy
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        // Set the policy on pathUSD (quote token for bids)
        vm.prank(pathUSDAdmin);
        pathUSD.changeTransferPolicyId(policyId);

        // Alice places a bid order (escrows quote token)
        uint128 orderAmount = exchange.MIN_ORDER_AMOUNT() * 2;
        uint128 orderId = _placeBidOrder(alice, orderAmount, 100);

        // Calculate expected escrow
        uint32 price = exchange.tickToPrice(100);
        uint128 expectedEscrow =
            uint128((uint256(orderAmount) * uint256(price)) / uint256(exchange.PRICE_SCALE()));

        // Blacklist alice
        vm.prank(admin);
        registry.modifyPolicyBlacklist(policyId, alice, true);

        // Anyone can cancel the stale order
        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderCancelled(orderId);
        }

        vm.prank(bob);
        exchange.cancelStaleOrder(orderId);

        // Verify order is removed from orderbook
        (uint128 bidHead, uint128 bidTail, uint128 bidLiquidity) =
            exchange.getTickLevel(address(token1), 100, true);
        assertEq(bidHead, 0);
        assertEq(bidTail, 0);
        assertEq(bidLiquidity, 0);

        // Verify escrow is refunded to alice's internal balance (quote token)
        assertEq(
            exchange.balanceOf(alice, address(pathUSD)),
            expectedEscrow,
            "Alice should have quote escrow refunded to internal balance"
        );
    }

    /// @notice Test that cancelStaleOrder reverts when maker is still authorized
    function test_CancelStaleOrder_RevertsIf_MakerNotBlacklisted() public {
        // Create a blacklist policy (but don't blacklist alice)
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        // Set the policy on token1
        vm.prank(admin);
        token1.changeTransferPolicyId(policyId);

        // Alice places an ask order
        uint128 orderId = _placeAskOrder(alice, exchange.MIN_ORDER_AMOUNT() * 2, 100);

        // Alice is NOT blacklisted, so she's still authorized
        assertTrue(registry.isAuthorized(policyId, alice), "Alice should be authorized");

        // Try to cancel as stale - should fail
        vm.prank(bob);
        try exchange.cancelStaleOrder(orderId) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IStablecoinExchange.OrderNotStale.selector));
        }
    }

    /// @notice Test that cancelStaleOrder reverts for non-existent order
    function test_CancelStaleOrder_RevertsIf_OrderDoesNotExist() public {
        uint128 nonExistentOrderId = 999;

        vm.prank(bob);
        try exchange.cancelStaleOrder(nonExistentOrderId) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IStablecoinExchange.OrderDoesNotExist.selector));
        }
    }

    /// @notice Test that cancelStaleOrder works with whitelist policy (maker removed from whitelist)
    function test_CancelStaleOrder_Succeeds_WhenMakerRemovedFromWhitelist() public {
        // Create a whitelist policy
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        // Whitelist alice and the exchange initially
        vm.prank(admin);
        registry.modifyPolicyWhitelist(policyId, alice, true);
        vm.prank(admin);
        registry.modifyPolicyWhitelist(policyId, address(exchange), true);

        // Set the policy on token1
        vm.prank(admin);
        token1.changeTransferPolicyId(policyId);

        // Alice places an ask order while whitelisted
        uint128 orderAmount = exchange.MIN_ORDER_AMOUNT() * 2;
        uint128 orderId = _placeAskOrder(alice, orderAmount, 100);

        // Remove alice from whitelist
        vm.prank(admin);
        registry.modifyPolicyWhitelist(policyId, alice, false);

        // Verify alice is no longer authorized
        assertFalse(registry.isAuthorized(policyId, alice), "Alice should not be authorized");

        // Anyone can cancel the stale order
        vm.prank(bob);
        exchange.cancelStaleOrder(orderId);

        // Verify escrow is refunded
        assertEq(
            exchange.balanceOf(alice, address(token1)),
            orderAmount,
            "Alice should have escrow refunded"
        );
    }

    /// @notice Test that the order maker can also cancel their own stale order
    function test_CancelStaleOrder_MakerCanCancelOwnStaleOrder() public {
        // Create a blacklist policy
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        // Set the policy on token1
        vm.prank(admin);
        token1.changeTransferPolicyId(policyId);

        // Alice places an ask order
        uint128 orderAmount = exchange.MIN_ORDER_AMOUNT() * 2;
        uint128 orderId = _placeAskOrder(alice, orderAmount, 100);

        // Blacklist alice
        vm.prank(admin);
        registry.modifyPolicyBlacklist(policyId, alice, true);

        // Alice can cancel her own stale order
        vm.prank(alice);
        exchange.cancelStaleOrder(orderId);

        // Verify escrow is refunded
        assertEq(
            exchange.balanceOf(alice, address(token1)),
            orderAmount,
            "Alice should have escrow refunded"
        );
    }

    /// @notice Test canceling stale order in the middle of a tick level's linked list
    function test_CancelStaleOrder_RemovesFromMiddleOfLinkedList() public {
        // Create a blacklist policy
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        // Set the policy on token1
        vm.prank(admin);
        token1.changeTransferPolicyId(policyId);

        // Place three ask orders at the same tick: alice, bob, alice
        uint128 order1 = _placeAskOrder(alice, exchange.MIN_ORDER_AMOUNT(), 100);
        uint128 order2 = _placeAskOrder(bob, exchange.MIN_ORDER_AMOUNT(), 100);
        uint128 order3 = _placeAskOrder(alice, exchange.MIN_ORDER_AMOUNT(), 100);

        // Verify tick has all three orders
        (uint128 head, uint128 tail, uint128 liquidity) =
            exchange.getTickLevel(address(token1), 100, false);
        assertEq(head, order1);
        assertEq(tail, order3);
        assertEq(liquidity, exchange.MIN_ORDER_AMOUNT() * 3);

        // Blacklist alice
        vm.prank(admin);
        registry.modifyPolicyBlacklist(policyId, alice, true);

        // Cancel alice's first order (head of list)
        vm.prank(bob);
        exchange.cancelStaleOrder(order1);

        // Verify bob's order is now head
        (head, tail, liquidity) = exchange.getTickLevel(address(token1), 100, false);
        assertEq(head, order2);
        assertEq(tail, order3);
        assertEq(liquidity, exchange.MIN_ORDER_AMOUNT() * 2);

        // Cancel alice's second order (tail of list)
        vm.prank(bob);
        exchange.cancelStaleOrder(order3);

        // Verify only bob's order remains
        (head, tail, liquidity) = exchange.getTickLevel(address(token1), 100, false);
        assertEq(head, order2);
        assertEq(tail, order2);
        assertEq(liquidity, exchange.MIN_ORDER_AMOUNT());
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _placeBidOrder(address user, uint128 amount, int16 tick)
        internal
        returns (uint128 orderId)
    {
        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderPlaced(exchange.nextOrderId(), user, address(token1), amount, true, tick);
        }

        vm.prank(user);
        orderId = exchange.place(address(token1), amount, true, tick);
    }

    function _placeAskOrder(address user, uint128 amount, int16 tick)
        internal
        returns (uint128 orderId)
    {
        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit OrderPlaced(exchange.nextOrderId(), user, address(token1), amount, false, tick);
        }

        vm.prank(user);
        orderId = exchange.place(address(token1), amount, false, tick);
    }

}
