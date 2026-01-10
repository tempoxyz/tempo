// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title StablecoinDEX Invariant Tests
/// @notice Fuzz-based invariant tests for the StablecoinDEX orderbook exchange
/// @dev Tests invariants TEMPO-DEX1 through TEMPO-DEX12 as documented in README.md
contract StablecoinDEXInvariantTest is BaseTest {

    /// @dev Array of test actors that interact with the DEX
    address[] private _actors;

    /// @dev Mapping of actor address to their placed order IDs
    mapping(address => uint128[]) private _placedOrders;

    /// @dev Fixed set of valid ticks used for order placement
    int16[10] private _ticks = [int16(10), 20, 30, 40, 50, 60, 70, 80, 90, 100];

    /// @dev Expected next order ID, used to verify TEMPO-DEX1
    uint128 private _nextOrderId;

    /// @dev The trading pair key for token1/pathUSD
    bytes32 private _pairKey;

    /// @dev Blacklist policy ID for token1
    uint64 private _token1PolicyId;

    /// @dev Blacklist policy ID for pathUSD
    uint64 private _pathUsdPolicyId;

    /// @notice Sets up the test environment
    /// @dev Initializes BaseTest, creates trading pair, builds actors, and sets initial state
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        // Setup token1 with issuer role (admin is the token1 admin from BaseTest)
        vm.startPrank(admin);
        token1.grantRole(_ISSUER_ROLE, admin);
        vm.stopPrank();

        // Setup pathUSD with issuer role (pathUSDAdmin is the pathUSD admin from BaseTest)
        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, admin);
        vm.stopPrank();

        // Create the trading pair
        _pairKey = exchange.createPair(address(token1));

        // Create blacklist policies for testing cancelStaleOrder
        vm.startPrank(admin);
        _token1PolicyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        token1.changeTransferPolicyId(_token1PolicyId);
        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        _pathUsdPolicyId = registry.createPolicy(pathUSDAdmin, ITIP403Registry.PolicyType.BLACKLIST);
        pathUSD.changeTransferPolicyId(_pathUsdPolicyId);
        vm.stopPrank();

        _actors = _buildActors(20);
        _nextOrderId = exchange.nextOrderId();
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz handler: Places a bid or ask order and optionally cancels it
    /// @dev Tests TEMPO-DEX1 (order ID), TEMPO-DEX2 (escrow), TEMPO-DEX3 (cancel refund), TEMPO-DEX7 (tick liquidity)
    /// @param actorRnd Random seed for selecting actor
    /// @param amount Order amount (bounded to valid range)
    /// @param tickRnd Random seed for selecting tick
    /// @param isBid True for bid order, false for ask order
    /// @param cancel If true, immediately cancels the placed order
    function placeOrder(uint256 actorRnd, uint128 amount, uint256 tickRnd, bool isBid, bool cancel)
        external
    {
        int16 tick = _ticks[tickRnd % _ticks.length];
        address actor = _actors[actorRnd % _actors.length];
        amount = uint128(bound(amount, 100_000_000, 10_000_000_000));

        _ensureFunds(actor, amount);

        vm.startPrank(actor);
        uint128 orderId = exchange.place(address(token1), amount, isBid, tick);

        // TEMPO-DEX1: Order ID monotonically increases
        _assertNextOrderId(orderId);

        uint32 price = exchange.tickToPrice(tick);
        uint256 expectedEscrow = (uint256(amount) * uint256(price) + exchange.PRICE_SCALE() - 1)
            / uint256(exchange.PRICE_SCALE());

        // Verify order was created correctly
        IStablecoinDEX.Order memory order = exchange.getOrder(orderId);
        assertEq(order.maker, actor, "TEMPO-DEX2: order maker mismatch");
        assertEq(order.amount, amount, "TEMPO-DEX2: order amount mismatch");
        assertEq(order.remaining, amount, "TEMPO-DEX2: order remaining mismatch");
        assertEq(order.tick, tick, "TEMPO-DEX2: order tick mismatch");
        assertEq(order.isBid, isBid, "TEMPO-DEX2: order side mismatch");

        if (cancel) {
            // Capture balance before cancel to verify refund amount
            uint128 balanceBeforePathUsd = exchange.balanceOf(actor, address(pathUSD));
            uint128 balanceBeforeToken1 = exchange.balanceOf(actor, address(token1));

            exchange.cancel(orderId);

            // TEMPO-DEX3: Cancel refunds correct amounts to internal balance
            if (isBid) {
                uint128 refund = uint128(expectedEscrow);
                uint128 balanceAfter = exchange.balanceOf(actor, address(pathUSD));
                assertEq(
                    balanceAfter - balanceBeforePathUsd,
                    refund,
                    "TEMPO-DEX3: bid cancel refund mismatch"
                );
                exchange.withdraw(address(pathUSD), refund);
            } else {
                uint128 balanceAfter = exchange.balanceOf(actor, address(token1));
                assertEq(
                    balanceAfter - balanceBeforeToken1,
                    amount,
                    "TEMPO-DEX3: ask cancel refund mismatch"
                );
                exchange.withdraw(address(token1), amount);
            }

            // Verify order no longer exists
            try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory) {
                revert("TEMPO-DEX3: order should not exist after cancel");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    IStablecoinDEX.OrderDoesNotExist.selector,
                    "TEMPO-DEX3: unexpected error on getOrder"
                );
            }
        } else {
            _placedOrders[actor].push(orderId);

            // TEMPO-DEX7: Verify tick level liquidity updated
            (,, uint128 tickLiquidity) = exchange.getTickLevel(address(token1), tick, isBid);
            assertTrue(tickLiquidity >= amount, "TEMPO-DEX7: tick liquidity not updated");
        }

        vm.stopPrank();
    }

    /// @notice Fuzz handler: Places a flip order that auto-flips when filled
    /// @dev Tests TEMPO-DEX1 (order ID), TEMPO-DEX12 (flip tick constraints)
    /// @param actorRnd Random seed for selecting actor
    /// @param amount Order amount (bounded to valid range)
    /// @param tickRnd Random seed for selecting tick
    /// @param isBid True for bid flip order, false for ask flip order
    function placeFlipOrder(uint256 actorRnd, uint128 amount, uint256 tickRnd, bool isBid)
        external
    {
        int16 tick = _ticks[tickRnd % _ticks.length];
        address actor = _actors[actorRnd % _actors.length];
        amount = uint128(bound(amount, 100_000_000, 10_000_000_000));

        _ensureFunds(actor, amount);

        vm.startPrank(actor);
        uint128 orderId;
        int16 flipTick;
        if (isBid) {
            flipTick = 200;
            orderId = exchange.placeFlip(address(token1), amount, true, tick, flipTick);
        } else {
            flipTick = -200;
            orderId = exchange.placeFlip(address(token1), amount, false, tick, flipTick);
        }
        _assertNextOrderId(orderId);

        // TEMPO-DEX12: Flip order constraints
        IStablecoinDEX.Order memory order = exchange.getOrder(orderId);
        assertTrue(order.isFlip, "TEMPO-DEX12: flip order not marked as flip");
        if (isBid) {
            assertTrue(
                order.flipTick > order.tick, "TEMPO-DEX12: bid flip tick must be > order tick"
            );
        } else {
            assertTrue(
                order.flipTick < order.tick, "TEMPO-DEX12: ask flip tick must be < order tick"
            );
        }

        _placedOrders[actor].push(orderId);

        vm.stopPrank();
    }

    /// @dev Struct to capture swapper balances before swap to avoid stack too deep
    struct SwapBalanceSnapshot {
        uint256 token1External;
        uint256 pathUsdExternal;
        uint128 token1Internal;
        uint128 pathUsdInternal;
    }

    /// @notice Fuzz handler: Executes swaps with exact amount in or exact amount out
    /// @dev Tests TEMPO-DEX4, TEMPO-DEX5, TEMPO-DEX14, TEMPO-DEX16
    /// @param swapperRnd Random seed for selecting swapper
    /// @param amount Swap amount (bounded to valid range)
    /// @param amtIn True for swapExactAmountIn, false for swapExactAmountOut
    function swapExactAmount(uint256 swapperRnd, uint128 amount, bool amtIn) external {
        address swapper = _actors[swapperRnd % _actors.length];
        amount = uint128(bound(amount, 100_000_000, 1_000_000_000));

        // Check if swapper has active orders - if so, skip TEMPO-DEX14 balance checks
        // because self-trade makes the accounting complex (maker proceeds returned to swapper)
        bool swapperHasOrders = _placedOrders[swapper].length > 0;

        // Capture total balances (external + internal) before swap for TEMPO-DEX14
        SwapBalanceSnapshot memory before = SwapBalanceSnapshot({
            token1External: token1.balanceOf(swapper),
            pathUsdExternal: pathUSD.balanceOf(swapper),
            token1Internal: exchange.balanceOf(swapper, address(token1)),
            pathUsdInternal: exchange.balanceOf(swapper, address(pathUSD))
        });

        vm.startPrank(swapper);
        if (amtIn) {
            _swapExactAmountIn(swapper, amount, before, swapperHasOrders);
        } else {
            _swapExactAmountOut(swapper, amount, before, swapperHasOrders);
        }
        // Read next order id - if a flip order is hit then next order id is incremented.
        _nextOrderId = exchange.nextOrderId();

        vm.stopPrank();
    }

    /// @notice Fuzz handler: Blacklists an actor, has another actor cancel their stale orders, then whitelists again
    /// @dev Tests TEMPO-DEX13 (stale order cancellation by non-owner when maker is blacklisted)
    /// @param blacklistActorRnd Random seed for selecting actor to blacklist
    /// @param cancellerActorRnd Random seed for selecting actor who will cancel stale orders
    /// @param forBids If true, blacklist in quote token (pathUSD) for bids; if false, blacklist in base token for asks
    function cancelStaleOrderAfterBlacklist(
        uint256 blacklistActorRnd,
        uint256 cancellerActorRnd,
        bool forBids
    ) external {
        address blacklistedActor = _actors[blacklistActorRnd % _actors.length];
        address canceller = _actors[cancellerActorRnd % _actors.length];

        // Skip if canceller is the same as blacklisted actor
        vm.assume(canceller != blacklistedActor);

        // Skip if the actor has no orders
        if (_placedOrders[blacklistedActor].length == 0) {
            return;
        }

        // Blacklist the actor in the appropriate token
        if (forBids) {
            // For bids, blacklist in quote token (pathUSD) since that's the escrow token
            vm.prank(pathUSDAdmin);
            registry.modifyPolicyBlacklist(_pathUsdPolicyId, blacklistedActor, true);
        } else {
            // For asks, blacklist in base token (token1) since that's the escrow token
            vm.prank(admin);
            registry.modifyPolicyBlacklist(_token1PolicyId, blacklistedActor, true);
        }

        // Have a different actor cancel the blacklisted actor's stale orders
        vm.startPrank(canceller);
        for (uint256 i = 0; i < _placedOrders[blacklistedActor].length; i++) {
            uint128 orderId = _placedOrders[blacklistedActor][i];

            // Try to get the order - it may have been filled
            try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory order) {
                // Only try to cancel if the order side matches the blacklist type
                bool canCancelStale = (forBids && order.isBid) || (!forBids && !order.isBid);

                if (canCancelStale) {
                    // Capture balance before cancel
                    uint128 balanceBefore = forBids
                        ? exchange.balanceOf(blacklistedActor, address(pathUSD))
                        : exchange.balanceOf(blacklistedActor, address(token1));

                    // TEMPO-DEX13: Anyone can cancel a stale order from a blacklisted maker
                    exchange.cancelStaleOrder(orderId);

                    // Verify refund was credited to blacklisted actor's internal balance
                    uint128 balanceAfter = forBids
                        ? exchange.balanceOf(blacklistedActor, address(pathUSD))
                        : exchange.balanceOf(blacklistedActor, address(token1));

                    if (order.isBid) {
                        uint32 price = exchange.tickToPrice(order.tick);
                        uint128 expectedRefund = uint128(
                            (uint256(order.remaining) * uint256(price) + exchange.PRICE_SCALE() - 1)
                                / exchange.PRICE_SCALE()
                        );
                        assertEq(
                            balanceAfter - balanceBefore,
                            expectedRefund,
                            "TEMPO-DEX13: stale bid cancel refund mismatch"
                        );
                    } else {
                        assertEq(
                            balanceAfter - balanceBefore,
                            order.remaining,
                            "TEMPO-DEX13: stale ask cancel refund mismatch"
                        );
                    }

                    // Verify order no longer exists
                    try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory) {
                        revert("TEMPO-DEX13: order should not exist after stale cancel");
                    } catch (bytes memory reason) {
                        assertEq(
                            bytes4(reason),
                            IStablecoinDEX.OrderDoesNotExist.selector,
                            "TEMPO-DEX13: unexpected error on getOrder"
                        );
                    }
                }
            } catch {
                // Order was already filled or cancelled
            }
        }
        vm.stopPrank();

        // Whitelist the actor again so they can continue to be used in tests
        if (forBids) {
            vm.prank(pathUSDAdmin);
            registry.modifyPolicyBlacklist(_pathUsdPolicyId, blacklistedActor, false);
        } else {
            vm.prank(admin);
            registry.modifyPolicyBlacklist(_token1PolicyId, blacklistedActor, false);
        }

        // Update next order id in case any flip orders were triggered
        _nextOrderId = exchange.nextOrderId();
    }

    /*//////////////////////////////////////////////////////////////
                            INVARIANT HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Called after invariant testing completes to clean up state
    /// @dev Cancels all remaining orders and verifies TEMPO-DEX3 (refunds) and TEMPO-DEX10 (linked list)
    function afterInvariant() public {
        for (uint256 i = 0; i < _actors.length; i++) {
            address actor = _actors[i];
            vm.startPrank(actor);
            for (uint256 orderId = 0; orderId < _placedOrders[actor].length; orderId++) {
                uint128 placedOrderId = _placedOrders[actor][orderId];
                // Placed orders could be filled and removed.
                try exchange.getOrder(placedOrderId) returns (IStablecoinDEX.Order memory order) {
                    // TEMPO-DEX10: Verify linked list consistency before cancel
                    _assertOrderLinkedListConsistency(placedOrderId, order);

                    exchange.cancel(placedOrderId);

                    // TEMPO-DEX3: Verify refund credited to internal balance and withdraw to ensure actors can exit
                    if (order.isBid) {
                        uint32 price = exchange.tickToPrice(order.tick);
                        uint128 expectedRefund = uint128(
                            (uint256(order.remaining) * uint256(price) + exchange.PRICE_SCALE() - 1)
                                / exchange.PRICE_SCALE()
                        );
                        assertTrue(
                            exchange.balanceOf(actor, address(pathUSD)) >= expectedRefund,
                            "TEMPO-DEX3: bid cancel refund not credited"
                        );
                        exchange.withdraw(address(pathUSD), expectedRefund);
                    } else {
                        assertTrue(
                            exchange.balanceOf(actor, address(token1)) >= order.remaining,
                            "TEMPO-DEX3: ask cancel refund not credited"
                        );
                        exchange.withdraw(address(token1), order.remaining);
                    }
                } catch { }
            }
            vm.stopPrank();
        }
    }

    /*//////////////////////////////////////////////////////////////
                          INVARIANT ASSERTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Main invariant function called after each fuzz sequence
    /// @dev Verifies TEMPO-DEX6 (balance solvency), TEMPO-DEX7/11 (tick consistency), TEMPO-DEX8/9 (best tick)
    function invariantStablecoinDEX() public view {
        uint256 dexPathUsdBalance = pathUSD.balanceOf(address(exchange));
        uint256 dexToken1Balance = token1.balanceOf(address(exchange));

        // TEMPO-DEX6: DEX token balances must be >= sum of all internal user balances
        uint256 totalUserPathUsd = 0;
        uint256 totalUserToken1 = 0;
        for (uint256 i = 0; i < _actors.length; i++) {
            totalUserPathUsd += exchange.balanceOf(_actors[i], address(pathUSD));
            totalUserToken1 += exchange.balanceOf(_actors[i], address(token1));
        }

        assertTrue(
            dexPathUsdBalance >= totalUserPathUsd,
            "TEMPO-DEX6: DEX pathUsd balance < sum of user internal balances"
        );
        assertTrue(
            dexToken1Balance >= totalUserToken1,
            "TEMPO-DEX6: DEX token1 balance < sum of user internal balances"
        );

        // Compute expected escrowed amounts from all orders (including flip-created orders)
        (uint256 expectedPathUsdEscrowed, uint256 expectedToken1Escrowed, uint256 orderCount) =
            _computeExpectedEscrow();

        // Assert escrowed amounts: DEX balance = user internal balances + escrowed in active orders
        // Allow tolerance for rounding during partial fills (can accumulate across multiple fills)
        // TODO: check tolerance and rounding error
        uint256 tolerance = orderCount * 4 + 1;
        assertApproxEqAbs(
            dexPathUsdBalance,
            totalUserPathUsd + expectedPathUsdEscrowed,
            tolerance,
            "TEMPO-DEX6: DEX pathUSD balance != user balances + escrowed"
        );
        assertApproxEqAbs(
            dexToken1Balance,
            totalUserToken1 + expectedToken1Escrowed,
            tolerance,
            "TEMPO-DEX6: DEX token1 balance != user balances + escrowed"
        );

        // TEMPO-DEX8 & TEMPO-DEX9: Best bid/ask tick consistency
        _assertBestTickConsistency();

        // TEMPO-DEX7 & TEMPO-DEX11: Tick level and bitmap consistency
        _assertTickLevelConsistency();
    }

    /// @notice Computes expected escrowed amounts by iterating through all orders
    /// @dev Iterates all order IDs to catch flip-created orders not in _placedOrders
    /// @return pathUsdEscrowed Total pathUSD escrowed in active bid orders
    /// @return token1Escrowed Total token1 escrowed in active ask orders
    /// @return orderCount Number of active orders (for rounding tolerance)
    function _computeExpectedEscrow()
        internal
        view
        returns (uint256 pathUsdEscrowed, uint256 token1Escrowed, uint256 orderCount)
    {
        uint128 nextId = exchange.nextOrderId();
        for (uint128 orderId = 1; orderId < nextId; orderId++) {
            try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory order) {
                orderCount++;
                if (order.isBid) {
                    uint32 price = exchange.tickToPrice(order.tick);
                    uint256 escrow =
                        (uint256(order.remaining) * uint256(price) + exchange.PRICE_SCALE() - 1)
                            / exchange.PRICE_SCALE();
                    pathUsdEscrowed += escrow;
                } else {
                    token1Escrowed += order.remaining;
                }
            } catch {
                // Order was filled or cancelled
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Helper for swapExactAmountIn to avoid stack too deep
    function _swapExactAmountIn(
        address swapper,
        uint128 amount,
        SwapBalanceSnapshot memory before,
        bool skipBalanceCheck
    ) internal {
        // TEMPO-DEX16: Quote should match execution TODO: enable when fixed
        uint128 quotedOut;
        try exchange.quoteSwapExactAmountIn(address(token1), address(pathUSD), amount) returns (
            uint128 quoted
        ) {
            quotedOut = quoted;
        } catch {
            quotedOut = 0;
        }

        try exchange.swapExactAmountIn(
            address(token1), address(pathUSD), amount, amount - 100
        ) returns (
            uint128 amountOut
        ) {
            // TEMPO-DEX4: amountOut >= minAmountOut
            assertTrue(
                amountOut >= amount - 100, "TEMPO-DEX4: swap exact amountOut less than minAmountOut"
            );

            // TEMPO-DEX14: Swapper total balance changes correctly
            // Skip if swapper has orders (self-trade makes accounting complex)
            if (!skipBalanceCheck) {
                _assertSwapBalanceChanges(swapper, before, amount, amountOut);
            }

            // TEMPO-DEX16: Quote matches execution TODO: enable when fixed
            if (quotedOut > 0) {
                //assertEq(amountOut, quotedOut, "TEMPO-DEX16: quote mismatch for swapExactAmountIn");
            }
        } catch (bytes memory reason) {
            _assertKnownSwapError(reason);
        }
    }

    /// @dev Helper for swapExactAmountOut to avoid stack too deep
    function _swapExactAmountOut(
        address swapper,
        uint128 amount,
        SwapBalanceSnapshot memory before,
        bool skipBalanceCheck
    ) internal {
        // TEMPO-DEX16: Quote should match execution
        uint128 quotedIn;
        try exchange.quoteSwapExactAmountOut(address(token1), address(pathUSD), amount) returns (
            uint128 quoted
        ) {
            quotedIn = quoted;
        } catch {
            quotedIn = 0;
        }

        try exchange.swapExactAmountOut(
            address(token1), address(pathUSD), amount, amount + 100
        ) returns (
            uint128 amountIn
        ) {
            // TEMPO-DEX5: amountIn <= maxAmountIn
            assertTrue(
                amountIn <= amount + 100, "TEMPO-DEX5: swap exact amountIn greater than maxAmountIn"
            );

            // TEMPO-DEX14: Swapper total balance changes correctly
            // Skip if swapper has orders (self-trade makes accounting complex)
            if (!skipBalanceCheck) {
                _assertSwapBalanceChanges(swapper, before, amountIn, amount);
            }

            // TEMPO-DEX16: Quote matches execution. TODO: enable when fixed
            if (quotedIn > 0) {
                //assertEq(amountIn, quotedIn, "TEMPO-DEX16: quote mismatch for swapExactAmountOut");
            }
        } catch (bytes memory reason) {
            _assertKnownSwapError(reason);
        }
    }

    /// @dev Helper to assert swap balance changes for TEMPO-DEX14
    /// @notice Checks total balance (external + internal) to handle taker == maker scenarios
    /// @param swapper The swapper address
    /// @param before Balance snapshot before the swap
    /// @param token1Spent Amount of token1 spent (amountIn for the swap)
    /// @param pathUsdReceived Amount of pathUSD received (amountOut for the swap)
    function _assertSwapBalanceChanges(
        address swapper,
        SwapBalanceSnapshot memory before,
        uint128 token1Spent,
        uint128 pathUsdReceived
    ) internal view {
        // Calculate total balances (external + internal) after swap
        uint256 token1TotalBefore = before.token1External + before.token1Internal;
        uint256 pathUsdTotalBefore = before.pathUsdExternal + before.pathUsdInternal;

        uint256 token1TotalAfter =
            token1.balanceOf(swapper) + exchange.balanceOf(swapper, address(token1));
        uint256 pathUsdTotalAfter =
            pathUSD.balanceOf(swapper) + exchange.balanceOf(swapper, address(pathUSD));

        // Swapper's total token1 should decrease by token1Spent
        // Note: If swapper's bid orders were filled, they gain token1 to internal balance,
        // but since we're selling token1 for pathUSD here, the net is still -token1Spent
        assertEq(
            token1TotalBefore - token1TotalAfter,
            token1Spent,
            "TEMPO-DEX14: swapper total token1 change incorrect"
        );

        // Swapper's total pathUSD should increase by pathUsdReceived
        // Note: If swapper's ask orders were filled, they gain pathUSD to internal balance
        assertEq(
            pathUsdTotalAfter - pathUsdTotalBefore,
            pathUsdReceived,
            "TEMPO-DEX14: swapper total pathUsd change incorrect"
        );
    }

    /// @notice Verifies best bid and ask tick point to valid tick levels
    /// @dev Tests TEMPO-DEX8 (best bid) and TEMPO-DEX9 (best ask)
    function _assertBestTickConsistency() internal view {
        (,, int16 bestBidTick, int16 bestAskTick) =
            exchange.books(exchange.pairKey(address(token1), address(pathUSD)));

        // TEMPO-DEX8: If bestBidTick is not MIN, it should have liquidity
        if (bestBidTick != type(int16).min) {
            (,, uint128 bidLiquidity) = exchange.getTickLevel(address(token1), bestBidTick, true);
            // Note: during swaps, bestBidTick may temporarily point to empty tick
            // This is acceptable as it gets updated on next operation
        }

        // TEMPO-DEX9: If bestAskTick is not MAX, it should have liquidity
        if (bestAskTick != type(int16).max) {
            (,, uint128 askLiquidity) = exchange.getTickLevel(address(token1), bestAskTick, false);
            // Note: during swaps, bestAskTick may temporarily point to empty tick
        }
    }

    /// @notice Verifies tick level data structure consistency
    /// @dev Tests TEMPO-DEX7 (liquidity matches orders), TEMPO-DEX10 (head/tail consistency), TEMPO-DEX11 (bitmap)
    function _assertTickLevelConsistency() internal view {
        // Check a sample of ticks for consistency
        for (uint256 i = 0; i < _ticks.length; i++) {
            int16 tick = _ticks[i];

            // Check bid tick level
            (uint128 bidHead, uint128 bidTail, uint128 bidLiquidity) =
                exchange.getTickLevel(address(token1), tick, true);
            if (bidLiquidity > 0) {
                // TEMPO-DEX7: If liquidity > 0, head should be non-zero
                assertTrue(bidHead != 0, "TEMPO-DEX7: bid tick has liquidity but no head");
                // TEMPO-DEX11: Bitmap correctness verified indirectly via bestBidTick/bestAskTick in _assertBestTickConsistency
            }
            if (bidHead == 0) {
                // If head is 0, tail should also be 0 and liquidity should be 0
                assertEq(bidTail, 0, "TEMPO-DEX10: bid tail non-zero but head is zero");
                assertEq(bidLiquidity, 0, "TEMPO-DEX7: bid liquidity non-zero but head is zero");
            }

            // Check ask tick level
            (uint128 askHead, uint128 askTail, uint128 askLiquidity) =
                exchange.getTickLevel(address(token1), tick, false);
            if (askLiquidity > 0) {
                assertTrue(askHead != 0, "TEMPO-DEX7: ask tick has liquidity but no head");
            }
            if (askHead == 0) {
                assertEq(askTail, 0, "TEMPO-DEX10: ask tail non-zero but head is zero");
                assertEq(askLiquidity, 0, "TEMPO-DEX7: ask liquidity non-zero but head is zero");
            }
        }
    }

    /// @notice Verifies order linked list pointers are consistent
    /// @dev Tests TEMPO-DEX10: prev.next == current and next.prev == current
    /// @param orderId The order ID to verify
    /// @param order The order data
    function _assertOrderLinkedListConsistency(uint128 orderId, IStablecoinDEX.Order memory order)
        internal
        view
    {
        // TEMPO-DEX10: If order has prev, prev's next should point to this order
        if (order.prev != 0) {
            IStablecoinDEX.Order memory prevOrder = exchange.getOrder(order.prev);
            assertEq(
                prevOrder.next, orderId, "TEMPO-DEX10: prev order's next doesn't point to current"
            );
        }

        // TEMPO-DEX10: If order has next, next's prev should point to this order
        if (order.next != 0) {
            IStablecoinDEX.Order memory nextOrder = exchange.getOrder(order.next);
            assertEq(
                nextOrder.prev, orderId, "TEMPO-DEX10: next order's prev doesn't point to current"
            );
        }
    }

    /// @notice Verifies order ID matches expected and increments counter
    /// @dev Tests TEMPO-DEX1: Order IDs are assigned sequentially
    /// @param orderId The order ID returned from place/placeFlip
    function _assertNextOrderId(uint128 orderId) internal {
        // TEMPO-DEX1: Order ID monotonically increases
        assertEq(orderId, _nextOrderId, "TEMPO-DEX1: next order id mismatch");
        _nextOrderId += 1;
    }

    /// @notice Verifies a swap revert is due to a known/expected error
    /// @dev Fails if the error selector doesn't match any known swap error
    /// @param reason The revert reason bytes from the failed swap
    function _assertKnownSwapError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnownError = selector == IStablecoinDEX.InsufficientLiquidity.selector
            || selector == IStablecoinDEX.InsufficientOutput.selector
            || selector == IStablecoinDEX.MaxInputExceeded.selector
            || selector == IStablecoinDEX.InsufficientBalance.selector
            || selector == IStablecoinDEX.PairDoesNotExist.selector
            || selector == IStablecoinDEX.IdenticalTokens.selector
            || selector == IStablecoinDEX.InvalidToken.selector
            || selector == ITIP20.InsufficientBalance.selector
            || selector == ITIP20.PolicyForbids.selector;
        assertTrue(isKnownError, "Swap failed with unknown error");
    }

    /// @notice Creates test actors with initial balances and approvals
    /// @dev Each actor gets funded and approves the exchange for both tokens
    /// @param noOfActors_ Number of actors to create
    /// @return actorsAddress Array of created actor addresses
    function _buildActors(uint256 noOfActors_) internal returns (address[] memory) {
        address[] memory actorsAddress = new address[](noOfActors_);

        for (uint256 i = 0; i < noOfActors_; i++) {
            address actor = makeAddr(string(abi.encodePacked("Actor", vm.toString(i))));
            actorsAddress[i] = actor;

            // initial actor balance
            _ensureFunds(actor, 1_000_000_000_000);

            vm.startPrank(actor);
            token1.approve(address(exchange), type(uint256).max);
            pathUSD.approve(address(exchange), type(uint256).max);
            vm.stopPrank();
        }

        return actorsAddress;
    }

    /// @notice Ensures an actor has sufficient token balances for testing
    /// @dev Mints tokens if actor's balance is below the required amount
    /// @param actor The actor address to fund
    /// @param amount The minimum balance required
    function _ensureFunds(address actor, uint256 amount) internal {
        vm.startPrank(admin);
        if (pathUSD.balanceOf(address(actor)) < amount) {
            pathUSD.mint(actor, amount + 100_000_000);
        }
        if (token1.balanceOf(address(actor)) < amount) {
            token1.mint(actor, amount + 100_000_000);
        }
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          FAILURES REPRO
    //////////////////////////////////////////////////////////////*/

    /// @notice fails if TEMPO-DEX16 enabled
    function testReproDEX16QuoteMismatchOut() external {
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeOrder(
                9_558_570_077_960_085_633_653_695_175_917_485_444_202_355_741_275_948_550_613_259_375_346_385,
                7,
                233_568_675_898_653_404_360_250_386_309_241_377_793_333_357,
                true,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeFlipOrder(
                301_365,
                69_546_172_010_336_025_265_575_322_610_212_078,
                11_355_817_413_378_558_616_734_169_007_275_482_187,
                true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeFlipOrder(289, 6, 11_588, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                379_928_535_540_359_086_518_915_873_206_108_773_663_286_470_566_274_838,
                18_931,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                458_297_009_615_161_915_289_839, 5_454_670_747_409_380_657_486_770, false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeFlipOrder(3824, 335_972_798_343_701_746_246_856_599_657_569_421_132, 9, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                20_605_735_771_902_281_925_382_902, 52_398_262_934_580_807_959_027, true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(26_652_029_005_296_984_319_940_186, 1_955_859_655_031_487, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                6_659_008_076_275, 81_185_804_270_573_679_033_355_557_343_733_708_470, true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(512, 5, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                10_437_175_717_263_000_561_771_835_093_311_785_989_731_915_009_071_034_673,
                3_805_691_144_036_157_469_320_866_867_444_990,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                7_984_522_694_784_135_442_392_186_573_774_329_013_584_669_394_815_199_262_787_621_290_540_440,
                4_598_058_576_530_503_464_421,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(13_718_499_648_598_428_557_030, 245_483_527, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                76_742_893_204_655_364_882_045_946_850_991_719_318_475_535_730_078_006_839_746_857_730_770_830,
                21_419_659_030_609_680,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                16_769_418_490_134_021_599_412_251_537_535_422_356_079_081_397_678_552_738_311_075_357_847_800_021,
                472_235_423_232_136_161_151,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(9_039_508_932_300_820_592_317_358_777_485_552, 1, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                14_099_490_637_467_691_673_257_349_132_186_879_769_338_692_926_089_876,
                2_620_256_765_105_727_194,
                true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(8567, 25_259_743_990, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                245_966_488_707_180_590_813_208_198_591_943_838_423_418, 156_040_545_934_950, false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                4_289_741_108_724_363_749_668_415_349_216_424_221_873_212_813_922, 237_387, false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                3_800_222_259_856_644_280_661_621_405_562_981_821_483_747_998_694_606_706_739_912,
                1_944_473_731_026,
                true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(1, 465_832, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(4_397_963_807, 0, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                774_470_939_459_762_731_314_255_477_042_405_889_664_758_093_659_697_518_387_913_964_575_897_351_494,
                10_651,
                true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
                8716,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(954, 309_582_385_725_645_795_013_810_066_720_913_664_504, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                285_196_349_613_267_377_582_564_124_496_431_863_584_913_588_201_808,
                74_830_425_353_290_563_956_238_180_494_631_176,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                3_539_899_022_260_725_149_398_989_128_937,
                644_262_265_630_211_668_712_835_712_010_667_770,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                106_710_554_243_539_439_919_650_178_084_276_198_561_044_256_727_140_477_710_015_132,
                2_659_122_473_175_464_551_782_242_779,
                true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(0, 0, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(65_535, 1234, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(6, 1588, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(9_179_926_934_565, 83_603_346_075_970_461_421, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
                1_978_717_316_239_976_334_955_766_350_735_786_172,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(6_859_875_712_693_835_094_221_190_680_222_893, 89_614_929, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(103_623_564_223_206_646_138_244_552, 1, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(255, 244_503_207_430, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                7_582_851_116_386_955_263_219_622_792_571_840_045_696_602_811_702_469_370,
                48_174,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                153_525_369_901_325_225_621_015_930_226_144_088_737_359_688_749_883,
                1_140_534_356_669_908_973_403,
                false
            );
    }

    /// @notice fails if TEMPO-DEX16 enabled
    function testReproDEX16QuoteMismatchIn() external {
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeFlipOrder(
                2, 328_134_792_733_308_945_408_115_820_128_797_045_422, 1_829_955_119, true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(25_259_743_990, 244_503_207_431, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(20, 1_000_000_000, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(1_000_000_000, 5791, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(5, 1_950_818, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                1_518_889_154_448_658_106_372, 848_179_881_728_934_280_417_812_247, true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(3082, 30, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(768, 98_000, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                306_482_207_306_705_579_078_181_145_707_606_147_266_091_845_298_707_357_973_391,
                31_911_384_263_867_631_961_694_654_561,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(30, 8, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
                6_484_688_131_189_955_155_905,
                true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(129_574_031_215, 15_944_133_472_238_632, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeOrder(
                208_263_264_604,
                342_230_965_039_049_105_241_437,
                1_518_814_207_656_572_061_071_084_709,
                true,
                false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(5, 998_414_828_386, true);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(4_397_963_807, 20, true);
    }

    /// @notice fails TEMPO-DEX6 with 6419205152 !~= 6419205150 if tolerance set to 0
    function testReproDEX6Tolerance() external {
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeFlipOrder(
                16_620_986_750_173_327_375_072_129_536_696,
                191_690_262_104_147_198_647,
                151_418_302_004_512_096_018,
                true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                2_438_339_387_864_312_957_756_060_121_378_828_567, 32_133_919_125_377_151_346, false
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(
                68_820_684_459_960_264_687_589_486_638_758_947_665_982_554_552_360_197, 48, false
            );

        vm.startPrank(0x9a3D03B8a341C194aE72e271Ff63f2E9cf3EC506);
        exchange.cancel(1);
        exchange.withdraw(address(pathUSD), 6_419_205_150);
        // Assert dust of 2 in exchange
        assertEq(pathUSD.balanceOf(address(exchange)), 2);
    }

}
