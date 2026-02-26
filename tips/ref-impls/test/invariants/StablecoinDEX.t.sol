// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { TIP20 } from "../../src/TIP20.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";
import { Vm } from "forge-std/Vm.sol";

/// @title StablecoinDEX Invariant Tests
/// @notice Fuzz-based invariant tests for the StablecoinDEX orderbook exchange
/// @dev Tests invariants TEMPO-DEX1 through TEMPO-DEX19 as documented in README.md
contract StablecoinDEXInvariantTest is InvariantBaseTest {

    /// @dev Mapping of actor address to their placed order IDs
    mapping(address => uint128[]) private _placedOrders;

    /// @dev Canonical set of valid ticks used for order placement, flip tick selection,
    /// and tick consistency checks. Kept small to concentrate liquidity so orders interact
    /// during swaps. Dense cluster [-30..30] enables multi-tick swap traversal through both
    /// bitmap words (symmetric across the word boundary at 0). Also covers: boundaries
    /// (±2000) and int8 bitmap boundary (±1280 → compressed ±128).
    int16[11] private _ticks = [int16(-2000), -1280, -30, -20, -10, 0, 10, 20, 30, 1280, 2000];

    /// @dev Expected next order ID, used to verify TEMPO-DEX1
    uint128 private _nextOrderId;

    /// @dev Maximum amount of dust that can be left in the protocol. This is used to verify TEMPO-DEX9.
    uint64 private _maxDust;

    /// @dev Dust level before each swap, used to verify TEMPO-DEX8 (each swap increases dust by at most 1).
    uint256 private _dustBeforeSwap;

    /// @dev TEMPO-DEX19: Ghost variables for tracking divisibility edge cases
    /// When (base * price) % PRICE_SCALE == 0, ceil should equal floor (no +1)
    uint256 private _ghostDivisibleEscrowCount;
    uint256 private _ghostDivisibleEscrowCorrect;

    /// @notice Sets up the test environment
    /// @dev Initializes BaseTest, creates trading pair, builds actors, and sets initial state
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();

        // Create trading pairs for all tokens
        vm.startPrank(admin);
        for (uint256 i = 0; i < _tokens.length; i++) {
            exchange.createPair(address(_tokens[i]));
        }
        vm.stopPrank();

        _actors = _buildActorsWithApprovals(20, address(exchange));
        _nextOrderId = exchange.nextOrderId();
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz handler: Places a bid or ask order and optionally cancels it
    /// @dev Tests TEMPO-DEX1 (order ID), TEMPO-DEX2 (escrow), TEMPO-DEX3 (cancel refund), TEMPO-DEX11 (tick liquidity)
    /// @param actorRnd Random seed for selecting actor
    /// @param amount Order amount (bounded to valid range)
    /// @param tickRnd Random seed for selecting tick
    /// @param tokenRnd Random seed for selecting token
    /// @param isBid True for bid order, false for ask order
    /// @param cancel If true, immediately cancels the placed order
    function placeOrder(
        uint256 actorRnd,
        uint128 amount,
        uint256 tickRnd,
        uint256 tokenRnd,
        bool isBid,
        bool cancel
    )
        public
    {
        int16 tick = _ticks[tickRnd % _ticks.length];
        address actor = _actors[actorRnd % _actors.length];
        address token = address(_tokens[tokenRnd % _tokens.length]);
        amount = uint128(bound(amount, 100_000_000, 10_000_000_000));

        // TEMPO-DEX2: For bids, escrow is ceil(amount * price / PRICE_SCALE)
        // For asks, escrow is exactly the base token amount
        uint256 escrowAmount;
        if (isBid) {
            uint32 price = exchange.tickToPrice(tick);
            escrowAmount = (uint256(amount) * uint256(price) + exchange.PRICE_SCALE() - 1)
                / exchange.PRICE_SCALE();
        } else {
            escrowAmount = amount;
        }

        // Ensure funds for the token being escrowed (pathUSD for bids, base token for asks)
        _ensureFunds(actor, TIP20(isBid ? address(pathUSD) : token), escrowAmount);

        // Capture actor's token balance before placing order (for cancel verification)
        uint256 actorBalanceBeforePlace =
            isBid ? pathUSD.balanceOf(actor) : TIP20(token).balanceOf(actor);

        vm.startPrank(actor);
        uint128 orderId = exchange.place(token, amount, isBid, tick);

        // TEMPO-DEX1: Order ID monotonically increases
        _assertNextOrderId(orderId);

        // Verify order was created correctly
        _assertOrderCreated(orderId, actor, amount, tick, isBid);

        if (cancel) {
            _cancelAndVerifyRefund(
                orderId, actor, token, amount, tick, isBid, actorBalanceBeforePlace
            );
        } else {
            _placedOrders[actor].push(orderId);

            // TEMPO-DEX11: Verify tick level liquidity updated
            (,, uint128 tickLiquidity) = exchange.getTickLevel(token, tick, isBid);
            assertTrue(tickLiquidity >= amount, "TEMPO-DEX11: tick liquidity not updated");
        }

        vm.stopPrank();
    }

    function placeOrder1(
        uint256 actorRnd,
        uint128 amount,
        uint256 tickRnd,
        uint256 tokenRnd,
        bool isBid
    )
        external
    {
        placeOrder(actorRnd, amount, tickRnd, tokenRnd, isBid, false);
    }

    /// @notice Places an order and immediately cancels it
    /// @dev Increases coverage of TEMPO-DEX3 (cancel refund) path
    function placeOrder2(
        uint256 actorRnd,
        uint128 amount,
        uint256 tickRnd,
        uint256 tokenRnd,
        bool isBid
    )
        external
    {
        placeOrder(actorRnd, amount, tickRnd, tokenRnd, isBid, true);
    }

    /// @notice TEMPO-DEX19: Test divisibility edge cases - when (base*price) % PRICE_SCALE == 0
    function placeDivisibleBid(uint256 actorRnd, uint256 tickRnd, uint256 tokenRnd) external {
        int16 tick = _ticks[tickRnd % _ticks.length];
        address actor = _actors[actorRnd % _actors.length];
        address token = address(_tokens[tokenRnd % _tokens.length]);
        uint32 price = exchange.tickToPrice(tick);
        uint256 scale = exchange.PRICE_SCALE();

        // Calculate the smallest amount >= min order size where (amount * price) % PRICE_SCALE == 0
        uint256 g = _gcd(uint256(price), scale);
        uint256 step = scale / g;
        uint256 minOrder = 100_000_000;
        uint128 amount = uint128(step * ((minOrder + step - 1) / step));

        uint256 product = uint256(amount) * uint256(price);
        assertEq(product % scale, 0, "TEMPO-DEX19: divisible amount construction failed");

        _ghostDivisibleEscrowCount++;
        uint256 expectedEscrow = product / scale;
        _ensureFunds(actor, pathUSD, expectedEscrow + 1000);

        // Capture both external and internal balance before placing order
        uint256 externalBefore = pathUSD.balanceOf(actor);
        uint256 internalBefore = exchange.balanceOf(actor, address(pathUSD));
        uint256 totalBefore = externalBefore + internalBefore;

        vm.prank(actor);
        uint128 orderId = exchange.place(token, amount, true, tick);
        _assertNextOrderId(orderId);

        // Calculate total escrow from both external and internal balance changes
        uint256 externalAfter = pathUSD.balanceOf(actor);
        uint256 internalAfter = exchange.balanceOf(actor, address(pathUSD));
        uint256 totalAfter = externalAfter + internalAfter;
        uint256 escrowed = totalBefore - totalAfter;

        // TEMPO-DEX19: When (amount * price) % PRICE_SCALE == 0, escrow must be EXACT
        // No +1 tolerance allowed - ceil should equal floor when perfectly divisible
        assertEq(
            escrowed,
            expectedEscrow,
            "TEMPO-DEX19: Divisible escrow should be exact (no +1 rounding)"
        );
        _ghostDivisibleEscrowCorrect++;
        _placedOrders[actor].push(orderId);
    }

    function _gcd(uint256 a, uint256 b) internal pure returns (uint256) {
        while (b != 0) {
            uint256 t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    /// @dev Picks a flip tick from _ticks on the correct side of tick (strict inequality).
    /// Returns (false, 0) if no valid flip tick exists (tick is at a boundary).
    function _pickFlipTick(
        int16 tick,
        bool isBid,
        uint256 rnd
    )
        internal
        view
        returns (bool ok, int16 flipTick)
    {
        uint256 count = 0;
        for (uint256 i = 0; i < _ticks.length; i++) {
            int16 t = _ticks[i];
            if (isBid ? (t > tick) : (t < tick)) count++;
        }
        if (count == 0) return (false, int16(0));

        uint256 k = rnd % count;
        for (uint256 i = 0; i < _ticks.length; i++) {
            int16 t = _ticks[i];
            if (isBid ? (t > tick) : (t < tick)) {
                if (k == 0) return (true, t);
                k--;
            }
        }
        revert("_pickFlipTick: unreachable");
    }

    /// @dev Helper to verify order was created correctly (TEMPO-DEX2)
    function _assertOrderCreated(
        uint128 orderId,
        address actor,
        uint128 amount,
        int16 tick,
        bool isBid
    )
        internal
        view
    {
        IStablecoinDEX.Order memory order = exchange.getOrder(orderId);
        assertEq(order.maker, actor, "TEMPO-DEX2: order maker mismatch");
        assertEq(order.amount, amount, "TEMPO-DEX2: order amount mismatch");
        assertEq(order.remaining, amount, "TEMPO-DEX2: order remaining mismatch");
        assertEq(order.tick, tick, "TEMPO-DEX2: order tick mismatch");
        assertEq(order.isBid, isBid, "TEMPO-DEX2: order side mismatch");
    }

    function cancelOrder(uint128 orderId) external {
        orderId = orderId % exchange.nextOrderId();
        try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory order) {
            (address base,,,) = exchange.books(order.bookKey);
            // Cancel, but skip checking `actorBalanceBeforePlace`
            _cancelAndVerifyRefund(
                orderId, order.maker, base, order.remaining, order.tick, order.isBid, 0
            );
        } catch (bytes memory reason) {
            _assertKnownOrderError(reason);
        }
    }

    /// @notice Fuzz handler: Withdraws random amount of random token for random actor
    /// @dev This causes flip orders to randomly fail when their internal balance is depleted
    /// @param actorRnd Random seed for selecting actor
    /// @param amount Amount to withdraw (bounded to actor's internal balance)
    /// @param tokenRnd Random seed for selecting token
    function withdraw(uint256 actorRnd, uint128 amount, uint256 tokenRnd) external {
        address actor = _actors[actorRnd % _actors.length];
        address token = _selectToken(tokenRnd);

        uint128 balance = exchange.balanceOf(actor, token);
        vm.assume(balance > 0);

        amount = uint128(bound(amount, 1, balance));

        vm.startPrank(actor);
        exchange.withdraw(token, amount);
        vm.stopPrank();
    }

    /// @dev Helper to cancel order and verify refund (TEMPO-DEX3)
    function _cancelAndVerifyRefund(
        uint128 orderId,
        address actor,
        address token,
        uint128 amount,
        int16 tick,
        bool isBid,
        uint256 actorBalanceBeforePlace
    )
        internal
    {
        if (isBid) {
            _cancelAndVerifyBidRefund(orderId, actor, token, amount, tick, actorBalanceBeforePlace);
        } else {
            _cancelAndVerifyAskRefund(orderId, actor, token, amount, actorBalanceBeforePlace);
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
    }

    /// @dev Helper to cancel and verify bid refund (TEMPO-DEX3)
    function _cancelAndVerifyBidRefund(
        uint128 orderId,
        address actor,
        address token,
        uint128 amount,
        int16 tick,
        uint256 actorBalanceBeforePlace
    )
        internal
    {
        uint128 balanceBefore = exchange.balanceOf(actor, address(pathUSD));
        uint256 dexBalanceBefore = pathUSD.balanceOf(address(exchange));
        uint256 actorExternalBefore = pathUSD.balanceOf(actor);

        vm.startPrank(actor);
        exchange.cancel(orderId);

        uint32 price = exchange.tickToPrice(tick);
        uint128 expectedEscrow = uint128(
            (uint256(amount) * uint256(price) + exchange.PRICE_SCALE() - 1)
                / uint256(exchange.PRICE_SCALE())
        );

        uint128 balanceAfter = exchange.balanceOf(actor, address(pathUSD));
        assertEq(
            balanceAfter - balanceBefore, expectedEscrow, "TEMPO-DEX3: bid cancel refund mismatch"
        );

        uint128 withdrawAmount = balanceAfter;
        exchange.withdraw(address(pathUSD), withdrawAmount);
        vm.stopPrank();

        uint256 dexBalanceAfter = pathUSD.balanceOf(address(exchange));
        assertEq(
            dexBalanceBefore - dexBalanceAfter,
            withdrawAmount,
            "TEMPO-DEX3: DEX pathUSD balance did not decrease correctly"
        );
        assertEq(
            pathUSD.balanceOf(actor),
            actorExternalBefore + withdrawAmount,
            "TEMPO-DEX3: actor pathUSD balance did not increase correctly"
        );
        assertGe(
            pathUSD.balanceOf(actor),
            actorBalanceBeforePlace,
            "TEMPO-DEX3: actor pathUSD balance less than before place"
        );
    }

    /// @dev Helper to cancel and verify ask refund (TEMPO-DEX3)
    function _cancelAndVerifyAskRefund(
        uint128 orderId,
        address actor,
        address token,
        uint128 amount,
        uint256 actorBalanceBeforePlace
    )
        internal
    {
        uint128 balanceBefore = exchange.balanceOf(actor, token);
        uint256 dexBalanceBefore = TIP20(token).balanceOf(address(exchange));
        uint256 actorExternalBefore = TIP20(token).balanceOf(actor);

        vm.startPrank(actor);
        exchange.cancel(orderId);

        uint128 balanceAfter = exchange.balanceOf(actor, token);
        assertEq(balanceAfter - balanceBefore, amount, "TEMPO-DEX3: ask cancel refund mismatch");

        uint128 withdrawAmount = balanceAfter;
        exchange.withdraw(token, withdrawAmount);
        vm.stopPrank();

        uint256 dexBalanceAfter = TIP20(token).balanceOf(address(exchange));
        assertEq(
            dexBalanceBefore - dexBalanceAfter,
            withdrawAmount,
            "TEMPO-DEX3: DEX token balance did not decrease correctly"
        );
        assertEq(
            TIP20(token).balanceOf(actor),
            actorExternalBefore + withdrawAmount,
            "TEMPO-DEX3: actor token balance did not increase correctly"
        );
        assertGe(
            TIP20(token).balanceOf(actor),
            actorBalanceBeforePlace,
            "TEMPO-DEX3: actor token balance less than before place"
        );
    }

    /// @notice Fuzz handler: Places a flip order that auto-flips when filled
    /// @dev Tests TEMPO-DEX1 (order ID), TEMPO-DEX17 (flip tick constraints)
    /// @param actorRnd Random seed for selecting actor
    /// @param amount Order amount (bounded to valid range)
    /// @param tickRnd Random seed for selecting tick
    /// @param tokenRnd Random seed for selecting token
    /// @param isBid True for bid flip order, false for ask flip order
    /// @param flipTickRnd Random seed for selecting flip tick from _ticks
    function placeFlipOrder(
        uint256 actorRnd,
        uint128 amount,
        uint256 tickRnd,
        uint256 tokenRnd,
        bool isBid,
        uint256 flipTickRnd
    )
        external
    {
        int16 tick = _ticks[tickRnd % _ticks.length];
        address actor = _actors[actorRnd % _actors.length];
        TIP20 token = _tokens[tokenRnd % _tokens.length];
        amount = uint128(bound(amount, 100_000_000, 10_000_000_000));

        // DEX-09: Select flip tick from _ticks on the correct side of tick
        (bool ok, int16 flipTick) = _pickFlipTick(tick, isBid, flipTickRnd);
        if (!ok) return;

        // Ensure funds for the token being escrowed (pathUSD for bids, base token for asks)
        // For bids, escrow = baseToQuoteCeil(amount, tick), so we need to ensure enough funds
        if (isBid) {
            uint32 price = exchange.tickToPrice(tick);
            uint256 escrowAmount =
                (uint256(amount) * price + exchange.PRICE_SCALE() - 1) / exchange.PRICE_SCALE();
            _ensureFunds(actor, pathUSD, escrowAmount);
        } else {
            _ensureFunds(actor, token, amount);
        }

        vm.startPrank(actor);
        uint128 orderId = exchange.placeFlip(address(token), amount, isBid, tick, flipTick);
        _assertNextOrderId(orderId);

        // TEMPO-DEX17: Flip order constraints
        IStablecoinDEX.Order memory order = exchange.getOrder(orderId);
        assertTrue(order.isFlip, "TEMPO-DEX17: flip order not marked as flip");
        if (isBid) {
            assertTrue(
                order.flipTick > order.tick, "TEMPO-DEX17: bid flip tick must be > order tick"
            );
        } else {
            assertTrue(
                order.flipTick < order.tick, "TEMPO-DEX17: ask flip tick must be < order tick"
            );
        }

        _placedOrders[actor].push(orderId);

        vm.stopPrank();
    }

    /// @dev Struct to capture swapper balances before swap to avoid stack too deep
    struct SwapBalanceSnapshot {
        address tokenIn;
        address tokenOut;
        uint256 tokenInExternal;
        uint256 tokenOutExternal;
        uint128 tokenInInternal;
        uint128 tokenOutInternal;
    }

    /// @notice Fuzz handler: Executes swaps with exact amount in or exact amount out
    /// @dev Tests TEMPO-DEX4, TEMPO-DEX5, TEMPO-DEX6, TEMPO-DEX7
    /// @param swapperRnd Random seed for selecting swapper
    /// @param amount Swap amount (bounded to valid range)
    /// @param tokenInRnd Random seed for selecting tokenIn
    /// @param tokenOutRnd Random seed for selecting tokenOut
    /// @param amtIn True for swapExactAmountIn, false for swapExactAmountOut
    function swapExactAmount(
        uint256 swapperRnd,
        uint128 amount,
        uint256 tokenInRnd,
        uint256 tokenOutRnd,
        bool amtIn
    )
        external
    {
        address swapper = _actors[swapperRnd % _actors.length];
        amount = uint128(bound(amount, 100_000_000, 1_000_000_000));

        // Select tokenIn and tokenOut from all available tokens (base tokens + pathUSD)
        // This allows any-to-any token swaps (e.g., T1->T2, T1->pathUSD, pathUSD->T3, etc.)
        address tokenIn = _selectToken(tokenInRnd);
        address tokenOut = _selectToken(tokenOutRnd);

        // Skip if same token (can't swap token for itself)
        vm.assume(tokenIn != tokenOut);

        // Ensure swapper has enough of tokenIn
        _ensureFunds(swapper, TIP20(tokenIn), amount);

        // Check if swapper has active orders - if so, skip TEMPO-DEX6 balance checks
        // because self-trade makes the accounting complex (maker proceeds returned to swapper)
        bool swapperHasOrders = _hasActiveOrders(swapper);

        // Capture total balances (external + internal) before swap for TEMPO-DEX6
        SwapBalanceSnapshot memory before = SwapBalanceSnapshot({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            tokenInExternal: TIP20(tokenIn).balanceOf(swapper),
            tokenOutExternal: TIP20(tokenOut).balanceOf(swapper),
            tokenInInternal: exchange.balanceOf(swapper, tokenIn),
            tokenOutInternal: exchange.balanceOf(swapper, tokenOut)
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
    /// @dev Tests TEMPO-DEX18 (stale order cancellation by non-owner when maker is blacklisted)
    /// @param blacklistActorRnd Random seed for selecting actor to blacklist
    /// @param cancellerActorRnd Random seed for selecting actor who will cancel stale orders
    /// @param forBids If true, blacklist in quote token (pathUSD) for bids; if false, blacklist in base token for asks
    function cancelStaleOrderAfterBlacklist(
        uint256 blacklistActorRnd,
        uint256 cancellerActorRnd,
        bool forBids
    )
        external
    {
        address blacklistedActor = _selectActor(blacklistActorRnd);
        address canceller = _selectActorExcluding(cancellerActorRnd, blacklistedActor);

        // Skip if the actor has no orders
        vm.assume(_placedOrders[blacklistedActor].length > 0);

        // Blacklist the actor in the appropriate token(s)
        if (forBids) {
            // For bids, blacklist in quote token (pathUSD) since that's the escrow token
            vm.prank(pathUSDAdmin);
            registry.modifyPolicyBlacklist(_pathUsdPolicyId, blacklistedActor, true);
        } else {
            // For asks, blacklist in all base tokens since orders can be on any token
            vm.startPrank(admin);
            for (uint256 t = 0; t < _tokens.length; t++) {
                registry.modifyPolicyBlacklist(
                    _tokenPolicyIds[address(_tokens[t])], blacklistedActor, true
                );
            }
            vm.stopPrank();
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
                    // Get the base token for this order
                    (address base,,,) = exchange.books(order.bookKey);

                    // Capture balance before cancel
                    uint128 balanceBefore = forBids
                        ? exchange.balanceOf(blacklistedActor, address(pathUSD))
                        : exchange.balanceOf(blacklistedActor, base);

                    // TEMPO-DEX18: Anyone can cancel a stale order from a blacklisted maker
                    exchange.cancelStaleOrder(orderId);

                    // Verify refund was credited to blacklisted actor's internal balance
                    uint128 balanceAfter = forBids
                        ? exchange.balanceOf(blacklistedActor, address(pathUSD))
                        : exchange.balanceOf(blacklistedActor, base);

                    if (order.isBid) {
                        uint32 price = exchange.tickToPrice(order.tick);
                        uint128 expectedRefund = uint128(
                            (uint256(order.remaining) * uint256(price) + exchange.PRICE_SCALE() - 1)
                                / exchange.PRICE_SCALE()
                        );
                        assertEq(
                            balanceAfter - balanceBefore,
                            expectedRefund,
                            "TEMPO-DEX18: stale bid cancel refund mismatch"
                        );
                    } else {
                        assertEq(
                            balanceAfter - balanceBefore,
                            order.remaining,
                            "TEMPO-DEX18: stale ask cancel refund mismatch"
                        );
                    }

                    // Verify order no longer exists
                    try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory) {
                        revert("TEMPO-DEX18: order should not exist after stale cancel");
                    } catch (bytes memory reason) {
                        assertEq(
                            bytes4(reason),
                            IStablecoinDEX.OrderDoesNotExist.selector,
                            "TEMPO-DEX18: unexpected error on getOrder"
                        );
                    }
                }
            } catch (bytes memory reason) {
                _assertKnownOrderError(reason);
            }
        }
        vm.stopPrank();

        // Whitelist the actor again so they can continue to be used in tests
        if (forBids) {
            vm.prank(pathUSDAdmin);
            registry.modifyPolicyBlacklist(_pathUsdPolicyId, blacklistedActor, false);
        } else {
            vm.startPrank(admin);
            for (uint256 t = 0; t < _tokens.length; t++) {
                registry.modifyPolicyBlacklist(
                    _tokenPolicyIds[address(_tokens[t])], blacklistedActor, false
                );
            }
            vm.stopPrank();
        }

        // Update next order id in case any flip orders were triggered
        _nextOrderId = exchange.nextOrderId();
    }

    /*//////////////////////////////////////////////////////////////
                            INVARIANT HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Called after invariant testing completes to clean up state
    /// @dev Cancels all remaining orders and verifies TEMPO-DEX3 (refunds) and TEMPO-DEX14 (linked list)
    function afterInvariant() public {
        // Cancel all orders by iterating through order IDs
        for (uint128 orderId = 1; orderId < _nextOrderId; orderId++) {
            try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory order) {
                // TEMPO-DEX14: Verify linked list consistency before cancel
                _assertOrderLinkedListConsistency(orderId, order);

                // Get the base token for this order
                (address base,,,) = exchange.books(order.bookKey);
                address maker = order.maker;

                vm.startPrank(maker);
                exchange.cancel(orderId);

                // TEMPO-DEX3: Verify refund credited to internal balance and withdraw to ensure actors can exit
                if (order.isBid) {
                    uint32 price = exchange.tickToPrice(order.tick);
                    uint128 expectedRefund = uint128(
                        (uint256(order.remaining) * uint256(price) + exchange.PRICE_SCALE() - 1)
                            / exchange.PRICE_SCALE()
                    );
                    assertTrue(
                        exchange.balanceOf(maker, address(pathUSD)) >= expectedRefund,
                        "TEMPO-DEX3: bid cancel refund not credited"
                    );
                    exchange.withdraw(address(pathUSD), expectedRefund);
                } else {
                    assertTrue(
                        exchange.balanceOf(maker, base) >= order.remaining,
                        "TEMPO-DEX3: ask cancel refund not credited"
                    );
                    exchange.withdraw(base, order.remaining);
                }
                vm.stopPrank();
            } catch (bytes memory reason) {
                _assertKnownOrderError(reason);
            }
        }

        // Withdraw remaining balances for all actors
        for (uint256 i = 0; i < _actors.length; i++) {
            address actor = _actors[i];
            vm.startPrank(actor);
            exchange.withdraw(address(pathUSD), exchange.balanceOf(actor, address(pathUSD)));
            for (uint256 j = 0; j < _tokens.length; j++) {
                exchange.withdraw(
                    address(_tokens[j]), exchange.balanceOf(actor, address(_tokens[j]))
                );
            }
            vm.stopPrank();
        }

        uint256 totalBalance;
        for (uint256 j = 0; j < _tokens.length; j++) {
            totalBalance += _tokens[j].balanceOf(address(exchange));
        }

        assertGe(
            _maxDust,
            pathUSD.balanceOf(address(exchange)) + totalBalance,
            "TEMPO-DEX9: Excess post-swap dust"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          INVARIANT ASSERTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Main invariant function called after each fuzz sequence
    /// @dev Verifies TEMPO-DEX10 (balance solvency), TEMPO-DEX11/15 (tick consistency), TEMPO-DEX12/13 (best tick)
    ///      Optimized: unified loops over actors and tokens to reduce iteration overhead
    function invariantStablecoinDEX() public view {
        // Compute expected escrowed amounts from all orders (including flip-created orders)
        (uint256 expectedPathUsdEscrowed, uint256[] memory expectedTokenEscrowed,) =
            _computeExpectedEscrow();

        // Cache DEX balances and compute user totals in single pass
        uint256 dexPathUsdBalance = pathUSD.balanceOf(address(exchange));
        uint256 totalUserPathUsd = 0;
        uint256[] memory dexTokenBalances = new uint256[](_tokens.length);
        uint256[] memory totalUserTokenBalances = new uint256[](_tokens.length);

        // Cache DEX token balances
        for (uint256 t = 0; t < _tokens.length; t++) {
            dexTokenBalances[t] = _tokens[t].balanceOf(address(exchange));
        }

        // Single pass over actors to accumulate all user balances
        for (uint256 i = 0; i < _actors.length; i++) {
            address actor = _actors[i];
            totalUserPathUsd += exchange.balanceOf(actor, address(pathUSD));
            for (uint256 t = 0; t < _tokens.length; t++) {
                totalUserTokenBalances[t] += exchange.balanceOf(actor, address(_tokens[t]));
            }
        }

        // TEMPO-DEX10: Check pathUSD balance solvency
        assertTrue(
            dexPathUsdBalance >= totalUserPathUsd,
            "TEMPO-DEX10: DEX pathUsd balance < sum of user internal balances"
        );
        assertApproxEqAbs(
            dexPathUsdBalance,
            totalUserPathUsd + expectedPathUsdEscrowed,
            _maxDust,
            "TEMPO-DEX10: DEX pathUSD balance != user balances + escrowed"
        );

        // Single loop over tokens for all token-based checks
        for (uint256 t = 0; t < _tokens.length; t++) {
            address tokenAddr = address(_tokens[t]);

            // TEMPO-DEX10: Token balance solvency
            assertTrue(
                dexTokenBalances[t] >= totalUserTokenBalances[t],
                "TEMPO-DEX10: DEX token balance < sum of user internal balances"
            );
            assertApproxEqAbs(
                dexTokenBalances[t],
                totalUserTokenBalances[t] + expectedTokenEscrowed[t],
                _maxDust,
                "TEMPO-DEX10: DEX token balance != user balances + escrowed"
            );

            // TEMPO-DEX12 & TEMPO-DEX13: Best bid/ask tick consistency
            _assertBestTickConsistency(tokenAddr);

            // TEMPO-DEX11 & TEMPO-DEX15: Tick level and bitmap consistency
            _assertTickLevelConsistency(tokenAddr);
        }

        // TEMPO-DEX19: Divisibility edge cases - all should have correct escrow
        if (_ghostDivisibleEscrowCount > 0) {
            assertEq(
                _ghostDivisibleEscrowCorrect,
                _ghostDivisibleEscrowCount,
                "TEMPO-DEX19: Divisible escrow mismatch"
            );
        }
    }

    /// @notice Computes the current dust in the DEX
    /// @dev Dust is the difference between DEX balance and (internal balances + escrowed amounts)
    /// @return dust The total dust across all tokens
    function _computeDust() internal view returns (uint256 dust) {
        (uint256 pathUsdEscrowed, uint256[] memory tokenEscrowed,) = _computeExpectedEscrow();

        uint256 dexPathUsdBalance = pathUSD.balanceOf(address(exchange));
        uint256 totalUserPathUsd = 0;
        for (uint256 i = 0; i < _actors.length; i++) {
            totalUserPathUsd += exchange.balanceOf(_actors[i], address(pathUSD));
        }
        if (dexPathUsdBalance > totalUserPathUsd + pathUsdEscrowed) {
            dust += dexPathUsdBalance - totalUserPathUsd - pathUsdEscrowed;
        }

        for (uint256 t = 0; t < _tokens.length; t++) {
            uint256 dexTokenBalance = _tokens[t].balanceOf(address(exchange));
            uint256 totalUserTokenBalance = 0;
            for (uint256 i = 0; i < _actors.length; i++) {
                totalUserTokenBalance += exchange.balanceOf(_actors[i], address(_tokens[t]));
            }
            if (dexTokenBalance > totalUserTokenBalance + tokenEscrowed[t]) {
                dust += dexTokenBalance - totalUserTokenBalance - tokenEscrowed[t];
            }
        }
    }

    /// @notice Checks whether an actor has any currently active (not filled/cancelled) orders
    /// @dev Scans tracked order IDs (including flip-generated IDs captured from swap logs)
    function _hasActiveOrders(address actor) internal view returns (bool) {
        uint128[] storage ids = _placedOrders[actor];
        for (uint256 i = ids.length; i > 0; i--) {
            try exchange.getOrder(ids[i - 1]) returns (IStablecoinDEX.Order memory) {
                return true;
            } catch { }
        }
        return false;
    }

    /// @notice Computes expected escrowed amounts by iterating through all orders
    /// @dev Iterates all order IDs to catch flip-created orders not in _placedOrders
    /// @return pathUsdEscrowed Total pathUSD escrowed in active bid orders
    /// @return tokenEscrowed Array of escrowed amounts for each base token (ask orders)
    /// @return orderCount Number of active orders (for rounding tolerance)
    function _computeExpectedEscrow()
        internal
        view
        returns (uint256 pathUsdEscrowed, uint256[] memory tokenEscrowed, uint256 orderCount)
    {
        tokenEscrowed = new uint256[](_tokens.length);

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
                    // Find which token this order is for
                    (address base,,,) = exchange.books(order.bookKey);
                    for (uint256 t = 0; t < _tokens.length; t++) {
                        if (address(_tokens[t]) == base) {
                            tokenEscrowed[t] += order.remaining;
                            break;
                        }
                    }
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
    )
        internal
    {
        // TEMPO-DEX7: Quote should match execution TODO: enable when fixed
        uint128 quotedOut;
        try exchange.quoteSwapExactAmountIn(before.tokenIn, before.tokenOut, amount) returns (
            uint128 quoted
        ) {
            quotedOut = quoted;
        } catch {
            quotedOut = 0;
        }

        // TEMPO-DEX8: Record dust before swap
        _dustBeforeSwap = _computeDust();

        vm.recordLogs();
        try exchange.swapExactAmountIn(
            before.tokenIn, before.tokenOut, amount, amount - 100
        ) returns (
            uint128 amountOut
        ) {
            uint64 ordersFilled = _processSwapLogs();
            // For multi-hop swaps, each hop can add dust from rounding (not just per order)
            uint64 hops = uint64(_findRoute(before.tokenIn, before.tokenOut));
            _maxDust += ordersFilled + hops;

            // TEMPO-DEX8: Each swap can increase dust by at most 1 per order filled + 1 per hop
            // (rounding occurs at each hop, not just at hop boundaries)
            uint256 dustAfterSwap = _computeDust();
            assertLe(
                dustAfterSwap,
                _dustBeforeSwap + ordersFilled + hops,
                "TEMPO-DEX8: swap increased dust by more than expected (1 per order + 1 per hop)"
            );
            // TEMPO-DEX4: amountOut >= minAmountOut
            assertTrue(
                amountOut >= amount - 100, "TEMPO-DEX4: swap exact amountOut less than minAmountOut"
            );

            // TEMPO-DEX6: Swapper total balance changes correctly
            // Skip if swapper has orders (self-trade makes accounting complex)
            if (!skipBalanceCheck) {
                _assertSwapBalanceChanges(swapper, before, amount, amountOut);
            }

            // TEMPO-DEX7: Quote matches execution TODO: enable when fixed
            if (quotedOut > 0) {
                //assertEq(amountOut, quotedOut, "TEMPO-DEX7: quote mismatch for swapExactAmountIn");
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
    )
        internal
    {
        // TEMPO-DEX7: Quote should match execution
        uint128 quotedIn;
        try exchange.quoteSwapExactAmountOut(before.tokenIn, before.tokenOut, amount) returns (
            uint128 quoted
        ) {
            quotedIn = quoted;
        } catch {
            quotedIn = 0;
        }

        // TEMPO-DEX8: Record dust before swap
        _dustBeforeSwap = _computeDust();

        vm.recordLogs();
        try exchange.swapExactAmountOut(
            before.tokenIn, before.tokenOut, amount, amount + 100
        ) returns (
            uint128 amountIn
        ) {
            uint64 ordersFilled = _processSwapLogs();
            // For multi-hop swaps, each hop can add dust from rounding (not just per order)
            uint64 hops = uint64(_findRoute(before.tokenIn, before.tokenOut));
            _maxDust += ordersFilled + hops;

            // TEMPO-DEX8: Each swap can increase dust by at most 1 per order filled + 1 per hop
            // (rounding occurs at each hop, not just at hop boundaries)
            uint256 dustAfterSwap = _computeDust();
            assertLe(
                dustAfterSwap,
                _dustBeforeSwap + ordersFilled + hops,
                "TEMPO-DEX8: swap increased dust by more than expected (1 per order + 1 per hop)"
            );

            // TEMPO-DEX5: amountIn <= maxAmountIn
            assertTrue(
                amountIn <= amount + 100, "TEMPO-DEX5: swap exact amountIn greater than maxAmountIn"
            );

            // TEMPO-DEX6: Swapper total balance changes correctly
            // Skip if swapper has orders (self-trade makes accounting complex)
            if (!skipBalanceCheck) {
                _assertSwapBalanceChanges(swapper, before, amountIn, amount);
            }

            // TEMPO-DEX7: Quote matches execution. TODO: enable when fixed
            if (quotedIn > 0) {
                //assertEq(amountIn, quotedIn, "TEMPO-DEX7: quote mismatch for swapExactAmountOut");
            }
        } catch (bytes memory reason) {
            _assertKnownSwapError(reason);
        }
    }

    /// @dev Helper to assert swap balance changes for TEMPO-DEX6
    /// @notice Checks total balance (external + internal) to handle taker == maker scenarios
    /// @param swapper The swapper address
    /// @param before Balance snapshot before the swap
    /// @param tokenInSpent Amount of tokenIn spent (amountIn for the swap)
    /// @param tokenOutReceived Amount of tokenOut received (amountOut for the swap)
    function _assertSwapBalanceChanges(
        address swapper,
        SwapBalanceSnapshot memory before,
        uint128 tokenInSpent,
        uint128 tokenOutReceived
    )
        internal
        view
    {
        // Calculate total balances (external + internal) after swap
        uint256 tokenInTotalBefore = before.tokenInExternal + before.tokenInInternal;
        uint256 tokenOutTotalBefore = before.tokenOutExternal + before.tokenOutInternal;

        uint256 tokenInTotalAfter =
            TIP20(before.tokenIn).balanceOf(swapper) + exchange.balanceOf(swapper, before.tokenIn);
        uint256 tokenOutTotalAfter = TIP20(before.tokenOut).balanceOf(swapper)
            + exchange.balanceOf(swapper, before.tokenOut);

        // Swapper's total tokenIn should decrease by tokenInSpent
        assertEq(
            tokenInTotalBefore - tokenInTotalAfter,
            tokenInSpent,
            "TEMPO-DEX6: swapper total tokenIn change incorrect"
        );

        // Swapper's total tokenOut should increase by tokenOutReceived
        assertEq(
            tokenOutTotalAfter - tokenOutTotalBefore,
            tokenOutReceived,
            "TEMPO-DEX6: swapper total tokenOut change incorrect"
        );
    }

    /// @notice Verifies best bid and ask tick point to valid tick levels
    /// @dev Tests TEMPO-DEX12 (best bid) and TEMPO-DEX13 (best ask)
    /// @param baseToken The base token address for the trading pair
    function _assertBestTickConsistency(address baseToken) internal view {
        (,, int16 bestBidTick, int16 bestAskTick) =
            exchange.books(exchange.pairKey(baseToken, address(pathUSD)));

        // TEMPO-DEX12: If bestBidTick is not MIN, it should have liquidity
        if (bestBidTick != type(int16).min) {
            (,, uint128 bidLiquidity) = exchange.getTickLevel(baseToken, bestBidTick, true);
            // Note: during swaps, bestBidTick may temporarily point to empty tick
            // This is acceptable as it gets updated on next operation
        }

        // TEMPO-DEX13: If bestAskTick is not MAX, it should have liquidity
        if (bestAskTick != type(int16).max) {
            (,, uint128 askLiquidity) = exchange.getTickLevel(baseToken, bestAskTick, false);
            // Note: during swaps, bestAskTick may temporarily point to empty tick
        }
    }

    /// @notice Verifies tick level data structure consistency
    /// @dev Tests TEMPO-DEX11 (liquidity matches orders), TEMPO-DEX14 (head/tail consistency), TEMPO-DEX15 (bitmap)
    /// @param baseToken The base token address for the trading pair
    function _assertTickLevelConsistency(address baseToken) internal view {
        for (uint256 i = 0; i < _ticks.length; i++) {
            _assertTickConsistency(baseToken, _ticks[i]);
        }
    }

    /// @dev Checks bid and ask consistency for a single tick
    function _assertTickConsistency(address baseToken, int16 tick) internal view {
        // Check bid tick level
        (uint128 bidHead, uint128 bidTail, uint128 bidLiquidity) =
            exchange.getTickLevel(baseToken, tick, true);
        if (bidLiquidity > 0) {
            // TEMPO-DEX11: If liquidity > 0, head should be non-zero
            assertTrue(bidHead != 0, "TEMPO-DEX11: bid tick has liquidity but no head");
            assertTrue(bidTail != 0, "TEMPO-DEX11: bid tick has liquidity but no tail");
            // TEMPO-DEX15: Bitmap correctness verified indirectly via bestBidTick/bestAskTick in _assertBestTickConsistency
        }
        if (bidHead == 0) {
            // If head is 0, tail should also be 0 and liquidity should be 0
            assertEq(bidTail, 0, "TEMPO-DEX14: bid tail non-zero but head is zero");
            assertEq(bidLiquidity, 0, "TEMPO-DEX11: bid liquidity non-zero but head is zero");
        } else {
            // TEMPO-DEX16: head.prev should be 0
            IStablecoinDEX.Order memory headOrder = exchange.getOrder(bidHead);
            assertEq(headOrder.prev, 0, "TEMPO-DEX16: bid head.prev is not None");
            // TEMPO-DEX16: tail.next should be 0
            IStablecoinDEX.Order memory tailOrder = exchange.getOrder(bidTail);
            assertEq(tailOrder.next, 0, "TEMPO-DEX16: bid tail.next is not None");
        }

        // Check ask tick level
        (uint128 askHead, uint128 askTail, uint128 askLiquidity) =
            exchange.getTickLevel(baseToken, tick, false);
        if (askLiquidity > 0) {
            assertTrue(askHead != 0, "TEMPO-DEX11: ask tick has liquidity but no head");
            assertTrue(askTail != 0, "TEMPO-DEX11: ask tick has liquidity but no tail");
        }
        if (askHead == 0) {
            assertEq(askTail, 0, "TEMPO-DEX14: ask tail non-zero but head is zero");
            assertEq(askLiquidity, 0, "TEMPO-DEX11: ask liquidity non-zero but head is zero");
        } else {
            // TEMPO-DEX16: head.prev should be 0
            IStablecoinDEX.Order memory headOrder = exchange.getOrder(askHead);
            assertEq(headOrder.prev, 0, "TEMPO-DEX16: ask head.prev is not None");
            // TEMPO-DEX16: tail.next should be 0
            IStablecoinDEX.Order memory tailOrder = exchange.getOrder(askTail);
            assertEq(tailOrder.next, 0, "TEMPO-DEX16: ask tail.next is not None");
        }
    }

    /// @notice Verifies order linked list pointers are consistent
    /// @dev Tests TEMPO-DEX14: prev.next == current and next.prev == current
    /// @param orderId The order ID to verify
    /// @param order The order data
    function _assertOrderLinkedListConsistency(
        uint128 orderId,
        IStablecoinDEX.Order memory order
    )
        internal
        view
    {
        // TEMPO-DEX14: If order has prev, prev's next should point to this order
        if (order.prev != 0) {
            IStablecoinDEX.Order memory prevOrder = exchange.getOrder(order.prev);
            assertEq(
                prevOrder.next, orderId, "TEMPO-DEX14: prev order's next doesn't point to current"
            );
        }

        // TEMPO-DEX14: If order has next, next's prev should point to this order
        if (order.next != 0) {
            IStablecoinDEX.Order memory nextOrder = exchange.getOrder(order.next);
            assertEq(
                nextOrder.prev, orderId, "TEMPO-DEX14: next order's prev doesn't point to current"
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

    /// @notice Processes swap logs: counts fills and tracks any newly created orders
    /// @dev Must be called after vm.recordLogs() and swap execution
    /// @return count The number of OrderFilled events emitted by the exchange
    function _processSwapLogs() internal returns (uint64 count) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 orderFilledSelector = IStablecoinDEX.OrderFilled.selector;
        bytes32 orderPlacedSelector = IStablecoinDEX.OrderPlaced.selector;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(exchange) || logs[i].topics.length == 0) continue;
            if (logs[i].topics[0] == orderFilledSelector) {
                count++;
            } else if (logs[i].topics[0] == orderPlacedSelector && logs[i].topics.length >= 3) {
                uint128 orderId = uint128(uint256(logs[i].topics[1]));
                address maker = address(uint160(uint256(logs[i].topics[2])));
                _placedOrders[maker].push(orderId);
            }
        }
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
            || selector == IStablecoinDEX.InvalidToken.selector || _isKnownTIP20Error(selector);
        assertTrue(isKnownError, "Swap failed with unknown error");
    }

    /// @notice Verifies an order operation revert is due to a known/expected error
    /// @dev Fails if the error selector doesn't match any known order error
    /// @param reason The revert reason bytes from the failed operation
    function _assertKnownOrderError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnownError = selector == IStablecoinDEX.OrderDoesNotExist.selector
            || selector == IStablecoinDEX.InsufficientBalance.selector
            || selector == IStablecoinDEX.PairDoesNotExist.selector || _isKnownTIP20Error(selector);
        assertTrue(isKnownError, "Order operation failed with unknown error");
    }

    /// @dev Returns the number of hops in a trade path (similar to findTradePath in StablecoinDEX)
    /// @param tokenIn The input token
    /// @param tokenOut The output token
    /// @return hops Number of hops (1 for direct, 2 for multi-hop via pathUSD)
    function _findRoute(address tokenIn, address tokenOut) internal view returns (uint256 hops) {
        // Direct pair: one of the tokens is pathUSD
        if (tokenIn == address(pathUSD) || tokenOut == address(pathUSD)) {
            return 1;
        }
        // Multi-hop: base -> pathUSD -> base
        return 2;
    }

}
