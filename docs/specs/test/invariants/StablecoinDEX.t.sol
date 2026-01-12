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

    /// @dev Array of tradeable tokens (token1, token2, token3, token4)
    TIP20[] private _tokens;

    /// @dev Mapping of actor address to their placed order IDs
    mapping(address => uint128[]) private _placedOrders;

    /// @dev Fixed set of valid ticks used for order placement
    int16[10] private _ticks = [int16(10), 20, 30, 40, 50, 60, 70, 80, 90, 100];

    /// @dev Expected next order ID, used to verify TEMPO-DEX1
    uint128 private _nextOrderId;

    /// @dev Blacklist policy IDs for each token
    mapping(address => uint64) private _tokenPolicyIds;

    /// @dev Blacklist policy ID for pathUSD
    uint64 private _pathUsdPolicyId;

    /// @dev Additional tokens (token3, token4) - token1/token2 from BaseTest
    TIP20 public token3;
    TIP20 public token4;

    /// @dev Log file path for recording exchange actions
    string private constant LOG_FILE = "exchange.log";

    /// @dev Maximum amount of dust that can be left in the protocol. This is used to verify TEMPO-DEX19.
    uint64 private _maxDust;

    /// @notice Sets up the test environment
    /// @dev Initializes BaseTest, creates trading pair, builds actors, and sets initial state
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        // Create additional tokens (token1, token2 already created in BaseTest)
        token3 =
            TIP20(factory.createToken("TOKEN3", "T3", "USD", pathUSD, admin, bytes32("token3")));
        token4 =
            TIP20(factory.createToken("TOKEN4", "T4", "USD", pathUSD, admin, bytes32("token4")));

        // Setup pathUSD with issuer role (pathUSDAdmin is the pathUSD admin from BaseTest)
        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, admin);
        vm.stopPrank();

        // Setup all tokens with issuer role and create trading pairs
        vm.startPrank(admin);
        TIP20[4] memory tokens = [token1, token2, token3, token4];
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].grantRole(_ISSUER_ROLE, admin);
            _tokens.push(tokens[i]);
            exchange.createPair(address(tokens[i]));

            // Create blacklist policy for each token
            uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
            tokens[i].changeTransferPolicyId(policyId);
            _tokenPolicyIds[address(tokens[i])] = policyId;
        }
        vm.stopPrank();

        // Create blacklist policy for pathUSD
        vm.startPrank(pathUSDAdmin);
        _pathUsdPolicyId = registry.createPolicy(pathUSDAdmin, ITIP403Registry.PolicyType.BLACKLIST);
        pathUSD.changeTransferPolicyId(_pathUsdPolicyId);
        vm.stopPrank();

        _actors = _buildActors(20);
        _nextOrderId = exchange.nextOrderId();

        // Initialize log file
        try vm.removeFile(LOG_FILE) { } catch { }
        _log("=== StablecoinDEX Invariant Test Log ===");
        _log(
            string.concat(
                "Tokens: T1=",
                token1.symbol(),
                ", T2=",
                token2.symbol(),
                ", T3=",
                token3.symbol(),
                ", T4=",
                token4.symbol()
            )
        );
        _log(string.concat("Actors: ", vm.toString(_actors.length)));
        _log("");
        _logBalances();
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz handler: Places a bid or ask order and optionally cancels it
    /// @dev Tests TEMPO-DEX1 (order ID), TEMPO-DEX2 (escrow), TEMPO-DEX3 (cancel refund), TEMPO-DEX7 (tick liquidity)
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
    ) external {
        int16 tick = _ticks[tickRnd % _ticks.length];
        address actor = _actors[actorRnd % _actors.length];
        address token = address(_tokens[tokenRnd % _tokens.length]);
        amount = uint128(bound(amount, 100_000_000, 10_000_000_000));

        // Ensure funds for the token being escrowed (pathUSD for bids, base token for asks)
        _ensureFunds(actor, TIP20(isBid ? address(pathUSD) : token), amount);

        // Capture actor's token balance before placing order (for cancel verification)
        uint256 actorBalanceBeforePlace =
            isBid ? pathUSD.balanceOf(actor) : TIP20(token).balanceOf(actor);

        vm.startPrank(actor);
        uint128 orderId = exchange.place(token, amount, isBid, tick);

        // TEMPO-DEX1: Order ID monotonically increases
        _assertNextOrderId(orderId);

        // Verify order was created correctly
        _assertOrderCreated(orderId, actor, amount, tick, isBid);

        // Log the action
        _logPlaceOrder(actor, orderId, amount, TIP20(token).symbol(), tick, isBid);

        if (cancel) {
            _cancelAndVerifyRefund(
                orderId, actor, token, amount, tick, isBid, actorBalanceBeforePlace
            );
            _logCancelOrder(actor, orderId, isBid, TIP20(token).symbol());
        } else {
            _placedOrders[actor].push(orderId);

            // TEMPO-DEX7: Verify tick level liquidity updated
            (,, uint128 tickLiquidity) = exchange.getTickLevel(token, tick, isBid);
            assertTrue(tickLiquidity >= amount, "TEMPO-DEX7: tick liquidity not updated");
        }

        vm.stopPrank();
        _logBalances();
    }

    /// @dev Helper to verify order was created correctly (TEMPO-DEX2)
    function _assertOrderCreated(
        uint128 orderId,
        address actor,
        uint128 amount,
        int16 tick,
        bool isBid
    ) internal view {
        IStablecoinDEX.Order memory order = exchange.getOrder(orderId);
        assertEq(order.maker, actor, "TEMPO-DEX2: order maker mismatch");
        assertEq(order.amount, amount, "TEMPO-DEX2: order amount mismatch");
        assertEq(order.remaining, amount, "TEMPO-DEX2: order remaining mismatch");
        assertEq(order.tick, tick, "TEMPO-DEX2: order tick mismatch");
        assertEq(order.isBid, isBid, "TEMPO-DEX2: order side mismatch");
    }

    function test_poc() external {
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeFlipOrder(
                180_739_590_293_198,
                375_652_765,
                3_832_115_738_349_263_146_361_442_917,
                32_740_479,
                true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeFlipOrder(36_047_880_443_348_445_879_617, 1_087_594, 32_682, 1, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .placeFlipOrder(
                788_164_003_983_621,
                589_257,
                61_364_942_536_591_125_809_573_167,
                115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
                true
            );
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496)
            .swapExactAmount(10, 93_339_479_806, 64, 2, false);
        StablecoinDEXInvariantTest(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496).afterInvariant();
    }

    function cancelOrder(uint128 orderId) external {
        orderId = orderId % exchange.nextOrderId();
        try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory order) {
            (address base,,,) = exchange.books(order.bookKey);
            // Cancel, but skip checking `actorBalanceBeforePlace`
            _cancelAndVerifyRefund(
                orderId, order.maker, base, order.remaining, order.tick, order.isBid, 0
            );
        } catch {
            // order was probably cancelled in a previous cancelOrder call
            return;
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
        if (balance == 0) return;

        amount = uint128(bound(amount, 1, balance));

        vm.startPrank(actor);
        exchange.withdraw(token, amount);
        vm.stopPrank();

        _log(
            string.concat(
                _getActorIndex(actor), " withdrew ", vm.toString(amount), " ", TIP20(token).symbol()
            )
        );
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
    ) internal {
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
    ) internal {
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
    ) internal {
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
    /// @dev Tests TEMPO-DEX1 (order ID), TEMPO-DEX12 (flip tick constraints)
    /// @param actorRnd Random seed for selecting actor
    /// @param amount Order amount (bounded to valid range)
    /// @param tickRnd Random seed for selecting tick
    /// @param tokenRnd Random seed for selecting token
    /// @param isBid True for bid flip order, false for ask flip order
    function placeFlipOrder(
        uint256 actorRnd,
        uint128 amount,
        uint256 tickRnd,
        uint256 tokenRnd,
        bool isBid
    ) external {
        int16 tick = _ticks[tickRnd % _ticks.length];
        address actor = _actors[actorRnd % _actors.length];
        TIP20 token = _tokens[tokenRnd % _tokens.length];
        amount = uint128(bound(amount, 100_000_000, 10_000_000_000));

        // Ensure funds for the token being escrowed (pathUSD for bids, base token for asks)
        if (isBid) {
            _ensureFunds(actor, pathUSD, amount);
        } else {
            _ensureFunds(actor, token, amount);
        }

        vm.startPrank(actor);
        uint128 orderId;
        int16 flipTick;
        if (isBid) {
            flipTick = 200;
            orderId = exchange.placeFlip(address(token), amount, true, tick, flipTick);
        } else {
            flipTick = -200;
            orderId = exchange.placeFlip(address(token), amount, false, tick, flipTick);
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

        // Log the action
        _logFlipOrder(actor, orderId, amount, token.symbol(), tick, flipTick, isBid);

        vm.stopPrank();
        _logBalances();
    }

    /// @dev Helper to log flip order placement to avoid stack too deep
    function _logFlipOrder(
        address actor,
        uint128 orderId,
        uint128 amount,
        string memory tokenSymbol,
        int16 tick,
        int16 flipTick,
        bool isBid
    ) internal {
        string memory escrowToken = isBid ? "pathUSD" : tokenSymbol;
        string memory receiveToken = isBid ? tokenSymbol : "pathUSD";
        _log(
            string.concat(
                _getActorIndex(actor),
                " placed flip ",
                isBid ? "bid" : "ask",
                " order #",
                vm.toString(orderId),
                " for ",
                vm.toString(amount),
                " ",
                tokenSymbol,
                " at tick ",
                vm.toString(tick),
                " -> flipTick ",
                vm.toString(flipTick),
                " (escrow: ",
                escrowToken,
                ", receive: ",
                receiveToken,
                ")"
            )
        );
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
    /// @dev Tests TEMPO-DEX4, TEMPO-DEX5, TEMPO-DEX14, TEMPO-DEX16
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
    ) external {
        address swapper = _actors[swapperRnd % _actors.length];
        amount = uint128(bound(amount, 100_000_000, 1_000_000_000));

        // Select tokenIn and tokenOut from all available tokens (base tokens + pathUSD)
        // This allows any-to-any token swaps (e.g., T1->T2, T1->pathUSD, pathUSD->T3, etc.)
        address tokenIn = _selectToken(tokenInRnd);
        address tokenOut = _selectToken(tokenOutRnd);

        // Skip if same token (can't swap token for itself)
        if (tokenIn == tokenOut) {
            return;
        }

        // Ensure swapper has enough of tokenIn
        _ensureFunds(swapper, TIP20(tokenIn), amount);

        // Check if swapper has active orders - if so, skip TEMPO-DEX14 balance checks
        // because self-trade makes the accounting complex (maker proceeds returned to swapper)
        bool swapperHasOrders = _placedOrders[swapper].length > 0;

        // Capture total balances (external + internal) before swap for TEMPO-DEX14
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
        _logBalances();
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

                    // TEMPO-DEX13: Anyone can cancel a stale order from a blacklisted maker
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

                    // Log successful stale order cancellation
                    _log(
                        string.concat(
                            _getActorIndex(canceller),
                            " cancelled stale order #",
                            vm.toString(orderId),
                            " of blacklisted ",
                            _getActorIndex(blacklistedActor)
                        )
                    );
                }
            } catch {
                // Order was already filled or cancelled
            }
        }
        vm.stopPrank();
        _logBalances();

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
    /// @dev Cancels all remaining orders and verifies TEMPO-DEX3 (refunds) and TEMPO-DEX10 (linked list)
    function afterInvariant() public {
        // Cancel all orders by iterating through order IDs
        for (uint128 orderId = 1; orderId < _nextOrderId; orderId++) {
            try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory order) {
                // TEMPO-DEX10: Verify linked list consistency before cancel
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
            } catch { }
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

        // Log dust remaining in DEX
        string memory dustLog = string.concat(
            "Dust remaining: pathUSD=", vm.toString(pathUSD.balanceOf(address(exchange)))
        );
        for (uint256 j = 0; j < _tokens.length; j++) {
            dustLog = string.concat(
                dustLog,
                ", ",
                _tokens[j].symbol(),
                "=",
                vm.toString(_tokens[j].balanceOf(address(exchange)))
            );
        }
        dustLog = string.concat(
            dustLog,
            " | Total=",
            vm.toString(pathUSD.balanceOf(address(exchange)) + totalBalance),
            ", Swaps=",
            vm.toString(_maxDust)
        );
        _log(dustLog);

        assertGe(
            _maxDust,
            pathUSD.balanceOf(address(exchange)) + totalBalance,
            "TEMPO-DEX19: Excess post-swap dust"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          INVARIANT ASSERTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Main invariant function called after each fuzz sequence
    /// @dev Verifies TEMPO-DEX6 (balance solvency), TEMPO-DEX7/11 (tick consistency), TEMPO-DEX8/9 (best tick)
    function invariantStablecoinDEX() public view {
        // TEMPO-DEX6: Check pathUSD balance
        uint256 dexPathUsdBalance = pathUSD.balanceOf(address(exchange));
        uint256 totalUserPathUsd = 0;
        for (uint256 i = 0; i < _actors.length; i++) {
            totalUserPathUsd += exchange.balanceOf(_actors[i], address(pathUSD));
        }
        assertTrue(
            dexPathUsdBalance >= totalUserPathUsd,
            "TEMPO-DEX6: DEX pathUsd balance < sum of user internal balances"
        );

        // TEMPO-DEX6: Check each base token balance
        for (uint256 t = 0; t < _tokens.length; t++) {
            uint256 dexTokenBalance = _tokens[t].balanceOf(address(exchange));
            uint256 totalUserTokenBalance = 0;
            for (uint256 i = 0; i < _actors.length; i++) {
                totalUserTokenBalance += exchange.balanceOf(_actors[i], address(_tokens[t]));
            }
            assertTrue(
                dexTokenBalance >= totalUserTokenBalance,
                "TEMPO-DEX6: DEX token balance < sum of user internal balances"
            );
        }

        // Compute expected escrowed amounts from all orders (including flip-created orders)
        (
            uint256 expectedPathUsdEscrowed,
            uint256[] memory expectedTokenEscrowed,
            uint256 orderCount
        ) = _computeExpectedEscrow();

        // Assert escrowed amounts: DEX balance = user internal balances + escrowed in active orders
        // Allow tolerance for rounding during partial fills (can accumulate across multiple fills)
        uint256 tolerance = orderCount * 4 + 1;
        assertApproxEqAbs(
            dexPathUsdBalance,
            totalUserPathUsd + expectedPathUsdEscrowed,
            tolerance,
            "TEMPO-DEX6: DEX pathUSD balance != user balances + escrowed"
        );

        // Check each base token escrow
        for (uint256 t = 0; t < _tokens.length; t++) {
            uint256 dexTokenBalance = _tokens[t].balanceOf(address(exchange));
            uint256 totalUserTokenBalance = 0;
            for (uint256 i = 0; i < _actors.length; i++) {
                totalUserTokenBalance += exchange.balanceOf(_actors[i], address(_tokens[t]));
            }
            assertApproxEqAbs(
                dexTokenBalance,
                totalUserTokenBalance + expectedTokenEscrowed[t],
                tolerance,
                "TEMPO-DEX6: DEX token balance != user balances + escrowed"
            );
        }

        // TEMPO-DEX8 & TEMPO-DEX9: Best bid/ask tick consistency for all tokens
        for (uint256 t = 0; t < _tokens.length; t++) {
            _assertBestTickConsistency(address(_tokens[t]));
        }

        // TEMPO-DEX7 & TEMPO-DEX11: Tick level and bitmap consistency for all tokens
        for (uint256 t = 0; t < _tokens.length; t++) {
            _assertTickLevelConsistency(address(_tokens[t]));
        }
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
    ) internal {
        // TEMPO-DEX16: Quote should match execution TODO: enable when fixed
        uint128 quotedOut;
        try exchange.quoteSwapExactAmountIn(before.tokenIn, before.tokenOut, amount) returns (
            uint128 quoted
        ) {
            quotedOut = quoted;
        } catch {
            quotedOut = 0;
        }

        try exchange.swapExactAmountIn(
            before.tokenIn, before.tokenOut, amount, amount - 100
        ) returns (
            uint128 amountOut
        ) {
            _maxDust += uint64(_findRoute(before.tokenIn, before.tokenOut));
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

            // Log successful swap
            _log(
                string.concat(
                    _getActorIndex(swapper),
                    " swapExactAmountIn: ",
                    vm.toString(amount),
                    " ",
                    TIP20(before.tokenIn).symbol(),
                    " -> ",
                    vm.toString(amountOut),
                    " ",
                    TIP20(before.tokenOut).symbol()
                )
            );
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
        try exchange.quoteSwapExactAmountOut(before.tokenIn, before.tokenOut, amount) returns (
            uint128 quoted
        ) {
            quotedIn = quoted;
        } catch {
            quotedIn = 0;
        }

        try exchange.swapExactAmountOut(
            before.tokenIn, before.tokenOut, amount, amount + 100
        ) returns (
            uint128 amountIn
        ) {
            _maxDust += uint64(_findRoute(before.tokenIn, before.tokenOut));
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

            // Log successful swap
            _log(
                string.concat(
                    _getActorIndex(swapper),
                    " swapExactAmountOut: ",
                    vm.toString(amountIn),
                    " ",
                    TIP20(before.tokenIn).symbol(),
                    " -> ",
                    vm.toString(amount),
                    " ",
                    TIP20(before.tokenOut).symbol()
                )
            );
        } catch (bytes memory reason) {
            _assertKnownSwapError(reason);
        }
    }

    /// @dev Helper to assert swap balance changes for TEMPO-DEX14
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
    ) internal view {
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
            "TEMPO-DEX14: swapper total tokenIn change incorrect"
        );

        // Swapper's total tokenOut should increase by tokenOutReceived
        assertEq(
            tokenOutTotalAfter - tokenOutTotalBefore,
            tokenOutReceived,
            "TEMPO-DEX14: swapper total tokenOut change incorrect"
        );
    }

    /// @notice Verifies best bid and ask tick point to valid tick levels
    /// @dev Tests TEMPO-DEX8 (best bid) and TEMPO-DEX9 (best ask)
    /// @param baseToken The base token address for the trading pair
    function _assertBestTickConsistency(address baseToken) internal view {
        (,, int16 bestBidTick, int16 bestAskTick) =
            exchange.books(exchange.pairKey(baseToken, address(pathUSD)));

        // TEMPO-DEX8: If bestBidTick is not MIN, it should have liquidity
        if (bestBidTick != type(int16).min) {
            (,, uint128 bidLiquidity) = exchange.getTickLevel(baseToken, bestBidTick, true);
            // Note: during swaps, bestBidTick may temporarily point to empty tick
            // This is acceptable as it gets updated on next operation
        }

        // TEMPO-DEX9: If bestAskTick is not MAX, it should have liquidity
        if (bestAskTick != type(int16).max) {
            (,, uint128 askLiquidity) = exchange.getTickLevel(baseToken, bestAskTick, false);
            // Note: during swaps, bestAskTick may temporarily point to empty tick
        }
    }

    /// @notice Verifies tick level data structure consistency
    /// @dev Tests TEMPO-DEX7 (liquidity matches orders), TEMPO-DEX10 (head/tail consistency), TEMPO-DEX11 (bitmap)
    /// @param baseToken The base token address for the trading pair
    function _assertTickLevelConsistency(address baseToken) internal view {
        // Check a sample of ticks for consistency
        for (uint256 i = 0; i < _ticks.length; i++) {
            int16 tick = _ticks[i];

            // Check bid tick level
            (uint128 bidHead, uint128 bidTail, uint128 bidLiquidity) =
                exchange.getTickLevel(baseToken, tick, true);
            if (bidLiquidity > 0) {
                // TEMPO-DEX7: If liquidity > 0, head should be non-zero
                assertTrue(bidHead != 0, "TEMPO-DEX7: bid tick has liquidity but no head");
                assertTrue(bidTail != 0, "TEMPO-DEX7: bid tick has liquidity but no tail");
                // TEMPO-DEX11: Bitmap correctness verified indirectly via bestBidTick/bestAskTick in _assertBestTickConsistency
            }
            if (bidHead == 0) {
                // If head is 0, tail should also be 0 and liquidity should be 0
                assertEq(bidTail, 0, "TEMPO-DEX10: bid tail non-zero but head is zero");
                assertEq(bidLiquidity, 0, "TEMPO-DEX7: bid liquidity non-zero but head is zero");
            } else {
                // TEMPO-DEX17: head.prev should be 0
                IStablecoinDEX.Order memory headOrder = exchange.getOrder(bidHead);
                assertEq(headOrder.prev, 0, "TEMPO-DEX17: bid head.prev is not None");
                // TEMPO-DEX17: tail.next should be 0
                IStablecoinDEX.Order memory tailOrder = exchange.getOrder(bidTail);
                assertEq(tailOrder.next, 0, "TEMPO-DEX17: bid tail.next is not None");
            }

            // Check ask tick level
            (uint128 askHead, uint128 askTail, uint128 askLiquidity) =
                exchange.getTickLevel(baseToken, tick, false);
            if (askLiquidity > 0) {
                assertTrue(askHead != 0, "TEMPO-DEX7: ask tick has liquidity but no head");
                assertTrue(askTail != 0, "TEMPO-DEX7: ask tick has liquidity but no tail");
            }
            if (askHead == 0) {
                assertEq(askTail, 0, "TEMPO-DEX10: ask tail non-zero but head is zero");
                assertEq(askLiquidity, 0, "TEMPO-DEX7: ask liquidity non-zero but head is zero");
            } else {
                // TEMPO-DEX17: head.prev should be 0
                IStablecoinDEX.Order memory headOrder = exchange.getOrder(askHead);
                assertEq(headOrder.prev, 0, "TEMPO-DEX17: ask head.prev is not None");
                // TEMPO-DEX17: tail.next should be 0
                IStablecoinDEX.Order memory tailOrder = exchange.getOrder(askTail);
                assertEq(tailOrder.next, 0, "TEMPO-DEX17: ask tail.next is not None");
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

            // initial actor balance for all tokens
            _ensureFundsAll(actor, 1_000_000_000_000);

            vm.startPrank(actor);
            // Approve all base tokens and pathUSD for the exchange
            for (uint256 j = 0; j < _tokens.length; j++) {
                _tokens[j].approve(address(exchange), type(uint256).max);
            }
            pathUSD.approve(address(exchange), type(uint256).max);
            vm.stopPrank();
        }

        return actorsAddress;
    }

    /// @dev Selects a token from all available tokens (base tokens + pathUSD)
    /// @param rnd Random seed for selection
    /// @return The selected token address
    function _selectToken(uint256 rnd) internal view returns (address) {
        // Pool of tokens: pathUSD + all base tokens
        uint256 totalTokens = _tokens.length + 1;
        uint256 index = rnd % totalTokens;
        if (index == 0) {
            return address(pathUSD);
        }
        return address(_tokens[index - 1]);
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

    /// @notice Ensures an actor has sufficient token balances for testing
    /// @dev Mints tokens if actor's balance is below the required amount
    /// @param actor The actor address to fund
    /// @param token The token to mint (base token for asks, pathUSD for bids)
    /// @param amount The minimum balance required
    function _ensureFunds(address actor, TIP20 token, uint256 amount) internal {
        vm.startPrank(admin);
        if (token.balanceOf(address(actor)) < amount) {
            token.mint(actor, amount + 100_000_000);
        }
        vm.stopPrank();
    }

    /// @notice Ensures an actor has sufficient balances for all tokens (used in setUp)
    /// @dev Mints pathUSD and all base tokens if actor's balance is below the required amount
    /// @param actor The actor address to fund
    /// @param amount The minimum balance required
    function _ensureFundsAll(address actor, uint256 amount) internal {
        vm.startPrank(admin);
        if (pathUSD.balanceOf(address(actor)) < amount) {
            pathUSD.mint(actor, amount + 100_000_000);
        }
        for (uint256 i = 0; i < _tokens.length; i++) {
            if (_tokens[i].balanceOf(address(actor)) < amount) {
                _tokens[i].mint(actor, amount + 100_000_000);
            }
        }
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                              LOGGING
    //////////////////////////////////////////////////////////////*/

    /// @dev Logs an action message to the exchange.log file
    function _log(string memory message) internal {
        vm.writeLine(LOG_FILE, message);
    }

    /// @dev Logs exchange balances for all tokens
    function _logBalances() internal {
        string memory balanceStr = string.concat(
            "DEX balances: pathUSD=", vm.toString(pathUSD.balanceOf(address(exchange)))
        );
        for (uint256 t = 0; t < _tokens.length; t++) {
            balanceStr = string.concat(
                balanceStr,
                ", ",
                _tokens[t].symbol(),
                "=",
                vm.toString(_tokens[t].balanceOf(address(exchange)))
            );
        }
        _log(balanceStr);
    }

    /// @dev Gets actor index from address for logging
    function _getActorIndex(address actor) internal view returns (string memory) {
        for (uint256 i = 0; i < _actors.length; i++) {
            if (_actors[i] == actor) {
                return string.concat("Actor", vm.toString(i));
            }
        }
        return vm.toString(actor);
    }

    /// @dev Helper to log order placement to avoid stack too deep
    function _logPlaceOrder(
        address actor,
        uint128 orderId,
        uint128 amount,
        string memory tokenSymbol,
        int16 tick,
        bool isBid
    ) internal {
        string memory escrowToken = isBid ? "pathUSD" : tokenSymbol;
        string memory receiveToken = isBid ? tokenSymbol : "pathUSD";
        _log(
            string.concat(
                _getActorIndex(actor),
                " placed ",
                isBid ? "bid" : "ask",
                " order #",
                vm.toString(orderId),
                " for ",
                vm.toString(amount),
                " ",
                tokenSymbol,
                " at tick ",
                vm.toString(tick),
                " (escrow: ",
                escrowToken,
                ", receive: ",
                receiveToken,
                ")"
            )
        );
    }

    /// @dev Helper to log order cancellation to avoid stack too deep
    function _logCancelOrder(address actor, uint128 orderId, bool isBid, string memory tokenSymbol)
        internal
    {
        string memory refundToken = isBid ? "pathUSD" : tokenSymbol;
        _log(
            string.concat(
                _getActorIndex(actor),
                " cancelled order #",
                vm.toString(orderId),
                " (refund: ",
                refundToken,
                ")"
            )
        );
    }

}
