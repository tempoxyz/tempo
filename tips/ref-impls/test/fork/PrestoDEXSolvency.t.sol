// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test, console } from "forge-std/Test.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";

/// @title Presto (Mainnet) DEX Solvency Fork Test
/// @notice Forks presto mainnet, walks the orderbook tick-level linked lists to discover
///         ALL active orders, pranks each maker to cancel + withdraw, verifies full solvency.
/// @dev Inspired by afterInvariant() in invariants/StablecoinDEX.t.sol.
///      Strategy: walk tick linked lists (not order IDs) so cost is O(active_orders).
///      Run with: tempo-forge test --match-test test_forkExitAllAndVerifySolvency
///               --fork-url <authenticated presto RPC URL> -vvv
contract PrestoDEXSolvencyTest is Test {

    IStablecoinDEX constant DEX = IStablecoinDEX(0xDEc0000000000000000000000000000000000000);
    ITIP20 constant PATH_USD = ITIP20(0x20C0000000000000000000000000000000000000);

    // Candidate base tokens on mainnet. Not all may be initialized.
    address[] private _candidateTokens;

    // Tokens confirmed live (initialized and have a pair on the DEX)
    address[] baseTokens;
    address[] makers;
    mapping(address => bool) seenMaker;

    // Collected active orders
    uint128[] orderIds;

    // Dedup for back-walk
    mapping(uint128 => bool) seenOrder;

    // Linked list consistency findings
    uint256 brokenLinks;

    function setUp() public {
        // Standard TIP-20 stablecoin slots
        _candidateTokens.push(0x20C0000000000000000000000000000000000001); // USDC slot
        _candidateTokens.push(0x20C0000000000000000000000000000000000002); // USDT slot

        // Probe each candidate: only include tokens that are initialized
        for (uint256 i = 0; i < _candidateTokens.length; i++) {
            address token = _candidateTokens[i];
            try ITIP20(token).name() returns (string memory) {
                baseTokens.push(token);
                console.log("Base token live:", token);
            } catch {
                console.log("Base token NOT initialized:", token);
            }
        }
    }

    // ----------------------------------------------------------------
    //  Discovery
    // ----------------------------------------------------------------

    function _discoverAll() internal {
        int16 spacing = DEX.TICK_SPACING();
        int16 minTick = DEX.MIN_TICK();
        int16 maxTick = DEX.MAX_TICK();

        for (uint256 t = 0; t < baseTokens.length; t++) {
            address base = baseTokens[t];
            console.log("Scanning base token:", base);

            for (int16 tick = minTick; tick <= maxTick; tick += spacing) {
                _walkList(base, tick, true);
                _walkList(base, tick, false);
            }

            console.log("  orders so far:", orderIds.length);
        }
    }

    function _walkList(address base, int16 tick, bool isBid) internal {
        (uint128 head, uint128 tail, uint128 liq) = DEX.getTickLevel(base, tick, isBid);
        if (liq == 0 || head == 0) return;

        uint128 cur = head;
        uint256 guard = 0;
        while (cur != 0 && guard < 500_000) {
            try DEX.getOrder(cur) returns (IStablecoinDEX.Order memory o) {
                _recordOrder(cur, o);
                cur = o.next;
            } catch {
                brokenLinks++;
                console.log("BROKEN LINK: orderId", cur, "at tick", uint16(tick));
                console.log("  isBid:", isBid, "base:", base);
                console.log("  tail:", tail);

                // Walk backwards from tail to recover orphaned orders
                if (cur != tail && tail != 0) {
                    _walkBackward(tail);
                }
                break;
            }
            guard++;
        }
    }

    function _walkBackward(uint128 tailId) internal {
        uint128 cur = tailId;
        uint256 guard = 0;
        while (cur != 0 && guard < 500_000) {
            if (seenOrder[cur]) break;

            try DEX.getOrder(cur) returns (IStablecoinDEX.Order memory o) {
                _recordOrder(cur, o);
                cur = o.prev;
            } catch {
                break;
            }
            guard++;
        }
    }

    function _recordOrder(uint128 oid, IStablecoinDEX.Order memory o) internal {
        if (seenOrder[oid]) return;
        seenOrder[oid] = true;
        orderIds.push(oid);

        if (!seenMaker[o.maker]) {
            seenMaker[o.maker] = true;
            makers.push(o.maker);
        }
    }

    // ----------------------------------------------------------------
    //  Main test
    // ----------------------------------------------------------------

    function test_forkExitAllAndVerifySolvency() public {
        uint128 nextId = DEX.nextOrderId();
        console.log("nextOrderId:", nextId);

        // --- Snapshot before ---
        uint256 dexPathBefore = PATH_USD.balanceOf(address(DEX));
        console.log("DEX PathUSD before:", dexPathBefore);
        for (uint256 t = 0; t < baseTokens.length; t++) {
            console.log("DEX base before:", ITIP20(baseTokens[t]).balanceOf(address(DEX)));
        }

        // --- Phase 1: Discover all active orders ---
        _discoverAll();

        console.log("Active orders:", orderIds.length);
        console.log("Unique makers:", makers.length);
        console.log("Broken links found:", brokenLinks);

        // If no active orders, verify DEX has no stuck funds
        if (orderIds.length == 0) {
            console.log("No active orders - verifying clean state");
            _verifySolvency(nextId);
            return;
        }

        // --- Phase 2: Cancel every order (prank as maker) ---
        uint256 cancelled;
        uint256 failed;

        for (uint256 i = 0; i < orderIds.length; i++) {
            uint128 oid = orderIds[i];

            try DEX.getOrder(oid) returns (IStablecoinDEX.Order memory order) {
                (address base,,,) = DEX.books(order.bookKey);
                address maker = order.maker;

                vm.startPrank(maker);
                try DEX.cancel(oid) {
                    cancelled++;

                    if (order.isBid) {
                        uint32 price = DEX.tickToPrice(order.tick);
                        uint128 refund = uint128(
                            (uint256(order.remaining) * price + DEX.PRICE_SCALE() - 1)
                                / DEX.PRICE_SCALE()
                        );
                        assertGe(
                            DEX.balanceOf(maker, address(PATH_USD)),
                            refund,
                            "Bid refund not credited"
                        );
                    } else {
                        assertGe(
                            DEX.balanceOf(maker, base),
                            order.remaining,
                            "Ask refund not credited"
                        );
                    }
                } catch {
                    failed++;
                }
                vm.stopPrank();
            } catch {}
        }

        console.log("Cancelled:", cancelled);
        console.log("Failed:", failed);

        // --- Phase 3: Withdraw all internal balances ---
        for (uint256 m = 0; m < makers.length; m++) {
            address maker = makers[m];
            vm.startPrank(maker);

            uint128 pBal = DEX.balanceOf(maker, address(PATH_USD));
            if (pBal > 0) DEX.withdraw(address(PATH_USD), pBal);

            for (uint256 t = 0; t < baseTokens.length; t++) {
                uint128 tBal = DEX.balanceOf(maker, baseTokens[t]);
                if (tBal > 0) DEX.withdraw(baseTokens[t], tBal);
            }

            vm.stopPrank();
        }

        // --- Phase 4: Verify solvency ---
        _verifySolvency(nextId);
    }

    function _verifySolvency(uint128 nextId) internal view {
        // 4a: All maker internal balances are zero
        for (uint256 m = 0; m < makers.length; m++) {
            address maker = makers[m];
            assertEq(DEX.balanceOf(maker, address(PATH_USD)), 0, "Maker PathUSD != 0");
            for (uint256 t = 0; t < baseTokens.length; t++) {
                assertEq(DEX.balanceOf(maker, baseTokens[t]), 0, "Maker base != 0");
            }
        }

        // 4b: All tick levels drained
        int16 spacing = DEX.TICK_SPACING();
        int16 minTick = DEX.MIN_TICK();
        int16 maxTick = DEX.MAX_TICK();

        for (uint256 t = 0; t < baseTokens.length; t++) {
            for (int16 tick = minTick; tick <= maxTick; tick += spacing) {
                (,, uint128 bidLiq) = DEX.getTickLevel(baseTokens[t], tick, true);
                (,, uint128 askLiq) = DEX.getTickLevel(baseTokens[t], tick, false);
                assertEq(bidLiq, 0, "Residual bid liquidity");
                assertEq(askLiq, 0, "Residual ask liquidity");
            }
        }

        // 4c: DEX balances are rounding dust only
        uint256 residual;
        uint256 dexPathAfter = PATH_USD.balanceOf(address(DEX));
        residual += dexPathAfter;
        console.log("DEX PathUSD after:", dexPathAfter);

        for (uint256 t = 0; t < baseTokens.length; t++) {
            uint256 bal = ITIP20(baseTokens[t]).balanceOf(address(DEX));
            console.log("DEX base after:", bal);
            residual += bal;
        }

        console.log("Total residual dust:", residual);
        assertLe(residual, uint256(nextId), "SOLVENCY FAIL: excess funds stuck in DEX");

        // Report broken links
        assertEq(brokenLinks, 0, "LINKED LIST BUG: broken next pointers found");

        console.log("=== SOLVENCY CHECK PASSED ===");
    }
}
