// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test, console2 } from "forge-std/Test.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { StablecoinDEX } from "../../src/StablecoinDEX.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title TEMPO-DEX10 Reproduction Test
/// @notice Reproduces the 1 wei discrepancy found in invariant test failure
/// @dev Failure log: DEX pathUSD balance != user balances + escrowed: 9901981008 !~= 9901981009
contract TempoDEX10ReproTest is BaseTest {

    function setUp() public override {
        super.setUp();
        
        // Setup pathUSD issuer role
        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, admin);
        vm.stopPrank();

        // Setup token1 issuer role
        vm.startPrank(admin);
        token1.grantRole(_ISSUER_ROLE, admin);
        vm.stopPrank();
        
        // Create trading pair
        vm.prank(admin);
        exchange.createPair(address(token1));
    }

    /// @notice Reproduce the exact failing sequence from invariant test
    /// @dev placeOrder1(41, 1007, 1991525457567830727374560743636255284171878534818981, 2469580963086947755985303596570040, true)
    function test_ReproduceTEMPO_DEX10_Failure() public {
        // Decode the fuzz inputs
        // actorRnd = 41 → _actors[41 % 20] = _actors[1]
        // amount = 1007 → bounded to 100_000_000 (MIN_ORDER_AMOUNT)
        // tickRnd = 1991525457567830727374560743636255284171878534818981 % 10 = 1 → tick = 20
        // tokenRnd = 2469580963086947755985303596570040 % 4 = 0 → token1
        // isBid = true

        address actor = alice; // Using alice as test actor
        uint128 amount = 100_000_000; // 100 units with 6 decimals
        int16 tick = 20;
        bool isBid = true;

        // Calculate expected escrow: ceil(amount * price / PRICE_SCALE)
        uint32 price = exchange.tickToPrice(tick); // 100_000 + 20 = 100_020
        uint256 expectedEscrow = (uint256(amount) * uint256(price) + 100_000 - 1) / 100_000;
        
        console2.log("Amount:", amount);
        console2.log("Price:", price);
        console2.log("Expected escrow:", expectedEscrow);
        
        // Ensure actor has enough pathUSD for escrow
        vm.prank(pathUSDAdmin);
        pathUSD.mint(actor, expectedEscrow + 1000);
        
        // Approve DEX to spend pathUSD
        vm.prank(actor);
        pathUSD.approve(address(exchange), type(uint256).max);
        
        // Record balances before
        uint256 dexPathUsdBefore = pathUSD.balanceOf(address(exchange));
        uint256 actorPathUsdBefore = pathUSD.balanceOf(actor);
        uint256 actorInternalBefore = exchange.balanceOf(actor, address(pathUSD));
        
        console2.log("DEX pathUSD before:", dexPathUsdBefore);
        console2.log("Actor pathUSD before:", actorPathUsdBefore);
        console2.log("Actor internal before:", actorInternalBefore);
        
        // Place bid order
        vm.prank(actor);
        uint128 orderId = exchange.place(address(token1), amount, isBid, tick);
        
        // Record balances after
        uint256 dexPathUsdAfter = pathUSD.balanceOf(address(exchange));
        uint256 actorPathUsdAfter = pathUSD.balanceOf(actor);
        uint256 actorInternalAfter = exchange.balanceOf(actor, address(pathUSD));
        
        console2.log("DEX pathUSD after:", dexPathUsdAfter);
        console2.log("Actor pathUSD after:", actorPathUsdAfter);
        console2.log("Actor internal after:", actorInternalAfter);
        
        // Calculate actual escrow
        uint256 actorTotalBefore = actorPathUsdBefore + actorInternalBefore;
        uint256 actorTotalAfter = actorPathUsdAfter + actorInternalAfter;
        uint256 actualEscrow = actorTotalBefore - actorTotalAfter;
        
        console2.log("Actual escrow (from actor balance change):", actualEscrow);
        console2.log("DEX balance increase:", dexPathUsdAfter - dexPathUsdBefore);
        
        // Get order to verify stored values
        IStablecoinDEX.Order memory order = exchange.getOrder(orderId);
        
        // Recalculate escrow using order.remaining (how test harness does it)
        uint256 harnessEscrow = (uint256(order.remaining) * uint256(price) + 100_000 - 1) / 100_000;
        
        console2.log("Order remaining:", order.remaining);
        console2.log("Harness escrow calculation:", harnessEscrow);
        
        // INVARIANT CHECK: DEX balance should equal user internal balance + escrowed
        uint256 totalUserInternal = exchange.balanceOf(actor, address(pathUSD));
        uint256 dexBalance = pathUSD.balanceOf(address(exchange));
        uint256 expected = totalUserInternal + harnessEscrow;
        
        console2.log("---");
        console2.log("DEX balance:", dexBalance);
        console2.log("User internal + harness escrow:", expected);
        console2.log("Difference:", dexBalance > expected ? dexBalance - expected : expected - dexBalance);
        
        // This assertion matches the invariant check
        assertEq(dexBalance, expected, "TEMPO-DEX10: DEX pathUSD balance != user balances + escrowed");
    }

    /// @notice Test with the specific tick values from the ticks array
    function test_AllTicksEscrowConsistency() public view {
        int16[10] memory ticks = [int16(10), 20, 30, 40, 50, 60, 70, 80, 90, 100];
        uint128 amount = 100_000_000;
        
        for (uint256 i = 0; i < ticks.length; i++) {
            int16 tick = ticks[i];
            uint32 price = exchange.tickToPrice(tick);
            
            // Expected escrow using ceil
            uint256 expectedEscrow = (uint256(amount) * uint256(price) + 100_000 - 1) / 100_000;
            
            // Check if (amount * price) % PRICE_SCALE == 0 (divisible case)
            uint256 product = uint256(amount) * uint256(price);
            bool isDivisible = product % 100_000 == 0;
            
            console2.log("---");
            console2.log("Tick:", uint256(uint16(tick)));
            console2.log("Price:", price);
            console2.log("Product:", product);
            console2.log("Divisible:", isDivisible);
            console2.log("Expected escrow:", expectedEscrow);
            
            // Floor calculation for comparison
            uint256 floorEscrow = product / 100_000;
            console2.log("Floor escrow:", floorEscrow);
            console2.log("Ceil - Floor:", expectedEscrow - floorEscrow);
        }
    }

    /// @notice Test that verifies DEX escrow matches expected for all fuzz inputs in failing test
    /// @dev Reproduce with fuzz seed: 0x53acf83b1030be6e7b1af8b4b1820f2bdb31dc57b469509671302927a9aa5ead
    function test_FuzzReproEscrowMismatch() public {
        // Decode the fuzz inputs from failing test
        // placeOrder1(41, 1007, 1991525457567830727374560743636255284171878534818981, 2469580963086947755985303596570040, true)
        uint256 tickRnd = 1991525457567830727374560743636255284171878534818981;
        int16[10] memory _ticks = [int16(10), 20, 30, 40, 50, 60, 70, 80, 90, 100];
        int16 tick = _ticks[tickRnd % _ticks.length]; // Should be index 1 → tick = 20
        
        address actor = alice;
        uint128 amount = 100_000_000; // bounded(1007, 100M, 10B) = 100M
        bool isBid = true;

        console2.log("Tick index:", tickRnd % 10);
        console2.log("Tick:", uint256(uint16(tick)));
        
        uint32 price = exchange.tickToPrice(tick);
        console2.log("Price:", price);
        
        // Calculate expected escrow using Solidity ceil formula
        uint256 solEscrow = (uint256(amount) * uint256(price) + 100_000 - 1) / 100_000;
        console2.log("Solidity ceil escrow:", solEscrow);
        
        // Fund and approve
        vm.prank(pathUSDAdmin);
        pathUSD.mint(actor, solEscrow + 1000);
        vm.prank(actor);
        pathUSD.approve(address(exchange), type(uint256).max);
        
        // Place order
        uint256 actorBalBefore = pathUSD.balanceOf(actor);
        vm.prank(actor);
        uint128 orderId = exchange.place(address(token1), amount, isBid, tick);
        uint256 actorBalAfter = pathUSD.balanceOf(actor);
        
        uint256 actualEscrow = actorBalBefore - actorBalAfter;
        console2.log("Actual escrow (from balance):", actualEscrow);
        console2.log("Difference:", actualEscrow > solEscrow ? actualEscrow - solEscrow : solEscrow - actualEscrow);
        
        // Verify they match
        assertEq(actualEscrow, solEscrow, "Escrow mismatch: Rust precompile vs Solidity calculation");
        
        // Now verify the invariant
        uint256 dexBal = pathUSD.balanceOf(address(exchange));
        uint256 userInternal = exchange.balanceOf(actor, address(pathUSD));
        
        // Get order and recompute expected escrow (as the test harness does)
        IStablecoinDEX.Order memory order = exchange.getOrder(orderId);
        uint256 harnessEscrow = (uint256(order.remaining) * uint256(price) + 100_000 - 1) / 100_000;
        
        console2.log("---");
        console2.log("DEX balance:", dexBal);
        console2.log("User internal:", userInternal);
        console2.log("Harness escrow:", harnessEscrow);
        console2.log("DEX - (internal + harness):", dexBal - (userInternal + harnessEscrow));
        
        // This is the TEMPO-DEX10 invariant
        assertEq(dexBal, userInternal + harnessEscrow, "TEMPO-DEX10 invariant failed");
    }
}
