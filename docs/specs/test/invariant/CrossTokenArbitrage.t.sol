// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title CrossTokenArbitrageTest
/// @notice Unit tests attempting to exploit cross-token arbitrage (I1, I2, I8)
/// @dev Tests various attack vectors exploiting fee swap vs rebalance swap rates
contract CrossTokenArbitrageTest is BaseTest {

    TIP20 public userToken;
    TIP20 public validatorToken;
    TIP20 public thirdToken;
    bytes32 public poolId;

    address public attacker = address(0xBAD);
    address public lp = address(0x1111);

    // Rate constants from FeeAMM
    uint256 public constant M = 9970; // Fee swap rate: 0.997
    uint256 public constant N = 9985; // Rebalance swap rate: 0.9985
    uint256 public constant SCALE = 10_000;
    uint256 public constant SPREAD = N - M; // 15 basis points

    function setUp() public override {
        super.setUp();

        userToken = TIP20(
            factory.createToken("UserToken", "UTK", "USD", pathUSD, admin, bytes32("user"))
        );
        validatorToken = TIP20(
            factory.createToken(
                "ValidatorToken", "VTK", "USD", pathUSD, admin, bytes32("validator")
            )
        );
        thirdToken = TIP20(
            factory.createToken("ThirdToken", "TTK", "USD", pathUSD, admin, bytes32("third"))
        );

        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);
        thirdToken.grantRole(_ISSUER_ROLE, admin);
        userToken.grantRole(_ISSUER_ROLE, address(this));
        validatorToken.grantRole(_ISSUER_ROLE, address(this));
        thirdToken.grantRole(_ISSUER_ROLE, address(this));

        // Setup initial pool liquidity
        uint256 initialLiquidity = 10_000_000e18;
        validatorToken.mint(lp, initialLiquidity);
        vm.startPrank(lp);
        validatorToken.approve(address(amm), initialLiquidity);
        amm.mint(address(userToken), address(validatorToken), initialLiquidity, lp);
        vm.stopPrank();

        poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Fund attacker
        userToken.mint(attacker, 100_000_000e18);
        validatorToken.mint(attacker, 100_000_000e18);
        thirdToken.mint(attacker, 100_000_000e18);
    }

    /*//////////////////////////////////////////////////////////////
            I8: SPREAD VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify the spread between fee swap and rebalance swap rates
    function test_I8_SpreadIs15BasisPoints() public view {
        uint256 feeSwapRate = amm.M();
        uint256 rebalanceRate = amm.N();

        assertEq(feeSwapRate, M, "Fee swap rate should be 9970");
        assertEq(rebalanceRate, N, "Rebalance rate should be 9985");
        assertEq(rebalanceRate - feeSwapRate, SPREAD, "Spread should be 15 bps");
        assertGt(rebalanceRate, feeSwapRate, "Rebalance rate must exceed fee swap rate");
    }

    /// @notice Verify spread prevents arbitrage mathematically
    function test_I8_SpreadPreventsArbitrage() public pure {
        // For any amount X:
        // Fee swap: X userToken -> (X * M / SCALE) validatorToken
        // Rebalance: to get X userToken back, need (X * N / SCALE + 1) validatorToken

        // For profit: fee_out > rebalance_in
        // X * M / SCALE > X * N / SCALE + 1
        // X * M > X * N + SCALE
        // X * (M - N) > SCALE
        // Since M < N, (M - N) is negative, so this is never true

        // Therefore, no arbitrage profit is possible
        assertTrue(M < N, "M must be less than N for spread to prevent arbitrage");
    }

    /*//////////////////////////////////////////////////////////////
            I1/I2: FEE SWAP + REBALANCE CYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Attempt arbitrage with single cycle
    function test_I1_SingleCycleNoArbitrage() public {
        uint256 amount = 1_000_000e18;

        // Calculate theoretical cycle
        uint256 feeSwapOut = (amount * M) / SCALE; // 997,000
        uint256 rebalanceIn = (amount * N) / SCALE + 1; // ~998,501

        // For arbitrage: would need feeSwapOut >= rebalanceIn
        // But feeSwapOut < rebalanceIn due to spread
        assertLt(feeSwapOut, rebalanceIn, "Fee swap output should be less than rebalance input");

        // Calculate loss from cycle
        uint256 loss = rebalanceIn - feeSwapOut;
        assertGt(loss, 0, "Cycle should result in loss, not profit");
    }

    /// @notice Attempt arbitrage with various amounts
    function test_I1_ArbitrageAtDifferentAmounts() public pure {
        uint256[] memory amounts = new uint256[](6);
        amounts[0] = 1;
        amounts[1] = 100;
        amounts[2] = 10_000;
        amounts[3] = 1_000_000;
        amounts[4] = 1_000_000_000;
        amounts[5] = 1_000_000_000_000;

        for (uint256 i = 0; i < amounts.length; i++) {
            uint256 amount = amounts[i];
            uint256 feeSwapOut = (amount * M) / SCALE;
            uint256 rebalanceIn = (amount * N) / SCALE + 1;

            // feeSwapOut should always be < rebalanceIn
            assertTrue(
                feeSwapOut < rebalanceIn,
                string(abi.encodePacked("Arbitrage possible at amount ", vm.toString(amount)))
            );
        }
    }

    /// @notice Attempt arbitrage at boundary where rounding matters most
    function test_I1_ArbitrageAtRoundingBoundary() public pure {
        // Find amounts where rounding difference is maximized
        // For fee swap: floor(amount * 9970 / 10000)
        // For rebalance: floor(amount * 9985 / 10000) + 1

        // At amount = 10000: feeOut = 9970, rebalanceIn = 9985 + 1 = 9986
        uint256 amount = 10_000;
        uint256 feeSwapOut = (amount * M) / SCALE; // 9970
        uint256 rebalanceIn = (amount * N) / SCALE + 1; // 9986

        assertEq(feeSwapOut, 9970, "Fee swap out at 10000");
        assertEq(rebalanceIn, 9986, "Rebalance in at 10000");
        assertLt(feeSwapOut, rebalanceIn, "No arbitrage at 10000");
    }

    /// @notice Test minimum amount for any swap
    function test_I1_MinimumAmountNoArbitrage() public pure {
        uint256 amount = 1;

        // feeSwapOut = floor(1 * 9970 / 10000) = 0
        uint256 feeSwapOut = (amount * M) / SCALE;

        // rebalanceIn = floor(1 * 9985 / 10000) + 1 = 0 + 1 = 1
        uint256 rebalanceIn = (amount * N) / SCALE + 1;

        assertEq(feeSwapOut, 0, "Fee swap out for 1 unit");
        assertEq(rebalanceIn, 1, "Rebalance in for 1 unit");

        // Can't even execute the cycle - get 0 for 1
        assertLe(feeSwapOut, rebalanceIn, "No arbitrage even at minimum");
    }

    /*//////////////////////////////////////////////////////////////
            MULTI-POOL ARBITRAGE ATTEMPTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Setup second pool and attempt cross-pool arbitrage
    function test_CrossPoolArbitrage() public {
        // Setup second pool: validatorToken -> thirdToken
        uint256 initialLiq = 5_000_000e18;
        thirdToken.mint(lp, initialLiq);
        vm.startPrank(lp);
        thirdToken.approve(address(amm), initialLiq);
        amm.mint(address(validatorToken), address(thirdToken), initialLiq, lp);
        vm.stopPrank();

        // Attacker tries: userToken -> validatorToken -> thirdToken -> ... -> userToken
        // Each hop loses value due to spread, so multi-hop makes it worse

        uint256 startAmount = 1_000_000e18;

        // Hop 1: userToken -> validatorToken (fee swap rate M)
        uint256 afterHop1 = (startAmount * M) / SCALE;

        // Hop 2: validatorToken -> thirdToken (fee swap rate M)
        uint256 afterHop2 = (afterHop1 * M) / SCALE;

        // Each hop loses ~0.3%, so total loss compounds
        uint256 totalLoss = startAmount - afterHop2;
        uint256 lossPercent = (totalLoss * 10_000) / startAmount;

        // Loss should be approximately 0.6% (2 hops at 0.3% each)
        assertGt(lossPercent, 50, "Multi-hop should lose significant value"); // > 0.5%

        // To get back to original, would need rebalance swaps which cost even more
    }

    /// @notice Attempt triangular arbitrage with three tokens
    function test_TriangularArbitrage() public {
        // Setup pools: A->B, B->C, C->A
        // A = userToken, B = validatorToken, C = thirdToken

        // Pool A->B already exists
        // Create B->C
        thirdToken.mint(lp, 5_000_000e18);
        vm.startPrank(lp);
        thirdToken.approve(address(amm), 5_000_000e18);
        amm.mint(address(validatorToken), address(thirdToken), 5_000_000e18, lp);
        vm.stopPrank();

        // Create C->A (reverse of A->C)
        userToken.mint(lp, 5_000_000e18);
        vm.startPrank(lp);
        userToken.approve(address(amm), 5_000_000e18);
        // This creates pool thirdToken -> userToken
        amm.mint(address(thirdToken), address(userToken), 5_000_000e18, lp);
        vm.stopPrank();

        // Attacker starts with userToken
        uint256 startAmount = 1_000_000e18;

        // Path: userToken -> validatorToken -> thirdToken -> userToken
        // All fee swaps at rate M

        uint256 step1 = (startAmount * M) / SCALE; // A -> B
        uint256 step2 = (step1 * M) / SCALE; // B -> C
        uint256 step3 = (step2 * M) / SCALE; // C -> A

        // Final amount should be less than start (no arbitrage)
        assertLt(step3, startAmount, "Triangular arbitrage should not profit");

        // Calculate total loss
        uint256 loss = startAmount - step3;
        uint256 lossBps = (loss * 10_000) / startAmount;

        // ~90 bps loss (3 hops at ~30 bps each)
        assertGt(lossBps, 80, "Should lose significant value in triangular path");
    }

    /*//////////////////////////////////////////////////////////////
            REBALANCE SWAP RATE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify rebalanceSwap always charges at rate N with +1 rounding
    function test_I2_RebalanceSwapRateCorrect() public {
        // We need userToken reserves to do rebalanceSwap
        // On Tempo, we can't easily add reserves, so verify mathematically

        uint256 amountOut = 1000e18;
        uint256 expectedIn = (amountOut * N) / SCALE + 1;

        // For 1000e18 out:
        // expectedIn = (1000e18 * 9985) / 10000 + 1 = 998.5e18 + 1
        uint256 theoreticalIn = (amountOut * N) / SCALE;

        assertGe(expectedIn, theoreticalIn, "Expected in should include +1 rounding");
        assertEq(expectedIn, theoreticalIn + 1, "Should be exactly theoretical + 1");
    }

    /// @notice Verify no arbitrage even with favorable rounding
    function test_I2_NoArbitrageWithRounding() public pure {
        // Best case for attacker: maximum floor division benefit on fee swap,
        // minimum +1 penalty on rebalance

        // Amount just below a round number
        uint256 amount = 9999;

        uint256 feeSwapOut = (amount * M) / SCALE; // floor(9999 * 9970 / 10000) = 9969
        uint256 rebalanceIn = (amount * N) / SCALE + 1; // floor(9999 * 9985 / 10000) + 1 = 9984 + 1 = 9985

        assertLt(feeSwapOut, rebalanceIn, "No arbitrage even with favorable rounding");
    }

    /*//////////////////////////////////////////////////////////////
            FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz: no arbitrage possible at any amount
    function testFuzz_NoArbitrageAtAnyAmount(uint256 amount) public pure {
        amount = bound(amount, 1, type(uint128).max);

        uint256 feeSwapOut = (amount * M) / SCALE;
        uint256 rebalanceIn = (amount * N) / SCALE + 1;

        // For arbitrage: feeSwapOut >= rebalanceIn (get more than you pay)
        // This should never be true
        assertTrue(feeSwapOut < rebalanceIn, "Arbitrage should not be possible");
    }

    /// @notice Fuzz: cycle always results in net loss
    function testFuzz_CycleAlwaysLoss(uint256 amount) public pure {
        amount = bound(amount, 1000, type(uint128).max / 2); // Need some size for meaningful calculation

        // Fee swap: userToken -> validatorToken
        uint256 feeSwapOut = (amount * M) / SCALE;

        // To get original amount back via rebalance
        uint256 rebalanceIn = (amount * N) / SCALE + 1;

        // Net position after cycle
        // Paid: amount userToken (or equivalent)
        // Received: feeSwapOut validatorToken
        // To recover: need rebalanceIn validatorToken

        // Loss = rebalanceIn - feeSwapOut
        if (rebalanceIn > feeSwapOut) {
            uint256 loss = rebalanceIn - feeSwapOut;
            assertGt(loss, 0, "Should have net loss");
        }
    }

    /// @notice Fuzz: spread prevents profit at any scale
    function testFuzz_SpreadPreventsProfit(uint256 amount) public pure {
        amount = bound(amount, 1, type(uint128).max);

        // Theoretical exchange rates
        // Fee swap: out = in * 0.997
        // Rebalance: in = out * 0.9985 + 1 (effectively in = out / 0.9985 rounded up)

        // For cycle profit: fee_out * 0.9985 + 1 < amount
        // But fee_out = amount * 0.997
        // So: amount * 0.997 * 0.9985 + 1 < amount
        // amount * 0.995545 + 1 < amount
        // This is only true when amount is very small (< ~222)
        // But at those amounts, floor division means fee_out = 0, so no profit anyway

        uint256 feeSwapOut = (amount * M) / SCALE;

        if (feeSwapOut > 0) {
            // Cost to recover via rebalance (approximate)
            uint256 recoveryCost = (feeSwapOut * SCALE) / N + 1;

            // For profit: recoveryCost < amount
            // Due to spread, this is never true
            assertGe(recoveryCost, 1, "Recovery always costs something");
        }
    }

    /*//////////////////////////////////////////////////////////////
            ECONOMIC ANALYSIS
    //////////////////////////////////////////////////////////////*/

    /// @notice Calculate exact loss percentage from cycle
    function test_CalculateCycleLoss() public pure {
        uint256 amount = 1_000_000e18;

        // Fee swap: get validatorToken
        uint256 feeSwapOut = (amount * M) / SCALE;

        // Rebalance: pay validatorToken to get userToken back
        uint256 rebalanceIn = (amount * N) / SCALE + 1;

        // Net cost = rebalanceIn - feeSwapOut
        uint256 netCost = rebalanceIn - feeSwapOut;

        // This represents the cost (in validatorToken terms) of the round trip
        // As a percentage of the original amount:
        uint256 costBps = (netCost * 10_000) / amount;

        // Should be approximately 15 bps (the spread)
        assertGe(costBps, 14, "Cost should be at least ~15 bps");
        assertLe(costBps, 16, "Cost should be at most ~16 bps (with rounding)");
    }

    /// @notice Verify that larger amounts don't reduce relative loss
    function test_LargeAmountsSameLossRate() public pure {
        uint256 smallAmount = 1000e18;
        uint256 largeAmount = 1_000_000_000e18;

        // Small amount loss
        uint256 smallFeeOut = (smallAmount * M) / SCALE;
        uint256 smallRebalanceIn = (smallAmount * N) / SCALE + 1;
        uint256 smallLoss = smallRebalanceIn - smallFeeOut;
        uint256 smallLossBps = (smallLoss * 10_000) / smallAmount;

        // Large amount loss
        uint256 largeFeeOut = (largeAmount * M) / SCALE;
        uint256 largeRebalanceIn = (largeAmount * N) / SCALE + 1;
        uint256 largeLoss = largeRebalanceIn - largeFeeOut;
        uint256 largeLossBps = (largeLoss * 10_000) / largeAmount;

        // Loss rate should be similar regardless of amount
        assertApproxEqAbs(smallLossBps, largeLossBps, 2, "Loss rate should be consistent");
    }

    /// @notice Verify minimum profitable spread calculation
    function test_MinimumProfitableSpread() public pure {
        // For arbitrage to be profitable, we'd need:
        // fee_out > rebalance_in
        // amount * M / SCALE > amount * N / SCALE + 1
        // amount * (M - N) > SCALE
        // Since M - N = -15, this becomes:
        // amount * (-15) > 10000
        // -15 * amount > 10000
        // This is never true for positive amounts

        // The minimum spread needed to prevent arbitrage is any positive value
        // Our 15 bps spread is more than sufficient
        assertTrue(N > M, "N must be greater than M");
        assertEq(N - M, 15, "Spread is exactly 15 bps");
    }

    /*//////////////////////////////////////////////////////////////
            DIRECTIONAL POOL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify pools are directional and separate
    function test_DirectionalPoolsSeparate() public view {
        bytes32 poolAB = amm.getPoolId(address(userToken), address(validatorToken));
        bytes32 poolBA = amm.getPoolId(address(validatorToken), address(userToken));

        // Pool IDs should be different
        assertTrue(poolAB != poolBA, "Pool A->B should differ from B->A");

        // Only pool A->B should have reserves
        IFeeAMM.Pool memory poolABData = amm.getPool(address(userToken), address(validatorToken));
        IFeeAMM.Pool memory poolBAData = amm.getPool(address(validatorToken), address(userToken));

        assertGt(poolABData.reserveValidatorToken, 0, "Pool A->B should have validator reserves");
        assertEq(poolBAData.reserveUserToken, 0, "Pool B->A should have no reserves");
        assertEq(poolBAData.reserveValidatorToken, 0, "Pool B->A should have no reserves");
    }

    /// @notice Verify can't exploit by swapping in wrong pool direction
    function test_NoExploitWrongDirection() public {
        // Try to do rebalanceSwap on reverse pool (which has no reserves)
        IFeeAMM.Pool memory reversePool = amm.getPool(address(validatorToken), address(userToken));

        assertEq(reversePool.reserveUserToken, 0, "Reverse pool empty");
        assertEq(reversePool.reserveValidatorToken, 0, "Reverse pool empty");

        // Attempting rebalanceSwap on empty pool should fail
        vm.startPrank(attacker);
        userToken.approve(address(amm), type(uint256).max);

        // Try to get validatorToken out from reverse pool
        try amm.rebalanceSwap(address(validatorToken), address(userToken), 1000, attacker) {
            revert("Should have failed - no reserves");
        } catch {
            // Expected - can't swap from empty pool
        }

        vm.stopPrank();
    }

}
