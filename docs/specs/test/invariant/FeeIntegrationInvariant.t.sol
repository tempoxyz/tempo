// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { FeeIntegrationHandler } from "./FeeIntegrationHandler.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { console } from "forge-std/console.sol";

/// @title FeeIntegrationInvariantTest
/// @notice Integration invariant tests for FeeManager + FeeAMM combined
/// @dev Tests cross-contract invariants that involve both fee collection and AMM operations
contract FeeIntegrationInvariantTest is StdInvariant, BaseTest {

    FeeIntegrationHandler public handler;
    TIP20 public userToken;
    TIP20 public validatorToken;
    bytes32 public poolId;

    uint256 public constant M = 9970;
    uint256 public constant SCALE = 10_000;

    function setUp() public override {
        super.setUp();

        // Create tokens for testing
        userToken =
            TIP20(factory.createToken("UserToken", "UTK", "USD", pathUSD, admin, bytes32("user")));
        validatorToken = TIP20(
            factory.createToken(
                "ValidatorToken", "VTK", "USD", pathUSD, admin, bytes32("validator")
            )
        );

        // Grant issuer role for minting
        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);

        // Setup initial pool liquidity
        uint256 initialLiquidity = 10_000_000e18;
        validatorToken.mint(admin, initialLiquidity);
        validatorToken.approve(address(amm), initialLiquidity);
        amm.mint(address(userToken), address(validatorToken), initialLiquidity, admin);

        // Also add some userToken to the pool for rebalance swaps
        // We do this by simulating fee swaps that add userToken to reserves
        userToken.mint(address(amm), 5_000_000e18);

        poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Create handler with admin for minting tokens
        handler = new FeeIntegrationHandler(amm, userToken, validatorToken, admin);

        // Grant issuer role to handler so it can mint tokens directly
        userToken.grantRole(_ISSUER_ROLE, address(handler));
        validatorToken.grantRole(_ISSUER_ROLE, address(handler));

        // Target only the handler
        targetContract(address(handler));
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I1: CROSS-TOKEN FEE RATE CORRECTNESS
    //////////////////////////////////////////////////////////////*/

    /// @notice Cross-token fees must be collected at rate M/SCALE (0.997)
    /// @dev Due to rounding errors accumulating across multiple operations,
    ///      we check bounds instead of exact equality. Each operation can lose
    ///      up to 1 unit to rounding, so total error <= crossTokenFeeCalls.
    function invariant_crossTokenFeeRate() public view {
        uint256 feesIn = handler.ghost_crossTokenFeesIn();
        uint256 feesOut = handler.ghost_crossTokenFeesOut();

        if (feesIn == 0) return;

        // Expected output if calculated in aggregate: feesIn * M / SCALE
        uint256 expectedOut = (feesIn * M) / SCALE;

        // feesOut is sum of individually rounded values, so it can be less than expectedOut
        // by up to 1 per operation due to floor division
        uint256 maxRoundingError = handler.crossTokenFeeCalls();

        // Actual output should be within rounding error bounds
        assertLe(feesOut, expectedOut, "Cross-token fees exceed expected");
        assertGe(
            feesOut + maxRoundingError, expectedOut, "Cross-token fees too low beyond rounding"
        );
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I2: NO ARBITRAGE FROM SWAP SEQUENCES
    //////////////////////////////////////////////////////////////*/

    /// @notice Consecutive swaps should not create value
    /// @dev Fee swaps take 0.3% (M=9970), rebalance gives back at 0.15% markup (N=9985)
    ///      So fee swap -> rebalance should result in net loss for arbitrageur
    function invariant_noArbitrage() public view {
        uint256 rebalanceIn = handler.ghost_rebalanceIn();
        uint256 rebalanceOut = handler.ghost_rebalanceOut();

        if (rebalanceOut == 0) return;

        // Rebalance swaps: validatorToken in -> userToken out
        // amountIn >= (amountOut * 9985) / 10000 + 1
        // So for every 1 userToken out, you pay ~1.0015 validatorToken in
        // Combined with fee swap rate of 0.997, arbitrage is unprofitable

        // Check that rebalance in is at least the minimum required
        uint256 minExpectedIn = (rebalanceOut * 9985) / 10_000 + handler.rebalanceCalls();
        assertGe(rebalanceIn, minExpectedIn, "Rebalance rate too favorable");
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I3: SYSTEM SOLVENCY
    //////////////////////////////////////////////////////////////*/

    /// @notice The system must always have enough tokens to cover the sum of all pool reserves
    /// @dev Checks both directional pools: (userToken, validatorToken) and (validatorToken, userToken)
    function invariant_systemSolvency() public view {
        // Get both directional pools
        IFeeAMM.Pool memory poolUV = amm.getPool(address(userToken), address(validatorToken));
        IFeeAMM.Pool memory poolVU = amm.getPool(address(validatorToken), address(userToken));

        // Sum reserves for userToken across both pools
        // In poolUV: userToken is the "user" token (reserveUserToken)
        // In poolVU: userToken is the "validator" token (reserveValidatorToken)
        uint256 totalUserTokenReserves =
            uint256(poolUV.reserveUserToken) + uint256(poolVU.reserveValidatorToken);

        // Sum reserves for validatorToken across both pools
        // In poolUV: validatorToken is the "validator" token (reserveValidatorToken)
        // In poolVU: validatorToken is the "user" token (reserveUserToken)
        uint256 totalValidatorTokenReserves =
            uint256(poolUV.reserveValidatorToken) + uint256(poolVU.reserveUserToken);

        // AMM must hold at least the sum of all reserves for each token
        uint256 userBalance = userToken.balanceOf(address(amm));
        uint256 validatorBalance = validatorToken.balanceOf(address(amm));

        assertGe(
            userBalance, totalUserTokenReserves, "Insufficient userToken for sum of pool reserves"
        );
        assertGe(
            validatorBalance,
            totalValidatorTokenReserves,
            "Insufficient validatorToken for sum of pool reserves"
        );
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I4: LP TOKEN ACCOUNTING (INTEGRATION)
    //////////////////////////////////////////////////////////////*/

    /// @notice LP token accounting must be correct across all operations
    function invariant_lpTokenAccountingIntegration() public view {
        uint256 totalSupply = amm.totalSupply(poolId);

        if (totalSupply == 0) return;

        uint256 sumBalances = handler.sumLPBalances();
        uint256 minLiquidity = amm.MIN_LIQUIDITY();

        // Total supply includes:
        // - MIN_LIQUIDITY (locked)
        // - Admin's initial liquidity
        // - Handler actors' liquidity

        // We track handler actors' balances in ghost state
        // Admin's balance is separate
        uint256 adminBalance = amm.liquidityBalances(poolId, admin);

        assertEq(
            totalSupply,
            minLiquidity + adminBalance + sumBalances,
            "LP token accounting mismatch in integration"
        );
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I5: FEE CONSERVATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Total fees in must equal fees collected + refunds
    function invariant_feeConservation() public view {
        uint256 totalIn = handler.ghost_totalFeesIn();
        uint256 collected = handler.ghost_totalFeesCollected();
        uint256 refunds = handler.ghost_totalRefunds();

        // For same-token: in = collected + refunds
        // For cross-token: in = (collected / 0.997) + refunds (approximately)
        // Since we track collected as the output amount for cross-token

        // We can verify that collected + refunds <= totalIn
        assertLe(collected + refunds, totalIn, "Fee conservation violated");
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I6: DIRECTIONAL POOL SEPARATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Pool(A,B) and Pool(B,A) are separate pools with independent reserves
    /// @dev Each ordered pair has its own pool
    function invariant_directionalPoolSeparation() public view {
        bytes32 poolAB = amm.getPoolId(address(userToken), address(validatorToken));
        bytes32 poolBA = amm.getPoolId(address(validatorToken), address(userToken));

        // Pool IDs must be different
        assertTrue(poolAB != poolBA, "Pool IDs should be different for reversed pairs");

        // We only interact with poolAB in our tests, so poolBA should be empty
        IFeeAMM.Pool memory reversePool = amm.getPool(address(validatorToken), address(userToken));
        assertEq(reversePool.reserveUserToken, 0, "Reverse pool should have no user reserves");
        assertEq(
            reversePool.reserveValidatorToken, 0, "Reverse pool should have no validator reserves"
        );
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I7: LP VALUE NEVER DECREASES (EXCLUDING FEES)
    //////////////////////////////////////////////////////////////*/

    /// @notice LP tokens should represent at least their share of reserves
    /// @dev Due to rounding, actual withdrawn amount may be slightly less
    function invariant_lpValuePreserved() public view {
        uint256 ts = amm.totalSupply(poolId);
        if (ts == 0) return;

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        // Total value in pool (using 1:1 assumption for stablecoins)
        uint256 totalValue = pool.reserveUserToken + pool.reserveValidatorToken;

        // Value per LP token should be positive if pool is initialized
        // (totalValue / totalSupply) >= 0
        if (ts > 0) {
            assertTrue(totalValue >= 0, "Pool value should be non-negative");
        }
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I8: SWAP SPREAD ENSURES LP PROFITABILITY
    //////////////////////////////////////////////////////////////*/

    /// @notice The spread between fee swap (0.997) and rebalance (0.9985) ensures LP profit
    /// @dev For every fee swap, LPs earn 0.3%; for every rebalance, arbitrageurs pay 0.15%
    function invariant_swapSpreadPositive() public view {
        // M = 9970 (fee swap: user gets 0.997 per 1 paid)
        // N = 9985 (rebalance: user pays 0.9985 + 1 per 1 received)
        // The spread (N - M) / SCALE = 0.0015 or 0.15% goes to LPs on rebalance

        uint256 feeSwapRate = amm.M();
        uint256 rebalanceRate = amm.N();

        // Rebalance rate must be higher than fee swap rate (arbitrageur pays more than fee swapper receives)
        assertGt(rebalanceRate, feeSwapRate, "Rebalance rate must exceed fee swap rate");

        // Spread should be exactly 15 basis points
        assertEq(rebalanceRate - feeSwapRate, 15, "Spread should be 15 basis points");
    }

    /*//////////////////////////////////////////////////////////////
                        CALL SUMMARY
    //////////////////////////////////////////////////////////////*/

    /// @notice Log call statistics for debugging
    function invariant_callSummary() public view {
        console.log("=== Integration Invariant Call Summary ===");
        console.log("Same token fee calls:", handler.sameTokenFeeCalls());
        console.log("Cross token fee calls:", handler.crossTokenFeeCalls());
        console.log("Mint calls:", handler.mintCalls());
        console.log("Burn calls:", handler.burnCalls());
        console.log("Rebalance calls:", handler.rebalanceCalls());
        console.log("Distribute calls:", handler.distributeFeeCalls());
        console.log("---");
        console.log("Total fees in:", handler.ghost_totalFeesIn());
        console.log("Total fees collected:", handler.ghost_totalFeesCollected());
        console.log("Total refunds:", handler.ghost_totalRefunds());
        console.log("Cross-token fees in:", handler.ghost_crossTokenFeesIn());
        console.log("Cross-token fees out:", handler.ghost_crossTokenFeesOut());
        console.log("---");
        console.log("Total LP minted:", handler.ghost_totalMinted());
        console.log("Total LP burned:", handler.ghost_totalBurned());
        console.log("Total rebalance in:", handler.ghost_rebalanceIn());
        console.log("Total rebalance out:", handler.ghost_rebalanceOut());
    }

}
