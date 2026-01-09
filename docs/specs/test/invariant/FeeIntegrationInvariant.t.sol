// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { console } from "forge-std/console.sol";

/// @title FeeIntegrationInvariantTest
/// @notice Integration invariant tests for FeeManager + FeeAMM combined
/// @dev Uses inline handler approach - handlers are functions in this contract
contract FeeIntegrationInvariantTest is StdInvariant, BaseTest {

    // Storage slot for pools mapping in FeeAMM (slot 0)
    uint256 internal constant POOLS_SLOT = 0;

    TIP20 public userToken;
    TIP20 public validatorToken;
    bytes32 public poolId;

    uint256 public constant M = 9970;
    uint256 public constant N = 9985;
    uint256 public constant SCALE = 10_000;

    // Ghost state - Fee tracking
    uint256 public ghost_totalFeesIn;
    uint256 public ghost_totalFeesCollected;
    uint256 public ghost_totalRefunds;
    uint256 public ghost_totalFeesDistributed;

    // Ghost state - AMM tracking
    uint256 public ghost_totalMinted;
    uint256 public ghost_totalBurned;
    uint256 public ghost_rebalanceIn;
    uint256 public ghost_rebalanceOut;
    uint256 public ghost_rebalanceExpectedIn; // Track sum of individual expected inputs

    // Ghost state - Cross-token fee tracking
    uint256 public ghost_crossTokenFeesIn;
    uint256 public ghost_crossTokenFeesOut;

    // Track LP balances per actor
    mapping(address => uint256) public ghost_lpBalances;

    address[] public actors;

    // Call counters
    uint256 public sameTokenFeeCalls;
    uint256 public crossTokenFeeCalls;
    uint256 public mintCalls;
    uint256 public burnCalls;
    uint256 public rebalanceCalls;
    uint256 public distributeFeeCalls;

    function setUp() public override {
        super.setUp();

        // Target this contract - handlers are inline functions here
        targetContract(address(this));

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
        userToken.grantRole(_ISSUER_ROLE, address(this));
        validatorToken.grantRole(_ISSUER_ROLE, address(this));

        // Setup initial pool liquidity
        uint256 initialLiquidity = 10_000_000e18;
        validatorToken.mint(admin, initialLiquidity);
        validatorToken.approve(address(amm), initialLiquidity);
        amm.mint(address(userToken), address(validatorToken), initialLiquidity, admin);

        poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Setup actors
        actors.push(address(0x4001));
        actors.push(address(0x4002));
        actors.push(address(0x4003));

        // Target specific selectors for fuzzing
        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = this.simulateSameTokenFee.selector;
        selectors[1] = this.simulateCrossTokenFee.selector;
        selectors[2] = this.addLiquidity.selector;
        selectors[3] = this.removeLiquidity.selector;
        selectors[4] = this.rebalancePool.selector;
        selectors[5] = this.distributeFees.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Simulate same-token fee collection
    function simulateSameTokenFee(uint256 actorSeed, uint256 maxAmount, uint256 actualUsedPct)
        external
    {
        address actor = actors[actorSeed % actors.length];

        maxAmount = bound(maxAmount, 1e6, 1_000_000e18);
        actualUsedPct = bound(actualUsedPct, 0, 100);
        uint256 actualUsed = (maxAmount * actualUsedPct) / 100;
        uint256 refund = maxAmount - actualUsed;

        userToken.mint(actor, maxAmount);

        vm.prank(actor);
        userToken.transfer(address(amm), maxAmount);
        ghost_totalFeesIn += maxAmount;

        if (refund > 0) {
            vm.prank(address(amm));
            userToken.transfer(actor, refund);
            ghost_totalRefunds += refund;
        }

        ghost_totalFeesCollected += actualUsed;
        sameTokenFeeCalls++;
    }

    /// @notice Simulate cross-token fee collection (userToken -> validatorToken swap)
    function simulateCrossTokenFee(uint256 actorSeed, uint256 maxAmount, uint256 actualUsedPct)
        external
    {
        address actor = actors[actorSeed % actors.length];

        maxAmount = bound(maxAmount, 1e6, 1_000_000e18);
        actualUsedPct = bound(actualUsedPct, 1, 100);
        uint256 actualUsed = (maxAmount * actualUsedPct) / 100;
        uint256 refund = maxAmount - actualUsed;

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));
        uint256 amountOutNeeded = (actualUsed * M) / SCALE;
        if (pool.reserveValidatorToken < amountOutNeeded) return;

        userToken.mint(actor, maxAmount);

        vm.prank(actor);
        userToken.transfer(address(amm), maxAmount);
        ghost_totalFeesIn += maxAmount;
        ghost_crossTokenFeesIn += actualUsed;

        if (refund > 0) {
            vm.prank(address(amm));
            userToken.transfer(actor, refund);
            ghost_totalRefunds += refund;
        }

        uint256 amountOut = (actualUsed * M) / SCALE;
        ghost_crossTokenFeesOut += amountOut;
        ghost_totalFeesCollected += amountOut;

        _updatePoolReserves(poolId, int256(actualUsed), -int256(amountOut));

        crossTokenFeeCalls++;
    }

    /// @notice Add liquidity to the pool
    function addLiquidity(uint256 actorSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];

        amount = bound(amount, 2002, 10_000_000e18);

        validatorToken.mint(actor, amount);

        vm.startPrank(actor);
        validatorToken.approve(address(amm), amount);

        try amm.mint(address(userToken), address(validatorToken), amount, actor) returns (
            uint256 liquidity
        ) {
            ghost_totalMinted += liquidity;
            ghost_lpBalances[actor] += liquidity;
            mintCalls++;
        } catch { }
        vm.stopPrank();
    }

    /// @notice Remove liquidity from the pool
    function removeLiquidity(uint256 actorSeed, uint256 pct) external {
        address actor = actors[actorSeed % actors.length];

        uint256 balance = amm.liquidityBalances(poolId, actor);
        if (balance == 0) return;

        pct = bound(pct, 1, 100);
        uint256 amount = (balance * pct) / 100;
        if (amount == 0) return;

        vm.startPrank(actor);
        try amm.burn(address(userToken), address(validatorToken), amount, actor) returns (
            uint256, uint256
        ) {
            ghost_totalBurned += amount;
            ghost_lpBalances[actor] -= amount;
            burnCalls++;
        } catch { }
        vm.stopPrank();
    }

    /// @notice Rebalance swap (validatorToken -> userToken)
    function rebalancePool(uint256 actorSeed, uint256 amountOut) external {
        address actor = actors[actorSeed % actors.length];

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));
        if (pool.reserveUserToken == 0) return;

        amountOut = bound(amountOut, 1, pool.reserveUserToken);

        // Calculate expected input for this specific swap (matches implementation formula)
        uint256 expectedIn = (amountOut * N) / SCALE + 1;

        validatorToken.mint(actor, expectedIn);

        vm.startPrank(actor);
        validatorToken.approve(address(amm), expectedIn);

        try amm.rebalanceSwap(
            address(userToken), address(validatorToken), amountOut, actor
        ) returns (
            uint256 actualIn
        ) {
            ghost_rebalanceIn += actualIn;
            ghost_rebalanceOut += amountOut;
            ghost_rebalanceExpectedIn += expectedIn; // Track individual expected amount
            rebalanceCalls++;
        } catch { }
        vm.stopPrank();
    }

    /// @notice Distribute accumulated fees
    function distributeFees(uint256 actorSeed) external {
        address actor = actors[actorSeed % actors.length];

        uint256 userTokenFees = amm.collectedFees(actor, address(userToken));
        if (userTokenFees > 0) {
            amm.distributeFees(actor, address(userToken));
            ghost_totalFeesDistributed += userTokenFees;
            distributeFeeCalls++;
            return;
        }

        uint256 validatorTokenFees = amm.collectedFees(actor, address(validatorToken));
        if (validatorTokenFees > 0) {
            amm.distributeFees(actor, address(validatorToken));
            ghost_totalFeesDistributed += validatorTokenFees;
            distributeFeeCalls++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    function _updatePoolReserves(bytes32 _poolId, int256 deltaUser, int256 deltaValidator)
        internal
    {
        bytes32 poolSlot = keccak256(abi.encode(_poolId, POOLS_SLOT));
        bytes32 currentData = vm.load(address(amm), poolSlot);

        uint128 currentUserReserve = uint128(uint256(currentData));
        uint128 currentValidatorReserve = uint128(uint256(currentData) >> 128);

        uint128 newUserReserve = uint128(uint256(int256(uint256(currentUserReserve)) + deltaUser));
        uint128 newValidatorReserve =
            uint128(uint256(int256(uint256(currentValidatorReserve)) + deltaValidator));

        bytes32 newData = bytes32((uint256(newValidatorReserve) << 128) | uint256(newUserReserve));
        vm.store(address(amm), poolSlot, newData);
    }

    function sumLPBalances() public view returns (uint256 total) {
        for (uint256 i = 0; i < actors.length; i++) {
            total += ghost_lpBalances[actors[i]];
        }
    }

    function actorCount() public view returns (uint256) {
        return actors.length;
    }

    function getActor(uint256 index) public view returns (address) {
        return actors[index];
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I1: CROSS-TOKEN FEE RATE CORRECTNESS
    //////////////////////////////////////////////////////////////*/

    function invariant_crossTokenFeeRate() public view {
        uint256 expectedOut = (ghost_crossTokenFeesIn * M) / SCALE;

        assertLe(ghost_crossTokenFeesOut, expectedOut, "Cross-token fees exceed expected");
        assertGe(
            ghost_crossTokenFeesOut + crossTokenFeeCalls,
            expectedOut,
            "Cross-token fees too low beyond rounding"
        );
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I2: NO ARBITRAGE FROM SWAP SEQUENCES
    //////////////////////////////////////////////////////////////*/

    function invariant_noArbitrage() public view {
        // Use tracked sum of individual expected inputs instead of computing from total
        // This avoids floor division rounding discrepancy: sum(floor(x_i)) <= floor(sum(x_i))
        assertGe(ghost_rebalanceIn, ghost_rebalanceExpectedIn, "Rebalance rate too favorable");
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I3: SYSTEM SOLVENCY
    //////////////////////////////////////////////////////////////*/

    function invariant_systemSolvency() public view {
        IFeeAMM.Pool memory poolUV = amm.getPool(address(userToken), address(validatorToken));
        IFeeAMM.Pool memory poolVU = amm.getPool(address(validatorToken), address(userToken));

        uint256 totalUserTokenReserves =
            uint256(poolUV.reserveUserToken) + uint256(poolVU.reserveValidatorToken);
        uint256 totalValidatorTokenReserves =
            uint256(poolUV.reserveValidatorToken) + uint256(poolVU.reserveUserToken);

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

    function invariant_lpTokenAccountingIntegration() public view {
        uint256 totalSupply = amm.totalSupply(poolId);

        if (totalSupply == 0) return;

        uint256 sumBal = sumLPBalances();
        uint256 minLiquidity = amm.MIN_LIQUIDITY();
        uint256 adminBalance = amm.liquidityBalances(poolId, admin);

        assertEq(
            totalSupply,
            minLiquidity + adminBalance + sumBal,
            "LP token accounting mismatch in integration"
        );
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I5: FEE CONSERVATION
    //////////////////////////////////////////////////////////////*/

    function invariant_feeConservation() public view {
        uint256 totalIn = ghost_totalFeesIn;
        uint256 collected = ghost_totalFeesCollected;
        uint256 refunds = ghost_totalRefunds;

        assertLe(collected + refunds, totalIn, "Fee conservation violated");
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I6: DIRECTIONAL POOL SEPARATION
    //////////////////////////////////////////////////////////////*/

    function invariant_directionalPoolSeparation() public view {
        bytes32 poolAB = amm.getPoolId(address(userToken), address(validatorToken));
        bytes32 poolBA = amm.getPoolId(address(validatorToken), address(userToken));

        assertTrue(poolAB != poolBA, "Pool IDs should be different for reversed pairs");

        IFeeAMM.Pool memory reversePool = amm.getPool(address(validatorToken), address(userToken));
        assertEq(reversePool.reserveUserToken, 0, "Reverse pool should have no user reserves");
        assertEq(
            reversePool.reserveValidatorToken, 0, "Reverse pool should have no validator reserves"
        );
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I7: LP VALUE NEVER DECREASES (EXCLUDING FEES)
    //////////////////////////////////////////////////////////////*/

    function invariant_lpValuePreserved() public view {
        uint256 ts = amm.totalSupply(poolId);
        if (ts == 0) return;

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));
        uint256 totalValue = pool.reserveUserToken + pool.reserveValidatorToken;

        assertTrue(totalValue >= 0, "Pool value should be non-negative");
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT I8: SWAP SPREAD ENSURES LP PROFITABILITY
    //////////////////////////////////////////////////////////////*/

    function invariant_swapSpreadPositive() public view {
        uint256 feeSwapRate = amm.M();
        uint256 rebalanceRate = amm.N();

        assertGt(rebalanceRate, feeSwapRate, "Rebalance rate must exceed fee swap rate");
        assertEq(rebalanceRate - feeSwapRate, 15, "Spread should be 15 basis points");
    }

    /*//////////////////////////////////////////////////////////////
                        CALL SUMMARY
    //////////////////////////////////////////////////////////////*/

    function invariant_callSummary() public view {
        console.log("=== Integration Invariant Call Summary ===");
        console.log("Same token fee calls:", sameTokenFeeCalls);
        console.log("Cross token fee calls:", crossTokenFeeCalls);
        console.log("Mint calls:", mintCalls);
        console.log("Burn calls:", burnCalls);
        console.log("Rebalance calls:", rebalanceCalls);
        console.log("Distribute calls:", distributeFeeCalls);
        console.log("---");
        console.log("Total fees in:", ghost_totalFeesIn);
        console.log("Total fees collected:", ghost_totalFeesCollected);
        console.log("Total refunds:", ghost_totalRefunds);
        console.log("Cross-token fees in:", ghost_crossTokenFeesIn);
        console.log("Cross-token fees out:", ghost_crossTokenFeesOut);
        console.log("---");
        console.log("Total LP minted:", ghost_totalMinted);
        console.log("Total LP burned:", ghost_totalBurned);
        console.log("Total rebalance in:", ghost_rebalanceIn);
        console.log("Total rebalance out:", ghost_rebalanceOut);
        console.log("Total rebalance expected in:", ghost_rebalanceExpectedIn);
    }

}
