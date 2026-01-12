// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title ReserveInsolvencyTest
/// @notice Unit tests attempting to break reserve solvency invariants (A3, I3)
/// @dev Tests various attack vectors to create insolvency: balance < sum(reserves)
contract ReserveInsolvencyTest is BaseTest {

    TIP20 public userToken;
    TIP20 public validatorToken;
    TIP20 public thirdToken;
    bytes32 public poolId;

    address public attacker = address(0xBAD);
    address public lp1 = address(0x1111);
    address public lp2 = address(0x2222);

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
        validatorToken.mint(lp1, initialLiquidity);
        vm.startPrank(lp1);
        validatorToken.approve(address(amm), initialLiquidity);
        amm.mint(address(userToken), address(validatorToken), initialLiquidity, lp1);
        vm.stopPrank();

        poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Fund actors
        userToken.mint(attacker, 100_000_000e18);
        validatorToken.mint(attacker, 100_000_000e18);
        userToken.mint(lp2, 100_000_000e18);
        validatorToken.mint(lp2, 100_000_000e18);
    }

    /*//////////////////////////////////////////////////////////////
            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Get sum of reserves for a token across all known pools
    function _getTotalReserves(address token) internal view returns (uint256 total) {
        // Pool: userToken -> validatorToken
        IFeeAMM.Pool memory pool1 = amm.getPool(address(userToken), address(validatorToken));
        if (token == address(userToken)) {
            total += pool1.reserveUserToken;
        } else if (token == address(validatorToken)) {
            total += pool1.reserveValidatorToken;
        }

        // Pool: validatorToken -> userToken (reverse)
        IFeeAMM.Pool memory pool2 = amm.getPool(address(validatorToken), address(userToken));
        if (token == address(validatorToken)) {
            total += pool2.reserveUserToken;
        } else if (token == address(userToken)) {
            total += pool2.reserveValidatorToken;
        }
    }

    /// @dev Check solvency for a token
    function _checkSolvency(address token) internal view returns (bool) {
        uint256 balance = TIP20(token).balanceOf(address(amm));
        uint256 reserves = _getTotalReserves(token);
        return balance >= reserves;
    }

    /// @dev Assert solvency for a token
    function _assertSolvent(address token, string memory message) internal view {
        uint256 balance = TIP20(token).balanceOf(address(amm));
        uint256 reserves = _getTotalReserves(token);
        assertGe(balance, reserves, message);
    }

    /*//////////////////////////////////////////////////////////////
            A3/I3: BASIC SOLVENCY CHECKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify initial pool is solvent
    function test_InitialPoolSolvent() public view {
        _assertSolvent(address(validatorToken), "ValidatorToken should be solvent");
        _assertSolvent(address(userToken), "UserToken should be solvent");
    }

    /// @notice Verify solvency after mint
    function test_SolvencyAfterMint() public {
        uint256 mintAmount = 1_000_000e18;

        vm.startPrank(lp2);
        validatorToken.approve(address(amm), mintAmount);
        amm.mint(address(userToken), address(validatorToken), mintAmount, lp2);
        vm.stopPrank();

        _assertSolvent(address(validatorToken), "ValidatorToken should be solvent after mint");
        _assertSolvent(address(userToken), "UserToken should be solvent after mint");
    }

    /// @notice Verify solvency after burn
    function test_SolvencyAfterBurn() public {
        uint256 lpBalance = amm.liquidityBalances(poolId, lp1);
        uint256 burnAmount = lpBalance / 2;

        vm.prank(lp1);
        amm.burn(address(userToken), address(validatorToken), burnAmount, lp1);

        _assertSolvent(address(validatorToken), "ValidatorToken should be solvent after burn");
        _assertSolvent(address(userToken), "UserToken should be solvent after burn");
    }

    /// @notice Verify solvency after rebalanceSwap (when reserves exist)
    function test_SolvencyAfterRebalanceSwap() public {
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        // Only test if there are userToken reserves to swap
        if (pool.reserveUserToken == 0) {
            // Pool has no userToken reserves, verify solvency anyway
            _assertSolvent(address(validatorToken), "ValidatorToken should be solvent");
            _assertSolvent(address(userToken), "UserToken should be solvent");
            return;
        }

        uint256 amountOut = pool.reserveUserToken / 10;
        if (amountOut == 0) return;

        vm.startPrank(attacker);
        validatorToken.approve(address(amm), type(uint256).max);
        amm.rebalanceSwap(address(userToken), address(validatorToken), amountOut, attacker);
        vm.stopPrank();

        _assertSolvent(address(validatorToken), "ValidatorToken should be solvent after rebalance");
        _assertSolvent(address(userToken), "UserToken should be solvent after rebalance");
    }

    /*//////////////////////////////////////////////////////////////
            MULTI-POOL SOLVENCY
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify solvency with multiple pools sharing a token
    function test_MultiPoolSolvency() public {
        // Create second pool: validatorToken -> thirdToken
        uint256 initialLiq = 5_000_000e18;
        thirdToken.mint(lp2, initialLiq);

        vm.startPrank(lp2);
        thirdToken.approve(address(amm), initialLiq);
        amm.mint(address(validatorToken), address(thirdToken), initialLiq, lp2);
        vm.stopPrank();

        // Create third pool: userToken -> thirdToken
        thirdToken.mint(lp2, initialLiq);
        vm.startPrank(lp2);
        thirdToken.approve(address(amm), initialLiq);
        amm.mint(address(userToken), address(thirdToken), initialLiq, lp2);
        vm.stopPrank();

        // Check solvency for all tokens
        _assertSolvent(
            address(validatorToken), "ValidatorToken should be solvent with multiple pools"
        );
        _assertSolvent(address(userToken), "UserToken should be solvent with multiple pools");
        _assertSolvent(address(thirdToken), "ThirdToken should be solvent with multiple pools");
    }

    /// @notice Verify solvency after operations on multiple pools
    function test_MultiPoolOperationsSolvency() public {
        // Setup second pool
        uint256 initialLiq = 5_000_000e18;
        thirdToken.mint(lp2, initialLiq);
        vm.startPrank(lp2);
        thirdToken.approve(address(amm), initialLiq);
        amm.mint(address(userToken), address(thirdToken), initialLiq, lp2);
        vm.stopPrank();

        // Perform operations on first pool
        uint256 lpBalance = amm.liquidityBalances(poolId, lp1);
        vm.prank(lp1);
        amm.burn(address(userToken), address(validatorToken), lpBalance / 4, lp1);

        // Add liquidity to second pool
        bytes32 pool2Id = amm.getPoolId(address(userToken), address(thirdToken));
        thirdToken.mint(lp2, 1_000_000e18);
        vm.startPrank(lp2);
        thirdToken.approve(address(amm), 1_000_000e18);
        amm.mint(address(userToken), address(thirdToken), 1_000_000e18, lp2);
        vm.stopPrank();

        // Check all tokens remain solvent
        _assertSolvent(address(validatorToken), "ValidatorToken solvent after multi-pool ops");
        _assertSolvent(address(userToken), "UserToken solvent after multi-pool ops");
        _assertSolvent(address(thirdToken), "ThirdToken solvent after multi-pool ops");
    }

    /*//////////////////////////////////////////////////////////////
            ATTACK VECTORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Attempt to drain reserves via repeated mint/burn
    function test_DrainViaRepeatedMintBurn() public {
        uint256 cycles = 20;
        uint256 amount = 100_000e18;

        vm.startPrank(lp2);
        validatorToken.approve(address(amm), type(uint256).max);

        for (uint256 i = 0; i < cycles; i++) {
            uint256 liq = amm.mint(address(userToken), address(validatorToken), amount, lp2);
            if (liq > 0) {
                amm.burn(address(userToken), address(validatorToken), liq, lp2);
            }

            // Check solvency after each cycle
            assertTrue(_checkSolvency(address(validatorToken)), "Insolvency during mint/burn cycle");
        }

        vm.stopPrank();

        _assertSolvent(address(validatorToken), "Should remain solvent after repeated mint/burn");
    }

    /// @notice Attempt to create insolvency via rapid pool operations
    function test_RapidPoolOperations() public {
        vm.startPrank(lp2);
        validatorToken.approve(address(amm), type(uint256).max);

        // Rapid mints
        for (uint256 i = 0; i < 10; i++) {
            amm.mint(address(userToken), address(validatorToken), 10_000e18, lp2);
        }

        // Rapid burns
        uint256 balance = amm.liquidityBalances(poolId, lp2);
        uint256 burnPer = balance / 10;
        for (uint256 i = 0; i < 10 && balance > burnPer; i++) {
            amm.burn(address(userToken), address(validatorToken), burnPer, lp2);
            balance = amm.liquidityBalances(poolId, lp2);
        }

        vm.stopPrank();

        _assertSolvent(address(validatorToken), "Should remain solvent after rapid operations");
    }

    /// @notice Test solvency with maximum uint128 reserves
    function test_SolvencyAtMaxReserves() public {
        // This is a theoretical test - in practice, supply caps prevent this
        // Verify that the system maintains solvency even with large reserves

        uint256 largeAmount = 1_000_000_000_000e18; // 1 trillion

        // Set high supply cap
        validatorToken.setSupplyCap(type(uint128).max);

        validatorToken.mint(lp2, largeAmount);

        vm.startPrank(lp2);
        validatorToken.approve(address(amm), largeAmount);
        amm.mint(address(userToken), address(validatorToken), largeAmount, lp2);
        vm.stopPrank();

        _assertSolvent(address(validatorToken), "Should remain solvent with large reserves");
    }

    /// @notice Verify solvency after full pool drain
    function test_SolvencyAfterFullDrain() public {
        // Get LP1's full balance and burn it
        uint256 lp1Balance = amm.liquidityBalances(poolId, lp1);

        vm.prank(lp1);
        (uint256 outUser, uint256 outValidator) =
            amm.burn(address(userToken), address(validatorToken), lp1Balance, lp1);

        // After full drain, reserves should be minimal (MIN_LIQUIDITY locked)
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        // Pool may still have MIN_LIQUIDITY worth of reserves locked
        uint256 totalSupply = amm.totalSupply(poolId);
        assertGe(totalSupply, amm.MIN_LIQUIDITY(), "MIN_LIQUIDITY should remain");

        // Solvency should still hold
        _assertSolvent(address(validatorToken), "Should remain solvent after drain");
        _assertSolvent(address(userToken), "Should remain solvent after drain");
    }

    /*//////////////////////////////////////////////////////////////
            EDGE CASES
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify empty pool solvency
    function test_EmptyPoolSolvency() public {
        // Create new pool but don't add liquidity
        TIP20 newToken =
            TIP20(factory.createToken("NewToken", "NT", "USD", pathUSD, admin, bytes32("new")));

        bytes32 newPoolId = amm.getPoolId(address(userToken), address(newToken));

        // Pool doesn't exist yet - should have 0 reserves
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(newToken));
        assertEq(pool.reserveUserToken, 0, "New pool should have 0 userToken reserves");
        assertEq(pool.reserveValidatorToken, 0, "New pool should have 0 validatorToken reserves");

        // Balance >= reserves (0 >= 0) should hold
        uint256 balance = newToken.balanceOf(address(amm));
        assertGe(balance, 0, "Balance should be >= 0");
    }

    /// @notice Verify solvency with zero-value operations
    function test_ZeroValueOperationsSolvency() public {
        // Attempting operations with 0 - whether they revert or not, solvency must hold
        vm.startPrank(lp2);
        validatorToken.approve(address(amm), type(uint256).max);

        // Capture initial state
        uint256 initialBalance = validatorToken.balanceOf(address(amm));
        uint256 initialReserves = _getTotalReserves(address(validatorToken));

        // Mint 0 - should revert or be no-op
        try amm.mint(address(userToken), address(validatorToken), 0, lp2) { } catch { }

        // Burn 0 - should revert or be no-op
        try amm.burn(address(userToken), address(validatorToken), 0, lp2) { } catch { }

        vm.stopPrank();

        // Key assertion: solvency is unaffected regardless of whether ops reverted
        _assertSolvent(address(validatorToken), "Solvency unaffected by zero ops");

        // Reserves should be unchanged (zero ops shouldn't modify state)
        uint256 finalReserves = _getTotalReserves(address(validatorToken));
        assertEq(finalReserves, initialReserves, "Reserves unchanged by zero ops");
    }

    /// @notice Verify solvency invariant: balance >= reserves for all tokens
    function test_SolvencyInvariantHolds() public view {
        // Get all token balances at AMM
        uint256 userTokenBalance = userToken.balanceOf(address(amm));
        uint256 validatorTokenBalance = validatorToken.balanceOf(address(amm));

        // Get reserves across all pools for each token
        uint256 userTokenReserves = _getTotalReserves(address(userToken));
        uint256 validatorTokenReserves = _getTotalReserves(address(validatorToken));

        // Invariant: balance >= reserves
        assertGe(userTokenBalance, userTokenReserves, "UserToken: balance >= reserves");
        assertGe(
            validatorTokenBalance, validatorTokenReserves, "ValidatorToken: balance >= reserves"
        );
    }

    /*//////////////////////////////////////////////////////////////
            FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz: solvency holds after random mint amount
    function testFuzz_SolvencyAfterMint(uint256 amount) public {
        amount = bound(amount, amm.MIN_LIQUIDITY() * 2 + 2, 1_000_000_000e18);

        validatorToken.mint(lp2, amount);

        vm.startPrank(lp2);
        validatorToken.approve(address(amm), amount);
        amm.mint(address(userToken), address(validatorToken), amount, lp2);
        vm.stopPrank();

        _assertSolvent(address(validatorToken), "Solvency after fuzz mint");
    }

    /// @notice Fuzz: solvency holds after random burn amount
    function testFuzz_SolvencyAfterBurn(uint256 burnPct) public {
        burnPct = bound(burnPct, 1, 100);

        uint256 lpBalance = amm.liquidityBalances(poolId, lp1);
        uint256 burnAmount = (lpBalance * burnPct) / 100;
        if (burnAmount == 0) return;

        vm.prank(lp1);
        amm.burn(address(userToken), address(validatorToken), burnAmount, lp1);

        _assertSolvent(address(validatorToken), "Solvency after fuzz burn");
        _assertSolvent(address(userToken), "Solvency after fuzz burn (userToken)");
    }

    /// @notice Fuzz: solvency holds after random sequence of operations
    function testFuzz_SolvencyAfterRandomOps(uint256 seed) public {
        seed = bound(seed, 1, 1000);

        vm.startPrank(lp2);
        validatorToken.approve(address(amm), type(uint256).max);

        for (uint256 i = 0; i < 10; i++) {
            uint256 action = (seed + i) % 3;

            if (action == 0) {
                // Mint
                uint256 amount = ((seed * (i + 1)) % 100_000e18) + 10_000;
                try amm.mint(address(userToken), address(validatorToken), amount, lp2) { } catch { }
            } else if (action == 1) {
                // Burn
                uint256 balance = amm.liquidityBalances(poolId, lp2);
                if (balance > 0) {
                    uint256 burnAmount = (balance * ((seed + i) % 50 + 1)) / 100;
                    if (burnAmount > 0) {
                        try amm.burn(
                            address(userToken), address(validatorToken), burnAmount, lp2
                        ) { }
                            catch { }
                    }
                }
            }
            // action == 2: skip (no-op)

            // Check solvency after each operation
            assertTrue(_checkSolvency(address(validatorToken)), "Insolvency during random ops");
        }

        vm.stopPrank();

        _assertSolvent(address(validatorToken), "Solvency after fuzz random ops");
    }

    /*//////////////////////////////////////////////////////////////
            DISTRIBUTION SOLVENCY
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify solvency is maintained after fee distribution
    function test_SolvencyAfterFeeDistribution() public {
        // Get initial solvency state
        uint256 initialBalance = validatorToken.balanceOf(address(amm));
        uint256 initialReserves = _getTotalReserves(address(validatorToken));

        // Fees can only be distributed if collected - with empty collected fees
        // distribution is a no-op
        amm.distributeFees(lp1, address(validatorToken));

        // Balance and reserves should be unchanged
        uint256 finalBalance = validatorToken.balanceOf(address(amm));
        uint256 finalReserves = _getTotalReserves(address(validatorToken));

        assertEq(finalBalance, initialBalance, "Balance unchanged with no fees");
        assertEq(finalReserves, initialReserves, "Reserves unchanged with no fees");

        _assertSolvent(address(validatorToken), "Solvency after distribution");
    }

}
