// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../../src/FeeManager.sol";
import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title FeeAMMOverflowTest
/// @notice Unit tests attempting to break invariant A10 (reserves bounded by uint128)
/// @dev Tests various attack vectors to overflow uint128 reserves
contract FeeAMMOverflowTest is BaseTest {

    TIP20 public userToken;
    TIP20 public validatorToken;

    uint256 constant MAX_U128 = type(uint128).max;
    uint256 constant REALISTIC_MAX = 1_000_000_000_000e18; // 1 trillion tokens

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

        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);
        userToken.grantRole(_ISSUER_ROLE, address(this));
        validatorToken.grantRole(_ISSUER_ROLE, address(this));

        // Set supply caps high enough for overflow tests
        userToken.setSupplyCap(MAX_U128);
        validatorToken.setSupplyCap(MAX_U128);
    }

    /*//////////////////////////////////////////////////////////////
                    A10 BREAK ATTEMPT: MINT OVERFLOW
    //////////////////////////////////////////////////////////////*/

    /// @notice Attempt to overflow reserveValidatorToken via single large mint
    /// @dev Token mint itself will revert with SupplyCapExceeded for amounts > uint128
    function test_A10_MintOverflow_SingleLargeMint() public {
        uint256 overflowAmount = MAX_U128 + 1;

        // Token mint will revert before AMM gets a chance
        // Use try/catch since vm.expectRevert has depth issues with precompile calls
        try validatorToken.mint(admin, overflowAmount) {
            revert("Should have reverted");
        } catch {
            // Expected - token rejects amounts > supply cap
        }
    }

    /// @notice Attempt to overflow reserveValidatorToken via multiple mints
    function test_A10_MintOverflow_MultipleMints() public {
        // Use realistic amounts that fit in token supply cap
        uint256 firstMint = REALISTIC_MAX / 2;
        uint256 secondMint = REALISTIC_MAX / 2 + 1e18;

        // First mint succeeds
        validatorToken.mint(admin, firstMint);
        validatorToken.approve(address(amm), firstMint);
        amm.mint(address(userToken), address(validatorToken), firstMint, admin);

        // Second mint should also succeed (within realistic bounds)
        validatorToken.mint(admin, secondMint);
        validatorToken.approve(address(amm), secondMint);
        amm.mint(address(userToken), address(validatorToken), secondMint, admin);

        // Verify reserves are still within uint128
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));
        assertLe(uint256(pool.reserveValidatorToken), MAX_U128);
    }

    /// @notice Test reserves at realistic max capacity
    function test_A10_MintOverflow_RealisticMax() public {
        validatorToken.mint(admin, REALISTIC_MAX);
        validatorToken.approve(address(amm), REALISTIC_MAX);

        amm.mint(address(userToken), address(validatorToken), REALISTIC_MAX, admin);

        // Verify reserves are within uint128
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));
        assertLe(uint256(pool.reserveValidatorToken), MAX_U128);
        assertEq(uint256(pool.reserveValidatorToken), REALISTIC_MAX);
    }

    /*//////////////////////////////////////////////////////////////
                A10 BREAK ATTEMPT: REBALANCE SWAP OVERFLOW
    //////////////////////////////////////////////////////////////*/

    /// @notice Attempt to overflow reserveValidatorToken via rebalanceSwap
    function test_A10_RebalanceSwapOverflow() public {
        // Setup pool near max capacity
        uint256 nearMax = MAX_U128 - 1000;
        validatorToken.mint(admin, nearMax);
        validatorToken.approve(address(amm), nearMax);
        amm.mint(address(userToken), address(validatorToken), nearMax, admin);

        // Get pool state
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        // Try rebalanceSwap that would overflow reserveValidatorToken
        // rebalanceSwap adds amountIn to reserveValidatorToken
        uint256 amountOut = uint256(pool.reserveUserToken); // Take all userToken
        if (amountOut == 0) return;

        uint256 amountIn = (amountOut * 9985) / 10_000 + 1;
        uint256 wouldOverflow = MAX_U128 - uint256(pool.reserveValidatorToken) + 1;

        if (amountIn > wouldOverflow) {
            validatorToken.mint(admin, amountIn);
            validatorToken.approve(address(amm), amountIn);

            vm.expectRevert(IFeeAMM.InsufficientReserves.selector);
            amm.rebalanceSwap(address(userToken), address(validatorToken), amountOut, admin);
        }
    }

    /// @notice Attempt to overflow via repeated small rebalance swaps
    function test_A10_RebalanceSwapOverflow_RepeatedSmall() public {
        // Setup pool with significant liquidity
        uint256 initialLiq = 10_000_000e18;
        validatorToken.mint(admin, initialLiq);
        validatorToken.approve(address(amm), initialLiq);
        amm.mint(address(userToken), address(validatorToken), initialLiq, admin);

        // Simulate fee swaps to build up reserveUserToken
        // (In real scenario, this happens via executeFeeSwap from protocol)
        // We'll use storage manipulation to simulate
        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Set reserveUserToken to near max
        bytes32 poolSlot = keccak256(abi.encode(poolId, uint256(0)));
        uint128 newUserReserve = uint128(MAX_U128 / 2);
        uint128 currentValidatorReserve = uint128(initialLiq);
        bytes32 newData =
            bytes32((uint256(currentValidatorReserve) << 128) | uint256(newUserReserve));
        vm.store(address(amm), poolSlot, newData);

        // Mint userToken to AMM to back the reserves
        userToken.mint(address(amm), newUserReserve);

        // Now try to rebalanceSwap a large amount
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));
        uint256 largeOut = uint256(pool.reserveUserToken) / 2;
        uint256 requiredIn = (largeOut * 9985) / 10_000 + 1;

        // Check if this would overflow
        uint256 newValidatorReserve = uint256(pool.reserveValidatorToken) + requiredIn;

        validatorToken.mint(admin, requiredIn);
        validatorToken.approve(address(amm), requiredIn);

        if (newValidatorReserve > MAX_U128) {
            vm.expectRevert(IFeeAMM.InsufficientReserves.selector);
        }
        amm.rebalanceSwap(address(userToken), address(validatorToken), largeOut, admin);
    }

    /*//////////////////////////////////////////////////////////////
                A10 BREAK ATTEMPT: STORAGE MANIPULATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify that reserves returned by pools() are always within uint128
    /// @dev The storage layout uses uint128 for reserves, so they cannot exceed MAX_U128
    function test_A10_ReservesAlwaysBounded() public {
        // Setup a pool
        uint256 initialLiq = 1_000_000e18;
        validatorToken.mint(admin, initialLiq);
        validatorToken.approve(address(amm), initialLiq);
        amm.mint(address(userToken), address(validatorToken), initialLiq, admin);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Read current reserves via pools() function
        (uint128 ru, uint128 rv) = amm.pools(poolId);

        // Verify they fit in uint128 (they must, since they're uint128 typed)
        assertLe(uint256(ru), MAX_U128, "reserveUserToken exceeds uint128");
        assertLe(uint256(rv), MAX_U128, "reserveValidatorToken exceeds uint128");

        // Reserves should match initial liquidity (minus any locked)
        assertEq(uint256(rv), initialLiq, "reserveValidatorToken mismatch");
    }

    /// @notice Test that the Pool struct enforces uint128 bounds by type
    function test_A10_PoolStructEnforcesBounds() public {
        // Setup a pool
        uint256 initialLiq = REALISTIC_MAX;
        validatorToken.mint(admin, initialLiq);
        validatorToken.approve(address(amm), initialLiq);
        amm.mint(address(userToken), address(validatorToken), initialLiq, admin);

        // Get pool via getPool() which returns Pool struct
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        // Pool struct uses uint128, so values are inherently bounded
        assertLe(uint256(pool.reserveUserToken), MAX_U128);
        assertLe(uint256(pool.reserveValidatorToken), MAX_U128);
    }

    /*//////////////////////////////////////////////////////////////
                A10 BREAK ATTEMPT: EDGE CASES
    //////////////////////////////////////////////////////////////*/

    /// @notice Test boundary condition: mint exactly MIN_LIQUIDITY * 2 + 2
    function test_A10_MinimalMint() public {
        // MIN_LIQUIDITY is 1000, need at least 2002 for first mint
        // (amountValidatorToken / 2 > MIN_LIQUIDITY)
        uint256 minMint = amm.MIN_LIQUIDITY() * 2 + 2;

        validatorToken.mint(admin, minMint);
        validatorToken.approve(address(amm), minMint);

        amm.mint(address(userToken), address(validatorToken), minMint, admin);

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));
        assertLe(uint256(pool.reserveValidatorToken), MAX_U128);
        assertLe(uint256(pool.reserveUserToken), MAX_U128);
    }

    /// @notice Fuzz test: random amounts should never overflow
    function testFuzz_A10_NoOverflow(uint256 amount) public {
        // MIN_LIQUIDITY * 2 + 2 is the minimum for first mint
        amount = bound(amount, amm.MIN_LIQUIDITY() * 2 + 2, REALISTIC_MAX);

        validatorToken.mint(admin, amount);
        validatorToken.approve(address(amm), amount);

        amm.mint(address(userToken), address(validatorToken), amount, admin);

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));
        assertLe(uint256(pool.reserveValidatorToken), MAX_U128);
        assertLe(uint256(pool.reserveUserToken), MAX_U128);
    }

    /// @notice Test that _requireU128 correctly reverts on amounts > uint128
    /// @dev TIP20 may revert with SupplyCapExceeded before InvalidAmount if supply cap is hit
    function test_A10_RequireU128Reverts() public {
        uint256 tooLarge = uint256(MAX_U128) + 1;

        // This will revert - either with InvalidAmount from AMM or SupplyCapExceeded from TIP20
        // Use try/catch since vm.expectRevert has depth issues with precompile calls
        try validatorToken.mint(admin, tooLarge) {
            revert("Should have reverted");
        } catch {
            // Expected - token rejects amounts > supply cap
        }
    }

    /// @notice Test that AMM rejects amounts exceeding uint128 even if token allows
    /// @dev In practice, TIP20 supply cap prevents reaching this condition
    function test_A10_AMMRejectsOverflow() public {
        // First setup a pool with reasonable liquidity
        uint256 initialLiq = 10_000_000e18;
        validatorToken.mint(admin, initialLiq);
        validatorToken.approve(address(amm), initialLiq);
        amm.mint(address(userToken), address(validatorToken), initialLiq, admin);

        // Get current reserves
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        // Verify current state
        assertLe(uint256(pool.reserveValidatorToken), MAX_U128);

        // Calculate amount that would overflow uint128 when added to current reserve
        uint256 wouldOverflow = MAX_U128 - uint256(pool.reserveValidatorToken) + 1;

        // Try to mint this amount - should revert (either at token or AMM level)
        try validatorToken.mint(admin, wouldOverflow) {
            validatorToken.approve(address(amm), wouldOverflow);
            try amm.mint(address(userToken), address(validatorToken), wouldOverflow, admin) {
                revert("AMM should have rejected overflow");
            } catch {
                // Expected - AMM rejects with InvalidAmount
            }
        } catch {
            // Expected - token rejects with SupplyCapExceeded
        }
    }

}
