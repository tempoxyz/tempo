// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeAMM } from "../src/FeeAMM.sol";
import { TIP20 } from "../src/TIP20.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract FeeAMMTest is BaseTest {

    TIP20 userToken;
    TIP20 validatorToken;

    function setUp() public override {
        super.setUp();

        // Create tokens using TIP20Factory
        userToken = TIP20(factory.createToken("User", "USR", "USD", linkingUSD, admin));
        validatorToken = TIP20(factory.createToken("Validator", "VAL", "USD", linkingUSD, admin));

        // Grant ISSUER_ROLE to admin so we can mint tokens
        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);

        // Fund alice with large balances
        userToken.mintWithMemo(alice, 10_000e18, bytes32(0));
        validatorToken.mintWithMemo(alice, 10_000e18, bytes32(0));
    }

    function test_MintWithValidatorToken_InitialLiquidity_Succeeds() public {
        uint256 amountV = 10_000e18; // above 2*MIN_LIQUIDITY and within alice balance

        uint256 minLiq = 1000; // MIN_LIQUIDITY constant

        vm.prank(alice);
        uint256 liquidity =
            amm.mintWithValidatorToken(address(userToken), address(validatorToken), amountV, alice);

        // Expected liquidity: amountV/2 - MIN_LIQUIDITY
        uint256 expected = amountV / 2 - minLiq;
        assertEq(liquidity, expected);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        (uint128 uRes, uint128 vRes) = _reserves(poolId);

        assertEq(uint256(uRes), 0);
        assertEq(uint256(vRes), amountV);

        assertEq(amm.totalSupply(poolId), expected + minLiq); // includes locked MIN_LIQUIDITY
        assertEq(amm.liquidityBalances(poolId, alice), expected);
    }

    function test_MintWithValidatorToken_InitialLiquidity_RevertsIf_TooSmall() public {
        uint256 minLiq = amm.MIN_LIQUIDITY(); // MIN_LIQUIDITY constant
        uint256 amountV = 2 * minLiq; // amountV/2 == MIN_LIQUIDITY -> should revert

        vm.prank(alice);
        try amm.mintWithValidatorToken(
            address(userToken), address(validatorToken), amountV, alice
        ) {
            revert("Expected revert but call succeeded");
        } catch (bytes memory reason) {
            // Verify it's either InsufficientLiquidity custom error (0xbb55fd27) or Error(string) (0x08c379a0)
            bytes4 errorSelector = bytes4(reason);
            assertTrue(errorSelector == bytes4(0xbb55fd27), "Wrong error thrown");
        }
    }

    function test_MintWithValidatorToken_SubsequentDeposit_ProportionalShares() public {
        // Initialize pool with equal reserves via two-sided mint
        uint256 U0 = 1e18;
        uint256 V0 = 1e18;

        vm.prank(alice);
        amm.mint(address(userToken), address(validatorToken), U0, V0, alice);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        uint256 s = amm.totalSupply(poolId);

        // Subsequent single-sided validator deposit
        uint256 vin = 1e18;

        vm.prank(alice);
        uint256 minted =
            amm.mintWithValidatorToken(address(userToken), address(validatorToken), vin, alice);

        // Compute expected: floor(s * vin / (V + n*U)), n=N/SCALE
        (uint128 uRes, uint128 vRes) = _reserves(poolId);
        // uRes,vRes now include the latest deposit; compute from previous state
        // Previous reserves were U0,V0. For expected minted we must use prior reserves.
        uint256 denom = uint256(V0) + (9985 * uint256(U0)) / 10_000; // N=9985, SCALE=10000
        uint256 expected = (vin * s) / denom;

        assertEq(minted, expected);

        // Reserves should increase only on validator side by vin
        assertEq(uint256(uRes), U0);
        assertEq(uint256(vRes), V0 + vin);

        // Supply and balances updated
        assertEq(amm.totalSupply(poolId), s + expected);
        assertEq(amm.liquidityBalances(poolId, alice), s - 1000 + expected); // 1000 is MIN_LIQUIDITY
    }

    function test_MintWithValidatorToken_RoundsDown() public {
        // Initialize with skewed reserves to create fractional outcome
        uint256 U0 = 123_456_789_012_345_678; // 0.123456789e18
        uint256 V0 = 987_654_321_098_765_432; // 0.987654321e18

        vm.prank(alice);
        amm.mint(address(userToken), address(validatorToken), U0, V0, alice);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        uint256 s = amm.totalSupply(poolId);

        uint256 vin = 55_555_555_555_555_555; // arbitrary

        // Expected using prior reserves
        uint256 denom = uint256(V0) + (9985 * uint256(U0)) / 10_000; // N=9985, SCALE=10000
        uint256 expected = (vin * s) / denom; // integer division floors

        vm.prank(alice);
        uint256 minted =
            amm.mintWithValidatorToken(address(userToken), address(validatorToken), vin, alice);

        assertEq(minted, expected);
    }

    function _reserves(bytes32 poolId) internal view returns (uint128, uint128) {
        (uint128 ru, uint128 rv) = amm.pools(poolId);
        return (ru, rv);
    }

}
