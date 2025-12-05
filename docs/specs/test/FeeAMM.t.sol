// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeAMM } from "../src/FeeAMM.sol";
import { TIP20 } from "../src/TIP20.sol";
import { IFeeAMM } from "../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "./BaseTest.t.sol";

/// @notice FeeAMM tests - post-Moderato behavior
/// Post-Moderato, two-sided mint is disabled. Only mintWithValidatorToken is available.
contract FeeAMMTest is BaseTest {

    TIP20 userToken;
    TIP20 validatorToken;

    function setUp() public override {
        super.setUp();

        // Create tokens using TIP20Factory
        userToken = TIP20(factory.createToken("User", "USR", "USD", pathUSD, admin));
        validatorToken = TIP20(factory.createToken("Validator", "VAL", "USD", pathUSD, admin));

        // Grant ISSUER_ROLE to admin so we can mint tokens
        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);

        // Fund alice with large balances
        userToken.mintWithMemo(alice, 10_000e18, bytes32(0));
        validatorToken.mintWithMemo(alice, 10_000e18, bytes32(0));

        // Approve FeeAMM to spend tokens
        vm.startPrank(alice);
        userToken.approve(address(amm), type(uint256).max);
        validatorToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    TWO-SIDED MINT DISABLED (POST-MODERATO)
    //////////////////////////////////////////////////////////////*/

    /// @notice Two-sided mint is disabled post-Moderato.
    /// The precompile returns UnknownFunctionSelector, we revert with MintDisabled.
    function test_Mint_RevertsWithMintDisabled() public {
        vm.prank(alice);
        try amm.mint(address(userToken), address(validatorToken), 1e18, 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            // In local foundry, we get MintDisabled
            // In tempo precompile, we get UnknownFunctionSelector(0xfa28d692)
            // Both indicate the function is disabled
            bytes4 errorSelector = bytes4(err);
            assertTrue(
                errorSelector == IFeeAMM.MintDisabled.selector
                    || errorSelector == bytes4(0xaa4bc69a), // UnknownFunctionSelector
                "Expected MintDisabled or UnknownFunctionSelector"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                        MINT WITH VALIDATOR TOKEN
    //////////////////////////////////////////////////////////////*/

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
        uint256 minLiq = amm.MIN_LIQUIDITY();
        uint256 amountV = 2 * minLiq; // amountV/2 == MIN_LIQUIDITY -> should revert

        vm.prank(alice);
        try amm.mintWithValidatorToken(
            address(userToken), address(validatorToken), amountV, alice
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory reason) {
            bytes4 errorSelector = bytes4(reason);
            assertTrue(
                errorSelector == IFeeAMM.InsufficientLiquidity.selector, "Wrong error thrown"
            );
        }
    }

    function test_MintWithValidatorToken_SubsequentDeposit() public {
        // First, initialize pool with validator token only
        uint256 initialAmount = 5000e18; // Use half so we have tokens left for subsequent deposit

        vm.prank(alice);
        amm.mintWithValidatorToken(
            address(userToken), address(validatorToken), initialAmount, alice
        );

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        uint256 supplyBefore = amm.totalSupply(poolId);
        uint256 aliceBalanceBefore = amm.liquidityBalances(poolId, alice);

        // Subsequent deposit
        uint256 additionalAmount = 1000e18;

        vm.prank(alice);
        uint256 liquidity = amm.mintWithValidatorToken(
            address(userToken), address(validatorToken), additionalAmount, alice
        );

        assertGt(liquidity, 0);
        assertEq(amm.totalSupply(poolId), supplyBefore + liquidity);
        assertEq(amm.liquidityBalances(poolId, alice), aliceBalanceBefore + liquidity);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _reserves(bytes32 poolId) internal view returns (uint128, uint128) {
        (uint128 ru, uint128 rv) = amm.pools(poolId);
        return (ru, rv);
    }

}
