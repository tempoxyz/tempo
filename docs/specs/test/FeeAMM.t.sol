// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeAMM } from "../src/FeeAMM.sol";
import { TIP20 } from "../src/TIP20.sol";
import { IFeeAMM } from "../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "./BaseTest.t.sol";
import { StdStorage, stdStorage } from "forge-std/Test.sol";

/// @notice FeeAMM tests - post-Moderato behavior
/// Post-Moderato, two-sided mint is disabled. Only mintWithValidatorToken is available.
contract FeeAMMTest is BaseTest {

    using stdStorage for StdStorage;

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
        uint256 liquidity = amm.mintWithValidatorToken(
            address(userToken), address(validatorToken), amountV, alice
        );

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
        } catch (bytes memory revertData) {
            assertEq(bytes4(revertData), IFeeAMM.InsufficientLiquidity.selector);
        }
    }

    function test_MintWithValidatorToken_RevertsIf_InvalidInputs() public {
        vm.startPrank(alice);

        // IDENTICAL_ADDRESSES
        try amm.mintWithValidatorToken(address(userToken), address(userToken), 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.IdenticalAddresses.selector));
        }

        // INVALID_TOKEN - userToken
        try amm.mintWithValidatorToken(address(0x1234), address(validatorToken), 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.InvalidToken.selector));
        }

        // INVALID_TOKEN - validatorToken
        try amm.mintWithValidatorToken(address(userToken), address(0x1234), 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.InvalidToken.selector));
        }

        // ONLY_USD_TOKENS (valid TIP20 but non-USD currency)
        TIP20 eurToken = TIP20(factory.createToken("Euro", "EUR", "EUR", pathUSD, admin));

        try amm.mintWithValidatorToken(address(eurToken), address(validatorToken), 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.InvalidCurrency.selector));
        }

        vm.stopPrank();
    }

    function test_MintWithValidatorToken_RevertsIf_ZeroLiquidityOnSubsequent() public {
        // Initialize pool with large amount
        vm.prank(alice);
        amm.mintWithValidatorToken(address(userToken), address(validatorToken), 5000e18, alice);

        // Try tiny subsequent deposit that rounds to 0 liquidity
        vm.prank(alice);
        try amm.mintWithValidatorToken(address(userToken), address(validatorToken), 1, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory reason) {
            assertEq(bytes4(reason), IFeeAMM.InsufficientLiquidity.selector);
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
                                BURN
    //////////////////////////////////////////////////////////////*/

    function test_Burn_RevertsIf_InsufficientLiquidity() public {
        vm.prank(alice);
        amm.mintWithValidatorToken(address(userToken), address(validatorToken), 5000e18, alice);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        uint256 aliceLiquidity = amm.liquidityBalances(poolId, alice);

        vm.prank(alice);
        try amm.burn(address(userToken), address(validatorToken), aliceLiquidity + 1, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.InsufficientLiquidity.selector));
        }
    }

    function test_Burn_Succeeds() public {
        vm.prank(alice);
        amm.mintWithValidatorToken(address(userToken), address(validatorToken), 5000e18, alice);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        uint256 aliceLiquidity = amm.liquidityBalances(poolId, alice);
        uint256 aliceValidatorBefore = validatorToken.balanceOf(alice);

        vm.prank(alice);
        (uint256 amountU, uint256 amountV) =
            amm.burn(address(userToken), address(validatorToken), aliceLiquidity, alice);

        assertEq(amountU, 0);
        assertEq(amountV, 4_999_999_999_999_999_998_000);
        assertEq(amm.liquidityBalances(poolId, alice), 0);
        assertEq(validatorToken.balanceOf(alice), aliceValidatorBefore + amountV);
    }

    /*//////////////////////////////////////////////////////////////
                            REBALANCE SWAP
    //////////////////////////////////////////////////////////////*/

    function test_RebalanceSwap_Succeeds() public {
        vm.prank(alice);
        amm.mintWithValidatorToken(address(userToken), address(validatorToken), 5000e18, alice);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));

        uint256 reserveValidatorToken = uint256(5000e18);
        uint256 reserveUserToken = uint256(1000e18);
        // Seed userToken into pool - need to pack both reserves into single slot
        // Pool struct: reserveUserToken (uint128) | reserveValidatorToken (uint128)
        // reserveValidatorToken is 5000e18, reserveUserToken we set to 1000e18
        bytes32 slot = keccak256(abi.encode(poolId, uint256(0))); // pools mapping at slot 0
        bytes32 packedValue = bytes32((reserveValidatorToken << 128) | reserveUserToken);
        vm.store(address(amm), slot, packedValue);
        userToken.mint(address(amm), 1000e18);

        // Validate that the pool reserves are seeded correctly
        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        require(pool.reserveValidatorToken == 5000e18);
        require(pool.reserveUserToken == 1000e18);

        uint256 aliceUserBefore = userToken.balanceOf(alice);

        vm.prank(alice);
        uint256 amountIn =
            amm.rebalanceSwap(address(userToken), address(validatorToken), 100e18, alice);

        // amountIn = (100e18 * 9985) / 10000 + 1
        assertEq(amountIn, 99_850_000_000_000_000_001);
        assertEq(userToken.balanceOf(alice), aliceUserBefore + 100e18);
    }

    /*//////////////////////////////////////////////////////////////
                            GET POOL
    //////////////////////////////////////////////////////////////*/

    function test_GetPool_ReturnsPoolData() public {
        vm.prank(alice);
        amm.mintWithValidatorToken(address(userToken), address(validatorToken), 5000e18, alice);

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        assertEq(pool.reserveUserToken, 0);
        assertEq(pool.reserveValidatorToken, 5000e18);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _reserves(bytes32 poolId) internal view returns (uint128, uint128) {
        (uint128 ru, uint128 rv) = amm.pools(poolId);
        return (ru, rv);
    }

}
