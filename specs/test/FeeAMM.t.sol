// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeAMM } from "../src/FeeAMM.sol";
import { TIP20 } from "../src/TIP20.sol";
import { IFeeAMM } from "../src/interfaces/IFeeAMM.sol";
import { BaseTest } from "./BaseTest.t.sol";
import { StdStorage, stdStorage } from "forge-std/Test.sol";

/// @notice FeeAMM tests
contract FeeAMMTest is BaseTest {

    using stdStorage for StdStorage;

    TIP20 userToken;
    TIP20 validatorToken;

    function setUp() public override {
        super.setUp();

        // Create tokens using TIP20Factory
        userToken =
            TIP20(factory.createToken("User", "USR", "USD", pathUSD, admin, bytes32("user")));
        validatorToken = TIP20(
            factory.createToken("Validator", "VAL", "USD", pathUSD, admin, bytes32("validator"))
        );

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
                        MINT (WITH VALIDATOR TOKEN)
    //////////////////////////////////////////////////////////////*/

    function test_Mint_InitialLiquidity_Succeeds() public {
        uint256 amountV = 10_000e18; // above 2*MIN_LIQUIDITY and within alice balance
        uint256 minLiq = 1000; // MIN_LIQUIDITY constant

        // Expected liquidity: amountV/2 - MIN_LIQUIDITY
        uint256 expectedLiquidity = amountV / 2 - minLiq;

        // Expect Mint event with correct args
        vm.expectEmit(true, true, true, true);
        emit IFeeAMM.Mint(
            alice, // sender
            alice, // recipient
            address(userToken), // userToken
            address(validatorToken), // validatorToken
            amountV, // amountValidatorToken
            expectedLiquidity // liquidity
        );

        vm.prank(alice);
        uint256 liquidity = amm.mint(address(userToken), address(validatorToken), amountV, alice);

        assertEq(liquidity, expectedLiquidity);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        (uint128 uRes, uint128 vRes) = _reserves(poolId);

        assertEq(uint256(uRes), 0);
        assertEq(uint256(vRes), amountV);

        assertEq(amm.totalSupply(poolId), expectedLiquidity + minLiq); // includes locked MIN_LIQUIDITY
        assertEq(amm.liquidityBalances(poolId, alice), expectedLiquidity);
    }

    function test_Mint_InitialLiquidity_RevertsIf_TooSmall() public {
        uint256 minLiq = amm.MIN_LIQUIDITY();
        uint256 amountV = 2 * minLiq; // amountV/2 == MIN_LIQUIDITY -> should revert

        vm.prank(alice);
        try amm.mint(address(userToken), address(validatorToken), amountV, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory revertData) {
            assertEq(bytes4(revertData), IFeeAMM.InsufficientLiquidity.selector);
        }
    }

    function test_Mint_RevertsIf_InvalidInputs() public {
        vm.startPrank(alice);

        // IDENTICAL_ADDRESSES
        try amm.mint(address(userToken), address(userToken), 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.IdenticalAddresses.selector));
        }

        // INVALID_TOKEN - userToken
        try amm.mint(address(0x1234), address(validatorToken), 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.InvalidToken.selector));
        }

        // INVALID_TOKEN - validatorToken
        try amm.mint(address(userToken), address(0x1234), 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.InvalidToken.selector));
        }

        // ONLY_USD_TOKENS (valid TIP20 but non-USD currency)
        TIP20 eurToken =
            TIP20(factory.createToken("Euro", "EUR", "EUR", pathUSD, admin, bytes32("eur")));

        try amm.mint(address(eurToken), address(validatorToken), 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.InvalidCurrency.selector));
        }

        try amm.mint(address(validatorToken), address(eurToken), 1e18, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IFeeAMM.InvalidCurrency.selector));
        }

        vm.stopPrank();
    }

    function test_Mint_RevertsIf_ZeroLiquidityOnSubsequent() public {
        // Initialize pool with large amount
        vm.prank(alice);
        amm.mint(address(userToken), address(validatorToken), 5000e18, alice);

        // Try tiny subsequent deposit that rounds to 0 liquidity
        vm.prank(alice);
        try amm.mint(address(userToken), address(validatorToken), 1, alice) {
            revert CallShouldHaveReverted();
        } catch (bytes memory reason) {
            assertEq(bytes4(reason), IFeeAMM.InsufficientLiquidity.selector);
        }
    }

    function test_Mint_SubsequentDeposit() public {
        // First, initialize pool with validator token only
        uint256 initialAmount = 5000e18; // Use half so we have tokens left for subsequent deposit

        vm.prank(alice);
        amm.mint(address(userToken), address(validatorToken), initialAmount, alice);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        uint256 supplyBefore = amm.totalSupply(poolId);
        uint256 aliceBalanceBefore = amm.liquidityBalances(poolId, alice);

        // Subsequent deposit
        uint256 additionalAmount = 1000e18;

        vm.prank(alice);
        uint256 liquidity =
            amm.mint(address(userToken), address(validatorToken), additionalAmount, alice);

        assertGt(liquidity, 0);
        assertEq(amm.totalSupply(poolId), supplyBefore + liquidity);
        assertEq(amm.liquidityBalances(poolId, alice), aliceBalanceBefore + liquidity);
    }

    /*//////////////////////////////////////////////////////////////
                                BURN
    //////////////////////////////////////////////////////////////*/

    function test_Burn_RevertsIf_InsufficientLiquidity() public {
        vm.prank(alice);
        amm.mint(address(userToken), address(validatorToken), 5000e18, alice);

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
        amm.mint(address(userToken), address(validatorToken), 5000e18, alice);

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
        amm.mint(address(userToken), address(validatorToken), 5000e18, alice);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));

        uint256 reserveValidatorToken = uint256(5000e18);
        uint256 reserveUserToken = uint256(1000e18);
        // Seed userToken into pool - need to pack both reserves into single slot
        // Pool struct: reserveUserToken (uint128) | reserveValidatorToken (uint128)
        // reserveValidatorToken is 5000e18, reserveUserToken we set to 1000e18
        // In TipFeeManager precompile, pools is at slot 3. In FeeAMM reference, it's at slot 0.
        uint256 poolsSlot = isTempo ? 3 : 0;
        bytes32 slot = keccak256(abi.encode(poolId, poolsSlot));
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
        amm.mint(address(userToken), address(validatorToken), 5000e18, alice);

        IFeeAMM.Pool memory pool = amm.getPool(address(userToken), address(validatorToken));

        assertEq(pool.reserveUserToken, 0);
        assertEq(pool.reserveValidatorToken, 5000e18);
    }

    function testFuzz_Mint(uint256 initialV, uint256 additionalV) public {
        uint256 minLiq = amm.MIN_LIQUIDITY();
        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // First mint
        initialV = bound(initialV, 2 * minLiq + 2, 5000e18);
        vm.prank(alice);
        uint256 liquidity1 = amm.mint(address(userToken), address(validatorToken), initialV, alice);

        assertEq(liquidity1, initialV / 2 - minLiq);
        (uint128 reserveU, uint128 reserveV) = amm.pools(poolId);
        assertEq(reserveU, 0);
        assertEq(reserveV, initialV);

        // Subsequent mint
        uint256 supplyBefore = amm.totalSupply(poolId);
        additionalV = bound(additionalV, 1e15, 5000e18);

        vm.prank(alice);
        uint256 liquidity2 =
            amm.mint(address(userToken), address(validatorToken), additionalV, alice);

        uint256 denom = uint256(reserveV) + (amm.N() * uint256(reserveU)) / amm.SCALE();
        assertEq(liquidity2, (additionalV * supplyBefore) / denom);

        (uint128 reserveUAfter, uint128 reserveVAfter) = amm.pools(poolId);
        assertEq(reserveUAfter, reserveU);
        assertEq(reserveVAfter, reserveV + uint128(additionalV));
    }

    function testFuzz_Burn(uint256 mintAmount, uint256 burnFraction) public {
        uint256 minLiq = amm.MIN_LIQUIDITY();

        mintAmount = bound(mintAmount, 2 * minLiq + 2, 10_000e18);
        vm.prank(alice);
        uint256 liquidity = amm.mint(address(userToken), address(validatorToken), mintAmount, alice);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        (uint128 reserveUBefore, uint128 reserveVBefore) = amm.pools(poolId);
        uint256 totalSupply = amm.totalSupply(poolId);

        burnFraction = bound(burnFraction, 1, 100);
        uint256 burnAmount = (liquidity * burnFraction) / 100;
        if (burnAmount == 0) burnAmount = 1;

        vm.prank(alice);
        (uint256 amountU, uint256 amountV) =
            amm.burn(address(userToken), address(validatorToken), burnAmount, alice);

        (uint128 reserveUAfter, uint128 reserveVAfter) = amm.pools(poolId);

        // Pro-rata invariant
        uint256 expectedU = (burnAmount * uint256(reserveUBefore)) / totalSupply;
        uint256 expectedV = (burnAmount * uint256(reserveVBefore)) / totalSupply;
        assertEq(amountU, expectedU);
        assertEq(amountV, expectedV);

        // Reserve conservation
        assertEq(uint256(reserveUAfter), uint256(reserveUBefore) - amountU);
        assertEq(uint256(reserveVAfter), uint256(reserveVBefore) - amountV);
    }

    function testFuzz_Solvency(uint256 mintAmount, uint256 burnFraction) public {
        uint256 minLiq = amm.MIN_LIQUIDITY();
        mintAmount = bound(mintAmount, 2 * minLiq + 2, 10_000e18);

        vm.prank(alice);
        uint256 liquidity = amm.mint(address(userToken), address(validatorToken), mintAmount, alice);

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));

        // Check solvency after mint
        (uint128 reserveU, uint128 reserveV) = amm.pools(poolId);
        assertGe(userToken.balanceOf(address(amm)), uint256(reserveU));
        assertGe(validatorToken.balanceOf(address(amm)), uint256(reserveV));

        // Burn some and check solvency again
        burnFraction = bound(burnFraction, 1, 100);
        uint256 burnAmount = (liquidity * burnFraction) / 100;
        if (burnAmount == 0) burnAmount = 1;

        vm.prank(alice);
        amm.burn(address(userToken), address(validatorToken), burnAmount, alice);

        (reserveU, reserveV) = amm.pools(poolId);
        assertGe(userToken.balanceOf(address(amm)), uint256(reserveU));
        assertGe(validatorToken.balanceOf(address(amm)), uint256(reserveV));
    }

    function testFuzz_RebalanceSwap(uint256 amountOut) public {
        vm.prank(alice);
        amm.mint(address(userToken), address(validatorToken), 5000e18, alice);

        // Seed userToken reserve so rebalance has tokens to give out
        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        uint256 poolsSlot = isTempo ? 3 : 0;
        bytes32 slot = keccak256(abi.encode(poolId, poolsSlot));
        bytes32 packedValue = bytes32((uint256(5000e18) << 128) | uint256(5000e18));
        vm.store(address(amm), slot, packedValue);
        userToken.mint(address(amm), 5000e18);

        (uint128 reserveUBefore, uint128 reserveVBefore) = amm.pools(poolId);

        amountOut = bound(amountOut, 1, 4000e18);

        vm.prank(alice);
        uint256 amountIn =
            amm.rebalanceSwap(address(userToken), address(validatorToken), amountOut, alice);

        (uint128 reserveUAfter, uint128 reserveVAfter) = amm.pools(poolId);

        // Rate invariant: amountIn = ceil(amountOut * N / SCALE)
        uint256 expectedAmountIn = (amountOut * amm.N()) / amm.SCALE() + 1;
        assertEq(amountIn, expectedAmountIn);

        // Reserve conservation: reserveV increases by amountIn, reserveU decreases by amountOut
        assertEq(uint256(reserveVAfter), uint256(reserveVBefore) + amountIn);
        assertEq(uint256(reserveUAfter), uint256(reserveUBefore) - amountOut);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _reserves(bytes32 poolId) internal view returns (uint128, uint128) {
        (uint128 ru, uint128 rv) = amm.pools(poolId);
        return (ru, rv);
    }

}
