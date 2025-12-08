// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../src/FeeManager.sol";
import { TIP20 } from "../src/TIP20.sol";
import { IFeeManager } from "../src/interfaces/IFeeManager.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract FeeManagerTest is BaseTest {

    TIP20 userToken;
    TIP20 validatorToken;
    TIP20 altToken;

    address validator = address(0x500);
    address user = address(0x600);

    function setUp() public override {
        super.setUp();

        // Create test tokens
        userToken = TIP20(factory.createToken("UserToken", "USR", "USD", pathUSD, admin));
        validatorToken = TIP20(factory.createToken("ValidatorToken", "VAL", "USD", pathUSD, admin));
        altToken = TIP20(factory.createToken("AltToken", "ALT", "USD", pathUSD, admin));

        vm.startPrank(admin);
        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);
        altToken.grantRole(_ISSUER_ROLE, admin);
        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(user, 10_000e18);
        pathUSD.mint(validator, 10_000e18);
        pathUSD.mint(admin, 100_000e18);
        pathUSD.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(admin);
        userToken.mint(user, 10_000e18);
        validatorToken.mint(validator, 10_000e18);
        userToken.mint(admin, 100_000e18);
        validatorToken.mint(admin, 100_000e18);

        userToken.approve(address(amm), type(uint256).max);
        validatorToken.approve(address(amm), type(uint256).max);

        // Create pools with initial liquidity
        amm.mintWithValidatorToken(address(userToken), address(validatorToken), 20_000e18, admin);
        amm.mintWithValidatorToken(address(userToken), address(pathUSD), 20_000e18, admin);
        amm.mintWithValidatorToken(address(validatorToken), address(pathUSD), 20_000e18, admin);
        vm.stopPrank();
    }

    function test_setValidatorToken() public {
        vm.prank(validator, validator);

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit IFeeManager.ValidatorTokenSet(validator, address(validatorToken));
        }

        amm.setValidatorToken(address(validatorToken));

        assertEq(amm.validatorTokens(validator), address(validatorToken));
    }

    function test_setValidatorToken_RevertsIf_CallerIsBlockProducer() public {
        vm.prank(validator, validator);
        vm.coinbase(validator);

        if (!isTempo) {
            vm.expectRevert("CANNOT_CHANGE_WITHIN_BLOCK");
        }

        try amm.setValidatorToken(address(validatorToken)) {
            if (isTempo) {
                revert CallShouldHaveReverted();
            }
        } catch {
            // Expected to revert
        }
    }

    function test_setValidatorToken_RevertsIf_InvalidToken() public {
        vm.prank(validator);
        vm.coinbase(validator);

        if (!isTempo) {
            vm.expectRevert("INVALID_TOKEN");
        }

        try amm.setValidatorToken(address(0x123)) {
            if (isTempo) {
                revert CallShouldHaveReverted();
            }
        } catch {
            // Expected to revert
        }
    }

    function test_setValidatorToken_RevertsIf_NonUSDToken() public {
        vm.prank(validator);
        vm.coinbase(validator);

        // Create a non-USD token
        TIP20 eurToken = TIP20(factory.createToken("EuroToken", "EUR", "EUR", pathUSD, admin));

        if (!isTempo) {
            vm.expectRevert("INVALID_TOKEN");
        }

        try amm.setValidatorToken(address(eurToken)) {
            if (isTempo) {
                revert CallShouldHaveReverted();
            }
        } catch {
            // Expected to revert
        }
    }

    function test_setUserToken() public {
        vm.prank(user, user);

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit IFeeManager.UserTokenSet(user, address(userToken));
        }

        amm.setUserToken(address(userToken));

        assertEq(amm.userTokens(user), address(userToken));
    }

    function test_setUserToken_RevertsIf_InvalidToken() public {
        vm.prank(user);

        if (!isTempo) {
            vm.expectRevert("INVALID_TOKEN");
        }

        try amm.setUserToken(address(0x123)) {
            if (isTempo) {
                revert CallShouldHaveReverted();
            }
        } catch {
            // Expected to revert
        }
    }

    function test_collectFeePreTx() public {
        vm.prank(validator, validator);
        amm.setValidatorToken(address(validatorToken));

        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        uint256 userBalanceBefore = userToken.balanceOf(user);
        uint256 maxAmount = 100e18;

        vm.prank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), maxAmount) {
            assertEq(userToken.balanceOf(user), userBalanceBefore - maxAmount);
        } catch (bytes memory err) {
            bytes4 errorSelector = bytes4(err);
            assertTrue(errorSelector == 0xaa4bc69a);
        }
    }

    function test_collectFeePreTx_RevertsIf_NotProtocol() public {
        vm.prank(user);

        if (!isTempo) {
            vm.expectRevert("ONLY_PROTOCOL");
        }

        try amm.collectFeePreTx(user, address(userToken), 100e18) {
            if (isTempo) {
                revert CallShouldHaveReverted();
            }
        } catch {
            // Expected to revert
        }
    }

    function test_collectFeePostTx_DifferentTokens() public {
        vm.prank(validator, validator);
        amm.setValidatorToken(address(validatorToken));

        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        uint256 maxAmount = 100e18;
        uint256 actualUsed = 80e18;

        vm.prank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), maxAmount) {
            uint256 userBalanceAfterPre = userToken.balanceOf(user);

            vm.prank(address(0));
            vm.coinbase(validator);
            amm.collectFeePostTx(user, maxAmount, actualUsed, address(userToken));

            assertEq(userToken.balanceOf(user), userBalanceAfterPre + (maxAmount - actualUsed));
        } catch (bytes memory err) {
            bytes4 errorSelector = bytes4(err);
            assertTrue(errorSelector == 0xaa4bc69a);
        }
    }

    /// @notice When userToken == validatorToken, 30 bps of the used fee should accrue to the issuer
    ///         (tracked per token in collectedFeesByToken), and the remaining ~99.7% should be paid
    ///         to the validator at end of block.
    function test_collectFeePostTx_SameToken_SplitsValidatorAndIssuer() public {
        // Validator prefers the same token the user pays with
        vm.prank(validator, validator);
        amm.setValidatorToken(address(userToken));

        // Give userToken balances and approvals
        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        uint256 maxAmount = 100e18;
        uint256 actualUsed = 80e18;

        uint256 validatorBalanceBefore = userToken.balanceOf(validator);

        vm.startPrank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), maxAmount) {
            amm.collectFeePostTx(user, maxAmount, actualUsed, address(userToken));
            // End of block settlement
            amm.executeBlock();
            vm.stopPrank();

            // Issuer fee should be 30 bps of actualUsed
            uint256 expectedIssuerCut = (actualUsed * 30) / 10_000;
            uint256 issuerFees = amm.collectedFeesByToken(address(userToken));
            assertEq(issuerFees, expectedIssuerCut);

            // Validator should receive the remainder
            uint256 validatorBalanceAfter = userToken.balanceOf(validator);
            uint256 expectedValidatorGain = actualUsed - expectedIssuerCut;
            assertEq(validatorBalanceAfter, validatorBalanceBefore + expectedValidatorGain);
        } catch (bytes memory err) {
            vm.stopPrank();
            // On Tempo, the reference FeeManager precompile may not implement this spec yet.
            // In that case, we only assert that the call failed with the unknown selector code.
            bytes4 errorSelector = bytes4(err);
            assertTrue(errorSelector == 0xaa4bc69a);
        }
    }

    /// @notice Holder of FEE_CLAIM_ROLE on a token can claim all accumulated issuer fees
    ///         for that token via claimTokenFees.
    function test_claimTokenFees_TransfersAccumulatedIssuerFees() public {
        // Validator prefers the same token the user pays with
        vm.prank(validator, validator);
        amm.setValidatorToken(address(userToken));

        // Grant FEE_CLAIM_ROLE to admin on userToken
        vm.startPrank(admin);
        userToken.grantRole(_FEE_CLAIM_ROLE, admin);
        vm.stopPrank();

        // User pays fees in userToken
        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        uint256 maxAmount = 100e18;
        uint256 actualUsed = 80e18;

        vm.startPrank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), maxAmount) {
            amm.collectFeePostTx(user, maxAmount, actualUsed, address(userToken));
            amm.executeBlock();
            vm.stopPrank();
        } catch (bytes memory err) {
            vm.stopPrank();
            bytes4 errorSelector = bytes4(err);
            assertTrue(errorSelector == 0xaa4bc69a);
            return;
        }

        uint256 issuerFees = amm.collectedFeesByToken(address(userToken));
        assertGt(issuerFees, 0);

        uint256 adminBalanceBefore = userToken.balanceOf(admin);

        // Claim the accumulated issuer fees to admin
        vm.startPrank(admin);
        amm.claimTokenFees(address(userToken), admin);
        vm.stopPrank();

        assertEq(amm.collectedFeesByToken(address(userToken)), 0);
        assertEq(userToken.balanceOf(admin), adminBalanceBefore + issuerFees);
    }

    function test_collectFeePostTx_RevertsIf_NotProtocol() public {
        vm.prank(user);

        if (!isTempo) {
            vm.expectRevert("ONLY_PROTOCOL");
        }

        try amm.collectFeePostTx(user, 100e18, 80e18, address(userToken)) {
            if (isTempo) {
                revert CallShouldHaveReverted();
            }
        } catch {
            // Expected to revert
        }
    }

    function test_executeBlock() public {
        vm.prank(validator, validator);
        amm.setValidatorToken(address(validatorToken));

        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        uint256 validatorBalanceBefore = validatorToken.balanceOf(validator);
        uint256 maxAmount = 100e18;
        uint256 actualUsed = 80e18;

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        (uint128 reservesBefore0, uint128 reservesBefore1) = amm.pools(poolId);

        vm.startPrank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), maxAmount) {
            amm.collectFeePostTx(user, maxAmount, actualUsed, address(userToken));
            amm.executeBlock();
            vm.stopPrank();

            assertGt(validatorToken.balanceOf(validator), validatorBalanceBefore);

            (uint128 reservesAfter0, uint128 reservesAfter1) = amm.pools(poolId);

            assertTrue(reservesAfter0 != reservesBefore0 || reservesAfter1 != reservesBefore1);
        } catch (bytes memory err) {
            vm.stopPrank();
            bytes4 errorSelector = bytes4(err);
            assertTrue(errorSelector == 0xaa4bc69a);
        }
    }

    function test_executeBlock_RevertsIf_NotProtocol() public {
        vm.prank(user);

        if (!isTempo) {
            vm.expectRevert("ONLY_PROTOCOL");
        }

        try amm.executeBlock() {
            if (isTempo) {
                revert CallShouldHaveReverted();
            }
        } catch {
            // Expected to revert
        }
    }

    function test_defaultValidatorTokenIsPathUSD() public {
        // Validator with no preference should use PATH_USD
        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        uint256 maxAmount = 100e18;
        uint256 actualUsed = 80e18;

        vm.startPrank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), maxAmount) {
            amm.collectFeePostTx(user, maxAmount, actualUsed, address(userToken));

            uint256 pathUSDBalanceBefore = pathUSD.balanceOf(validator);
            amm.executeBlock();
            vm.stopPrank();

            assertGt(pathUSD.balanceOf(validator), pathUSDBalanceBefore);
        } catch (bytes memory err) {
            vm.stopPrank();
            bytes4 errorSelector = bytes4(err);
            assertTrue(errorSelector == 0xaa4bc69a);
        }
    }

    function test_setValidatorToken_RevertsIf_PendingFees() public {
        vm.prank(validator, validator);
        amm.setValidatorToken(address(validatorToken));

        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        vm.prank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), 100e18) {
            vm.prank(address(0));
            vm.coinbase(validator);
            amm.collectFeePostTx(user, 100e18, 80e18, address(userToken));
        } catch (bytes memory err) {
            bytes4 errorSelector = bytes4(err);
            assertTrue(errorSelector == 0xaa4bc69a);
            return;
        }

        vm.prank(validator, validator);
        vm.coinbase(validator);

        if (!isTempo) {
            vm.expectRevert("CANNOT_CHANGE_WITH_PENDING_FEES");
        }

        try amm.setValidatorToken(address(altToken)) {
            if (isTempo) {
                revert CallShouldHaveReverted();
            }
        } catch {
            // Expected to revert
        }
    }

}
