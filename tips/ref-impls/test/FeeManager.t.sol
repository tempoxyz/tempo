// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { FeeManager } from "../src/FeeManager.sol";
import { TIP20 } from "../src/TIP20.sol";
import { IFeeManager } from "../src/interfaces/IFeeManager.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract FeeManagerTest is BaseTest {

    TIP20 userToken;
    TIP20 validatorToken;
    TIP20 altToken;

    address validator = address(0x500);
    address user = address(0x600);

    function setUp() public override {
        super.setUp();

        userToken =
            TIP20(factory.createToken("UserToken", "USR", "USD", pathUSD, admin, bytes32("user")));
        validatorToken = TIP20(
            factory.createToken(
                "ValidatorToken", "VAL", "USD", pathUSD, admin, bytes32("validator")
            )
        );
        altToken =
            TIP20(factory.createToken("AltToken", "ALT", "USD", pathUSD, admin, bytes32("alt")));

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
        validatorToken.mint(address(amm), 100_000e18);

        userToken.approve(address(amm), type(uint256).max);
        validatorToken.approve(address(amm), type(uint256).max);

        amm.mint(address(userToken), address(validatorToken), 20_000e18, admin);
        amm.mint(address(userToken), address(pathUSD), 20_000e18, admin);
        amm.mint(address(validatorToken), address(pathUSD), 20_000e18, admin);
        vm.stopPrank();
    }

    function test_setValidatorToken() public {
        vm.prank(validator, validator);

        vm.expectEmit(true, true, true, true);
        emit IFeeManager.ValidatorTokenSet(validator, address(validatorToken));

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

        TIP20 eurToken =
            TIP20(factory.createToken("EuroToken", "EUR", "EUR", pathUSD, admin, bytes32("eur")));

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

        vm.expectEmit(true, true, true, true);
        emit IFeeManager.UserTokenSet(user, address(userToken));

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

    function test_collectFeePreTx_RevertsIf_InsufficientLiquidity() public {
        vm.prank(validator, validator);
        amm.setValidatorToken(address(altToken));

        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        vm.prank(address(0));
        vm.coinbase(validator);

        if (!isTempo) {
            vm.expectRevert("INSUFFICIENT_LIQUIDITY_FOR_FEE_SWAP");
        }

        try amm.collectFeePreTx(user, address(userToken), 100e18) {
            if (isTempo) {
                revert CallShouldHaveReverted();
            }
        } catch {
            // Expected to revert
        }
    }

    function test_collectFeePreTx_RevertsIf_FeePayerNotAuthorizedSender() public {
        // Blacklist user as sender on the fee token.
        address[] memory accounts = new address[](1);
        accounts[0] = user;
        uint64 policyId = registry.createPolicyWithAccounts(
            admin, ITIP403Registry.PolicyType.BLACKLIST, accounts
        );

        vm.prank(admin);
        userToken.changeTransferPolicyId(policyId);

        vm.prank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }
    }

    function test_collectFeePreTx_RevertsIf_FeeManagerNotAuthorizedRecipient() public {
        // Whitelist user but not FeeManager as recipient on the fee token.
        address[] memory accounts = new address[](1);
        accounts[0] = user;
        uint64 policyId = registry.createPolicyWithAccounts(
            admin, ITIP403Registry.PolicyType.WHITELIST, accounts
        );

        vm.prank(admin);
        userToken.changeTransferPolicyId(policyId);

        vm.prank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
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

    function test_distributeFees() public {
        if (isTempo) return;

        vm.prank(validator, validator);
        amm.setValidatorToken(address(validatorToken));

        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        uint256 maxAmount = 100e18;
        uint256 actualUsed = 80e18;

        vm.startPrank(address(0));
        vm.coinbase(validator);

        amm.collectFeePreTx(user, address(userToken), maxAmount);
        amm.collectFeePostTx(user, maxAmount, actualUsed, address(userToken));
        vm.stopPrank();

        uint256 expectedFees = (actualUsed * 9970) / 10_000;
        assertEq(amm.collectedFees(validator, address(validatorToken)), expectedFees);

        uint256 validatorBalanceBefore = validatorToken.balanceOf(validator);

        vm.expectEmit(true, true, true, true);
        emit IFeeManager.FeesDistributed(validator, address(validatorToken), expectedFees);

        amm.distributeFees(validator, address(validatorToken));

        assertEq(validatorToken.balanceOf(validator), validatorBalanceBefore + expectedFees);
        assertEq(amm.collectedFees(validator, address(validatorToken)), 0);
    }

    function test_distributeFees_ZeroBalance() public {
        if (isTempo) return;

        vm.prank(validator, validator);
        amm.setValidatorToken(address(validatorToken));

        uint256 validatorBalanceBefore = validatorToken.balanceOf(validator);

        amm.distributeFees(validator, address(validatorToken));

        assertEq(validatorToken.balanceOf(validator), validatorBalanceBefore);
        assertEq(amm.collectedFees(validator, address(validatorToken)), 0);
    }

    function test_collectedFees() public {
        if (isTempo) return;

        vm.prank(validator, validator);
        amm.setValidatorToken(address(userToken));

        assertEq(amm.collectedFees(validator, address(validatorToken)), 0);

        uint256 maxAmount = 100e18;

        vm.startPrank(address(0));
        vm.coinbase(validator);
        amm.collectFeePreTx(user, address(userToken), maxAmount);
        amm.collectFeePostTx(user, maxAmount, maxAmount, address(userToken));
        vm.stopPrank();

        assertEq(amm.collectedFees(validator, address(userToken)), maxAmount);
    }

    function test_defaultValidatorTokenIsPathUSD() public {
        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        uint256 maxAmount = 100e18;
        uint256 actualUsed = 80e18;

        vm.startPrank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), maxAmount) {
            uint256 validatorBalanceBefore = amm.collectedFees(validator, _PATH_USD);

            amm.collectFeePostTx(user, maxAmount, actualUsed, address(userToken));

            uint256 validatorBalanceAfter = amm.collectedFees(validator, _PATH_USD);
            vm.stopPrank();

            assertGt(validatorBalanceAfter, validatorBalanceBefore);
        } catch (bytes memory err) {
            vm.stopPrank();
            bytes4 errorSelector = bytes4(err);
            assertTrue(errorSelector == 0xaa4bc69a);
        }
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_FeeSwap(uint256 actualUsed) public {
        if (isTempo) return;

        vm.prank(validator, validator);
        amm.setValidatorToken(address(validatorToken));

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        (uint128 reserveUBefore, uint128 reserveVBefore) = amm.pools(poolId);

        actualUsed = bound(actualUsed, 1e15, 1000e18);

        vm.startPrank(address(0));
        vm.coinbase(validator);
        amm.collectFeePreTx(user, address(userToken), actualUsed);
        amm.collectFeePostTx(user, actualUsed, actualUsed, address(userToken));
        vm.stopPrank();

        uint256 amountOut = (actualUsed * 9970) / 10_000;

        // Rate invariant
        assertEq(amm.collectedFees(validator, address(validatorToken)), amountOut);

        // Reserve conservation
        (uint128 reserveUAfter, uint128 reserveVAfter) = amm.pools(poolId);
        assertEq(uint256(reserveUAfter), uint256(reserveUBefore) + actualUsed);
        assertEq(uint256(reserveVAfter), uint256(reserveVBefore) - amountOut);
    }

    function testFuzz_SameToken_NoSwap(uint256 actualUsed) public {
        if (isTempo) return;

        vm.prank(validator, validator);
        amm.setValidatorToken(address(userToken));

        bytes32 poolId = amm.getPoolId(address(userToken), address(validatorToken));
        (uint128 reserveUBefore, uint128 reserveVBefore) = amm.pools(poolId);

        actualUsed = bound(actualUsed, 1e15, 1000e18);

        vm.startPrank(address(0));
        vm.coinbase(validator);
        amm.collectFeePreTx(user, address(userToken), actualUsed);
        amm.collectFeePostTx(user, actualUsed, actualUsed, address(userToken));
        vm.stopPrank();

        (uint128 reserveUAfter, uint128 reserveVAfter) = amm.pools(poolId);

        assertEq(reserveUAfter, reserveUBefore);
        assertEq(reserveVAfter, reserveVBefore);

        assertEq(amm.collectedFees(validator, address(userToken)), actualUsed);
    }

    function testFuzz_DistributeFees_ClearsBalance(uint256 actualUsed) public {
        if (isTempo) return;

        vm.prank(validator, validator);
        amm.setValidatorToken(address(validatorToken));

        actualUsed = bound(actualUsed, 1e15, 1000e18);

        vm.startPrank(address(0));
        vm.coinbase(validator);
        amm.collectFeePreTx(user, address(userToken), actualUsed);
        amm.collectFeePostTx(user, actualUsed, actualUsed, address(userToken));
        vm.stopPrank();

        uint256 collectedBefore = amm.collectedFees(validator, address(validatorToken));
        assertGt(collectedBefore, 0);

        uint256 validatorBalanceBefore = validatorToken.balanceOf(validator);

        amm.distributeFees(validator, address(validatorToken));

        assertEq(amm.collectedFees(validator, address(validatorToken)), 0);

        assertEq(validatorToken.balanceOf(validator), validatorBalanceBefore + collectedBefore);
    }

    function testFuzz_Refund_Calculation(uint256 maxAmount, uint256 actualUsed) public {
        if (isTempo) return;

        vm.prank(validator, validator);
        amm.setValidatorToken(address(validatorToken));

        maxAmount = bound(maxAmount, 1e15, 1000e18);
        actualUsed = bound(actualUsed, 0, maxAmount);

        uint256 userBalanceBefore = userToken.balanceOf(user);

        vm.startPrank(address(0));
        vm.coinbase(validator);
        amm.collectFeePreTx(user, address(userToken), maxAmount);

        uint256 userBalanceAfterPre = userToken.balanceOf(user);
        assertEq(userBalanceAfterPre, userBalanceBefore - maxAmount);

        amm.collectFeePostTx(user, maxAmount, actualUsed, address(userToken));
        vm.stopPrank();

        uint256 userBalanceAfterPost = userToken.balanceOf(user);
        uint256 refund = maxAmount - actualUsed;

        assertEq(userBalanceAfterPost, userBalanceAfterPre + refund);
    }

}
