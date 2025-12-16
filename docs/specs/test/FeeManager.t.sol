// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {FeeManager} from "../src/FeeManager.sol";
import {TIP20} from "../src/TIP20.sol";
import {IFeeManager} from "../src/interfaces/IFeeManager.sol";
import {ITIP20} from "../src/interfaces/ITIP20.sol";
import {BaseTest} from "./BaseTest.t.sol";

contract FeeManagerTest is BaseTest {
    TIP20 userToken;
    TIP20 validatorToken;
    TIP20 altToken;

    address validator = address(0x500);
    address user = address(0x600);

    function setUp() public override {
        super.setUp();

        userToken = TIP20(
            factory.createToken("UserToken", "USR", "USD", pathUSD, admin)
        );
        validatorToken = TIP20(
            factory.createToken("ValidatorToken", "VAL", "USD", pathUSD, admin)
        );
        altToken = TIP20(
            factory.createToken("AltToken", "ALT", "USD", pathUSD, admin)
        );

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

        amm.mintWithValidatorToken(
            address(userToken),
            address(validatorToken),
            20_000e18,
            admin
        );
        amm.mintWithValidatorToken(
            address(userToken),
            address(pathUSD),
            20_000e18,
            admin
        );
        amm.mintWithValidatorToken(
            address(validatorToken),
            address(pathUSD),
            20_000e18,
            admin
        );
        vm.stopPrank();
    }

    function test_setValidatorToken() public {
        vm.prank(validator, validator);

        if (!isTempo) {
            vm.expectEmit(true, true, true, true);
            emit IFeeManager.ValidatorTokenSet(
                validator,
                address(validatorToken)
            );
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

        TIP20 eurToken = TIP20(
            factory.createToken("EuroToken", "EUR", "EUR", pathUSD, admin)
        );

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
            amm.collectFeePostTx(
                user,
                maxAmount,
                actualUsed,
                address(userToken)
            );

            assertEq(
                userToken.balanceOf(user),
                userBalanceAfterPre + (maxAmount - actualUsed)
            );
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

    function test_defaultValidatorTokenIsPathUSD() public {
        vm.startPrank(user);
        userToken.approve(address(amm), type(uint256).max);
        vm.stopPrank();

        uint256 maxAmount = 100e18;
        uint256 actualUsed = 80e18;

        vm.startPrank(address(0));
        vm.coinbase(validator);

        try amm.collectFeePreTx(user, address(userToken), maxAmount) {
            uint256 validatorBalanceBefore = amm.collectedFeesByValidator(
                validator
            );

            amm.collectFeePostTx(
                user,
                maxAmount,
                actualUsed,
                address(userToken)
            );

            uint256 validatorBalanceAfter = amm.collectedFeesByValidator(
                validator
            );
            vm.stopPrank();

            assertGt(validatorBalanceAfter, validatorBalanceBefore);
        } catch (bytes memory err) {
            vm.stopPrank();
            bytes4 errorSelector = bytes4(err);
            assertTrue(errorSelector == 0xaa4bc69a);
        }
    }
}
