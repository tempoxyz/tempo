// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import "./TempoTest.t.sol";
import { IFeeManager } from "tempo-std/interfaces/IFeeManager.sol";
import { ITIP20, ITIP20Token } from "tempo-std/interfaces/ITIP20.sol";

contract FeeManagerTest is TempoTest {

    ITIP20Token userToken;
    ITIP20Token validatorToken;
    ITIP20Token altToken;

    address validator = address(0x500);
    address user = address(0x600);

    function setUp() public override {
        super.setUp();

        userToken = ITIP20Token(
            factory.createToken("UserToken", "USR", "USD", pathUSD, admin, bytes32("user"))
        );
        validatorToken = ITIP20Token(
            factory.createToken(
                "ValidatorToken", "VAL", "USD", pathUSD, admin, bytes32("validator")
            )
        );
        altToken = ITIP20Token(
            factory.createToken("AltToken", "ALT", "USD", pathUSD, admin, bytes32("alt"))
        );

        vm.startPrank(admin);
        userToken.grantRole(_ISSUER_ROLE, admin);
        validatorToken.grantRole(_ISSUER_ROLE, admin);
        altToken.grantRole(_ISSUER_ROLE, admin);
        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        ITIP20Token(address(pathUSD)).grantRole(_ISSUER_ROLE, pathUSDAdmin);
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

        try amm.setValidatorToken(address(validatorToken)) {
            revert CallShouldHaveReverted();
        } catch {
            // Expected to revert
        }
    }

    function test_setValidatorToken_RevertsIf_InvalidToken() public {
        vm.prank(validator);
        vm.coinbase(validator);

        try amm.setValidatorToken(address(0x123)) {
            revert CallShouldHaveReverted();
        } catch {
            // Expected to revert
        }
    }

    function test_setValidatorToken_RevertsIf_NonUSDToken() public {
        vm.prank(validator);
        vm.coinbase(validator);

        ITIP20 eurToken =
            ITIP20(factory.createToken("EuroToken", "EUR", "EUR", pathUSD, admin, bytes32("eur")));

        try amm.setValidatorToken(address(eurToken)) {
            revert CallShouldHaveReverted();
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

        try amm.setUserToken(address(0x123)) {
            revert CallShouldHaveReverted();
        } catch {
            // Expected to revert
        }
    }

}
