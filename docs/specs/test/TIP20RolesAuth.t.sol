// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20 } from "../src/TIP20.sol";
import { TIP20Factory } from "../src/TIP20Factory.sol";
import { ITIP20RolesAuth } from "../src/interfaces/ITIP20RolesAuth.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract TIP20RolesAuthTest is BaseTest {

    TIP20 token;

    function setUp() public override {
        super.setUp();
        token = TIP20(factory.createToken("Test Token", "TST", "USD", TIP20(_PATH_USD), admin));
    }

    function test_grantRole_RevertsWhenUnauthorized() public {
        vm.prank(alice);
        try token.grantRole(_ISSUER_ROLE, bob) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
    }

    function test_revokeRole() public {
        vm.prank(admin);
        token.grantRole(_ISSUER_ROLE, bob);
        assertTrue(token.hasRole(bob, _ISSUER_ROLE));

        // Unauthorized caller fails
        vm.prank(alice);
        try token.revokeRole(_ISSUER_ROLE, bob) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
        assertTrue(token.hasRole(bob, _ISSUER_ROLE));

        // Admin succeeds
        vm.prank(admin);
        token.revokeRole(_ISSUER_ROLE, bob);
        assertFalse(token.hasRole(bob, _ISSUER_ROLE));
    }

    function test_renounceRole() public {
        vm.prank(admin);
        token.grantRole(_ISSUER_ROLE, bob);
        assertTrue(token.hasRole(bob, _ISSUER_ROLE));

        // Non-holder fails
        assertFalse(token.hasRole(alice, _ISSUER_ROLE));
        vm.prank(alice);
        try token.renounceRole(_ISSUER_ROLE) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }

        // Holder succeeds
        vm.prank(bob);
        token.renounceRole(_ISSUER_ROLE);
        assertFalse(token.hasRole(bob, _ISSUER_ROLE));
    }

    function test_setRoleAdmin() public {
        bytes32 NEW_ADMIN_ROLE = keccak256("NEW_ADMIN");

        // Unauthorized caller fails
        vm.prank(alice);
        try token.setRoleAdmin(_ISSUER_ROLE, NEW_ADMIN_ROLE) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }

        // Admin succeeds
        vm.prank(admin);
        token.setRoleAdmin(_ISSUER_ROLE, NEW_ADMIN_ROLE);

        // Old admin can no longer grant
        vm.prank(admin);
        try token.grantRole(_ISSUER_ROLE, bob) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuth.Unauthorized.selector));
        }
    }

}
