// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP403Registry } from "../src/TIP403Registry.sol";
import { ITIP403Registry } from "../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract TIP403RegistryTest is BaseTest {

    address public david = address(0x500);
    address public eve = address(0x600);

    uint64 public constant ALWAYS_REJECT_POLICY = 0;
    uint64 public constant ALWAYS_ALLOW_POLICY = 1;
    uint64 public constant FIRST_USER_POLICY = 2;

    /*//////////////////////////////////////////////////////////////
                           POLICY CREATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CreatePolicy_Basic() public {
        address admin = alice;
        TIP403Registry.PolicyType policyType = ITIP403Registry.PolicyType.WHITELIST;

        uint64 newPolicyId = registry.createPolicy(admin, policyType);

        assertEq(newPolicyId, FIRST_USER_POLICY);
        assertEq(registry.policyIdCounter(), FIRST_USER_POLICY + 1);

        (TIP403Registry.PolicyType storedType, address storedAdmin) =
            registry.policyData(newPolicyId);
        assertEq(uint8(storedType), uint8(policyType));
        assertEq(storedAdmin, admin);
    }

    function test_CreatePolicy_WithInitialAccounts_Whitelist() public {
        address admin = alice;
        TIP403Registry.PolicyType policyType = ITIP403Registry.PolicyType.WHITELIST;
        address[] memory accounts = new address[](2);
        accounts[0] = alice;
        accounts[1] = bob;

        uint64 newPolicyId = registry.createPolicyWithAccounts(admin, policyType, accounts);

        assertEq(newPolicyId, FIRST_USER_POLICY);
        assertEq(registry.policyIdCounter(), FIRST_USER_POLICY + 1);

        // Check that accounts are whitelisted
        assertTrue(registry.isAuthorized(newPolicyId, alice));
        assertTrue(registry.isAuthorized(newPolicyId, bob));
        assertFalse(registry.isAuthorized(newPolicyId, charlie)); // Not in
        // initial set
    }

    function test_CreatePolicy_WithInitialAccounts_Blacklist() public {
        address admin = alice;
        TIP403Registry.PolicyType policyType = ITIP403Registry.PolicyType.BLACKLIST;
        address[] memory accounts = new address[](2);
        accounts[0] = alice;
        accounts[1] = bob;

        uint64 newPolicyId = registry.createPolicyWithAccounts(admin, policyType, accounts);

        assertEq(newPolicyId, FIRST_USER_POLICY);
        assertEq(registry.policyIdCounter(), FIRST_USER_POLICY + 1);

        // Check that accounts are blacklisted
        assertFalse(registry.isAuthorized(newPolicyId, alice));
        assertFalse(registry.isAuthorized(newPolicyId, bob));
        assertTrue(registry.isAuthorized(newPolicyId, charlie)); // Not in
        // initial set
    }

    function test_CreatePolicy_WithAdmin() public {
        TIP403Registry.PolicyType policyType = ITIP403Registry.PolicyType.WHITELIST;
        address[] memory accounts = new address[](1);
        accounts[0] = alice;

        uint64 newPolicyId = registry.createPolicyWithAccounts(bob, policyType, accounts);

        // Check that the policy admin is bob
        (, address storedAdmin) = registry.policyData(newPolicyId);
        assertEq(storedAdmin, bob);
    }

    function test_CreatePolicy_FixedPolicy() public {
        TIP403Registry.PolicyType policyType = ITIP403Registry.PolicyType.WHITELIST;

        uint64 newPolicyId = registry.createPolicy(address(0), policyType);

        (, address storedAdmin) = registry.policyData(newPolicyId);
        assertEq(storedAdmin, address(0)); // Fixed policy
    }

    /*//////////////////////////////////////////////////////////////
                           POLICY ADMINISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetPolicyAdmin_Success() public {
        // Create a policy with alice as admin
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        // Alice can update since she is the admin
        vm.prank(alice);
        registry.setPolicyAdmin(policyId, bob);

        (, address storedAdmin) = registry.policyData(policyId);
        assertEq(storedAdmin, bob);
    }

    function test_SetPolicyAdmin_VerifyAdminAddress() public {
        // Create a policy with alice as admin
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        // Set admin to a specific address and verify it's actually set
        address newAdmin = charlie;
        vm.prank(alice);
        registry.setPolicyAdmin(policyId, newAdmin);

        (, address storedAdmin) = registry.policyData(policyId);
        assertEq(storedAdmin, newAdmin, "Admin address should be set to the provided value");
    }

    function test_SetPolicyAdmin_Unauthorized() public {
        // Create a policy with alice as admin
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        // Bob should not be able to change admin since he is not the admin
        vm.prank(bob);
        try registry.setPolicyAdmin(policyId, charlie) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }
    }

    function test_SetPolicyAdmin_OnlyAdminCanChange() public {
        // Create a whitelist policy with alice and bob
        address[] memory accounts = new address[](2);
        accounts[0] = alice;
        accounts[1] = bob;

        // Create policy with charlie as admin
        uint64 policyId = registry.createPolicyWithAccounts(
            charlie, ITIP403Registry.PolicyType.WHITELIST, accounts
        );

        // Charlie should be able to change the admin
        vm.prank(charlie);
        registry.setPolicyAdmin(policyId, alice);

        // Now alice should be able to change the admin
        vm.prank(alice);
        registry.setPolicyAdmin(policyId, bob);

        // Charlie should NOT be able to admin anymore
        vm.prank(charlie);
        try registry.setPolicyAdmin(policyId, david) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }
    }

    function testFuzz_SetPolicyAdmin_FixedPolicyCannotChange(address caller, address newAdmin)
        public
    {
        // Create a fixed policy (admin is address(0))
        uint64 policyId = registry.createPolicy(address(0), ITIP403Registry.PolicyType.WHITELIST);

        // No address other than address(0) should be able to change the admin of a fixed policy
        vm.assume(caller != address(0));
        vm.prank(caller);
        try registry.setPolicyAdmin(policyId, newAdmin) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                           WHITELIST OPERATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ModifyPolicyWhitelist_AddToWhitelist() public {
        uint64 policyId = registry.createPolicy(bob, ITIP403Registry.PolicyType.WHITELIST);

        // Initially, alice should not be authorized (not whitelisted)
        assertFalse(registry.isAuthorized(policyId, alice));

        // Bob (admin) adds alice to whitelist
        vm.prank(bob);
        registry.modifyPolicyWhitelist(policyId, alice, true);

        // Now alice should be authorized
        assertTrue(registry.isAuthorized(policyId, alice));
    }

    function test_ModifyPolicyWhitelist_RemoveFromWhitelist() public {
        address[] memory accounts = new address[](1);
        accounts[0] = alice;
        uint64 policyId =
            registry.createPolicyWithAccounts(bob, ITIP403Registry.PolicyType.WHITELIST, accounts);

        // Initially, alice should be authorized (whitelisted)
        assertTrue(registry.isAuthorized(policyId, alice));

        // Bob (admin) removes alice from whitelist
        vm.prank(bob);
        registry.modifyPolicyWhitelist(policyId, alice, false);

        // Now alice should not be authorized
        assertFalse(registry.isAuthorized(policyId, alice));
    }

    function test_ModifyPolicyWhitelist_Unauthorized() public {
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        // Bob cannot modify since he is not the admin
        vm.prank(bob);
        try registry.modifyPolicyWhitelist(policyId, charlie, true) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }
    }

    function test_ModifyPolicyWhitelist_IncompatiblePolicyType() public {
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.BLACKLIST);

        vm.prank(alice);
        try registry.modifyPolicyWhitelist(policyId, bob, true) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.IncompatiblePolicyType.selector));
        }
    }

    function test_ModifyPolicyWhitelist_PolicyDoesNotExist() public {
        // For non-existent policies, isAuthorized returns false (default blacklist behavior)
        // So modifyPolicyWhitelist will fail with Unauthorized
        try registry.modifyPolicyWhitelist(999, alice, true) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                           BLACKLIST OPERATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ModifyPolicyBlacklist_AddToBlacklist() public {
        uint64 policyId = registry.createPolicy(bob, ITIP403Registry.PolicyType.BLACKLIST);

        // Initially, alice should be authorized (not blacklisted)
        assertTrue(registry.isAuthorized(policyId, alice));

        // Bob (admin) adds alice to blacklist
        vm.prank(bob);
        registry.modifyPolicyBlacklist(policyId, alice, true);

        // Now alice should not be authorized
        assertFalse(registry.isAuthorized(policyId, alice));
    }

    function test_ModifyPolicyBlacklist_RemoveFromBlacklist() public {
        address[] memory accounts = new address[](1);
        accounts[0] = alice;
        uint64 policyId =
            registry.createPolicyWithAccounts(bob, ITIP403Registry.PolicyType.BLACKLIST, accounts);

        // Initially, alice should not be authorized (blacklisted)
        assertFalse(registry.isAuthorized(policyId, alice));

        // Bob (admin) removes alice from blacklist
        vm.prank(bob);
        registry.modifyPolicyBlacklist(policyId, alice, false);

        // Now alice should be authorized
        assertTrue(registry.isAuthorized(policyId, alice));
    }

    function test_ModifyPolicyBlacklist_Unauthorized() public {
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.BLACKLIST);

        // Bob cannot modify since he is not the admin
        vm.prank(bob);
        try registry.modifyPolicyBlacklist(policyId, charlie, true) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }
    }

    function test_ModifyPolicyBlacklist_IncompatiblePolicyType() public {
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        vm.prank(alice);
        try registry.modifyPolicyBlacklist(policyId, bob, true) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.IncompatiblePolicyType.selector));
        }
    }

    function test_ModifyPolicyBlacklist_PolicyDoesNotExist() public {
        // For non-existent policies, admin is address(0)
        // So modifyPolicyBlacklist will fail with Unauthorized
        vm.prank(alice);
        try registry.modifyPolicyBlacklist(999, alice, true) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                           BATCH OPERATION TESTS (REMOVED - NOT IMPLEMENTED)
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                           AUTHORIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_IsAuthorized_AlwaysRejectPolicy() public view {
        assertFalse(registry.isAuthorized(ALWAYS_REJECT_POLICY, alice));
        assertFalse(registry.isAuthorized(ALWAYS_REJECT_POLICY, bob));
        assertFalse(registry.isAuthorized(ALWAYS_REJECT_POLICY, address(0)));
    }

    function test_IsAuthorized_AlwaysAllowPolicy() public view {
        assertTrue(registry.isAuthorized(ALWAYS_ALLOW_POLICY, alice));
        assertTrue(registry.isAuthorized(ALWAYS_ALLOW_POLICY, bob));
        assertTrue(registry.isAuthorized(ALWAYS_ALLOW_POLICY, address(0)));
    }

    function test_IsAuthorized_WhitelistPolicy() public {
        uint64 policyId = registry.createPolicy(david, ITIP403Registry.PolicyType.WHITELIST);

        // Initially, all addresses should not be authorized (not whitelisted)
        assertFalse(registry.isAuthorized(policyId, alice));
        assertFalse(registry.isAuthorized(policyId, bob));
        assertFalse(registry.isAuthorized(policyId, charlie));

        // David (admin) adds alice to whitelist
        vm.prank(david);
        registry.modifyPolicyWhitelist(policyId, alice, true);

        // Now alice should be authorized, others should not be
        assertTrue(registry.isAuthorized(policyId, alice));
        assertFalse(registry.isAuthorized(policyId, bob));
        assertFalse(registry.isAuthorized(policyId, charlie));
    }

    function test_IsAuthorized_BlacklistPolicy() public {
        uint64 policyId = registry.createPolicy(david, ITIP403Registry.PolicyType.BLACKLIST);

        // Initially, all addresses should be authorized (not blacklisted)
        assertTrue(registry.isAuthorized(policyId, alice));
        assertTrue(registry.isAuthorized(policyId, bob));
        assertTrue(registry.isAuthorized(policyId, charlie));

        // David (admin) adds alice to blacklist
        vm.prank(david);
        registry.modifyPolicyBlacklist(policyId, alice, true);

        // Now alice should not be authorized, others should still be
        assertFalse(registry.isAuthorized(policyId, alice));
        assertTrue(registry.isAuthorized(policyId, bob));
        assertTrue(registry.isAuthorized(policyId, charlie));
    }

    function test_IsAuthorized_ComplexWhitelistScenario() public {
        address[] memory initialAccounts = new address[](2);
        initialAccounts[0] = alice;
        initialAccounts[1] = bob;

        uint64 policyId = registry.createPolicyWithAccounts(
            david, ITIP403Registry.PolicyType.WHITELIST, initialAccounts
        );

        // Alice and bob should be whitelisted initially
        assertTrue(registry.isAuthorized(policyId, alice));
        assertTrue(registry.isAuthorized(policyId, bob));
        assertFalse(registry.isAuthorized(policyId, charlie));

        // David (admin) removes alice from whitelist
        vm.prank(david);
        registry.modifyPolicyWhitelist(policyId, alice, false);

        // Now alice should not be authorized, bob still whitelisted
        assertFalse(registry.isAuthorized(policyId, alice));
        assertTrue(registry.isAuthorized(policyId, bob));
        assertFalse(registry.isAuthorized(policyId, charlie));

        // David (admin) adds charlie to whitelist
        vm.prank(david);
        registry.modifyPolicyWhitelist(policyId, charlie, true);

        // Now charlie should be whitelisted too
        assertFalse(registry.isAuthorized(policyId, alice));
        assertTrue(registry.isAuthorized(policyId, bob));
        assertTrue(registry.isAuthorized(policyId, charlie));
    }

    function test_IsAuthorized_ComplexBlacklistScenario() public {
        address[] memory initialAccounts = new address[](2);
        initialAccounts[0] = alice;
        initialAccounts[1] = bob;

        uint64 policyId = registry.createPolicyWithAccounts(
            david, ITIP403Registry.PolicyType.BLACKLIST, initialAccounts
        );

        // Alice and bob should be blacklisted initially
        assertFalse(registry.isAuthorized(policyId, alice));
        assertFalse(registry.isAuthorized(policyId, bob));
        assertTrue(registry.isAuthorized(policyId, charlie));

        // David (admin) removes alice from blacklist
        vm.prank(david);
        registry.modifyPolicyBlacklist(policyId, alice, false);

        // Now alice should be authorized, bob still blacklisted
        assertTrue(registry.isAuthorized(policyId, alice));
        assertFalse(registry.isAuthorized(policyId, bob));
        assertTrue(registry.isAuthorized(policyId, charlie));

        // David (admin) adds charlie to blacklist
        vm.prank(david);
        registry.modifyPolicyBlacklist(policyId, charlie, true);

        // Now charlie should be blacklisted too
        assertTrue(registry.isAuthorized(policyId, alice));
        assertFalse(registry.isAuthorized(policyId, bob));
        assertFalse(registry.isAuthorized(policyId, charlie));
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetPolicyAdmin() public {
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        (, address admin) = registry.policyData(policyId);
        assertEq(admin, alice);
    }

    function test_GetPolicyIdCounter() public {
        uint64 initialCount = registry.policyIdCounter();
        assertEq(initialCount, 2); // Special policies 0 and 1

        // Create a policy
        registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        uint64 newCount = registry.policyIdCounter();
        assertEq(newCount, 3);

        // Create another policy
        registry.createPolicy(bob, ITIP403Registry.PolicyType.BLACKLIST);

        uint64 finalCount = registry.policyIdCounter();
        assertEq(finalCount, 4);
    }

    function test_PolicyExists_Succeeds() public {
        // Built-in policies always exist
        assertTrue(registry.policyExists(ALWAYS_REJECT_POLICY));
        assertTrue(registry.policyExists(ALWAYS_ALLOW_POLICY));

        // Create a custom policy
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);
        assertTrue(registry.policyExists(policyId));
    }

    function testFuzz_PolicyExists_ReturnsFalseIf_PolicyDoesNotExist(uint64 policyId) public {
        vm.assume(policyId >= registry.policyIdCounter());
        assertFalse(registry.policyExists(policyId));
    }

    /*//////////////////////////////////////////////////////////////
                           EVENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Events_PolicyCreation_Basic() public {
        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyCreated(
            FIRST_USER_POLICY, address(this), ITIP403Registry.PolicyType.WHITELIST
        );

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyAdminUpdated(FIRST_USER_POLICY, address(this), alice);

        registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);
    }

    function test_Events_PolicyCreation_WithAccounts() public {
        address[] memory accounts = new address[](2);
        accounts[0] = alice;
        accounts[1] = bob;

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.WhitelistUpdated(FIRST_USER_POLICY, address(this), alice, true);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.WhitelistUpdated(FIRST_USER_POLICY, address(this), bob, true);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyCreated(
            FIRST_USER_POLICY, address(this), ITIP403Registry.PolicyType.WHITELIST
        );

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyAdminUpdated(FIRST_USER_POLICY, address(this), charlie);

        registry.createPolicyWithAccounts(charlie, ITIP403Registry.PolicyType.WHITELIST, accounts);
    }

    function test_Events_PolicyCreation_BlacklistWithAccounts() public {
        address[] memory accounts = new address[](2);
        accounts[0] = alice;
        accounts[1] = bob;

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.BlacklistUpdated(FIRST_USER_POLICY, address(this), alice, true);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.BlacklistUpdated(FIRST_USER_POLICY, address(this), bob, true);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyCreated(
            FIRST_USER_POLICY, address(this), ITIP403Registry.PolicyType.BLACKLIST
        );

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyAdminUpdated(FIRST_USER_POLICY, address(this), charlie);

        registry.createPolicyWithAccounts(charlie, ITIP403Registry.PolicyType.BLACKLIST, accounts);
    }

    function test_Events_PolicyCreation_WithAdmin() public {
        address[] memory accounts = new address[](1);
        accounts[0] = alice;

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.WhitelistUpdated(FIRST_USER_POLICY, address(this), alice, true);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyCreated(
            FIRST_USER_POLICY, address(this), ITIP403Registry.PolicyType.WHITELIST
        );

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyAdminUpdated(FIRST_USER_POLICY, address(this), bob);

        registry.createPolicyWithAccounts(bob, ITIP403Registry.PolicyType.WHITELIST, accounts);
    }

    function test_Events_WhitelistUpdate_Add() public {
        uint64 policyId = registry.createPolicy(bob, ITIP403Registry.PolicyType.WHITELIST);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.WhitelistUpdated(policyId, bob, alice, true);

        vm.prank(bob);
        registry.modifyPolicyWhitelist(policyId, alice, true);
    }

    function test_Events_WhitelistUpdate_Remove() public {
        address[] memory accounts = new address[](1);
        accounts[0] = alice;
        uint64 policyId =
            registry.createPolicyWithAccounts(bob, ITIP403Registry.PolicyType.WHITELIST, accounts);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.WhitelistUpdated(policyId, bob, alice, false);

        vm.prank(bob);
        registry.modifyPolicyWhitelist(policyId, alice, false);
    }

    function test_Events_BlacklistUpdate_Add() public {
        uint64 policyId = registry.createPolicy(bob, ITIP403Registry.PolicyType.BLACKLIST);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.BlacklistUpdated(policyId, bob, alice, true);

        vm.prank(bob);
        registry.modifyPolicyBlacklist(policyId, alice, true);
    }

    function test_Events_BlacklistUpdate_Remove() public {
        address[] memory accounts = new address[](1);
        accounts[0] = alice;
        uint64 policyId =
            registry.createPolicyWithAccounts(bob, ITIP403Registry.PolicyType.BLACKLIST, accounts);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.BlacklistUpdated(policyId, bob, alice, false);

        vm.prank(bob);
        registry.modifyPolicyBlacklist(policyId, alice, false);
    }

    function test_Events_PolicyAdminUpdate() public {
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyAdminUpdated(policyId, alice, bob);

        vm.prank(alice);
        registry.setPolicyAdmin(policyId, bob);
    }

    function test_Events_PolicyAdminUpdate_Complex() public {
        // Create a policy with alice as admin
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        // Alice changes admin to bob
        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyAdminUpdated(policyId, alice, bob);

        vm.prank(alice);
        registry.setPolicyAdmin(policyId, bob);

        // Now bob changes admin to charlie
        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.PolicyAdminUpdated(policyId, bob, charlie);

        vm.prank(bob);
        registry.setPolicyAdmin(policyId, charlie);
    }

    function test_Events_MultipleUpdates() public {
        uint64 policyId = registry.createPolicy(david, ITIP403Registry.PolicyType.WHITELIST);

        // Add multiple accounts to whitelist
        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.WhitelistUpdated(policyId, david, alice, true);

        vm.prank(david);
        registry.modifyPolicyWhitelist(policyId, alice, true);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.WhitelistUpdated(policyId, david, bob, true);

        vm.prank(david);
        registry.modifyPolicyWhitelist(policyId, bob, true);

        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.WhitelistUpdated(policyId, david, charlie, true);

        vm.prank(david);
        registry.modifyPolicyWhitelist(policyId, charlie, true);

        // Remove one account
        vm.expectEmit(true, true, true, true);
        emit ITIP403Registry.WhitelistUpdated(policyId, david, alice, false);

        vm.prank(david);
        registry.modifyPolicyWhitelist(policyId, alice, false);
    }

    /*//////////////////////////////////////////////////////////////
                           EDGE CASES AND ERROR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_IsAuthorized_NonExistentPolicy() public view {
        // Non-existent policies should return false like blacklist
        assertFalse(registry.isAuthorized(999, alice));
    }

    function test_PolicyData_RevertsForNonExistentPolicy() public {
        // Querying policy data for non-existent policy should revert
        try registry.policyData(999) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.PolicyNotFound.selector));
        }
    }

    function test_PolicyIdCounter_Increment() public {
        uint64 initialCounter = registry.policyIdCounter();

        registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);
        assertEq(registry.policyIdCounter(), initialCounter + 1);

        registry.createPolicy(bob, ITIP403Registry.PolicyType.BLACKLIST);
        assertEq(registry.policyIdCounter(), initialCounter + 2);
    }

    function test_AdminPolicy_Authorization_Whitelist() public {
        address[] memory accounts = new address[](1);
        accounts[0] = alice;

        uint64 policyId = registry.createPolicyWithAccounts(
            alice, ITIP403Registry.PolicyType.WHITELIST, accounts
        );

        // Alice is the admin, so she should be able to modify it
        vm.prank(alice);
        registry.modifyPolicyWhitelist(policyId, bob, true);

        // Bob should now be whitelisted
        assertTrue(registry.isAuthorized(policyId, bob));
    }

    function test_AdminPolicy_BlacklistAllowed() public {
        address[] memory accounts = new address[](1);
        accounts[0] = alice;

        // Should be able to create a blacklist policy with an admin
        uint64 policyId =
            registry.createPolicyWithAccounts(bob, ITIP403Registry.PolicyType.BLACKLIST, accounts);

        (, address storedAdmin) = registry.policyData(policyId);
        assertEq(storedAdmin, bob);
        assertFalse(registry.isAuthorized(policyId, alice)); // Alice is blacklisted
    }

    function test_FixedPolicy_NoAdmin() public {
        uint64 policyId = registry.createPolicy(address(0), ITIP403Registry.PolicyType.WHITELIST);

        // Should not be able to modify a fixed policy (no admin)
        vm.prank(alice);
        try registry.modifyPolicyWhitelist(policyId, alice, true) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }

        vm.prank(alice);
        try registry.setPolicyAdmin(policyId, bob) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }
    }

    function test_Authorization_AdminCanUpdate() public {
        // Create a whitelist policy with alice as admin
        address[] memory accounts = new address[](1);
        accounts[0] = bob;
        uint64 policyId = registry.createPolicyWithAccounts(
            alice, ITIP403Registry.PolicyType.WHITELIST, accounts
        );

        // Alice should be able to modify the policy (she is the admin)
        vm.prank(alice);
        registry.modifyPolicyWhitelist(policyId, charlie, true);

        // Charlie should now be whitelisted
        assertTrue(registry.isAuthorized(policyId, charlie));
    }

    function test_Authorization_OnlyAdminCanUpdate() public {
        // Create a blacklist policy with alice as admin
        address[] memory accounts = new address[](1);
        accounts[0] = bob;
        uint64 policyId = registry.createPolicyWithAccounts(
            alice, ITIP403Registry.PolicyType.BLACKLIST, accounts
        );

        // Alice should be able to modify the policy (she is the admin)
        vm.prank(alice);
        registry.modifyPolicyBlacklist(policyId, charlie, true);

        // Charlie should now be blacklisted
        assertFalse(registry.isAuthorized(policyId, charlie));

        // Bob cannot modify (he is not the admin)
        vm.prank(bob);
        try registry.modifyPolicyBlacklist(policyId, david, true) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }
    }

    /*//////////////////////////////////////////////////////////////
                           ADDITIONAL EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_CreatePolicy_DuplicateAccounts() public {
        address[] memory accounts = new address[](3);
        accounts[0] = alice;
        accounts[1] = alice; // Duplicate
        accounts[2] = bob;

        uint64 policyId = registry.createPolicyWithAccounts(
            charlie, ITIP403Registry.PolicyType.WHITELIST, accounts
        );

        // Both alice and bob should be whitelisted (duplicates are handled
        // gracefully)
        assertTrue(registry.isAuthorized(policyId, alice));
        assertTrue(registry.isAuthorized(policyId, bob));
    }

    function test_ZeroAddress_Handling() public {
        uint64 policyId = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);

        // Zero address should be treated like any other address
        vm.prank(alice);
        registry.modifyPolicyWhitelist(policyId, address(0), true);
        assertTrue(registry.isAuthorized(policyId, address(0)));

        vm.prank(alice);
        registry.modifyPolicyWhitelist(policyId, address(0), false);
        assertFalse(registry.isAuthorized(policyId, address(0)));
    }

    function test_MaxUint64_Handling() public view {
        // Test with maximum uint64 values
        uint64 maxPolicyId = type(uint64).max;

        // Non-existent policies return false like a blacklist
        assertFalse(registry.isAuthorized(maxPolicyId, alice));
    }

    function test_ComplexAdminChain() public {
        // Create policies with different admins
        uint64 policy1 = registry.createPolicy(alice, ITIP403Registry.PolicyType.WHITELIST);
        uint64 policy2 = registry.createPolicy(bob, ITIP403Registry.PolicyType.WHITELIST);
        uint64 policy3 = registry.createPolicy(charlie, ITIP403Registry.PolicyType.WHITELIST);

        // Alice modifies policy1
        vm.prank(alice);
        registry.modifyPolicyWhitelist(policy1, david, true);

        // Bob modifies policy2
        vm.prank(bob);
        registry.modifyPolicyWhitelist(policy2, david, true);

        // Charlie modifies policy3
        vm.prank(charlie);
        registry.modifyPolicyWhitelist(policy3, david, true);

        // Verify david is whitelisted in all policies
        assertTrue(registry.isAuthorized(policy1, david));
        assertTrue(registry.isAuthorized(policy2, david));
        assertTrue(registry.isAuthorized(policy3, david));
    }

    function test_AdminTransfer_ComplexScenario() public {
        // Create a policy with alice as admin
        address[] memory accounts = new address[](1);
        accounts[0] = david;
        uint64 policyId = registry.createPolicyWithAccounts(
            alice, ITIP403Registry.PolicyType.WHITELIST, accounts
        );

        // Alice transfers admin to bob
        vm.prank(alice);
        registry.setPolicyAdmin(policyId, bob);

        // Bob should now be able to add charlie
        vm.prank(bob);
        registry.modifyPolicyWhitelist(policyId, charlie, true);

        // Alice should no longer be able to modify
        vm.prank(alice);
        try registry.modifyPolicyWhitelist(policyId, eve, true) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP403Registry.Unauthorized.selector));
        }

        // Bob transfers admin to charlie
        vm.prank(bob);
        registry.setPolicyAdmin(policyId, charlie);

        // Charlie should now be able to add eve
        vm.prank(charlie);
        registry.modifyPolicyWhitelist(policyId, eve, true);

        // Verify authorized users
        assertTrue(registry.isAuthorized(policyId, david)); // Initially added
        assertTrue(registry.isAuthorized(policyId, charlie)); // Added by bob
        assertTrue(registry.isAuthorized(policyId, eve)); // Added by charlie
    }

}
