// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title TIP403Registry Invariant Tests
/// @notice Fuzz-based invariant tests for the TIP403Registry implementation
/// @dev Tests invariants TEMPO-REG1 through TEMPO-REG19 as documented in README.md
contract TIP403RegistryInvariantTest is InvariantBaseTest {

    /// @dev Ghost variable for tracking total policies created in handlers
    uint256 private _totalPoliciesCreated;

    /// @dev Ghost variable for counter monotonicity tracking (TEMPO-REG15)
    uint64 private _lastSeenCounter;

    /// @dev Policies created during base setup (derived, not hardcoded)
    uint64 private _basePoliciesCreated;

    /// @dev Track created policies
    uint64[] private _createdPolicies;
    mapping(uint64 => ITIP403Registry.PolicyType) private _policyTypes;

    /// @dev Track policy membership for invariant verification
    mapping(uint64 => mapping(address => bool)) private _ghostPolicySet;

    /// @dev Track accounts added to each policy for iteration
    mapping(uint64 => address[]) private _policyAccounts;

    /// @dev Track if account already added to policy account list
    mapping(uint64 => mapping(address => bool)) private _policyAccountTracked;

    /// @dev Sentinel value for "any policy type" in _ensurePolicy
    uint8 internal constant ANY_POLICY = type(uint8).max;

    /*//////////////////////////////////////////////////////////////
                         CORE CREATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Core policy creation with ghost state updates. Does NOT include assertions.
    /// @param actor The address that will be the admin of the new policy
    /// @param policyType The type of policy to create
    /// @return policyId The ID of the newly created policy
    function _createPolicyInternal(
        address actor,
        ITIP403Registry.PolicyType policyType
    )
        internal
        returns (uint64 policyId)
    {
        vm.startPrank(actor);
        policyId = registry.createPolicy(actor, policyType);
        vm.stopPrank();

        _totalPoliciesCreated++;
        _createdPolicies.push(policyId);
        _policyTypes[policyId] = policyType;
    }

    /// @dev Find an existing policy of the specified type
    /// @param seed Random seed for selection
    /// @param policyType The type of policy to find
    /// @return policyId The found policy ID (0 if not found)
    /// @return found Whether a matching policy was found
    function _findPolicy(
        uint256 seed,
        ITIP403Registry.PolicyType policyType
    )
        internal
        view
        returns (uint64 policyId, bool found)
    {
        if (_createdPolicies.length == 0) {
            return (0, false);
        }

        uint256 startIdx = seed % _createdPolicies.length;
        for (uint256 i = 0; i < _createdPolicies.length; i++) {
            uint256 idx = (startIdx + i) % _createdPolicies.length;
            if (_policyTypes[_createdPolicies[idx]] == policyType) {
                return (_createdPolicies[idx], true);
            }
        }
        return (0, false);
    }

    /// @dev Ensure a policy exists, creating one as a fallback if needed
    /// @param actor The actor to use if creating a new policy
    /// @param seed Random seed for finding existing policy
    /// @param policyTypeOrAny Either a PolicyType cast to uint8, or ANY_POLICY for any type
    /// @return policyId The policy ID (existing or newly created)
    /// @return admin The admin of the policy (actor if created, existing admin if found)
    function _ensurePolicy(
        address actor,
        uint256 seed,
        uint8 policyTypeOrAny
    )
        internal
        returns (uint64 policyId, address admin)
    {
        if (policyTypeOrAny == ANY_POLICY) {
            // Any type: reuse any existing policy, or create a whitelist
            if (_createdPolicies.length > 0) {
                policyId = _createdPolicies[seed % _createdPolicies.length];
                (, admin) = registry.policyData(policyId);
                return (policyId, admin);
            }
            // No policies exist, create a whitelist
            policyId = _createPolicyInternal(actor, ITIP403Registry.PolicyType.WHITELIST);
            return (policyId, actor);
        }

        // Specific type requested
        ITIP403Registry.PolicyType requestedType = ITIP403Registry.PolicyType(policyTypeOrAny);
        bool found;
        (policyId, found) = _findPolicy(seed, requestedType);

        if (found) {
            (, admin) = registry.policyData(policyId);
            return (policyId, admin);
        }

        // Not found, create one as fallback
        policyId = _createPolicyInternal(actor, requestedType);
        return (policyId, actor);
    }

    /// @notice Sets up the test environment
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        uint64 counterBefore = registry.policyIdCounter();
        _setupInvariantBase();
        _basePoliciesCreated = registry.policyIdCounter() - counterBefore;

        _actors = _buildActors(10);

        // One-time constant checks (immutable after deployment)
        // TEMPO-REG13: Special policies 0 and 1 always exist
        assertTrue(registry.policyExists(0), "TEMPO-REG13: Policy 0 should always exist");
        assertTrue(registry.policyExists(1), "TEMPO-REG13: Policy 1 should always exist");
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for creating policies
    /// @dev Tests TEMPO-REG1 (policy ID monotonicity), TEMPO-REG2 (policy creation)
    function createPolicy(uint256 actorSeed, bool isWhitelist) external {
        address actor = _selectActor(actorSeed);
        ITIP403Registry.PolicyType policyType = isWhitelist
            ? ITIP403Registry.PolicyType.WHITELIST
            : ITIP403Registry.PolicyType.BLACKLIST;

        uint64 counterBefore = registry.policyIdCounter();

        uint64 policyId = _createPolicyInternal(actor, policyType);

        // TEMPO-REG1: Policy ID should equal counter before creation
        assertEq(
            policyId, counterBefore, "TEMPO-REG1: Policy ID should match counter before creation"
        );

        // TEMPO-REG2: Counter should increment
        assertEq(
            registry.policyIdCounter(),
            counterBefore + 1,
            "TEMPO-REG2: Counter should increment after creation"
        );

        // TEMPO-REG3: Policy should exist
        assertTrue(registry.policyExists(policyId), "TEMPO-REG3: Created policy should exist");

        // TEMPO-REG4: Policy data should be correct
        (ITIP403Registry.PolicyType storedType, address storedAdmin) = registry.policyData(policyId);
        assertEq(uint256(storedType), uint256(policyType), "TEMPO-REG4: Policy type mismatch");
        assertEq(storedAdmin, actor, "TEMPO-REG4: Policy admin mismatch");
    }

    /// @notice Handler for creating policies with initial accounts
    /// @dev Tests TEMPO-REG5 (bulk creation)
    function createPolicyWithAccounts(
        uint256 actorSeed,
        bool isWhitelist,
        uint8 numAccountsSeed
    )
        external
    {
        address actor = _selectActor(actorSeed);
        ITIP403Registry.PolicyType policyType = isWhitelist
            ? ITIP403Registry.PolicyType.WHITELIST
            : ITIP403Registry.PolicyType.BLACKLIST;

        uint256 numAccounts = (numAccountsSeed % 5) + 1; // 1-5 accounts
        address[] memory accounts = new address[](numAccounts);
        for (uint256 i = 0; i < numAccounts; i++) {
            accounts[i] = _selectActor(uint256(keccak256(abi.encodePacked(actorSeed, i))));
        }

        vm.startPrank(actor);
        try registry.createPolicyWithAccounts(actor, policyType, accounts) returns (
            uint64 policyId
        ) {
            vm.stopPrank();

            _totalPoliciesCreated++;
            _createdPolicies.push(policyId);
            _policyTypes[policyId] = policyType;

            // Track ghost state
            for (uint256 i = 0; i < accounts.length; i++) {
                _ghostPolicySet[policyId][accounts[i]] = true;
                if (!_policyAccountTracked[policyId][accounts[i]]) {
                    _policyAccountTracked[policyId][accounts[i]] = true;
                    _policyAccounts[policyId].push(accounts[i]);
                }
            }

            // TEMPO-REG5: All initial accounts should have correct authorization
            for (uint256 i = 0; i < accounts.length; i++) {
                bool isAuthorized = registry.isAuthorized(policyId, accounts[i]);
                if (isWhitelist) {
                    // Whitelist: accounts in list are authorized
                    assertTrue(isAuthorized, "TEMPO-REG5: Whitelist account should be authorized");
                } else {
                    // Blacklist: accounts in list are NOT authorized
                    assertFalse(
                        isAuthorized, "TEMPO-REG5: Blacklist account should not be authorized"
                    );
                }
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for setting policy admin
    /// @dev Tests TEMPO-REG6 (admin transfer)
    function setPolicyAdmin(uint256 policySeed, uint256 newAdminSeed) external {
        address actor = _selectActor(policySeed);
        (uint64 policyId, address currentAdmin) = _ensurePolicy(actor, policySeed, ANY_POLICY);
        address newAdmin = _selectActor(newAdminSeed);

        vm.startPrank(currentAdmin);
        try registry.setPolicyAdmin(policyId, newAdmin) {
            vm.stopPrank();

            // TEMPO-REG6: Admin should be updated
            (, address storedAdmin) = registry.policyData(policyId);
            assertEq(storedAdmin, newAdmin, "TEMPO-REG6: Admin not updated correctly");
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for unauthorized admin change attempts
    /// @dev Tests TEMPO-REG7 (admin-only enforcement)
    function setPolicyAdminUnauthorized(uint256 policySeed, uint256 attackerSeed) external {
        address actor = _selectActor(policySeed);
        (uint64 policyId, address currentAdmin) = _ensurePolicy(actor, policySeed, ANY_POLICY);
        address attacker = _selectActorExcluding(attackerSeed, currentAdmin);

        vm.startPrank(attacker);
        try registry.setPolicyAdmin(policyId, attacker) {
            vm.stopPrank();
            revert("TEMPO-REG7: Non-admin should not be able to set admin");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                ITIP403Registry.Unauthorized.selector,
                "TEMPO-REG7: Should revert with Unauthorized"
            );
        }
    }

    /// @notice Handler for modifying whitelist
    /// @dev Tests TEMPO-REG8 (whitelist modification)
    function modifyWhitelist(uint256 policySeed, uint256 accountSeed, bool allowed) external {
        address actor = _selectActor(policySeed);
        (uint64 policyId, address policyAdmin) =
            _ensurePolicy(actor, policySeed, uint8(ITIP403Registry.PolicyType.WHITELIST));

        address account = _selectActor(accountSeed);

        vm.startPrank(policyAdmin);
        try registry.modifyPolicyWhitelist(policyId, account, allowed) {
            vm.stopPrank();

            _ghostPolicySet[policyId][account] = allowed;
            if (!_policyAccountTracked[policyId][account]) {
                _policyAccountTracked[policyId][account] = true;
                _policyAccounts[policyId].push(account);
            }

            // TEMPO-REG8: Authorization should reflect whitelist status
            bool authAfter = registry.isAuthorized(policyId, account);
            assertEq(authAfter, allowed, "TEMPO-REG8: Whitelist authorization mismatch");
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for modifying blacklist
    /// @dev Tests TEMPO-REG9 (blacklist modification)
    function modifyBlacklist(uint256 policySeed, uint256 accountSeed, bool restricted) external {
        address actor = _selectActor(policySeed);
        (uint64 policyId, address policyAdmin) =
            _ensurePolicy(actor, policySeed, uint8(ITIP403Registry.PolicyType.BLACKLIST));

        address account = _selectActor(accountSeed);

        vm.startPrank(policyAdmin);
        try registry.modifyPolicyBlacklist(policyId, account, restricted) {
            vm.stopPrank();

            _ghostPolicySet[policyId][account] = restricted;
            if (!_policyAccountTracked[policyId][account]) {
                _policyAccountTracked[policyId][account] = true;
                _policyAccounts[policyId].push(account);
            }

            // TEMPO-REG9: Authorization should be opposite of blacklist status
            bool authAfter = registry.isAuthorized(policyId, account);
            assertEq(authAfter, !restricted, "TEMPO-REG9: Blacklist authorization mismatch");
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for modifying wrong policy type
    /// @dev Tests TEMPO-REG10 (policy type enforcement)
    function modifyWrongPolicyType(uint256 policySeed, uint256 accountSeed) external {
        address actor = _selectActor(policySeed);
        (uint64 policyId, address policyAdmin) = _ensurePolicy(actor, policySeed, ANY_POLICY);
        address account = _selectActor(accountSeed);
        ITIP403Registry.PolicyType policyType = _policyTypes[policyId];

        vm.startPrank(policyAdmin);
        if (policyType == ITIP403Registry.PolicyType.WHITELIST) {
            // Try to modify as blacklist
            try registry.modifyPolicyBlacklist(policyId, account, true) {
                vm.stopPrank();
                revert("TEMPO-REG10: Should revert for incompatible policy type");
            } catch (bytes memory reason) {
                vm.stopPrank();
                assertEq(
                    bytes4(reason),
                    ITIP403Registry.IncompatiblePolicyType.selector,
                    "TEMPO-REG10: Should revert with IncompatiblePolicyType"
                );
            }
        } else {
            // Try to modify as whitelist
            try registry.modifyPolicyWhitelist(policyId, account, true) {
                vm.stopPrank();
                revert("TEMPO-REG10: Should revert for incompatible policy type");
            } catch (bytes memory reason) {
                vm.stopPrank();
                assertEq(
                    bytes4(reason),
                    ITIP403Registry.IncompatiblePolicyType.selector,
                    "TEMPO-REG10: Should revert with IncompatiblePolicyType"
                );
            }
        }
    }

    /// @notice Handler for checking authorization on special policies
    /// @dev Tests TEMPO-REG11 (special policy behavior)
    function checkSpecialPolicies(uint256 accountSeed) external {
        address account = _selectActor(accountSeed);

        // TEMPO-REG11: Policy 0 is always-reject
        assertFalse(registry.isAuthorized(0, account), "TEMPO-REG11: Policy 0 should always reject");

        // TEMPO-REG12: Policy 1 is always-allow
        assertTrue(registry.isAuthorized(1, account), "TEMPO-REG12: Policy 1 should always allow");

        // TEMPO-REG13: Special policies always exist
        assertTrue(registry.policyExists(0), "TEMPO-REG13: Policy 0 should always exist");
        assertTrue(registry.policyExists(1), "TEMPO-REG13: Policy 1 should always exist");
    }

    /// @notice Handler for checking non-existent policies
    /// @dev Tests TEMPO-REG14 (policy existence checks)
    function checkNonExistentPolicy(uint64 policyId) external {
        uint64 counter = registry.policyIdCounter();
        uint64 nonExistentId = counter + uint64(bound(policyId, 0, 1000));

        // TEMPO-REG14: Non-existent policy should not exist
        assertFalse(
            registry.policyExists(nonExistentId),
            "TEMPO-REG14: Non-existent policy should not exist"
        );
    }

    /// @notice Handler for checking authorization of accounts never added to a policy
    /// @dev Verifies default authorization behavior for whitelist (reject unknown) and blacklist (allow unknown)
    function checkUnknownAccountAuth(uint256 policySeed, uint256 accountSeed) external {
        address actor = _selectActor(policySeed);
        (uint64 policyId,) = _ensurePolicy(actor, policySeed, ANY_POLICY);
        address account = _selectActor(accountSeed);

        if (_policyAccountTracked[policyId][account]) {
            return;
        }

        bool isAuthorized = registry.isAuthorized(policyId, account);
        if (_policyTypes[policyId] == ITIP403Registry.PolicyType.WHITELIST) {
            assertFalse(isAuthorized, "Whitelist: unknown account should not be authorized");
        } else {
            assertTrue(isAuthorized, "Blacklist: unknown account should be authorized");
        }
    }

    /// @notice Handler for attempting to modify special policies (0 and 1)
    /// @dev Tests TEMPO-REG17 (special policies cannot be modified) and TEMPO-REG18 (admin cannot change)
    function tryModifySpecialPolicies(
        uint256 actorSeed,
        uint256 accountSeed,
        uint8 policyChoice
    )
        external
    {
        address actor = _selectActor(actorSeed);
        address account = _selectActor(accountSeed);
        uint64 policyId = (policyChoice % 2 == 0) ? 0 : 1;

        // Try whitelist modification - should fail
        vm.startPrank(actor);
        try registry.modifyPolicyWhitelist(policyId, account, true) {
            vm.stopPrank();
            revert("TEMPO-REG17: Should not be able to modify special policy");
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }

        // Try blacklist modification - should fail
        vm.startPrank(actor);
        try registry.modifyPolicyBlacklist(policyId, account, true) {
            vm.stopPrank();
            revert("TEMPO-REG17: Should not be able to modify special policy");
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }

        // Try admin change - should fail
        vm.startPrank(actor);
        try registry.setPolicyAdmin(policyId, account) {
            vm.stopPrank();
            revert("TEMPO-REG18: Should not be able to change special policy admin");
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks in a single unified loop
    /// @dev Combines TEMPO-REG3, REG15, REG16, REG19 checks
    ///      Special policies check (REG13) moved to setUp() as they're immutable
    function invariant_globalInvariants() public {
        // TEMPO-REG15: Counter monotonicity (done once, not per-policy)
        uint64 counter = registry.policyIdCounter();
        assertTrue(counter >= 2, "TEMPO-REG15: Counter should be at least 2");
        uint64 expectedCounter = 2 + _basePoliciesCreated + uint64(_totalPoliciesCreated);
        assertEq(
            counter, expectedCounter, "TEMPO-REG15: Counter must equal 2 + totalPoliciesCreated"
        );
        assertGe(counter, _lastSeenCounter, "TEMPO-REG15: Counter must never decrease");
        _lastSeenCounter = counter;

        // Single loop over all created policies
        for (uint256 i = 0; i < _createdPolicies.length; i++) {
            uint64 policyId = _createdPolicies[i];

            // TEMPO-REG3: Created policy exists
            assertTrue(registry.policyExists(policyId), "TEMPO-REG3: Created policy should exist");

            // TEMPO-REG16: Policy type immutability
            (ITIP403Registry.PolicyType currentType,) = registry.policyData(policyId);
            assertEq(
                uint256(currentType),
                uint256(_policyTypes[policyId]),
                "TEMPO-REG16: Policy type should not change"
            );

            // TEMPO-REG19: Ghost policy membership matches registry
            address[] memory accounts = _policyAccounts[policyId];
            for (uint256 j = 0; j < accounts.length; j++) {
                address account = accounts[j];
                bool ghostMember = _ghostPolicySet[policyId][account];
                bool isAuthorized = registry.isAuthorized(policyId, account);

                if (currentType == ITIP403Registry.PolicyType.WHITELIST) {
                    assertEq(
                        isAuthorized, ghostMember, "TEMPO-REG19: Whitelist membership mismatch"
                    );
                } else {
                    assertEq(
                        isAuthorized, !ghostMember, "TEMPO-REG19: Blacklist membership mismatch"
                    );
                }
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Checks if an error is known/expected
    function _assertKnownError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnown = selector == ITIP403Registry.Unauthorized.selector
            || selector == ITIP403Registry.IncompatiblePolicyType.selector
            || selector == ITIP403Registry.PolicyNotFound.selector;
        assertTrue(isKnown, "Unknown error encountered");
    }

}
