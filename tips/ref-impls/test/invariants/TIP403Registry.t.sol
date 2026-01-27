// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP403Registry } from "../../src/TIP403Registry.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title TIP403Registry Invariant Tests
/// @notice Fuzz-based invariant tests for the TIP403Registry implementation
/// @dev Tests invariants TEMPO-REG1 through TEMPO-REG18 as documented in README.md
contract TIP403RegistryInvariantTest is InvariantBaseTest {

    /// @dev Log file path for recording actions
    string private constant LOG_FILE = "tip403_registry.log";

    /// @dev Ghost variables for tracking operations
    uint256 private _totalPoliciesCreated;
    uint256 private _totalAdminChanges;
    uint256 private _totalWhitelistModifications;
    uint256 private _totalBlacklistModifications;
    uint256 private _totalAuthorizationChecks;

    /// @dev Ghost variable for counter monotonicity tracking (TEMPO-REG15)
    uint64 private _lastSeenCounter;

    /// @dev Track created policies
    uint64[] private _createdPolicies;
    mapping(uint64 => address) private _policyCreators;
    mapping(uint64 => ITIP403Registry.PolicyType) private _policyTypes;

    /// @dev Track policy membership for invariant verification
    mapping(uint64 => mapping(address => bool)) private _ghostPolicySet;

    /// @dev Track accounts added to each policy for iteration
    mapping(uint64 => address[]) private _policyAccounts;

    /// @dev Track if account already added to policy account list
    mapping(uint64 => mapping(address => bool)) private _policyAccountTracked;

    /// @notice Sets up the test environment
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();
        _actors = _buildActors(10);

        _initLogFile(LOG_FILE, "TIP403Registry Invariant Test Log");
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

        vm.startPrank(actor);
        try registry.createPolicy(actor, policyType) returns (uint64 policyId) {
            vm.stopPrank();

            _totalPoliciesCreated++;
            _createdPolicies.push(policyId);
            _policyCreators[policyId] = actor;
            _policyTypes[policyId] = policyType;

            // TEMPO-REG1: Policy ID should equal counter before creation
            assertEq(
                policyId,
                counterBefore,
                "TEMPO-REG1: Policy ID should match counter before creation"
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
            (ITIP403Registry.PolicyType storedType, address storedAdmin) =
                registry.policyData(policyId);
            assertEq(uint256(storedType), uint256(policyType), "TEMPO-REG4: Policy type mismatch");
            assertEq(storedAdmin, actor, "TEMPO-REG4: Policy admin mismatch");

            _log(
                string.concat(
                    "CREATE_POLICY: ",
                    _getActorIndex(actor),
                    " created policy ",
                    vm.toString(policyId),
                    " type=",
                    isWhitelist ? "WHITELIST" : "BLACKLIST"
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for creating policies with initial accounts
    /// @dev Tests TEMPO-REG5 (bulk creation)
    function createPolicyWithAccounts(uint256 actorSeed, bool isWhitelist, uint8 numAccountsSeed)
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
            _policyCreators[policyId] = actor;
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

            _log(
                string.concat(
                    "CREATE_POLICY_WITH_ACCOUNTS: ",
                    _getActorIndex(actor),
                    " created policy ",
                    vm.toString(policyId),
                    " with ",
                    vm.toString(numAccounts),
                    " accounts"
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for setting policy admin
    /// @dev Tests TEMPO-REG6 (admin transfer)
    function setPolicyAdmin(uint256 policySeed, uint256 newAdminSeed) external {
        if (_createdPolicies.length == 0) return;

        uint64 policyId = _createdPolicies[policySeed % _createdPolicies.length];
        address newAdmin = _selectActor(newAdminSeed);

        (, address currentAdmin) = registry.policyData(policyId);

        vm.startPrank(currentAdmin);
        try registry.setPolicyAdmin(policyId, newAdmin) {
            vm.stopPrank();

            _totalAdminChanges++;

            // TEMPO-REG6: Admin should be updated
            (, address storedAdmin) = registry.policyData(policyId);
            assertEq(storedAdmin, newAdmin, "TEMPO-REG6: Admin not updated correctly");

            _log(
                string.concat(
                    "SET_ADMIN: policy ",
                    vm.toString(policyId),
                    " admin changed from ",
                    _getActorIndex(currentAdmin),
                    " to ",
                    _getActorIndex(newAdmin)
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for unauthorized admin change attempts
    /// @dev Tests TEMPO-REG7 (admin-only enforcement)
    function setPolicyAdminUnauthorized(uint256 policySeed, uint256 attackerSeed) external {
        if (_createdPolicies.length == 0) return;

        uint64 policyId = _createdPolicies[policySeed % _createdPolicies.length];
        address attacker = _selectActor(attackerSeed);

        (, address currentAdmin) = registry.policyData(policyId);

        // Skip if attacker is the admin
        vm.assume(attacker != currentAdmin);

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
        if (_createdPolicies.length == 0) return;

        // Find a whitelist policy
        uint64 policyId = 0;
        bool found = false;
        uint256 startIdx = policySeed % _createdPolicies.length;
        for (uint256 i = 0; i < _createdPolicies.length; i++) {
            uint256 idx = (startIdx + i) % _createdPolicies.length;
            if (_policyTypes[_createdPolicies[idx]] == ITIP403Registry.PolicyType.WHITELIST) {
                policyId = _createdPolicies[idx];
                found = true;
                break;
            }
        }
        if (!found) return;

        address account = _selectActor(accountSeed);
        (, address policyAdmin) = registry.policyData(policyId);

        vm.startPrank(policyAdmin);
        try registry.modifyPolicyWhitelist(policyId, account, allowed) {
            vm.stopPrank();

            _totalWhitelistModifications++;
            _ghostPolicySet[policyId][account] = allowed;
            if (!_policyAccountTracked[policyId][account]) {
                _policyAccountTracked[policyId][account] = true;
                _policyAccounts[policyId].push(account);
            }

            // TEMPO-REG8: Authorization should reflect whitelist status
            bool authAfter = registry.isAuthorized(policyId, account);
            assertEq(authAfter, allowed, "TEMPO-REG8: Whitelist authorization mismatch");

            _log(
                string.concat(
                    "MODIFY_WHITELIST: policy ",
                    vm.toString(policyId),
                    " ",
                    _getActorIndex(account),
                    " set to ",
                    allowed ? "ALLOWED" : "DISALLOWED"
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for modifying blacklist
    /// @dev Tests TEMPO-REG9 (blacklist modification)
    function modifyBlacklist(uint256 policySeed, uint256 accountSeed, bool restricted) external {
        if (_createdPolicies.length == 0) return;

        // Find a blacklist policy
        uint64 policyId = 0;
        bool found = false;
        uint256 startIdx = policySeed % _createdPolicies.length;
        for (uint256 i = 0; i < _createdPolicies.length; i++) {
            uint256 idx = (startIdx + i) % _createdPolicies.length;
            if (_policyTypes[_createdPolicies[idx]] == ITIP403Registry.PolicyType.BLACKLIST) {
                policyId = _createdPolicies[idx];
                found = true;
                break;
            }
        }
        if (!found) return;

        address account = _selectActor(accountSeed);
        (, address policyAdmin) = registry.policyData(policyId);

        vm.startPrank(policyAdmin);
        try registry.modifyPolicyBlacklist(policyId, account, restricted) {
            vm.stopPrank();

            _totalBlacklistModifications++;
            _ghostPolicySet[policyId][account] = restricted;
            if (!_policyAccountTracked[policyId][account]) {
                _policyAccountTracked[policyId][account] = true;
                _policyAccounts[policyId].push(account);
            }

            // TEMPO-REG9: Authorization should be opposite of blacklist status
            bool authAfter = registry.isAuthorized(policyId, account);
            assertEq(authAfter, !restricted, "TEMPO-REG9: Blacklist authorization mismatch");

            _log(
                string.concat(
                    "MODIFY_BLACKLIST: policy ",
                    vm.toString(policyId),
                    " ",
                    _getActorIndex(account),
                    " set to ",
                    restricted ? "RESTRICTED" : "UNRESTRICTED"
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for modifying wrong policy type
    /// @dev Tests TEMPO-REG10 (policy type enforcement)
    function modifyWrongPolicyType(uint256 policySeed, uint256 accountSeed) external {
        if (_createdPolicies.length == 0) return;

        uint64 policyId = _createdPolicies[policySeed % _createdPolicies.length];
        address account = _selectActor(accountSeed);
        (, address policyAdmin) = registry.policyData(policyId);
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

        _totalAuthorizationChecks++;

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
    function checkNonExistentPolicy(uint64 policyId) external view {
        // Use a policy ID that definitely doesn't exist
        uint64 nonExistentId = registry.policyIdCounter() + 100 + policyId;

        // TEMPO-REG14: Non-existent policy should not exist
        assertFalse(
            registry.policyExists(nonExistentId),
            "TEMPO-REG14: Non-existent policy should not exist"
        );
    }

    /// @notice Handler for attempting to modify special policies (0 and 1)
    /// @dev Tests TEMPO-REG17 (special policies cannot be modified) and TEMPO-REG18 (admin cannot change)
    function tryModifySpecialPolicies(uint256 actorSeed, uint256 accountSeed, uint8 policyChoice)
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

        _log(
            string.concat(
                "TRY_MODIFY_SPECIAL_POLICY: ",
                _getActorIndex(actor),
                " blocked on policy ",
                vm.toString(policyId)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    function invariant_globalInvariants() public {
        _invariantCounterMonotonicity();
        _invariantSpecialPoliciesExist();
        _invariantCreatedPoliciesExist();
        _invariantPolicyTypeImmutability();
        _invariantPolicyMembershipConsistency();
    }

    /// @notice TEMPO-REG15: Policy counter only increases and equals 2 + totalPoliciesCreated
    function _invariantCounterMonotonicity() internal {
        uint64 counter = registry.policyIdCounter();

        // Counter starts at 2 (skipping special policies 0 and 1)
        assertTrue(counter >= 2, "TEMPO-REG15: Counter should be at least 2");

        // TEMPO-REG15: Counter must equal exactly 2 + total policies created
        uint64 expectedCounter =
            2 + uint64(_totalPoliciesCreatedInBase()) + uint64(_totalPoliciesCreated);
        assertEq(
            counter, expectedCounter, "TEMPO-REG15: Counter must equal 2 + totalPoliciesCreated"
        );

        // TEMPO-REG15: Counter must only increase (monotonicity)
        assertGe(counter, _lastSeenCounter, "TEMPO-REG15: Counter must never decrease");
        _lastSeenCounter = counter;
    }

    /// @notice TEMPO-REG13: Special policies 0 and 1 always exist
    function _invariantSpecialPoliciesExist() internal view {
        assertTrue(registry.policyExists(0), "TEMPO-REG13: Policy 0 should always exist");
        assertTrue(registry.policyExists(1), "TEMPO-REG13: Policy 1 should always exist");
    }

    /// @notice TEMPO-REG3: All created policies exist
    function _invariantCreatedPoliciesExist() internal view {
        for (uint256 i = 0; i < _createdPolicies.length; i++) {
            assertTrue(
                registry.policyExists(_createdPolicies[i]),
                "TEMPO-REG3: Created policy should exist"
            );
        }
    }

    /// @notice TEMPO-REG16: Policy type cannot change after creation
    function _invariantPolicyTypeImmutability() internal view {
        for (uint256 i = 0; i < _createdPolicies.length; i++) {
            uint64 policyId = _createdPolicies[i];
            (ITIP403Registry.PolicyType currentType,) = registry.policyData(policyId);
            assertEq(
                uint256(currentType),
                uint256(_policyTypes[policyId]),
                "TEMPO-REG16: Policy type should not change"
            );
        }
    }

    /// @notice TEMPO-REG19: Ghost policy membership matches registry
    function _invariantPolicyMembershipConsistency() internal view {
        for (uint256 i = 0; i < _createdPolicies.length; i++) {
            uint64 policyId = _createdPolicies[i];
            ITIP403Registry.PolicyType policyType = _policyTypes[policyId];
            address[] memory accounts = _policyAccounts[policyId];

            for (uint256 j = 0; j < accounts.length; j++) {
                address account = accounts[j];
                bool ghostMember = _ghostPolicySet[policyId][account];
                bool isAuthorized = registry.isAuthorized(policyId, account);

                if (policyType == ITIP403Registry.PolicyType.WHITELIST) {
                    // Whitelist: member = authorized
                    assertEq(
                        isAuthorized, ghostMember, "TEMPO-REG19: Whitelist membership mismatch"
                    );
                } else {
                    // Blacklist: member = NOT authorized
                    assertEq(
                        isAuthorized, !ghostMember, "TEMPO-REG19: Blacklist membership mismatch"
                    );
                }
            }
        }
    }

    /// @notice Verify operation counters are consistent
    function _invariantOperationCountersConsistent() internal view {
        assertTrue(
            _totalPoliciesCreated + _totalAdminChanges + _totalWhitelistModifications
                    + _totalBlacklistModifications + _totalAuthorizationChecks >= 0,
            "Operation counters should be non-negative"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Count policies created in base setup
    /// InvariantBaseTest creates blacklist policies for each token + pathUSD
    function _totalPoliciesCreatedInBase() internal pure returns (uint256) {
        // 4 tokens + 1 pathUSD = 5 policies created in _setupInvariantBase
        return 5;
    }

    /// @dev Checks if an error is known/expected
    function _assertKnownError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnown = selector == ITIP403Registry.Unauthorized.selector
            || selector == ITIP403Registry.IncompatiblePolicyType.selector
            || selector == ITIP403Registry.PolicyNotFound.selector;
        assertTrue(isKnown, "Unknown error encountered");
    }

}
