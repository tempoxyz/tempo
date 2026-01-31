// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title TIP-1015 Compound Policy Invariant Tests
/// @notice Invariant tests for compound transfer policies as specified in TIP-1015
/// @dev Tests the 6 invariants from the TIP-1015 specification
///      These tests only run against the Solidity reference implementation (!isTempo)
///      since the Rust precompiles don't implement TIP-1015 yet.
contract TIP1015InvariantTest is InvariantBaseTest {

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Simple policies created for testing
    uint64 internal whitelistPolicy;
    uint64 internal blacklistPolicy;
    uint64 internal senderOnlyPolicy;
    uint64 internal recipientOnlyPolicy;

    /// @dev Compound policies created for testing
    uint64[] internal compoundPolicies;

    /// @dev Test users
    address internal whitelistedUser;
    address internal blacklistedUser;
    address internal neutralUser;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        // Skip all TIP-1015 tests when running against Rust precompiles
        // since TIP-1015 is not yet implemented there
        if (isTempo) {
            return;
        }

        _setupInvariantBase();

        whitelistedUser = makeAddr("whitelistedUser");
        blacklistedUser = makeAddr("blacklistedUser");
        neutralUser = makeAddr("neutralUser");

        vm.startPrank(admin);

        // Create simple policies for testing
        whitelistPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        blacklistPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        senderOnlyPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        recipientOnlyPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        // Configure policies
        registry.modifyPolicyWhitelist(whitelistPolicy, whitelistedUser, true);
        registry.modifyPolicyBlacklist(blacklistPolicy, blacklistedUser, true);
        registry.modifyPolicyWhitelist(senderOnlyPolicy, whitelistedUser, true);
        registry.modifyPolicyWhitelist(recipientOnlyPolicy, neutralUser, true);

        vm.stopPrank();
    }

    /// @dev Modifier to skip tests when running on Tempo (Rust precompiles)
    modifier onlySolidityImpl() {
        if (isTempo) {
            return;
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 1: Simple Policy Constraint
    //////////////////////////////////////////////////////////////*/

    /// @notice Compound policies can only reference simple policies
    /// @dev "All three policy IDs in a compound policy MUST reference simple policies"
    function test_invariant1_cannotReferenceCompoundPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        // Create a compound policy first
        uint64 compoundPolicy =
            registry.createCompoundPolicy(whitelistPolicy, blacklistPolicy, whitelistPolicy);

        // Attempting to reference this compound policy should revert
        vm.expectRevert(ITIP403Registry.PolicyNotSimple.selector);
        registry.createCompoundPolicy(compoundPolicy, whitelistPolicy, whitelistPolicy);

        vm.expectRevert(ITIP403Registry.PolicyNotSimple.selector);
        registry.createCompoundPolicy(whitelistPolicy, compoundPolicy, whitelistPolicy);

        vm.expectRevert(ITIP403Registry.PolicyNotSimple.selector);
        registry.createCompoundPolicy(whitelistPolicy, whitelistPolicy, compoundPolicy);

        vm.stopPrank();
    }

    /// @notice All three positions can reference different simple policies
    function test_invariant1_canReferenceSimplePolicies() public onlySolidityImpl {
        vm.startPrank(admin);

        uint64 compoundPolicy =
            registry.createCompoundPolicy(whitelistPolicy, blacklistPolicy, senderOnlyPolicy);

        // Verify the compound policy was created with correct references
        (uint64 senderPid, uint64 recipientPid, uint64 mintRecipientPid) =
            registry.compoundPolicyData(compoundPolicy);

        assertEq(senderPid, whitelistPolicy, "Sender policy mismatch");
        assertEq(recipientPid, blacklistPolicy, "Recipient policy mismatch");
        assertEq(mintRecipientPid, senderOnlyPolicy, "Mint recipient policy mismatch");

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 2: Immutability
    //////////////////////////////////////////////////////////////*/

    /// @notice Compound policies are immutable with no admin
    /// @dev "Once created, a compound policy's constituent policy IDs cannot be changed"
    function test_invariant2_compoundPolicyHasNoAdmin() public onlySolidityImpl {
        vm.startPrank(admin);

        uint64 compoundPolicy =
            registry.createCompoundPolicy(whitelistPolicy, whitelistPolicy, whitelistPolicy);

        // Get policy data - admin should be zero address
        (ITIP403Registry.PolicyType policyType, address policyAdmin) =
            registry.policyData(compoundPolicy);

        assertEq(uint8(policyType), uint8(ITIP403Registry.PolicyType.COMPOUND), "Wrong policy type");
        assertEq(policyAdmin, address(0), "Compound policy should have no admin");

        vm.stopPrank();
    }

    /// @notice Cannot modify compound policy whitelist/blacklist
    /// @dev Compound policies have no admin (address(0)), so modification attempts fail
    function test_invariant2_cannotModifyCompoundPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        uint64 compoundPolicy =
            registry.createCompoundPolicy(whitelistPolicy, whitelistPolicy, whitelistPolicy);

        vm.stopPrank();

        // Attempting to modify should revert - either Unauthorized (no admin) or IncompatiblePolicyType
        // The exact error depends on implementation order of checks
        vm.expectRevert();
        registry.modifyPolicyWhitelist(compoundPolicy, neutralUser, true);

        vm.expectRevert();
        registry.modifyPolicyBlacklist(compoundPolicy, neutralUser, true);
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 3: Existence Check
    //////////////////////////////////////////////////////////////*/

    /// @notice createCompoundPolicy MUST revert if any referenced policy doesn't exist
    function test_invariant3_revertsOnNonExistentPolicy() public onlySolidityImpl {
        uint64 nonExistentPolicy = 99_999;

        vm.startPrank(admin);

        vm.expectRevert(abi.encodeWithSelector(ITIP403Registry.PolicyNotFound.selector, nonExistentPolicy));
        registry.createCompoundPolicy(nonExistentPolicy, whitelistPolicy, whitelistPolicy);

        vm.expectRevert(abi.encodeWithSelector(ITIP403Registry.PolicyNotFound.selector, nonExistentPolicy));
        registry.createCompoundPolicy(whitelistPolicy, nonExistentPolicy, whitelistPolicy);

        vm.expectRevert(abi.encodeWithSelector(ITIP403Registry.PolicyNotFound.selector, nonExistentPolicy));
        registry.createCompoundPolicy(whitelistPolicy, whitelistPolicy, nonExistentPolicy);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 4: Delegation Correctness
    //////////////////////////////////////////////////////////////*/

    /// @notice For simple policies: sender = recipient = mintRecipient authorization
    /// @dev "For simple policies, isAuthorizedSender(p, u) MUST equal isAuthorizedRecipient(p, u)
    ///       MUST equal isAuthorizedMintRecipient(p, u)"
    function test_invariant4_simplePolicyEquivalence() public onlySolidityImpl {
        // Test with whitelisted user on whitelist policy
        bool sender = registry.isAuthorizedSender(whitelistPolicy, whitelistedUser);
        bool recipient = registry.isAuthorizedRecipient(whitelistPolicy, whitelistedUser);
        bool mintRecipient = registry.isAuthorizedMintRecipient(whitelistPolicy, whitelistedUser);
        bool general = registry.isAuthorized(whitelistPolicy, whitelistedUser);

        assertEq(sender, recipient, "Sender != Recipient for simple policy");
        assertEq(recipient, mintRecipient, "Recipient != MintRecipient for simple policy");
        assertEq(sender, general, "Sender != isAuthorized for simple policy");

        // Test with non-whitelisted user on whitelist policy
        sender = registry.isAuthorizedSender(whitelistPolicy, neutralUser);
        recipient = registry.isAuthorizedRecipient(whitelistPolicy, neutralUser);
        mintRecipient = registry.isAuthorizedMintRecipient(whitelistPolicy, neutralUser);

        assertEq(sender, recipient, "Sender != Recipient for simple policy (non-whitelisted)");
        assertEq(
            recipient,
            mintRecipient,
            "Recipient != MintRecipient for simple policy (non-whitelisted)"
        );

        // Test with blacklist policy
        sender = registry.isAuthorizedSender(blacklistPolicy, neutralUser);
        recipient = registry.isAuthorizedRecipient(blacklistPolicy, neutralUser);
        mintRecipient = registry.isAuthorizedMintRecipient(blacklistPolicy, neutralUser);

        assertEq(sender, recipient, "Sender != Recipient for blacklist policy");
        assertEq(recipient, mintRecipient, "Recipient != MintRecipient for blacklist policy");
    }

    /// @notice Fuzz test: delegation correctness for any simple policy and user
    function testFuzz_invariant4_simplePolicyEquivalence(uint256 policySeed, address user)
        public
        onlySolidityImpl
    {
        vm.assume(user != address(0));

        vm.startPrank(admin);

        // Create a random simple policy
        ITIP403Registry.PolicyType policyType = policySeed % 2 == 0
            ? ITIP403Registry.PolicyType.WHITELIST
            : ITIP403Registry.PolicyType.BLACKLIST;

        uint64 testPolicy = registry.createPolicy(admin, policyType);

        // Optionally add the user to the policy
        if (policySeed % 3 == 0) {
            if (policyType == ITIP403Registry.PolicyType.WHITELIST) {
                registry.modifyPolicyWhitelist(testPolicy, user, true);
            } else {
                registry.modifyPolicyBlacklist(testPolicy, user, true);
            }
        }

        vm.stopPrank();

        // All three authorization functions must return the same value
        bool sender = registry.isAuthorizedSender(testPolicy, user);
        bool recipient = registry.isAuthorizedRecipient(testPolicy, user);
        bool mintRecipient = registry.isAuthorizedMintRecipient(testPolicy, user);

        assertEq(sender, recipient, "Fuzz: Sender != Recipient");
        assertEq(recipient, mintRecipient, "Fuzz: Recipient != MintRecipient");
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 5: isAuthorized Equivalence
    //////////////////////////////////////////////////////////////*/

    /// @notice isAuthorized(p, u) MUST equal isAuthorizedSender(p, u) && isAuthorizedRecipient(p, u)
    function test_invariant5_isAuthorizedEquivalence() public onlySolidityImpl {
        vm.startPrank(admin);

        // Create compound policy with different sender/recipient policies
        uint64 compoundPolicy = registry.createCompoundPolicy(
            senderOnlyPolicy, // Only whitelistedUser can send
            recipientOnlyPolicy, // Only neutralUser can receive
            whitelistPolicy // Any whitelisted user for mints
        );

        vm.stopPrank();

        // Test: whitelistedUser can send but not receive
        bool senderAuth = registry.isAuthorizedSender(compoundPolicy, whitelistedUser);
        bool recipientAuth = registry.isAuthorizedRecipient(compoundPolicy, whitelistedUser);
        bool isAuth = registry.isAuthorized(compoundPolicy, whitelistedUser);

        assertTrue(senderAuth, "whitelistedUser should be authorized sender");
        assertFalse(recipientAuth, "whitelistedUser should NOT be authorized recipient");
        assertEq(isAuth, senderAuth && recipientAuth, "isAuthorized != sender && recipient");
        assertFalse(isAuth, "isAuthorized should be false (not both)");

        // Test: neutralUser can receive but not send
        senderAuth = registry.isAuthorizedSender(compoundPolicy, neutralUser);
        recipientAuth = registry.isAuthorizedRecipient(compoundPolicy, neutralUser);
        isAuth = registry.isAuthorized(compoundPolicy, neutralUser);

        assertFalse(senderAuth, "neutralUser should NOT be authorized sender");
        assertTrue(recipientAuth, "neutralUser should be authorized recipient");
        assertEq(isAuth, senderAuth && recipientAuth, "isAuthorized != sender && recipient");
        assertFalse(isAuth, "isAuthorized should be false (not both)");
    }

    /// @notice Fuzz test: isAuthorized equivalence for compound policies
    function testFuzz_invariant5_isAuthorizedEquivalence(address user) public onlySolidityImpl {
        vm.assume(user != address(0));

        vm.startPrank(admin);

        uint64 compoundPolicy =
            registry.createCompoundPolicy(whitelistPolicy, blacklistPolicy, whitelistPolicy);

        vm.stopPrank();

        bool senderAuth = registry.isAuthorizedSender(compoundPolicy, user);
        bool recipientAuth = registry.isAuthorizedRecipient(compoundPolicy, user);
        bool isAuth = registry.isAuthorized(compoundPolicy, user);

        assertEq(isAuth, senderAuth && recipientAuth, "Fuzz: isAuthorized != sender && recipient");
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 6: Built-in Policy Compatibility
    //////////////////////////////////////////////////////////////*/

    /// @notice Compound policies MAY reference built-in policies 0 and 1
    function test_invariant6_canReferenceBuiltinPolicies() public onlySolidityImpl {
        uint64 alwaysReject = 0;
        uint64 alwaysAllow = 1;

        vm.startPrank(admin);

        // Should be able to create compound with built-in policies
        uint64 compoundWithBuiltins = registry.createCompoundPolicy(
            alwaysAllow, // Anyone can send
            alwaysAllow, // Anyone can receive
            alwaysAllow // Anyone can receive mints
        );

        // Verify anyone is authorized
        assertTrue(
            registry.isAuthorizedSender(compoundWithBuiltins, neutralUser),
            "Should allow any sender with policy 1"
        );
        assertTrue(
            registry.isAuthorizedRecipient(compoundWithBuiltins, neutralUser),
            "Should allow any recipient with policy 1"
        );

        // Create restrictive compound
        uint64 restrictiveCompound = registry.createCompoundPolicy(
            alwaysReject, // No one can send
            alwaysAllow, // Anyone can receive
            alwaysAllow // Anyone can receive mints
        );

        // Verify no one can send
        assertFalse(
            registry.isAuthorizedSender(restrictiveCompound, neutralUser),
            "Should reject sender with policy 0"
        );
        assertTrue(
            registry.isAuthorizedRecipient(restrictiveCompound, neutralUser),
            "Should allow recipient with policy 1"
        );

        vm.stopPrank();
    }

    /// @notice Test the vendor credits use case from the spec
    /// @dev "Credits that can be minted to anyone and spent to a specific vendor"
    function test_vendorCreditsUseCase() public onlySolidityImpl {
        address vendor = makeAddr("vendor");
        address customer = makeAddr("customer");
        address randomPerson = makeAddr("randomPerson");

        vm.startPrank(admin);

        // Create vendor whitelist (only vendor can receive transfers)
        uint64 vendorWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        registry.modifyPolicyWhitelist(vendorWhitelist, vendor, true);

        // Create vendor credits policy:
        // - senderPolicyId = 1 (always-allow) - anyone holding credits can spend them
        // - recipientPolicyId = vendorWhitelist - can only transfer TO vendor
        // - mintRecipientPolicyId = 1 (always-allow) - credits can be minted to anyone
        uint64 vendorCreditsPolicy = registry.createCompoundPolicy(
            1, // Anyone can send
            vendorWhitelist, // Only vendor can receive
            1 // Anyone can receive mints
        );

        vm.stopPrank();

        // Verify mint: anyone can receive minted credits
        assertTrue(
            registry.isAuthorizedMintRecipient(vendorCreditsPolicy, customer),
            "Customer should be able to receive mints"
        );
        assertTrue(
            registry.isAuthorizedMintRecipient(vendorCreditsPolicy, randomPerson),
            "Random person should be able to receive mints"
        );

        // Verify transfers: anyone can send, but only to vendor
        assertTrue(
            registry.isAuthorizedSender(vendorCreditsPolicy, customer),
            "Customer should be able to send"
        );
        assertTrue(
            registry.isAuthorizedSender(vendorCreditsPolicy, randomPerson),
            "Random person should be able to send"
        );

        assertTrue(
            registry.isAuthorizedRecipient(vendorCreditsPolicy, vendor),
            "Vendor should be able to receive"
        );
        assertFalse(
            registry.isAuthorizedRecipient(vendorCreditsPolicy, customer),
            "Customer should NOT be able to receive (peer-to-peer blocked)"
        );
        assertFalse(
            registry.isAuthorizedRecipient(vendorCreditsPolicy, randomPerson),
            "Random person should NOT be able to receive"
        );
    }

    /// @notice Test asymmetric transfer scenario from the spec
    /// @dev "Block sanctioned addresses from sending, while allowing anyone to receive"
    function test_asymmetricSenderRestriction() public onlySolidityImpl {
        address sanctionedUser = makeAddr("sanctionedUser");
        address normalUser = makeAddr("normalUser");

        vm.startPrank(admin);

        // Create sender blacklist (sanctioned addresses cannot send)
        uint64 senderBlacklist = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(senderBlacklist, sanctionedUser, true);

        // Create asymmetric policy:
        // - Sender must not be on blacklist
        // - Anyone can receive (for refunds/seizure)
        uint64 asymmetricPolicy = registry.createCompoundPolicy(
            senderBlacklist, // Blacklisted users cannot send
            1, // Anyone can receive
            1 // Anyone can receive mints
        );

        vm.stopPrank();

        // Sanctioned user cannot send
        assertFalse(
            registry.isAuthorizedSender(asymmetricPolicy, sanctionedUser),
            "Sanctioned user should NOT be able to send"
        );

        // Normal user can send
        assertTrue(
            registry.isAuthorizedSender(asymmetricPolicy, normalUser),
            "Normal user should be able to send"
        );

        // Both can receive (for seizure/refunds)
        assertTrue(
            registry.isAuthorizedRecipient(asymmetricPolicy, sanctionedUser),
            "Sanctioned user should be able to receive"
        );
        assertTrue(
            registry.isAuthorizedRecipient(asymmetricPolicy, normalUser),
            "Normal user should be able to receive"
        );
    }

}
