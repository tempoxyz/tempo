// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../src/TIP20.sol";
import { IStablecoinDEX } from "../src/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "./BaseTest.t.sol";

/// @title TIP-1015 Compound Policy Tests
/// @notice Unit tests and stateless fuzz tests for compound transfer policies as specified in TIP-1015
/// @dev Tests both TIP403Registry compound policy functions and TIP-20 integration
contract TIP1015Test is BaseTest {

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    uint64 internal whitelistPolicy;
    uint64 internal blacklistPolicy;
    uint64 internal senderOnlyPolicy;
    uint64 internal recipientOnlyPolicy;
    uint64 internal mintRecipientWhitelist;
    uint64 internal senderBlacklist;

    uint64 internal compoundPolicy;
    uint64 internal asymmetricCompound;
    uint64 internal vendorCreditsPolicy;

    address internal sender;
    address internal recipient;
    address internal mintRecipient;
    address internal blockedUser;
    address internal whitelistedUser;
    address internal neutralUser;

    TIP20 internal compoundToken;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        sender = makeAddr("sender");
        recipient = makeAddr("recipient");
        mintRecipient = makeAddr("mintRecipient");
        blockedUser = makeAddr("blockedUser");
        whitelistedUser = makeAddr("whitelistedUser");
        neutralUser = makeAddr("neutralUser");

        vm.startPrank(admin);

        whitelistPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        blacklistPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        senderOnlyPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        recipientOnlyPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        mintRecipientWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        senderBlacklist = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        registry.modifyPolicyWhitelist(whitelistPolicy, whitelistedUser, true);
        registry.modifyPolicyBlacklist(blacklistPolicy, blockedUser, true);
        registry.modifyPolicyWhitelist(senderOnlyPolicy, whitelistedUser, true);
        registry.modifyPolicyWhitelist(senderOnlyPolicy, sender, true);
        registry.modifyPolicyWhitelist(recipientOnlyPolicy, neutralUser, true);
        registry.modifyPolicyWhitelist(recipientOnlyPolicy, recipient, true);
        registry.modifyPolicyWhitelist(mintRecipientWhitelist, mintRecipient, true);
        registry.modifyPolicyBlacklist(senderBlacklist, blockedUser, true);

        compoundPolicy = registry.createCompoundPolicy(
            senderOnlyPolicy, recipientOnlyPolicy, mintRecipientWhitelist
        );

        asymmetricCompound = registry.createCompoundPolicy(
            senderBlacklist,
            1,
            1
        );

        vendorCreditsPolicy = registry.createCompoundPolicy(
            1,
            recipientOnlyPolicy,
            1
        );

        compoundToken = TIP20(
            factory.createToken("COMPOUND", "CMP", "USD", pathUSD, admin, bytes32("compound"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        compoundToken.changeTransferPolicyId(compoundPolicy);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 1: Simple Policy Constraint
    //////////////////////////////////////////////////////////////*/

    function test_invariant1_cannotReferenceCompoundPolicy() public {
        vm.startPrank(admin);

        uint64 cp = registry.createCompoundPolicy(whitelistPolicy, blacklistPolicy, whitelistPolicy);

        vm.expectRevert(ITIP403Registry.PolicyNotSimple.selector);
        registry.createCompoundPolicy(cp, whitelistPolicy, whitelistPolicy);

        vm.expectRevert(ITIP403Registry.PolicyNotSimple.selector);
        registry.createCompoundPolicy(whitelistPolicy, cp, whitelistPolicy);

        vm.expectRevert(ITIP403Registry.PolicyNotSimple.selector);
        registry.createCompoundPolicy(whitelistPolicy, whitelistPolicy, cp);

        vm.stopPrank();
    }

    function test_invariant1_canReferenceSimplePolicies() public {
        vm.startPrank(admin);

        uint64 cp = registry.createCompoundPolicy(whitelistPolicy, blacklistPolicy, senderOnlyPolicy);

        (uint64 senderPid, uint64 recipientPid, uint64 mintPid) = registry.compoundPolicyData(cp);

        assertEq(senderPid, whitelistPolicy);
        assertEq(recipientPid, blacklistPolicy);
        assertEq(mintPid, senderOnlyPolicy);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 2: Immutability
    //////////////////////////////////////////////////////////////*/

    function test_invariant2_compoundPolicyHasNoAdmin() public {
        vm.startPrank(admin);

        uint64 cp = registry.createCompoundPolicy(whitelistPolicy, whitelistPolicy, whitelistPolicy);

        (ITIP403Registry.PolicyType policyType, address policyAdmin) = registry.policyData(cp);

        assertEq(uint8(policyType), uint8(ITIP403Registry.PolicyType.COMPOUND));
        assertEq(policyAdmin, address(0));

        vm.stopPrank();
    }

    function test_invariant2_cannotModifyCompoundPolicy() public {
        vm.startPrank(admin);
        uint64 cp = registry.createCompoundPolicy(whitelistPolicy, whitelistPolicy, whitelistPolicy);
        vm.stopPrank();

        vm.expectRevert();
        registry.modifyPolicyWhitelist(cp, neutralUser, true);

        vm.expectRevert();
        registry.modifyPolicyBlacklist(cp, neutralUser, true);
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 3: Existence Check
    //////////////////////////////////////////////////////////////*/

    function test_invariant3_revertsOnNonExistentPolicy() public {
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

    function test_invariant4_simplePolicyEquivalence() public {
        bool senderAuth = registry.isAuthorizedSender(whitelistPolicy, whitelistedUser);
        bool recipientAuth = registry.isAuthorizedRecipient(whitelistPolicy, whitelistedUser);
        bool mintAuth = registry.isAuthorizedMintRecipient(whitelistPolicy, whitelistedUser);
        bool general = registry.isAuthorized(whitelistPolicy, whitelistedUser);

        assertEq(senderAuth, recipientAuth);
        assertEq(recipientAuth, mintAuth);
        assertEq(senderAuth, general);

        senderAuth = registry.isAuthorizedSender(whitelistPolicy, neutralUser);
        recipientAuth = registry.isAuthorizedRecipient(whitelistPolicy, neutralUser);
        mintAuth = registry.isAuthorizedMintRecipient(whitelistPolicy, neutralUser);

        assertEq(senderAuth, recipientAuth);
        assertEq(recipientAuth, mintAuth);

        senderAuth = registry.isAuthorizedSender(blacklistPolicy, neutralUser);
        recipientAuth = registry.isAuthorizedRecipient(blacklistPolicy, neutralUser);
        mintAuth = registry.isAuthorizedMintRecipient(blacklistPolicy, neutralUser);

        assertEq(senderAuth, recipientAuth);
        assertEq(recipientAuth, mintAuth);
    }

    function testFuzz_invariant4_simplePolicyEquivalence(uint256 policySeed, address user)
        public
       
    {
        vm.assume(user != address(0));

        vm.startPrank(admin);

        ITIP403Registry.PolicyType policyType = policySeed % 2 == 0
            ? ITIP403Registry.PolicyType.WHITELIST
            : ITIP403Registry.PolicyType.BLACKLIST;

        uint64 testPolicy = registry.createPolicy(admin, policyType);

        if (policySeed % 3 == 0) {
            if (policyType == ITIP403Registry.PolicyType.WHITELIST) {
                registry.modifyPolicyWhitelist(testPolicy, user, true);
            } else {
                registry.modifyPolicyBlacklist(testPolicy, user, true);
            }
        }

        vm.stopPrank();

        bool senderAuth = registry.isAuthorizedSender(testPolicy, user);
        bool recipientAuth = registry.isAuthorizedRecipient(testPolicy, user);
        bool mintAuth = registry.isAuthorizedMintRecipient(testPolicy, user);

        assertEq(senderAuth, recipientAuth, "Fuzz: Sender != Recipient");
        assertEq(recipientAuth, mintAuth, "Fuzz: Recipient != MintRecipient");
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 5: isAuthorized Equivalence
    //////////////////////////////////////////////////////////////*/

    function test_invariant5_isAuthorizedEquivalence() public {
        vm.startPrank(admin);

        uint64 cp = registry.createCompoundPolicy(
            senderOnlyPolicy,
            recipientOnlyPolicy,
            whitelistPolicy
        );

        vm.stopPrank();

        bool senderAuth = registry.isAuthorizedSender(cp, whitelistedUser);
        bool recipientAuth = registry.isAuthorizedRecipient(cp, whitelistedUser);
        bool isAuth = registry.isAuthorized(cp, whitelistedUser);

        assertTrue(senderAuth);
        assertFalse(recipientAuth);
        assertEq(isAuth, senderAuth && recipientAuth);
        assertFalse(isAuth);

        senderAuth = registry.isAuthorizedSender(cp, neutralUser);
        recipientAuth = registry.isAuthorizedRecipient(cp, neutralUser);
        isAuth = registry.isAuthorized(cp, neutralUser);

        assertFalse(senderAuth);
        assertTrue(recipientAuth);
        assertEq(isAuth, senderAuth && recipientAuth);
        assertFalse(isAuth);
    }

    function testFuzz_invariant5_isAuthorizedEquivalence(address user) public {
        vm.assume(user != address(0));

        vm.startPrank(admin);
        uint64 cp = registry.createCompoundPolicy(whitelistPolicy, blacklistPolicy, whitelistPolicy);
        vm.stopPrank();

        bool senderAuth = registry.isAuthorizedSender(cp, user);
        bool recipientAuth = registry.isAuthorizedRecipient(cp, user);
        bool isAuth = registry.isAuthorized(cp, user);

        assertEq(isAuth, senderAuth && recipientAuth, "Fuzz: isAuthorized != sender && recipient");
    }

    /*//////////////////////////////////////////////////////////////
                    INVARIANT 6: Built-in Policy Compatibility
    //////////////////////////////////////////////////////////////*/

    function test_invariant6_canReferenceBuiltinPolicies() public {
        uint64 alwaysReject = 0;
        uint64 alwaysAllow = 1;

        vm.startPrank(admin);

        uint64 cpAllow = registry.createCompoundPolicy(alwaysAllow, alwaysAllow, alwaysAllow);

        assertTrue(registry.isAuthorizedSender(cpAllow, neutralUser));
        assertTrue(registry.isAuthorizedRecipient(cpAllow, neutralUser));

        uint64 cpRestrict = registry.createCompoundPolicy(alwaysReject, alwaysAllow, alwaysAllow);

        assertFalse(registry.isAuthorizedSender(cpRestrict, neutralUser));
        assertTrue(registry.isAuthorizedRecipient(cpRestrict, neutralUser));

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    USE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_vendorCreditsUseCase() public {
        address vendor = makeAddr("vendor");
        address customer = makeAddr("customer");
        address randomPerson = makeAddr("randomPerson");

        vm.startPrank(admin);

        uint64 vendorWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        registry.modifyPolicyWhitelist(vendorWhitelist, vendor, true);

        uint64 vendorPolicy = registry.createCompoundPolicy(1, vendorWhitelist, 1);

        vm.stopPrank();

        assertTrue(registry.isAuthorizedMintRecipient(vendorPolicy, customer));
        assertTrue(registry.isAuthorizedMintRecipient(vendorPolicy, randomPerson));

        assertTrue(registry.isAuthorizedSender(vendorPolicy, customer));
        assertTrue(registry.isAuthorizedSender(vendorPolicy, randomPerson));

        assertTrue(registry.isAuthorizedRecipient(vendorPolicy, vendor));
        assertFalse(registry.isAuthorizedRecipient(vendorPolicy, customer));
        assertFalse(registry.isAuthorizedRecipient(vendorPolicy, randomPerson));
    }

    function test_asymmetricSenderRestriction() public {
        address sanctionedUser = makeAddr("sanctionedUser");
        address normalUser = makeAddr("normalUser");

        vm.startPrank(admin);

        uint64 senderBL = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(senderBL, sanctionedUser, true);

        uint64 asymPolicy = registry.createCompoundPolicy(senderBL, 1, 1);

        vm.stopPrank();

        assertFalse(registry.isAuthorizedSender(asymPolicy, sanctionedUser));
        assertTrue(registry.isAuthorizedSender(asymPolicy, normalUser));

        assertTrue(registry.isAuthorizedRecipient(asymPolicy, sanctionedUser));
        assertTrue(registry.isAuthorizedRecipient(asymPolicy, normalUser));
    }

    /*//////////////////////////////////////////////////////////////
                    TIP-20 MINT INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_mint_succeeds_authorizedMintRecipient_simplePolicy() public {
        vm.startPrank(admin);

        TIP20 simpleToken =
            TIP20(factory.createToken("SIMPLE", "SMP", "USD", pathUSD, admin, bytes32("simple")));
        simpleToken.grantRole(_ISSUER_ROLE, admin);
        simpleToken.changeTransferPolicyId(mintRecipientWhitelist);

        simpleToken.mint(mintRecipient, 1000);
        assertEq(simpleToken.balanceOf(mintRecipient), 1000);

        vm.stopPrank();
    }

    function test_mint_fails_unauthorizedMintRecipient_simplePolicy() public {
        vm.startPrank(admin);

        TIP20 simpleToken = TIP20(
            factory.createToken("SIMPLE2", "SMP2", "USD", pathUSD, admin, bytes32("simple2"))
        );
        simpleToken.grantRole(_ISSUER_ROLE, admin);
        simpleToken.changeTransferPolicyId(mintRecipientWhitelist);

        vm.expectRevert(ITIP20.PolicyForbids.selector);
        simpleToken.mint(blockedUser, 1000);

        vm.stopPrank();
    }

    function test_mint_succeeds_authorizedMintRecipient_compoundPolicy() public {
        vm.startPrank(admin);
        compoundToken.mint(mintRecipient, 1000);
        assertEq(compoundToken.balanceOf(mintRecipient), 1000);
        vm.stopPrank();
    }

    function test_mint_fails_unauthorizedMintRecipient_compoundPolicy() public {
        vm.startPrank(admin);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        compoundToken.mint(blockedUser, 1000);
        vm.stopPrank();
    }

    function test_mint_usesCorrectSubPolicy() public {
        vm.startPrank(admin);

        vm.expectRevert(ITIP20.PolicyForbids.selector);
        compoundToken.mint(sender, 1000);

        vm.expectRevert(ITIP20.PolicyForbids.selector);
        compoundToken.mint(recipient, 1000);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    TIP-20 TRANSFER INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_transfer_succeeds_bothAuthorized_simplePolicy() public {
        vm.startPrank(admin);

        TIP20 simpleToken =
            TIP20(factory.createToken("XFER1", "XF1", "USD", pathUSD, admin, bytes32("xfer1")));
        simpleToken.grantRole(_ISSUER_ROLE, admin);
        simpleToken.changeTransferPolicyId(1);
        simpleToken.mint(sender, 1000);

        vm.stopPrank();

        vm.prank(sender);
        simpleToken.transfer(recipient, 500);

        assertEq(simpleToken.balanceOf(sender), 500);
        assertEq(simpleToken.balanceOf(recipient), 500);
    }

    function test_transfer_fails_senderBlacklisted_simplePolicy() public {
        vm.startPrank(admin);

        TIP20 simpleToken =
            TIP20(factory.createToken("XFER2", "XF2", "USD", pathUSD, admin, bytes32("xfer2")));
        simpleToken.grantRole(_ISSUER_ROLE, admin);
        simpleToken.changeTransferPolicyId(1);
        simpleToken.mint(blockedUser, 1000);
        simpleToken.changeTransferPolicyId(senderBlacklist);

        vm.stopPrank();

        vm.prank(blockedUser);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        simpleToken.transfer(recipient, 500);
    }

    function test_transfer_succeeds_bothAuthorized_compoundPolicy() public {
        vm.startPrank(admin);

        registry.modifyPolicyWhitelist(mintRecipientWhitelist, sender, true);
        compoundToken.mint(sender, 1000);

        vm.stopPrank();

        vm.prank(sender);
        compoundToken.transfer(recipient, 500);

        assertEq(compoundToken.balanceOf(sender), 500);
        assertEq(compoundToken.balanceOf(recipient), 500);
    }

    function test_transfer_fails_senderUnauthorized_compoundPolicy() public {
        vm.startPrank(admin);

        TIP20 testToken =
            TIP20(factory.createToken("XFER3", "XF3", "USD", pathUSD, admin, bytes32("xfer3")));
        testToken.grantRole(_ISSUER_ROLE, admin);

        uint64 testCompound = registry.createCompoundPolicy(senderOnlyPolicy, 1, 1);

        testToken.changeTransferPolicyId(1);
        testToken.mint(blockedUser, 1000);
        testToken.changeTransferPolicyId(testCompound);

        vm.stopPrank();

        vm.prank(blockedUser);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.transfer(recipient, 500);
    }

    function test_transfer_fails_recipientUnauthorized_compoundPolicy() public {
        vm.startPrank(admin);

        TIP20 testToken =
            TIP20(factory.createToken("XFER4", "XF4", "USD", pathUSD, admin, bytes32("xfer4")));
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.changeTransferPolicyId(1);
        testToken.mint(sender, 1000);
        testToken.changeTransferPolicyId(vendorCreditsPolicy);

        vm.stopPrank();

        vm.prank(sender);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.transfer(blockedUser, 500);
    }

    function test_transfer_asymmetricCompound_blockedCanReceiveNotSend() public {
        vm.startPrank(admin);

        TIP20 testToken =
            TIP20(factory.createToken("ASYM1", "ASY1", "USD", pathUSD, admin, bytes32("asym1")));
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.changeTransferPolicyId(1);
        testToken.mint(sender, 1000);
        testToken.mint(blockedUser, 500);
        testToken.changeTransferPolicyId(asymmetricCompound);

        vm.stopPrank();

        vm.prank(sender);
        testToken.transfer(blockedUser, 200);
        assertEq(testToken.balanceOf(blockedUser), 700);

        vm.prank(blockedUser);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.transfer(sender, 100);
    }

    /*//////////////////////////////////////////////////////////////
                    TIP-20 BURN_BLOCKED INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_burnBlocked_succeeds_blockedSender_simplePolicy() public {
        vm.startPrank(admin);

        TIP20 testToken =
            TIP20(factory.createToken("BURN1", "BRN1", "USD", pathUSD, admin, bytes32("burn1")));
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);

        testToken.changeTransferPolicyId(1);
        testToken.mint(blockedUser, 1000);
        testToken.changeTransferPolicyId(senderBlacklist);

        testToken.burnBlocked(blockedUser, 500);
        assertEq(testToken.balanceOf(blockedUser), 500);

        vm.stopPrank();
    }

    function test_burnBlocked_fails_authorizedSender_simplePolicy() public {
        vm.startPrank(admin);

        TIP20 testToken =
            TIP20(factory.createToken("BURN2", "BRN2", "USD", pathUSD, admin, bytes32("burn2")));
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        testToken.changeTransferPolicyId(1);
        testToken.mint(sender, 1000);

        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.burnBlocked(sender, 500);

        vm.stopPrank();
    }

    function test_burnBlocked_succeeds_blockedSender_compoundPolicy() public {
        vm.startPrank(admin);

        TIP20 testToken =
            TIP20(factory.createToken("BURN3", "BRN3", "USD", pathUSD, admin, bytes32("burn3")));
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);

        testToken.changeTransferPolicyId(1);
        testToken.mint(blockedUser, 1000);
        testToken.changeTransferPolicyId(asymmetricCompound);

        testToken.burnBlocked(blockedUser, 500);
        assertEq(testToken.balanceOf(blockedUser), 500);

        vm.stopPrank();
    }

    function test_burnBlocked_fails_authorizedSender_compoundPolicy() public {
        vm.startPrank(admin);

        TIP20 testToken =
            TIP20(factory.createToken("BURN4", "BRN4", "USD", pathUSD, admin, bytes32("burn4")));
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);

        testToken.changeTransferPolicyId(1);
        testToken.mint(sender, 1000);
        testToken.changeTransferPolicyId(asymmetricCompound);

        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.burnBlocked(sender, 500);

        vm.stopPrank();
    }

    function test_burnBlocked_checksCorrectSubPolicy() public {
        vm.startPrank(admin);

        uint64 recipientBlacklist = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(recipientBlacklist, blockedUser, true);

        uint64 recipientBlockedCompound = registry.createCompoundPolicy(1, recipientBlacklist, 1);

        TIP20 testToken =
            TIP20(factory.createToken("BURN5", "BRN5", "USD", pathUSD, admin, bytes32("burn5")));
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);

        testToken.changeTransferPolicyId(1);
        testToken.mint(blockedUser, 1000);
        testToken.changeTransferPolicyId(recipientBlockedCompound);

        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.burnBlocked(blockedUser, 500);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    DEX CANCEL_STALE_ORDER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_cancelStaleOrder_succeeds_blockedMaker_simplePolicy() public {
        uint128 MIN_ORDER = 100_000_000;

        vm.startPrank(admin);

        TIP20 baseToken =
            TIP20(factory.createToken("BASE1", "BS1", "USD", pathUSD, admin, bytes32("base1")));
        baseToken.grantRole(_ISSUER_ROLE, admin);
        baseToken.changeTransferPolicyId(1);
        baseToken.mint(sender, MIN_ORDER * 10);

        exchange.createPair(address(baseToken));

        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(sender, MIN_ORDER * 10);
        vm.stopPrank();

        vm.startPrank(sender);
        baseToken.approve(address(exchange), type(uint256).max);
        pathUSD.approve(address(exchange), type(uint256).max);

        uint128 orderId = exchange.place(address(baseToken), MIN_ORDER, true, 0);
        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        uint64 makerBlacklist = registry.createPolicy(pathUSDAdmin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(makerBlacklist, sender, true);
        pathUSD.changeTransferPolicyId(makerBlacklist);
        vm.stopPrank();

        vm.prank(recipient);
        exchange.cancelStaleOrder(orderId);
    }

    function test_cancelStaleOrder_fails_authorizedMaker_simplePolicy() public {
        uint128 MIN_ORDER = 100_000_000;

        vm.startPrank(admin);

        TIP20 baseToken =
            TIP20(factory.createToken("BASE2", "BS2", "USD", pathUSD, admin, bytes32("base2")));
        baseToken.grantRole(_ISSUER_ROLE, admin);
        baseToken.changeTransferPolicyId(1);
        baseToken.mint(sender, MIN_ORDER * 10);

        exchange.createPair(address(baseToken));

        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(sender, MIN_ORDER * 10);
        vm.stopPrank();

        vm.startPrank(sender);
        baseToken.approve(address(exchange), type(uint256).max);
        pathUSD.approve(address(exchange), type(uint256).max);

        uint128 orderId = exchange.place(address(baseToken), MIN_ORDER, true, 0);
        vm.stopPrank();

        vm.prank(recipient);
        vm.expectRevert(IStablecoinDEX.OrderNotStale.selector);
        exchange.cancelStaleOrder(orderId);
    }

    function test_cancelStaleOrder_succeeds_blockedMaker_compoundPolicy() public {
        uint128 MIN_ORDER = 100_000_000;

        vm.startPrank(admin);

        TIP20 baseToken =
            TIP20(factory.createToken("BASE3", "BS3", "USD", pathUSD, admin, bytes32("base3")));
        baseToken.grantRole(_ISSUER_ROLE, admin);
        baseToken.changeTransferPolicyId(1);
        baseToken.mint(sender, MIN_ORDER * 10);

        exchange.createPair(address(baseToken));

        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(sender, MIN_ORDER * 10);
        vm.stopPrank();

        vm.startPrank(sender);
        baseToken.approve(address(exchange), type(uint256).max);
        pathUSD.approve(address(exchange), type(uint256).max);

        uint128 orderId = exchange.place(address(baseToken), MIN_ORDER, true, 0);
        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        uint64 senderOnlyBL = registry.createPolicy(pathUSDAdmin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(senderOnlyBL, sender, true);

        uint64 staleCompound = registry.createCompoundPolicy(senderOnlyBL, 1, 1);
        pathUSD.changeTransferPolicyId(staleCompound);
        vm.stopPrank();

        vm.prank(recipient);
        exchange.cancelStaleOrder(orderId);
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_transfer_compoundPolicyRespected(
        bool senderInWhitelist,
        bool recipientInWhitelist,
        uint256 amount
    ) public {
        amount = bound(amount, 1, 1_000_000);

        address testSender = makeAddr("fuzzSender");
        address testRecipient = makeAddr("fuzzRecipient");

        vm.startPrank(admin);

        uint64 sPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        uint64 rPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        if (senderInWhitelist) {
            registry.modifyPolicyWhitelist(sPolicy, testSender, true);
        }
        if (recipientInWhitelist) {
            registry.modifyPolicyWhitelist(rPolicy, testRecipient, true);
        }

        uint64 fuzzCompound = registry.createCompoundPolicy(sPolicy, rPolicy, 1);

        TIP20 fuzzToken = TIP20(
            factory.createToken(
                "FUZZ",
                "FZZ",
                "USD",
                pathUSD,
                admin,
                keccak256(abi.encode(senderInWhitelist, recipientInWhitelist))
            )
        );
        fuzzToken.grantRole(_ISSUER_ROLE, admin);
        fuzzToken.changeTransferPolicyId(1);
        fuzzToken.mint(testSender, amount);
        fuzzToken.changeTransferPolicyId(fuzzCompound);

        vm.stopPrank();

        vm.prank(testSender);
        if (senderInWhitelist && recipientInWhitelist) {
            fuzzToken.transfer(testRecipient, amount);
            assertEq(fuzzToken.balanceOf(testRecipient), amount);
        } else {
            vm.expectRevert(ITIP20.PolicyForbids.selector);
            fuzzToken.transfer(testRecipient, amount);
        }
    }

    function testFuzz_mint_onlyChecksMintRecipientPolicy(
        bool inSenderPolicy,
        bool inRecipientPolicy,
        bool inMintPolicy,
        uint256 amount
    ) public {
        amount = bound(amount, 1, 1_000_000);

        address testMintRecipient = makeAddr("fuzzMintRecipient");

        vm.startPrank(admin);

        uint64 sPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        uint64 rPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        uint64 mPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        if (inSenderPolicy) {
            registry.modifyPolicyWhitelist(sPolicy, testMintRecipient, true);
        }
        if (inRecipientPolicy) {
            registry.modifyPolicyWhitelist(rPolicy, testMintRecipient, true);
        }
        if (inMintPolicy) {
            registry.modifyPolicyWhitelist(mPolicy, testMintRecipient, true);
        }

        uint64 fuzzCompound = registry.createCompoundPolicy(sPolicy, rPolicy, mPolicy);

        TIP20 fuzzToken = TIP20(
            factory.createToken(
                "FUZZ2",
                "FZ2",
                "USD",
                pathUSD,
                admin,
                keccak256(abi.encode(inSenderPolicy, inRecipientPolicy, inMintPolicy))
            )
        );
        fuzzToken.grantRole(_ISSUER_ROLE, admin);
        fuzzToken.changeTransferPolicyId(fuzzCompound);

        if (inMintPolicy) {
            fuzzToken.mint(testMintRecipient, amount);
            assertEq(fuzzToken.balanceOf(testMintRecipient), amount);
        } else {
            vm.expectRevert(ITIP20.PolicyForbids.selector);
            fuzzToken.mint(testMintRecipient, amount);
        }

        vm.stopPrank();
    }

}
