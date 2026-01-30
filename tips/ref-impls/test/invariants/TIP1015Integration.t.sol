// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title TIP-1015 Integration Tests
/// @notice Tests all precompile calls that perform TIP-403 authorization checks
/// @dev Covers TIP-20 (mint, burn, transfer), DEX (cancelStaleOrder), and fee payment
///      Tests both simple policies (whitelist/blacklist) and compound policies
contract TIP1015IntegrationTest is InvariantBaseTest {

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    // Test users
    address internal sender;
    address internal recipient;
    address internal mintRecipient;
    address internal blockedUser;

    // Simple policies
    uint64 internal senderWhitelist;
    uint64 internal recipientWhitelist;
    uint64 internal mintRecipientWhitelist;
    uint64 internal senderBlacklist;

    // Compound policies
    uint64 internal compoundPolicy;
    uint64 internal asymmetricCompound;
    uint64 internal vendorCreditsPolicy;

    // Test token with compound policy
    TIP20 internal compoundToken;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        // Skip all TIP-1015 tests when running against Rust precompiles
        if (isTempo) {
            return;
        }

        _setupInvariantBase();

        // Create test users
        sender = makeAddr("sender");
        recipient = makeAddr("recipient");
        mintRecipient = makeAddr("mintRecipient");
        blockedUser = makeAddr("blockedUser");

        vm.startPrank(admin);

        // Create simple policies
        senderWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        recipientWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        mintRecipientWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        senderBlacklist = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);

        // Configure simple policies
        registry.modifyPolicyWhitelist(senderWhitelist, sender, true);
        registry.modifyPolicyWhitelist(recipientWhitelist, recipient, true);
        registry.modifyPolicyWhitelist(mintRecipientWhitelist, mintRecipient, true);
        registry.modifyPolicyBlacklist(senderBlacklist, blockedUser, true);

        // Create compound policy: sender whitelist, recipient whitelist, mint recipient whitelist
        compoundPolicy = registry.createCompoundPolicy(
            senderWhitelist,
            recipientWhitelist,
            mintRecipientWhitelist
        );

        // Create asymmetric compound: sender blacklist (block bad actors), anyone can receive
        asymmetricCompound = registry.createCompoundPolicy(
            senderBlacklist,  // blockedUser cannot send
            1,                // anyone can receive (always-allow)
            1                 // anyone can receive mints
        );

        // Create vendor credits: anyone can send, only recipient can receive, anyone can get mints
        vendorCreditsPolicy = registry.createCompoundPolicy(
            1,                   // anyone can send
            recipientWhitelist,  // only recipient can receive
            1                    // anyone can receive mints
        );

        // Create a token with compound policy
        compoundToken = TIP20(
            factory.createToken("COMPOUND", "CMP", "USD", pathUSD, admin, bytes32("compound"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        compoundToken.changeTransferPolicyId(compoundPolicy);

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
                    TIP-20 MINT AUTHORIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mint succeeds when recipient is authorized as mint recipient (simple policy)
    function test_mint_succeeds_authorizedMintRecipient_simplePolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        // Create token with simple whitelist policy
        TIP20 simpleToken = TIP20(
            factory.createToken("SIMPLE", "SMP", "USD", pathUSD, admin, bytes32("simple"))
        );
        simpleToken.grantRole(_ISSUER_ROLE, admin);
        simpleToken.changeTransferPolicyId(mintRecipientWhitelist);

        // Mint to whitelisted recipient should succeed
        simpleToken.mint(mintRecipient, 1000);
        assertEq(simpleToken.balanceOf(mintRecipient), 1000, "Mint should succeed");

        vm.stopPrank();
    }

    /// @notice Mint fails when recipient is not authorized as mint recipient (simple policy)
    function test_mint_fails_unauthorizedMintRecipient_simplePolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        TIP20 simpleToken = TIP20(
            factory.createToken("SIMPLE2", "SMP2", "USD", pathUSD, admin, bytes32("simple2"))
        );
        simpleToken.grantRole(_ISSUER_ROLE, admin);
        simpleToken.changeTransferPolicyId(mintRecipientWhitelist);

        // Mint to non-whitelisted user should fail
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        simpleToken.mint(blockedUser, 1000);

        vm.stopPrank();
    }

    /// @notice Mint succeeds when recipient is authorized via compound policy's mintRecipientPolicyId
    function test_mint_succeeds_authorizedMintRecipient_compoundPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        // mintRecipient is whitelisted in mintRecipientWhitelist (used by compoundPolicy)
        compoundToken.mint(mintRecipient, 1000);
        assertEq(compoundToken.balanceOf(mintRecipient), 1000, "Mint should succeed");

        vm.stopPrank();
    }

    /// @notice Mint fails when recipient is not authorized via compound policy's mintRecipientPolicyId
    function test_mint_fails_unauthorizedMintRecipient_compoundPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        // blockedUser is not in mintRecipientWhitelist
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        compoundToken.mint(blockedUser, 1000);

        vm.stopPrank();
    }

    /// @notice Mint uses mintRecipientPolicyId, not senderPolicyId or recipientPolicyId
    function test_mint_usesCorrectSubPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        // sender is whitelisted as sender but NOT as mint recipient
        // This should fail because mint checks mintRecipientPolicyId
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        compoundToken.mint(sender, 1000);

        // recipient is whitelisted as recipient but NOT as mint recipient
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        compoundToken.mint(recipient, 1000);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    TIP-20 TRANSFER AUTHORIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Transfer succeeds when both sender and recipient are authorized (simple policy)
    function test_transfer_succeeds_bothAuthorized_simplePolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        TIP20 simpleToken = TIP20(
            factory.createToken("XFER1", "XF1", "USD", pathUSD, admin, bytes32("xfer1"))
        );
        simpleToken.grantRole(_ISSUER_ROLE, admin);
        
        // Use always-allow policy (policy ID 1)
        simpleToken.changeTransferPolicyId(1);
        simpleToken.mint(sender, 1000);

        vm.stopPrank();

        vm.prank(sender);
        simpleToken.transfer(recipient, 500);

        assertEq(simpleToken.balanceOf(sender), 500, "Sender balance incorrect");
        assertEq(simpleToken.balanceOf(recipient), 500, "Recipient balance incorrect");
    }

    /// @notice Transfer fails when sender is not authorized (simple blacklist)
    function test_transfer_fails_senderBlacklisted_simplePolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        TIP20 simpleToken = TIP20(
            factory.createToken("XFER2", "XF2", "USD", pathUSD, admin, bytes32("xfer2"))
        );
        simpleToken.grantRole(_ISSUER_ROLE, admin);
        simpleToken.changeTransferPolicyId(senderBlacklist);
        
        // Mint to blockedUser first (using admin privilege before policy is enforced)
        // Actually we need to set policy after mint, or use a permissive mint policy
        simpleToken.changeTransferPolicyId(1); // temporarily allow
        simpleToken.mint(blockedUser, 1000);
        simpleToken.changeTransferPolicyId(senderBlacklist);

        vm.stopPrank();

        vm.prank(blockedUser);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        simpleToken.transfer(recipient, 500);
    }

    /// @notice Transfer succeeds with compound policy when sender and recipient are authorized
    function test_transfer_succeeds_bothAuthorized_compoundPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        // First mint to sender (need to add sender to mint whitelist temporarily)
        registry.modifyPolicyWhitelist(mintRecipientWhitelist, sender, true);
        compoundToken.mint(sender, 1000);

        vm.stopPrank();

        // sender is in senderWhitelist, recipient is in recipientWhitelist
        vm.prank(sender);
        compoundToken.transfer(recipient, 500);

        assertEq(compoundToken.balanceOf(sender), 500, "Sender balance incorrect");
        assertEq(compoundToken.balanceOf(recipient), 500, "Recipient balance incorrect");
    }

    /// @notice Transfer fails with compound policy when sender is not authorized
    function test_transfer_fails_senderUnauthorized_compoundPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        // Mint to blockedUser via always-allow mint recipient policy
        TIP20 testToken = TIP20(
            factory.createToken("XFER3", "XF3", "USD", pathUSD, admin, bytes32("xfer3"))
        );
        testToken.grantRole(_ISSUER_ROLE, admin);
        
        // Create compound: blockedUser not in sender whitelist
        uint64 testCompound = registry.createCompoundPolicy(
            senderWhitelist,     // blockedUser is NOT here
            1,                   // anyone can receive
            1                    // anyone can get mints
        );
        
        testToken.changeTransferPolicyId(1);  // allow mint
        testToken.mint(blockedUser, 1000);
        testToken.changeTransferPolicyId(testCompound);

        vm.stopPrank();

        vm.prank(blockedUser);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.transfer(recipient, 500);
    }

    /// @notice Transfer fails with compound policy when recipient is not authorized
    function test_transfer_fails_recipientUnauthorized_compoundPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        // Use vendorCreditsPolicy: anyone can send, only recipient whitelist can receive
        TIP20 testToken = TIP20(
            factory.createToken("XFER4", "XF4", "USD", pathUSD, admin, bytes32("xfer4"))
        );
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.changeTransferPolicyId(1);  // allow mint
        testToken.mint(sender, 1000);
        testToken.changeTransferPolicyId(vendorCreditsPolicy);

        vm.stopPrank();

        // sender can send (policy 1), but blockedUser cannot receive (not in recipientWhitelist)
        vm.prank(sender);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.transfer(blockedUser, 500);
    }

    /// @notice Asymmetric compound: blocked sender can receive but not send
    function test_transfer_asymmetricCompound_blockedCanReceiveNotSend() public onlySolidityImpl {
        vm.startPrank(admin);

        TIP20 testToken = TIP20(
            factory.createToken("ASYM1", "ASY1", "USD", pathUSD, admin, bytes32("asym1"))
        );
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.changeTransferPolicyId(1);  // allow mints
        testToken.mint(sender, 1000);
        testToken.mint(blockedUser, 500);
        testToken.changeTransferPolicyId(asymmetricCompound);

        vm.stopPrank();

        // sender (not blocked) can send to blockedUser (anyone can receive)
        vm.prank(sender);
        testToken.transfer(blockedUser, 200);
        assertEq(testToken.balanceOf(blockedUser), 700, "blockedUser should receive");

        // blockedUser cannot send (blacklisted as sender)
        vm.prank(blockedUser);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.transfer(sender, 100);
    }

    /*//////////////////////////////////////////////////////////////
                    TIP-20 BURN_BLOCKED AUTHORIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice burnBlocked succeeds when address is blocked from sending (simple policy)
    function test_burnBlocked_succeeds_blockedSender_simplePolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        TIP20 testToken = TIP20(
            factory.createToken("BURN1", "BRN1", "USD", pathUSD, admin, bytes32("burn1"))
        );
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        
        // Mint first, then set restrictive policy
        testToken.changeTransferPolicyId(1);
        testToken.mint(blockedUser, 1000);
        testToken.changeTransferPolicyId(senderBlacklist);

        // blockedUser is blacklisted, so burnBlocked should succeed
        testToken.burnBlocked(blockedUser, 500);
        assertEq(testToken.balanceOf(blockedUser), 500, "Burn should reduce balance");

        vm.stopPrank();
    }

    /// @notice burnBlocked fails when address is authorized to send (simple policy)
    function test_burnBlocked_fails_authorizedSender_simplePolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        TIP20 testToken = TIP20(
            factory.createToken("BURN2", "BRN2", "USD", pathUSD, admin, bytes32("burn2"))
        );
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        testToken.changeTransferPolicyId(1);  // always allow
        testToken.mint(sender, 1000);

        // sender is authorized, so burnBlocked should fail
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.burnBlocked(sender, 500);

        vm.stopPrank();
    }

    /// @notice burnBlocked succeeds when address is blocked via compound policy's senderPolicyId
    function test_burnBlocked_succeeds_blockedSender_compoundPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        TIP20 testToken = TIP20(
            factory.createToken("BURN3", "BRN3", "USD", pathUSD, admin, bytes32("burn3"))
        );
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        
        testToken.changeTransferPolicyId(1);
        testToken.mint(blockedUser, 1000);
        testToken.changeTransferPolicyId(asymmetricCompound);  // blockedUser is in senderBlacklist

        // blockedUser is blocked as sender via compound policy
        testToken.burnBlocked(blockedUser, 500);
        assertEq(testToken.balanceOf(blockedUser), 500, "Burn should reduce balance");

        vm.stopPrank();
    }

    /// @notice burnBlocked fails when address is authorized via compound policy
    function test_burnBlocked_fails_authorizedSender_compoundPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        TIP20 testToken = TIP20(
            factory.createToken("BURN4", "BRN4", "USD", pathUSD, admin, bytes32("burn4"))
        );
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        
        testToken.changeTransferPolicyId(1);
        testToken.mint(sender, 1000);
        testToken.changeTransferPolicyId(asymmetricCompound);  // sender is NOT blocked

        // sender is authorized as sender, burnBlocked should fail
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.burnBlocked(sender, 500);

        vm.stopPrank();
    }

    /// @notice burnBlocked checks senderPolicyId, not recipientPolicyId
    function test_burnBlocked_checksCorrectSubPolicy() public onlySolidityImpl {
        vm.startPrank(admin);

        // Create a blacklist where ONLY blockedUser is blocked as recipient (not sender)
        uint64 recipientBlacklist = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(recipientBlacklist, blockedUser, true);

        // Create compound where user is blocked as recipient but allowed as sender
        uint64 recipientBlockedCompound = registry.createCompoundPolicy(
            1,                   // anyone can send (blockedUser CAN send)
            recipientBlacklist,  // blockedUser cannot receive
            1                    // anyone can mint
        );

        TIP20 testToken = TIP20(
            factory.createToken("BURN5", "BRN5", "USD", pathUSD, admin, bytes32("burn5"))
        );
        testToken.grantRole(_ISSUER_ROLE, admin);
        testToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        
        testToken.changeTransferPolicyId(1);
        testToken.mint(blockedUser, 1000);
        testToken.changeTransferPolicyId(recipientBlockedCompound);

        // blockedUser is blocked as RECIPIENT but allowed as SENDER
        // burnBlocked checks sender authorization, so this should FAIL (user CAN send)
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        testToken.burnBlocked(blockedUser, 500);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    DEX CANCEL_STALE_ORDER TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice cancelStaleOrder succeeds when maker is blocked from sending
    function test_cancelStaleOrder_succeeds_blockedMaker_simplePolicy() public onlySolidityImpl {
        uint128 MIN_ORDER = 100_000_000; // DEX minimum order amount
        
        vm.startPrank(admin);

        // Create and configure token for DEX
        TIP20 baseToken = TIP20(
            factory.createToken("BASE1", "BS1", "USD", pathUSD, admin, bytes32("base1"))
        );
        baseToken.grantRole(_ISSUER_ROLE, admin);
        
        // Mint to sender first
        baseToken.changeTransferPolicyId(1);
        baseToken.mint(sender, MIN_ORDER * 10);
        
        // Create DEX pair
        exchange.createPair(address(baseToken));

        vm.stopPrank();
        
        // Mint pathUSD to sender for placing bid orders (pathUSDAdmin is the issuer)
        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(sender, MIN_ORDER * 10);
        vm.stopPrank();

        // sender places an order
        vm.startPrank(sender);
        baseToken.approve(address(exchange), type(uint256).max);
        pathUSD.approve(address(exchange), type(uint256).max);
        
        uint128 orderId = exchange.place(address(baseToken), MIN_ORDER, true, 0);
        vm.stopPrank();

        // Now blacklist the sender on pathUSD (the escrowed token for bid orders)
        // For bid orders, the checked token is book.quote (pathUSD)
        vm.startPrank(pathUSDAdmin);
        uint64 makerBlacklist = registry.createPolicy(pathUSDAdmin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(makerBlacklist, sender, true);
        pathUSD.changeTransferPolicyId(makerBlacklist);
        vm.stopPrank();

        // Anyone can cancel the stale order since maker is blocked on pathUSD
        vm.prank(recipient);
        exchange.cancelStaleOrder(orderId);
    }

    /// @notice cancelStaleOrder fails when maker is still authorized
    function test_cancelStaleOrder_fails_authorizedMaker_simplePolicy() public onlySolidityImpl {
        uint128 MIN_ORDER = 100_000_000;
        
        vm.startPrank(admin);

        TIP20 baseToken = TIP20(
            factory.createToken("BASE2", "BS2", "USD", pathUSD, admin, bytes32("base2"))
        );
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

        // Try to cancel without blacklisting - should fail
        vm.prank(recipient);
        vm.expectRevert(IStablecoinDEX.OrderNotStale.selector);
        exchange.cancelStaleOrder(orderId);
    }

    /// @notice cancelStaleOrder with compound policy checks senderPolicyId
    function test_cancelStaleOrder_succeeds_blockedMaker_compoundPolicy() public onlySolidityImpl {
        uint128 MIN_ORDER = 100_000_000;
        
        vm.startPrank(admin);

        TIP20 baseToken = TIP20(
            factory.createToken("BASE3", "BS3", "USD", pathUSD, admin, bytes32("base3"))
        );
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

        // Blacklist sender via compound policy on pathUSD (the escrowed token for bid orders)
        vm.startPrank(pathUSDAdmin);
        uint64 senderOnlyBlacklist = registry.createPolicy(pathUSDAdmin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(senderOnlyBlacklist, sender, true);
        
        uint64 staleCompound = registry.createCompoundPolicy(
            senderOnlyBlacklist,  // sender is blocked
            1,                    // anyone can receive
            1                     // anyone can mint
        );
        pathUSD.changeTransferPolicyId(staleCompound);
        vm.stopPrank();

        // Cancel should succeed since maker is blocked as sender on pathUSD
        vm.prank(recipient);
        exchange.cancelStaleOrder(orderId);
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz: Transfer authorization respects compound policy structure
    function testFuzz_transfer_compoundPolicyRespected(
        bool senderInWhitelist,
        bool recipientInWhitelist,
        uint256 amount
    ) public onlySolidityImpl {
        amount = bound(amount, 1, 1_000_000);

        address testSender = makeAddr("fuzzSender");
        address testRecipient = makeAddr("fuzzRecipient");

        vm.startPrank(admin);

        // Create fresh policies for this test
        uint64 senderPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        uint64 recipientPolicy = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        if (senderInWhitelist) {
            registry.modifyPolicyWhitelist(senderPolicy, testSender, true);
        }
        if (recipientInWhitelist) {
            registry.modifyPolicyWhitelist(recipientPolicy, testRecipient, true);
        }

        uint64 fuzzCompound = registry.createCompoundPolicy(senderPolicy, recipientPolicy, 1);

        TIP20 fuzzToken = TIP20(
            factory.createToken("FUZZ", "FZZ", "USD", pathUSD, admin, keccak256(abi.encode(senderInWhitelist, recipientInWhitelist)))
        );
        fuzzToken.grantRole(_ISSUER_ROLE, admin);
        fuzzToken.changeTransferPolicyId(1);
        fuzzToken.mint(testSender, amount);
        fuzzToken.changeTransferPolicyId(fuzzCompound);

        vm.stopPrank();

        vm.prank(testSender);
        if (senderInWhitelist && recipientInWhitelist) {
            // Should succeed
            fuzzToken.transfer(testRecipient, amount);
            assertEq(fuzzToken.balanceOf(testRecipient), amount, "Transfer should succeed");
        } else {
            // Should fail
            vm.expectRevert(ITIP20.PolicyForbids.selector);
            fuzzToken.transfer(testRecipient, amount);
        }
    }

    /// @notice Fuzz: Mint authorization only checks mintRecipientPolicyId
    function testFuzz_mint_onlyChecksMintRecipientPolicy(
        bool inSenderPolicy,
        bool inRecipientPolicy,
        bool inMintPolicy,
        uint256 amount
    ) public onlySolidityImpl {
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
                "FUZZ2", "FZ2", "USD", pathUSD, admin,
                keccak256(abi.encode(inSenderPolicy, inRecipientPolicy, inMintPolicy))
            )
        );
        fuzzToken.grantRole(_ISSUER_ROLE, admin);
        fuzzToken.changeTransferPolicyId(fuzzCompound);

        if (inMintPolicy) {
            // Should succeed regardless of sender/recipient policy membership
            fuzzToken.mint(testMintRecipient, amount);
            assertEq(fuzzToken.balanceOf(testMintRecipient), amount, "Mint should succeed");
        } else {
            // Should fail because not in mint policy
            vm.expectRevert(ITIP20.PolicyForbids.selector);
            fuzzToken.mint(testMintRecipient, amount);
        }

        vm.stopPrank();
    }

}
