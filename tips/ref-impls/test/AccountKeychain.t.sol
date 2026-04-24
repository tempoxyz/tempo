// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { TempoTest } from "./TempoTest.t.sol";
import { IAccountKeychain } from "tempo-std/interfaces/IAccountKeychain.sol";

/**
 * @title Account Keychain Tests
 * @notice Tests for the Account Keychain precompile
 * @dev These tests run against the native Tempo precompile.
 */
/// forge-config: default.isolate = true
/// forge-config: fuzz500.isolate = true
contract AccountKeychainTest is TempoTest {

    // Using addresses for keyIds (derived from public keys)
    address aliceAccessKey = address(0x1001);
    address bobAccessKey = address(0x1002);
    address charlieAccessKey = address(0x1003);

    // Token addresses for spending limits (using TIP20 address space)
    address constant USDC = address(0x20C0000000000000000000000000000000000001);
    address constant USDT = address(0x20C0000000000000000000000000000000000002);

    function setUp() public override {
        super.setUp();
    }

    /*//////////////////////////////////////////////////////////////
                        BASIC FUNCTIONALITY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AuthorizeKey() public {
        vm.startPrank(alice, alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({
            token: USDC,
            amount: 1000e6, // 1000 USDC
            period: 0
        });

        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: limits,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        IAccountKeychain.KeyInfo memory info = keychain.getKey(alice, aliceAccessKey);
        assertEq(uint8(info.signatureType), uint8(IAccountKeychain.SignatureType.P256));
        assertEq(info.keyId, aliceAccessKey);
        assertGt(info.expiry, 0);
        assertTrue(info.enforceLimits);
        assertFalse(info.isRevoked);

        // Verify spending limit was set
        (uint256 remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        assertEq(remaining, 1000e6);

        vm.stopPrank();
    }

    function test_AuthorizeKeyWithMultipleLimits() public {
        vm.startPrank(alice, alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](2);
        limits[0] = IAccountKeychain.TokenLimit({
            token: USDC,
            amount: 1000e6, // 1000 USDC
            period: 0
        });
        limits[1] = IAccountKeychain.TokenLimit({
            token: USDT,
            amount: 500e6, // 500 USDT
            period: 0
        });

        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.Secp256k1,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: limits,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        IAccountKeychain.KeyInfo memory info = keychain.getKey(alice, aliceAccessKey);

        assertEq(uint8(info.signatureType), uint8(IAccountKeychain.SignatureType.Secp256k1));
        assertEq(info.keyId, aliceAccessKey);
        assertGt(info.expiry, 0);
        assertTrue(info.enforceLimits);
        assertFalse(info.isRevoked);

        // Verify both limits were set
        (uint256 remainingUsdc,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        (uint256 remainingUsdt,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDT);
        assertEq(remainingUsdc, 1000e6);
        assertEq(remainingUsdt, 500e6);

        vm.stopPrank();
    }

    function test_AuthorizeKeyNoLimits() public {
        vm.startPrank(alice, alice);

        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.WebAuthn,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        IAccountKeychain.KeyInfo memory info = keychain.getKey(alice, aliceAccessKey);
        assertEq(uint8(info.signatureType), uint8(IAccountKeychain.SignatureType.WebAuthn));
        assertFalse(info.enforceLimits);

        vm.stopPrank();
    }

    function test_RevokeKey() public {
        vm.startPrank(alice, alice);

        // First authorize a key
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify key exists
        IAccountKeychain.KeyInfo memory infoBefore = keychain.getKey(alice, aliceAccessKey);
        assertEq(infoBefore.keyId, aliceAccessKey);
        assertFalse(infoBefore.isRevoked);

        // Revoke the key
        keychain.revokeKey(aliceAccessKey);

        // Verify key is revoked
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(alice, aliceAccessKey);
        assertTrue(infoAfter.isRevoked);
        assertEq(infoAfter.expiry, 0);
        assertEq(infoAfter.keyId, address(0)); // Returns default when revoked

        vm.stopPrank();
    }

    function test_UpdateSpendingLimit() public {
        vm.startPrank(alice, alice);

        // First authorize a key with initial limits
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 1000e6, period: 0 });

        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.Secp256k1,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: limits,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify initial limit
        (uint256 remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        assertEq(remaining, 1000e6);

        // Update the spending limit
        keychain.updateSpendingLimit(aliceAccessKey, USDC, 2000e6);

        // Verify new limit
        (remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        assertEq(remaining, 2000e6);

        vm.stopPrank();
    }

    function test_UpdateSpendingLimit_EnablesLimitsOnUnlimitedKey() public {
        vm.startPrank(alice, alice);

        // Authorize a key with no limits enforced
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify key has no limits
        IAccountKeychain.KeyInfo memory infoBefore = keychain.getKey(alice, aliceAccessKey);
        assertFalse(infoBefore.enforceLimits);

        // Update spending limit - this should enable limits
        keychain.updateSpendingLimit(aliceAccessKey, USDC, 500e6);

        // Verify limits are now enforced
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(alice, aliceAccessKey);
        assertTrue(infoAfter.enforceLimits);
        (uint256 remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        assertEq(remaining, 500e6);

        vm.stopPrank();
    }

    function test_GetKey_NonExistent() public view {
        IAccountKeychain.KeyInfo memory info = keychain.getKey(alice, aliceAccessKey);

        // Default values for non-existent key
        assertEq(uint8(info.signatureType), 0);
        assertEq(info.keyId, address(0));
        assertEq(info.expiry, 0);
        assertFalse(info.enforceLimits);
        assertFalse(info.isRevoked);
    }

    function test_GetRemainingLimit_NonExistent() public view {
        (uint256 remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        assertEq(remaining, 0);
    }

    function test_GetTransactionKey() public view {
        // When called directly (not through protocol), returns address(0)
        address txKey = keychain.getTransactionKey();
        assertEq(txKey, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                        ERROR CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RevokeKey_AlreadyRevokedReturnsKeyNotFound() public {
        vm.startPrank(alice, alice);

        // Authorize and revoke a key
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );
        keychain.revokeKey(aliceAccessKey);

        // Try to revoke again - should fail with KeyNotFound (not KeyAlreadyRevoked)
        // because expiry is set to 0 when revoked
        try keychain.revokeKey(aliceAccessKey) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.KeyNotFound.selector));
        }

        vm.stopPrank();
    }

    function test_GetRemainingLimit_ReturnsZeroForRevokedKey() public {
        vm.startPrank(alice, alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 1000e6, period: 0 });

        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: limits,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );
        (uint256 remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        assertEq(remaining, 1000e6);

        keychain.revokeKey(aliceAccessKey);
        (remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        assertEq(remaining, 0);

        vm.stopPrank();
    }

    function test_AuthorizeKey_RevertZeroKeyId() public {
        vm.startPrank(alice, alice);

        try keychain.authorizeKey(
            address(0), // Zero key ID
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.ZeroPublicKey.selector));
        }

        vm.stopPrank();
    }

    function test_AuthorizeKey_RevertExpiryInPast() public {
        vm.startPrank(alice, alice);

        // Test with expiry = 0 (in the past)
        try keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: 0,
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.ExpiryInPast.selector));
        }

        // Test with expiry = 1 (also in the past)
        try keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: 1,
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.ExpiryInPast.selector));
        }

        vm.stopPrank();
    }

    function test_AuthorizeKey_RevertKeyAlreadyExists() public {
        vm.startPrank(alice, alice);

        // Authorize key first time
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Try to authorize same key again
        try keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.Secp256k1,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 2 days),
                enforceLimits: true,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.KeyAlreadyExists.selector));
        }

        vm.stopPrank();
    }

    function test_AuthorizeKey_RevertKeyAlreadyRevoked() public {
        vm.startPrank(alice, alice);

        // Authorize and then revoke the key
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );
        keychain.revokeKey(aliceAccessKey);

        // Try to re-authorize the revoked key (replay attack)
        try keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        ) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.KeyAlreadyRevoked.selector));
        }

        vm.stopPrank();
    }

    function test_RevokeKey_RevertKeyNotFound() public {
        vm.startPrank(alice, alice);

        // Try to revoke a key that doesn't exist
        try keychain.revokeKey(aliceAccessKey) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.KeyNotFound.selector));
        }

        vm.stopPrank();
    }

    function test_UpdateSpendingLimit_RevertKeyNotFound() public {
        vm.startPrank(alice, alice);

        // Try to update limit for non-existent key
        try keychain.updateSpendingLimit(aliceAccessKey, USDC, 1000e6) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.KeyNotFound.selector));
        }

        vm.stopPrank();
    }

    function test_UpdateSpendingLimit_RevertKeyAlreadyRevoked() public {
        vm.startPrank(alice, alice);

        // Authorize and revoke key
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );
        keychain.revokeKey(aliceAccessKey);

        // Try to update limit on revoked key
        try keychain.updateSpendingLimit(aliceAccessKey, USDC, 1000e6) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.KeyAlreadyRevoked.selector));
        }

        vm.stopPrank();
    }

    function test_UpdateSpendingLimit_RevertKeyExpired() public {
        vm.startPrank(alice, alice);

        uint64 expiry = uint64(block.timestamp + 1 hours);
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: expiry,
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Warp time past expiry
        vm.warp(block.timestamp + 2 hours);

        // Try to update limit on expired key
        try keychain.updateSpendingLimit(aliceAccessKey, USDC, 1000e6) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(IAccountKeychain.KeyExpired.selector));
        }

        vm.stopPrank();
    }

    function test_UpdateSpendingLimit_AddNewTokenLimit() public {
        vm.startPrank(alice, alice);

        // Authorize a key with only USDC limit
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 1000e6, period: 0 });

        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: limits,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify USDT limit is 0 initially
        (uint256 remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDT);
        assertEq(remaining, 0);

        // Add a NEW token limit for USDT
        keychain.updateSpendingLimit(aliceAccessKey, USDT, 500e6);

        // Verify new USDT limit was added
        (remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDT);
        assertEq(remaining, 500e6);
        // Verify USDC limit unchanged
        (remaining,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        assertEq(remaining, 1000e6);

        vm.stopPrank();
    }

    function test_AuthorizeKey_LimitsIgnoredWhenEnforceLimitsFalse() public {
        vm.startPrank(alice, alice);

        // Authorize key with enforceLimits=false but pass limits anyway
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](2);
        limits[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 1000e6, period: 0 });
        limits[1] = IAccountKeychain.TokenLimit({ token: USDT, amount: 500e6, period: 0 });

        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: limits,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify limits were NOT stored (should be 0)
        (uint256 remainingUsdc,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDC);
        (uint256 remainingUsdt,) = keychain.getRemainingLimitWithPeriod(alice, aliceAccessKey, USDT);
        assertEq(remainingUsdc, 0);
        assertEq(remainingUsdt, 0);

        // Verify enforceLimits is false
        IAccountKeychain.KeyInfo memory info = keychain.getKey(alice, aliceAccessKey);
        assertFalse(info.enforceLimits);

        vm.stopPrank();
    }

    function test_DifferentKeyCanBeAuthorizedAfterRevocation() public {
        vm.startPrank(alice, alice);

        // Authorize and revoke first key
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );
        keychain.revokeKey(aliceAccessKey);

        // Authorizing a DIFFERENT key should still work
        keychain.authorizeKey(
            bobAccessKey, // Different key
            IAccountKeychain.SignatureType.Secp256k1,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify new key is authorized
        IAccountKeychain.KeyInfo memory info = keychain.getKey(alice, bobAccessKey);
        assertEq(info.keyId, bobAccessKey);
        assertEq(uint8(info.signatureType), uint8(IAccountKeychain.SignatureType.Secp256k1));
        assertFalse(info.isRevoked);

        // Verify old key is still revoked
        IAccountKeychain.KeyInfo memory oldInfo = keychain.getKey(alice, aliceAccessKey);
        assertTrue(oldInfo.isRevoked);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        SIGNATURE TYPE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SignatureTypeEnum() public pure {
        assertEq(uint8(IAccountKeychain.SignatureType.Secp256k1), 0);
        assertEq(uint8(IAccountKeychain.SignatureType.P256), 1);
        assertEq(uint8(IAccountKeychain.SignatureType.WebAuthn), 2);
    }

    function test_AuthorizeKey_AllSignatureTypes() public {
        IAccountKeychain.KeyRestrictions memory config = IAccountKeychain.KeyRestrictions({
            expiry: uint64(block.timestamp + 1 days),
            enforceLimits: false,
            limits: new IAccountKeychain.TokenLimit[](0),
            allowAnyCalls: true,
            allowedCalls: new IAccountKeychain.CallScope[](0)
        });

        // Secp256k1
        vm.prank(alice, alice);
        keychain.authorizeKey(aliceAccessKey, IAccountKeychain.SignatureType.Secp256k1, config);
        assertEq(
            uint8(keychain.getKey(alice, aliceAccessKey).signatureType),
            uint8(IAccountKeychain.SignatureType.Secp256k1)
        );

        // P256
        vm.prank(bob, bob);
        keychain.authorizeKey(bobAccessKey, IAccountKeychain.SignatureType.P256, config);
        assertEq(
            uint8(keychain.getKey(bob, bobAccessKey).signatureType),
            uint8(IAccountKeychain.SignatureType.P256)
        );

        // WebAuthn
        vm.prank(charlie, charlie);
        keychain.authorizeKey(charlieAccessKey, IAccountKeychain.SignatureType.WebAuthn, config);
        assertEq(
            uint8(keychain.getKey(charlie, charlieAccessKey).signatureType),
            uint8(IAccountKeychain.SignatureType.WebAuthn)
        );
    }

    /*//////////////////////////////////////////////////////////////
                        KEY ISOLATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_KeyIsolationBetweenAccounts() public {
        IAccountKeychain.TokenLimit[] memory limits1 = new IAccountKeychain.TokenLimit[](1);
        limits1[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 1000e6, period: 0 });

        IAccountKeychain.TokenLimit[] memory limits2 = new IAccountKeychain.TokenLimit[](1);
        limits2[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 2000e6, period: 0 });

        // Same keyId for two different accounts
        address sharedKeyId = address(0x9999);
        uint64 expiry1 = uint64(block.timestamp + 100);
        uint64 expiry2 = uint64(block.timestamp + 200);

        vm.prank(alice, alice);
        keychain.authorizeKey(
            sharedKeyId,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: expiry1,
                enforceLimits: true,
                limits: limits1,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        vm.prank(bob, bob);
        keychain.authorizeKey(
            sharedKeyId,
            IAccountKeychain.SignatureType.Secp256k1,
            IAccountKeychain.KeyRestrictions({
                expiry: expiry2,
                enforceLimits: true,
                limits: limits2,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify keys are isolated per account
        IAccountKeychain.KeyInfo memory info1 = keychain.getKey(alice, sharedKeyId);
        IAccountKeychain.KeyInfo memory info2 = keychain.getKey(bob, sharedKeyId);

        assertEq(uint8(info1.signatureType), 1); // P256
        assertEq(uint8(info2.signatureType), 0); // Secp256k1
        assertEq(info1.expiry, expiry1);
        assertEq(info2.expiry, expiry2);

        // Verify spending limits are isolated
        (uint256 limit1,) = keychain.getRemainingLimitWithPeriod(alice, sharedKeyId, USDC);
        (uint256 limit2,) = keychain.getRemainingLimitWithPeriod(bob, sharedKeyId, USDC);
        assertEq(limit1, 1000e6);
        assertEq(limit2, 2000e6);
    }

    function test_MultipleKeysPerAccount() public {
        vm.startPrank(alice, alice);

        IAccountKeychain.KeyRestrictions memory noLimitsConfig = IAccountKeychain.KeyRestrictions({
            expiry: uint64(block.timestamp + 1 days),
            enforceLimits: false,
            limits: new IAccountKeychain.TokenLimit[](0),
            allowAnyCalls: true,
            allowedCalls: new IAccountKeychain.CallScope[](0)
        });

        IAccountKeychain.KeyRestrictions memory withLimitsConfig = IAccountKeychain.KeyRestrictions({
            expiry: uint64(block.timestamp + 1 days),
            enforceLimits: true,
            limits: new IAccountKeychain.TokenLimit[](0),
            allowAnyCalls: true,
            allowedCalls: new IAccountKeychain.CallScope[](0)
        });

        keychain.authorizeKey(
            aliceAccessKey, IAccountKeychain.SignatureType.Secp256k1, noLimitsConfig
        );
        keychain.authorizeKey(bobAccessKey, IAccountKeychain.SignatureType.P256, withLimitsConfig);
        keychain.authorizeKey(
            charlieAccessKey, IAccountKeychain.SignatureType.WebAuthn, noLimitsConfig
        );

        // Verify all keys exist with correct types
        assertEq(uint8(keychain.getKey(alice, aliceAccessKey).signatureType), 0);
        assertEq(uint8(keychain.getKey(alice, bobAccessKey).signatureType), 1);
        assertEq(uint8(keychain.getKey(alice, charlieAccessKey).signatureType), 2);

        // Verify enforceLimits
        assertFalse(keychain.getKey(alice, aliceAccessKey).enforceLimits);
        assertTrue(keychain.getKey(alice, bobAccessKey).enforceLimits);
        assertFalse(keychain.getKey(alice, charlieAccessKey).enforceLimits);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        EVENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Event_KeyAuthorized() public {
        vm.startPrank(alice, alice);
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );
        vm.stopPrank();
    }

    function test_Event_KeyRevoked() public {
        vm.startPrank(alice, alice);

        // First authorize
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        keychain.revokeKey(aliceAccessKey);

        vm.stopPrank();
    }

    function test_Event_SpendingLimitUpdated() public {
        vm.startPrank(alice, alice);

        // First authorize
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 1000e6, period: 0 });
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: limits,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        keychain.updateSpendingLimit(aliceAccessKey, USDC, 2000e6);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_AuthorizeKey_ValidSignatureTypes(
        address keyId,
        uint8 sigType,
        uint64 expiry,
        bool enforceLimits
    )
        public
    {
        vm.assume(keyId != address(0));
        vm.assume(sigType <= 2);
        vm.assume(expiry > block.timestamp); // Ensure expiry is in future for valid key

        vm.startPrank(alice, alice);

        keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType(sigType),
            IAccountKeychain.KeyRestrictions({
                expiry: expiry,
                enforceLimits: enforceLimits,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        IAccountKeychain.KeyInfo memory info = keychain.getKey(alice, keyId);
        assertEq(uint8(info.signatureType), sigType);
        assertEq(info.keyId, keyId);
        assertEq(info.expiry, expiry);
        assertEq(info.enforceLimits, enforceLimits);
        assertFalse(info.isRevoked);

        vm.stopPrank();
    }

    function testFuzz_AuthorizeKey_WithTokenLimits(
        address keyId,
        address token1,
        address token2,
        uint256 amount1,
        uint256 amount2
    )
        public
    {
        vm.assume(keyId != address(0));
        vm.assume(token1 != token2);
        // T3 caps spending limits to u128
        amount1 = bound(amount1, 0, type(uint128).max);
        amount2 = bound(amount2, 0, type(uint128).max);

        vm.startPrank(alice, alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](2);
        limits[0] = IAccountKeychain.TokenLimit({ token: token1, amount: amount1, period: 0 });
        limits[1] = IAccountKeychain.TokenLimit({ token: token2, amount: amount2, period: 0 });

        keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: limits,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify limits are stored
        (uint256 remaining1,) = keychain.getRemainingLimitWithPeriod(alice, keyId, token1);
        (uint256 remaining2,) = keychain.getRemainingLimitWithPeriod(alice, keyId, token2);
        assertEq(remaining1, amount1);
        assertEq(remaining2, amount2);

        vm.stopPrank();
    }

    function testFuzz_UpdateSpendingLimit(
        address keyId,
        address token,
        uint256 initialLimit,
        uint256 newLimit
    )
        public
    {
        vm.assume(keyId != address(0));
        // T3 caps spending limits to u128
        initialLimit = bound(initialLimit, 0, type(uint128).max);
        newLimit = bound(newLimit, 0, type(uint128).max);

        vm.startPrank(alice, alice);

        // First authorize the key
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({ token: token, amount: initialLimit, period: 0 });

        keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.Secp256k1,
            IAccountKeychain.KeyRestrictions({
                expiry: uint64(block.timestamp + 1 days),
                enforceLimits: true,
                limits: limits,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Update the spending limit
        keychain.updateSpendingLimit(keyId, token, newLimit);

        // Verify new limit
        (uint256 remaining,) = keychain.getRemainingLimitWithPeriod(alice, keyId, token);
        assertEq(remaining, newLimit);

        vm.stopPrank();
    }

    function testFuzz_RevokeKey(address keyId, uint64 expiry) public {
        vm.assume(keyId != address(0));
        vm.assume(expiry > block.timestamp);

        vm.startPrank(alice, alice);

        keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: expiry,
                enforceLimits: false,
                limits: new IAccountKeychain.TokenLimit[](0),
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify key exists
        IAccountKeychain.KeyInfo memory infoBefore = keychain.getKey(alice, keyId);
        assertEq(infoBefore.keyId, keyId);
        assertFalse(infoBefore.isRevoked);

        // Revoke the key
        keychain.revokeKey(keyId);

        // Verify key is revoked
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(alice, keyId);
        assertTrue(infoAfter.isRevoked);

        vm.stopPrank();
    }

    function testFuzz_GetKey_NonExistentKey(address account, address keyId) public view {
        // Getting a non-existent key should return default values
        IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);

        // Default values
        assertEq(uint8(info.signatureType), 0);
        assertEq(info.keyId, address(0));
        assertEq(info.expiry, 0);
        assertFalse(info.enforceLimits);
        assertFalse(info.isRevoked);
    }

    function testFuzz_GetRemainingLimit_NonExistentKey(
        address account,
        address keyId,
        address token
    )
        public
        view
    {
        // Getting limit for non-existent key should return 0
        (uint256 remaining,) = keychain.getRemainingLimitWithPeriod(account, keyId, token);
        assertEq(remaining, 0);
    }

    function testFuzz_KeyIsolationBetweenAccounts(
        address account1,
        address account2,
        address keyId
    )
        public
    {
        vm.assume(account1 != address(0));
        vm.assume(account2 != address(0));
        vm.assume(account1 != account2);
        vm.assume(keyId != address(0));
        vm.assume(account1.code.length == 0);
        vm.assume(account2.code.length == 0);

        IAccountKeychain.TokenLimit[] memory limits1 = new IAccountKeychain.TokenLimit[](1);
        limits1[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 1000e6, period: 0 });

        IAccountKeychain.TokenLimit[] memory limits2 = new IAccountKeychain.TokenLimit[](1);
        limits2[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 2000e6, period: 0 });

        uint64 expiry1 = uint64(block.timestamp + 100);
        uint64 expiry2 = uint64(block.timestamp + 200);

        // Authorize same keyId for two different accounts
        vm.prank(account1, account1);
        keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.P256,
            IAccountKeychain.KeyRestrictions({
                expiry: expiry1,
                enforceLimits: true,
                limits: limits1,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        vm.prank(account2, account2);
        keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.Secp256k1,
            IAccountKeychain.KeyRestrictions({
                expiry: expiry2,
                enforceLimits: true,
                limits: limits2,
                allowAnyCalls: true,
                allowedCalls: new IAccountKeychain.CallScope[](0)
            })
        );

        // Verify keys are isolated per account
        IAccountKeychain.KeyInfo memory info1 = keychain.getKey(account1, keyId);
        IAccountKeychain.KeyInfo memory info2 = keychain.getKey(account2, keyId);

        assertEq(uint8(info1.signatureType), 1); // P256
        assertEq(uint8(info2.signatureType), 0); // Secp256k1
        assertEq(info1.expiry, expiry1);
        assertEq(info2.expiry, expiry2);

        // Verify spending limits are isolated
        (uint256 limit1,) = keychain.getRemainingLimitWithPeriod(account1, keyId, USDC);
        (uint256 limit2,) = keychain.getRemainingLimitWithPeriod(account2, keyId, USDC);
        assertEq(limit1, 1000e6);
        assertEq(limit2, 2000e6);
    }

}
