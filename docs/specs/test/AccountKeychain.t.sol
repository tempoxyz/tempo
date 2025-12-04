// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../src/interfaces/IAccountKeychain.sol";
import "forge-std/Test.sol";

/**
 * @title Account Keychain Interface Tests
 * @notice Tests for the Account Keychain precompile interface
 * @dev These tests verify the interface compiles and can interact with a mock implementation.
 *      The actual precompile is implemented in Rust and tested there.
 *      These tests serve as interface verification and usage examples.
 */
contract AccountKeychainTest is Test {

    IAccountKeychain keychain;
    MockAccountKeychain mockKeychain;

    address alice = address(0x1);
    address bob = address(0x2);

    address constant USDC = address(0x20C0000000000000000000000000000000000001);
    address constant USDT = address(0x20C0000000000000000000000000000000000002);

    // Using addresses for keyIds (derived from public keys)
    address aliceAccessKey = address(0x1001);
    address bobAccessKey = address(0x1002);

    function setUp() public {
        mockKeychain = new MockAccountKeychain();
        keychain = IAccountKeychain(address(mockKeychain));
    }

    /*//////////////////////////////////////////////////////////////
                        INTERFACE COMPILATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Interface_AuthorizeKey() public {
        vm.startPrank(alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({
            token: USDC,
            amount: 1000e6 // 1000 USDC
        });

        // Verify interface compiles and can be called
        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.P256,
            0, // Never expires
            true, // Enforce spending limits
            limits
        );

        vm.stopPrank();
    }

    function test_Interface_RevokeKey() public {
        vm.prank(alice);

        // Verify interface compiles and can be called
        keychain.revokeKey(aliceAccessKey);
    }

    function test_Interface_UpdateSpendingLimit() public {
        vm.prank(alice);

        // Verify interface compiles and can be called
        keychain.updateSpendingLimit(
            aliceAccessKey,
            USDC,
            2000e6 // New limit
        );
    }

    function test_Interface_GetKey() public view {
        // Verify interface compiles and can be called
        IAccountKeychain.KeyInfo memory info = keychain.getKey(alice, aliceAccessKey);

        // Verify struct fields are accessible
        IAccountKeychain.SignatureType sigType = info.signatureType;
        address keyId = info.keyId;
        uint64 expiry = info.expiry;
        bool enforceLimits = info.enforceLimits;
        bool isRevoked = info.isRevoked;

        // Suppress unused variable warnings
        sigType;
        keyId;
        expiry;
        enforceLimits;
        isRevoked;
    }

    function test_Interface_GetRemainingLimit() public view {
        // Verify interface compiles and can be called
        uint256 remaining = keychain.getRemainingLimit(alice, aliceAccessKey, USDC);

        // Suppress unused variable warning
        remaining;
    }

    function test_Interface_GetTransactionKey() public view {
        // Verify interface compiles and can be called
        address txKey = keychain.getTransactionKey();

        // Suppress unused variable warning
        txKey;
    }

    /*//////////////////////////////////////////////////////////////
                        USAGE EXAMPLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Example_AuthorizeKeyWithMultipleLimits() public {
        vm.startPrank(alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](2);
        limits[0] = IAccountKeychain.TokenLimit({
            token: USDC,
            amount: 1000e6 // 1000 USDC
        });
        limits[1] = IAccountKeychain.TokenLimit({
            token: USDT,
            amount: 500e6 // 500 USDT
        });

        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.Secp256k1,
            uint64(block.timestamp + 1 days), // Expires in 1 day
            true, // Enforce spending limits
            limits
        );

        IAccountKeychain.KeyInfo memory info = keychain.getKey(alice, aliceAccessKey);

        assertEq(uint8(info.signatureType), uint8(IAccountKeychain.SignatureType.Secp256k1));
        assertEq(info.keyId, aliceAccessKey);
        assertGt(info.expiry, 0);
        assertTrue(info.enforceLimits);
        assertFalse(info.isRevoked);

        vm.stopPrank();
    }

    function test_Example_AuthorizeKeyNoLimits() public {
        vm.startPrank(alice);

        // Can authorize with enforceLimits = false for unlimited spending
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        keychain.authorizeKey(
            aliceAccessKey,
            IAccountKeychain.SignatureType.WebAuthn,
            0, // Never expires
            false, // No spending limits enforced
            limits
        );

        vm.stopPrank();
    }

    function test_Example_SignatureTypeEnum() public pure {
        // Verify enum values
        assertEq(uint8(IAccountKeychain.SignatureType.Secp256k1), 0);
        assertEq(uint8(IAccountKeychain.SignatureType.P256), 1);
        assertEq(uint8(IAccountKeychain.SignatureType.WebAuthn), 2);
    }

    /*//////////////////////////////////////////////////////////////
                        ERROR SELECTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ErrorSelectors() public pure {
        // Verify error selectors are accessible
        bytes4 keyAlreadyExists = IAccountKeychain.KeyAlreadyExists.selector;
        bytes4 keyNotFound = IAccountKeychain.KeyNotFound.selector;
        bytes4 keyInactive = IAccountKeychain.KeyInactive.selector;
        bytes4 keyExpired = IAccountKeychain.KeyExpired.selector;
        bytes4 keyAlreadyRevoked = IAccountKeychain.KeyAlreadyRevoked.selector;
        bytes4 spendingLimitExceeded = IAccountKeychain.SpendingLimitExceeded.selector;
        bytes4 invalidSignatureType = IAccountKeychain.InvalidSignatureType.selector;
        bytes4 zeroPublicKey = IAccountKeychain.ZeroPublicKey.selector;
        bytes4 unauthorizedCaller = IAccountKeychain.UnauthorizedCaller.selector;

        // Suppress unused variable warnings
        keyAlreadyExists;
        keyNotFound;
        keyInactive;
        keyExpired;
        keyAlreadyRevoked;
        spendingLimitExceeded;
        invalidSignatureType;
        zeroPublicKey;
        unauthorizedCaller;
    }

    /*//////////////////////////////////////////////////////////////
                        EVENT SELECTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EventTopics() public {
        // Verify events can be emitted (through mock)
        vm.startPrank(alice);

        vm.expectEmit(true, true, false, true);
        emit IAccountKeychain.KeyAuthorized(
            alice,
            bytes32(uint256(uint160(aliceAccessKey))),
            1, // P256
            0
        );

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        keychain.authorizeKey(aliceAccessKey, IAccountKeychain.SignatureType.P256, 0, true, limits);

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
    ) public {
        vm.assume(keyId != address(0));
        // Signature type must be 0, 1, or 2
        vm.assume(sigType <= 2);

        vm.startPrank(alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        keychain.authorizeKey(
            keyId, IAccountKeychain.SignatureType(sigType), expiry, enforceLimits, limits
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
    ) public {
        vm.assume(keyId != address(0));
        vm.assume(token1 != token2);

        vm.startPrank(alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](2);
        limits[0] = IAccountKeychain.TokenLimit({ token: token1, amount: amount1 });
        limits[1] = IAccountKeychain.TokenLimit({ token: token2, amount: amount2 });

        keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.P256, 0, true, limits);

        // Verify limits are stored
        assertEq(keychain.getRemainingLimit(alice, keyId, token1), amount1);
        assertEq(keychain.getRemainingLimit(alice, keyId, token2), amount2);

        vm.stopPrank();
    }

    function testFuzz_UpdateSpendingLimit(
        address keyId,
        address token,
        uint256 initialLimit,
        uint256 newLimit
    ) public {
        vm.assume(keyId != address(0));

        vm.startPrank(alice);

        // First authorize the key
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](1);
        limits[0] = IAccountKeychain.TokenLimit({ token: token, amount: initialLimit });

        keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.Secp256k1, 0, true, limits);

        // Update the spending limit
        keychain.updateSpendingLimit(keyId, token, newLimit);

        // Verify new limit
        assertEq(keychain.getRemainingLimit(alice, keyId, token), newLimit);

        vm.stopPrank();
    }

    function testFuzz_RevokeKey(address keyId, uint64 expiry) public {
        vm.assume(keyId != address(0));

        vm.startPrank(alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.P256, expiry, false, limits);

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
    ) public view {
        // Getting limit for non-existent key should return 0
        uint256 limit = keychain.getRemainingLimit(account, keyId, token);
        assertEq(limit, 0);
    }

    function testFuzz_MultipleKeysPerAccount(address keyId1, address keyId2, address keyId3)
        public
    {
        vm.assume(keyId1 != address(0));
        vm.assume(keyId2 != address(0));
        vm.assume(keyId3 != address(0));
        vm.assume(keyId1 != keyId2 && keyId2 != keyId3 && keyId1 != keyId3);

        vm.startPrank(alice);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        // Authorize multiple keys
        keychain.authorizeKey(keyId1, IAccountKeychain.SignatureType.Secp256k1, 0, false, limits);
        keychain.authorizeKey(keyId2, IAccountKeychain.SignatureType.P256, 0, true, limits);
        keychain.authorizeKey(keyId3, IAccountKeychain.SignatureType.WebAuthn, 0, false, limits);

        // Verify all keys exist with correct types
        assertEq(uint8(keychain.getKey(alice, keyId1).signatureType), 0);
        assertEq(uint8(keychain.getKey(alice, keyId2).signatureType), 1);
        assertEq(uint8(keychain.getKey(alice, keyId3).signatureType), 2);

        // Verify enforceLimits
        assertFalse(keychain.getKey(alice, keyId1).enforceLimits);
        assertTrue(keychain.getKey(alice, keyId2).enforceLimits);
        assertFalse(keychain.getKey(alice, keyId3).enforceLimits);

        vm.stopPrank();
    }

    function testFuzz_KeyIsolationBetweenAccounts(
        address account1,
        address account2,
        address keyId
    ) public {
        vm.assume(account1 != address(0));
        vm.assume(account2 != address(0));
        vm.assume(account1 != account2);
        vm.assume(keyId != address(0));

        IAccountKeychain.TokenLimit[] memory limits1 = new IAccountKeychain.TokenLimit[](1);
        limits1[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 1000e6 });

        IAccountKeychain.TokenLimit[] memory limits2 = new IAccountKeychain.TokenLimit[](1);
        limits2[0] = IAccountKeychain.TokenLimit({ token: USDC, amount: 2000e6 });

        // Authorize same keyId for two different accounts (both with enforceLimits = true)
        vm.prank(account1);
        keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.P256, 100, true, limits1);

        vm.prank(account2);
        keychain.authorizeKey(keyId, IAccountKeychain.SignatureType.Secp256k1, 200, true, limits2);

        // Verify keys are isolated per account
        IAccountKeychain.KeyInfo memory info1 = keychain.getKey(account1, keyId);
        IAccountKeychain.KeyInfo memory info2 = keychain.getKey(account2, keyId);

        assertEq(uint8(info1.signatureType), 1); // P256
        assertEq(uint8(info2.signatureType), 0); // Secp256k1
        assertEq(info1.expiry, 100);
        assertEq(info2.expiry, 200);
        assertTrue(info1.enforceLimits);
        assertTrue(info2.enforceLimits);

        // Verify spending limits are isolated
        assertEq(keychain.getRemainingLimit(account1, keyId, USDC), 1000e6);
        assertEq(keychain.getRemainingLimit(account2, keyId, USDC), 2000e6);
    }

}

/**
 * @title Mock Account Keychain
 * @notice Minimal mock implementation for testing the interface
 * @dev Only implements basic functionality to verify interface works
 */
contract MockAccountKeychain is IAccountKeychain {

    mapping(address => mapping(address => KeyInfo)) private keys;
    mapping(address => mapping(address => mapping(address => uint256))) private limits;

    function authorizeKey(
        address keyId,
        SignatureType signatureType,
        uint64 expiry,
        bool enforceLimits,
        TokenLimit[] calldata tokenLimits
    ) external {
        keys[msg.sender][keyId] = KeyInfo({
            signatureType: signatureType,
            keyId: keyId,
            expiry: expiry,
            enforceLimits: enforceLimits,
            isRevoked: false
        });

        if (enforceLimits) {
            for (uint256 i = 0; i < tokenLimits.length; i++) {
                limits[msg.sender][keyId][tokenLimits[i].token] = tokenLimits[i].amount;
            }
        }

        emit KeyAuthorized(
            msg.sender, bytes32(uint256(uint160(keyId))), uint8(signatureType), expiry
        );
    }

    function revokeKey(address keyId) external {
        keys[msg.sender][keyId].isRevoked = true;
        keys[msg.sender][keyId].expiry = 0;

        emit KeyRevoked(msg.sender, bytes32(uint256(uint160(keyId))));
    }

    function updateSpendingLimit(address keyId, address token, uint256 newLimit) external {
        // Enable enforceLimits if it wasn't already
        keys[msg.sender][keyId].enforceLimits = true;
        limits[msg.sender][keyId][token] = newLimit;

        emit SpendingLimitUpdated(msg.sender, bytes32(uint256(uint160(keyId))), token, newLimit);
    }

    function getKey(address account, address keyId) external view returns (KeyInfo memory) {
        return keys[account][keyId];
    }

    function getRemainingLimit(address account, address keyId, address token)
        external
        view
        returns (uint256)
    {
        return limits[account][keyId][token];
    }

    function getTransactionKey() external pure returns (address) {
        return address(0); // Mock: always return root key
    }

}
