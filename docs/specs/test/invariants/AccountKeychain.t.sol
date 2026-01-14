// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { IAccountKeychain } from "../../src/interfaces/IAccountKeychain.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title AccountKeychain Invariant Tests
/// @notice Fuzz-based invariant tests for the AccountKeychain precompile
/// @dev Tests invariants TEMPO-KEY1 through TEMPO-KEY15 for access key management
contract AccountKeychainInvariantTest is InvariantBaseTest {

    /// @dev Potential key IDs
    address[] private _potentialKeyIds;

    /// @dev Token addresses for spending limits (uses _tokens from base)

    /// @dev Ghost state for authorized keys
    /// account => keyId => exists
    mapping(address => mapping(address => bool)) private _ghostKeyExists;

    /// @dev Ghost state for revoked keys
    /// account => keyId => isRevoked
    mapping(address => mapping(address => bool)) private _ghostKeyRevoked;

    /// @dev Ghost state for key expiry
    /// account => keyId => expiry
    mapping(address => mapping(address => uint64)) private _ghostKeyExpiry;

    /// @dev Ghost state for enforce limits flag
    /// account => keyId => enforceLimits
    mapping(address => mapping(address => bool)) private _ghostKeyEnforceLimits;

    /// @dev Ghost state for signature type
    /// account => keyId => signatureType
    mapping(address => mapping(address => uint8)) private _ghostKeySignatureType;

    /// @dev Ghost state for spending limits
    /// account => keyId => token => limit
    mapping(address => mapping(address => mapping(address => uint256))) private
        _ghostSpendingLimits;

    /// @dev Track all keys created per account
    mapping(address => address[]) private _accountKeys;

    /// @dev Track if a key has been used for an account
    mapping(address => mapping(address => bool)) private _keyUsed;

    /// @dev Counters
    uint256 private _totalKeysAuthorized;
    uint256 private _totalKeysRevoked;
    uint256 private _totalLimitUpdates;

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();
        _actors = _buildActors(10);
        _potentialKeyIds = _buildKeyIds(20);

        _initLogFile("account_keychain.log", "AccountKeychain Invariant Test Log");
    }

    /// @dev Creates potential key IDs
    function _buildKeyIds(uint256 count) internal pure returns (address[] memory) {
        address[] memory keyIds = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            keyIds[i] = address(uint160(0x1001 + i));
        }
        return keyIds;
    }

    /// @dev Selects a potential key ID based on seed
    function _selectKeyId(uint256 seed) internal view returns (address) {
        return _potentialKeyIds[seed % _potentialKeyIds.length];
    }

    /// @dev Generates a valid expiry timestamp
    function _generateExpiry(uint256 seed) internal view returns (uint64) {
        return uint64(block.timestamp + 1 days + (seed % 365 days));
    }

    /// @dev Generates a signature type (0-2)
    function _generateSignatureType(uint256 seed)
        internal
        pure
        returns (IAccountKeychain.SignatureType)
    {
        return IAccountKeychain.SignatureType(seed % 3);
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for authorizing a new key
    /// @dev Tests TEMPO-KEY1 (key authorization), TEMPO-KEY2 (spending limits)
    function authorizeKey(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 sigTypeSeed,
        uint256 expirySeed,
        bool enforceLimits,
        uint256 limitAmountSeed
    ) external {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Skip if key already exists or was revoked for this account
        if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) return;

        uint64 expiry = _generateExpiry(expirySeed);
        IAccountKeychain.SignatureType sigType = _generateSignatureType(sigTypeSeed);

        IAccountKeychain.TokenLimit[] memory limits;
        if (enforceLimits && _tokens.length > 0) {
            limits = new IAccountKeychain.TokenLimit[](1);
            limits[0] = IAccountKeychain.TokenLimit({
                token: address(_tokens[limitAmountSeed % _tokens.length]),
                amount: (limitAmountSeed % 1_000_000) * 1e6
            });
        } else {
            limits = new IAccountKeychain.TokenLimit[](0);
        }

        vm.startPrank(account);
        try keychain.authorizeKey(keyId, sigType, expiry, enforceLimits, limits) {
            vm.stopPrank();

            _totalKeysAuthorized++;

            // Update ghost state
            _ghostKeyExists[account][keyId] = true;
            _ghostKeyExpiry[account][keyId] = expiry;
            _ghostKeyEnforceLimits[account][keyId] = enforceLimits;
            _ghostKeySignatureType[account][keyId] = uint8(sigType);

            if (enforceLimits && limits.length > 0) {
                _ghostSpendingLimits[account][keyId][limits[0].token] = limits[0].amount;
            }

            if (!_keyUsed[account][keyId]) {
                _keyUsed[account][keyId] = true;
                _accountKeys[account].push(keyId);
            }

            // TEMPO-KEY1: Verify key was stored correctly
            IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);
            assertEq(info.keyId, keyId, "TEMPO-KEY1: KeyId should match");
            assertEq(info.expiry, expiry, "TEMPO-KEY1: Expiry should match");
            assertEq(info.enforceLimits, enforceLimits, "TEMPO-KEY1: EnforceLimits should match");
            assertFalse(info.isRevoked, "TEMPO-KEY1: Should not be revoked");

            _log(
                string.concat(
                    "AUTHORIZE_KEY: account=",
                    _getActorIndex(account),
                    " keyId=",
                    vm.toString(keyId),
                    " sigType=",
                    vm.toString(uint8(sigType)),
                    " enforceLimits=",
                    enforceLimits ? "true" : "false"
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownKeychainError(reason);
        }
    }

    /// @notice Handler for revoking a key
    /// @dev Tests TEMPO-KEY3 (key revocation), TEMPO-KEY4 (revocation prevents reauthorization)
    function revokeKey(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);

        // Get an existing key for this account
        if (_accountKeys[account].length == 0) return;
        address keyId = _accountKeys[account][keyIdSeed % _accountKeys[account].length];

        // Skip if key doesn't exist or is already revoked
        if (!_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) return;

        vm.startPrank(account);
        try keychain.revokeKey(keyId) {
            vm.stopPrank();

            _totalKeysRevoked++;

            // Update ghost state
            _ghostKeyExists[account][keyId] = false;
            _ghostKeyRevoked[account][keyId] = true;
            _ghostKeyExpiry[account][keyId] = 0;

            // TEMPO-KEY3: Verify key is revoked
            IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);
            assertTrue(info.isRevoked, "TEMPO-KEY3: Key should be marked as revoked");
            assertEq(info.expiry, 0, "TEMPO-KEY3: Expiry should be cleared");
            assertEq(info.keyId, address(0), "TEMPO-KEY3: KeyId should return 0 for revoked");

            _log(
                string.concat(
                    "REVOKE_KEY: account=", _getActorIndex(account), " keyId=", vm.toString(keyId)
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownKeychainError(reason);
        }
    }

    /// @notice Handler for attempting to reauthorize a revoked key
    /// @dev Tests TEMPO-KEY4 (revoked keys cannot be reauthorized)
    function tryReauthorizeRevokedKey(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);

        // Find a revoked key for this account
        address keyId = address(0);
        for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
            address potentialKey = _potentialKeyIds[(keyIdSeed + i) % _potentialKeyIds.length];
            if (_ghostKeyRevoked[account][potentialKey]) {
                keyId = potentialKey;
                break;
            }
        }

        if (keyId == address(0)) return;

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        vm.startPrank(account);
        try keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.Secp256k1,
            uint64(block.timestamp + 1 days),
            false,
            limits
        ) {
            vm.stopPrank();
            revert("TEMPO-KEY4: Reauthorizing revoked key should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyAlreadyRevoked.selector,
                "TEMPO-KEY4: Should revert with KeyAlreadyRevoked"
            );
        }

        _log(
            string.concat(
                "TRY_REAUTHORIZE_REVOKED: account=",
                _getActorIndex(account),
                " keyId=",
                vm.toString(keyId),
                " correctly rejected"
            )
        );
    }

    /// @notice Handler for updating spending limits
    /// @dev Tests TEMPO-KEY5 (limit update), TEMPO-KEY6 (enables limits on unlimited key)
    function updateSpendingLimit(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    ) external {
        address account = _selectActor(accountSeed);

        // Get an existing key for this account
        if (_accountKeys[account].length == 0) return;
        address keyId = _accountKeys[account][keyIdSeed % _accountKeys[account].length];

        // Skip if key doesn't exist or is revoked
        if (!_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) return;

        // Need tokens for spending limits
        if (_tokens.length == 0) return;

        address token = address(_tokens[tokenSeed % _tokens.length]);
        uint256 newLimit = (newLimitSeed % 1_000_000) * 1e6;

        bool hadLimitsBefore = _ghostKeyEnforceLimits[account][keyId];

        vm.startPrank(account);
        try keychain.updateSpendingLimit(keyId, token, newLimit) {
            vm.stopPrank();

            _totalLimitUpdates++;

            // Update ghost state
            _ghostSpendingLimits[account][keyId][token] = newLimit;
            _ghostKeyEnforceLimits[account][keyId] = true; // Always enables limits

            // TEMPO-KEY5: Verify limit was updated
            uint256 storedLimit = keychain.getRemainingLimit(account, keyId, token);
            assertEq(storedLimit, newLimit, "TEMPO-KEY5: Spending limit should be updated");

            // TEMPO-KEY6: Verify enforceLimits is now true
            IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);
            assertTrue(info.enforceLimits, "TEMPO-KEY6: EnforceLimits should be true after update");

            _log(
                string.concat(
                    "UPDATE_LIMIT: account=",
                    _getActorIndex(account),
                    " keyId=",
                    vm.toString(keyId),
                    " token=",
                    vm.toString(token),
                    " limit=",
                    vm.toString(newLimit),
                    hadLimitsBefore ? "" : " (enabled limits)"
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownKeychainError(reason);
        }
    }

    /// @notice Handler for authorizing key with zero address (should fail)
    /// @dev Tests TEMPO-KEY7 (zero public key rejection)
    function tryAuthorizeZeroKey(uint256 accountSeed) external {
        address account = _selectActor(accountSeed);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        vm.startPrank(account);
        try keychain.authorizeKey(
            address(0), // Zero key ID
            IAccountKeychain.SignatureType.Secp256k1,
            uint64(block.timestamp + 1 days),
            false,
            limits
        ) {
            vm.stopPrank();
            revert("TEMPO-KEY7: Zero key ID should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.ZeroPublicKey.selector,
                "TEMPO-KEY7: Should revert with ZeroPublicKey"
            );
        }

        _log(
            string.concat("TRY_ZERO_KEY: account=", _getActorIndex(account), " correctly rejected")
        );
    }

    /// @notice Handler for authorizing duplicate key (should fail)
    /// @dev Tests TEMPO-KEY8 (duplicate key rejection)
    function tryAuthorizeDuplicateKey(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);

        // Find an existing key for this account
        address keyId = address(0);
        for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
            address potentialKey = _potentialKeyIds[(keyIdSeed + i) % _potentialKeyIds.length];
            if (_ghostKeyExists[account][potentialKey] && !_ghostKeyRevoked[account][potentialKey])
            {
                keyId = potentialKey;
                break;
            }
        }

        if (keyId == address(0)) return;

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        vm.startPrank(account);
        try keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.P256,
            uint64(block.timestamp + 2 days),
            false,
            limits
        ) {
            vm.stopPrank();
            revert("TEMPO-KEY8: Duplicate key should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyAlreadyExists.selector,
                "TEMPO-KEY8: Should revert with KeyAlreadyExists"
            );
        }

        _log(
            string.concat(
                "TRY_DUPLICATE_KEY: account=",
                _getActorIndex(account),
                " keyId=",
                vm.toString(keyId),
                " correctly rejected"
            )
        );
    }

    /// @notice Handler for revoking non-existent key (should fail)
    /// @dev Tests TEMPO-KEY9 (revoke non-existent key)
    function tryRevokeNonExistentKey(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Skip if key exists
        if (_ghostKeyExists[account][keyId]) return;
        // Skip if key was revoked (would give KeyNotFound due to expiry=0)
        if (_ghostKeyRevoked[account][keyId]) return;

        vm.startPrank(account);
        try keychain.revokeKey(keyId) {
            vm.stopPrank();
            revert("TEMPO-KEY9: Revoking non-existent key should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyNotFound.selector,
                "TEMPO-KEY9: Should revert with KeyNotFound"
            );
        }

        _log(
            string.concat(
                "TRY_REVOKE_NONEXISTENT: account=",
                _getActorIndex(account),
                " keyId=",
                vm.toString(keyId),
                " correctly rejected"
            )
        );
    }

    /// @notice Handler for verifying account isolation
    /// @dev Tests TEMPO-KEY10 (keys are isolated per account)
    function verifyAccountIsolation(uint256 account1Seed, uint256 account2Seed, uint256 keyIdSeed)
        external
    {
        address account1 = _selectActor(account1Seed);
        address account2 = _selectActor(account2Seed);

        vm.assume(account1 != account2);

        address keyId = _selectKeyId(keyIdSeed);

        // Skip if either account has this key already
        if (_ghostKeyExists[account1][keyId] || _ghostKeyRevoked[account1][keyId]) return;
        if (_ghostKeyExists[account2][keyId] || _ghostKeyRevoked[account2][keyId]) return;

        // Need at least one token for limits
        if (_tokens.length == 0) return;

        // Authorize key for account1
        IAccountKeychain.TokenLimit[] memory limits1 = new IAccountKeychain.TokenLimit[](1);
        limits1[0] = IAccountKeychain.TokenLimit({ token: address(_tokens[0]), amount: 1000e6 });

        vm.prank(account1);
        keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.P256,
            uint64(block.timestamp + 1 days),
            true,
            limits1
        );

        // Update ghost state for account1
        _ghostKeyExists[account1][keyId] = true;
        _ghostKeyExpiry[account1][keyId] = uint64(block.timestamp + 1 days);
        _ghostKeyEnforceLimits[account1][keyId] = true;
        _ghostKeySignatureType[account1][keyId] = 1;
        _ghostSpendingLimits[account1][keyId][address(_tokens[0])] = 1000e6;

        if (!_keyUsed[account1][keyId]) {
            _keyUsed[account1][keyId] = true;
            _accountKeys[account1].push(keyId);
        }

        // Authorize same keyId for account2 with different settings
        IAccountKeychain.TokenLimit[] memory limits2 = new IAccountKeychain.TokenLimit[](1);
        limits2[0] = IAccountKeychain.TokenLimit({ token: address(_tokens[0]), amount: 2000e6 });

        vm.prank(account2);
        keychain.authorizeKey(
            keyId,
            IAccountKeychain.SignatureType.Secp256k1,
            uint64(block.timestamp + 2 days),
            true,
            limits2
        );

        // Update ghost state for account2
        _ghostKeyExists[account2][keyId] = true;
        _ghostKeyExpiry[account2][keyId] = uint64(block.timestamp + 2 days);
        _ghostKeyEnforceLimits[account2][keyId] = true;
        _ghostKeySignatureType[account2][keyId] = 0;
        _ghostSpendingLimits[account2][keyId][address(_tokens[0])] = 2000e6;

        if (!_keyUsed[account2][keyId]) {
            _keyUsed[account2][keyId] = true;
            _accountKeys[account2].push(keyId);
        }

        _totalKeysAuthorized += 2;

        // TEMPO-KEY10: Verify keys are isolated
        IAccountKeychain.KeyInfo memory info1 = keychain.getKey(account1, keyId);
        IAccountKeychain.KeyInfo memory info2 = keychain.getKey(account2, keyId);

        assertEq(uint8(info1.signatureType), 1, "TEMPO-KEY10: Account1 should have P256");
        assertEq(uint8(info2.signatureType), 0, "TEMPO-KEY10: Account2 should have Secp256k1");

        uint256 limit1 = keychain.getRemainingLimit(account1, keyId, address(_tokens[0]));
        uint256 limit2 = keychain.getRemainingLimit(account2, keyId, address(_tokens[0]));

        assertEq(limit1, 1000e6, "TEMPO-KEY10: Account1 limit should be 1000");
        assertEq(limit2, 2000e6, "TEMPO-KEY10: Account2 limit should be 2000");

        _log(
            string.concat(
                "ACCOUNT_ISOLATION: keyId=",
                vm.toString(keyId),
                " ",
                _getActorIndex(account1),
                " ",
                _getActorIndex(account2),
                " verified"
            )
        );
    }

    /// @notice Handler for checking getTransactionKey
    /// @dev Tests TEMPO-KEY11 (transaction key returns 0 when not in transaction)
    function checkTransactionKey() external {
        // TEMPO-KEY11: When called directly, should return address(0)
        address txKey = keychain.getTransactionKey();
        assertEq(txKey, address(0), "TEMPO-KEY11: Transaction key should be 0 outside tx context");
    }

    /// @notice Handler for getting key info on non-existent key
    /// @dev Tests TEMPO-KEY12 (non-existent key returns defaults)
    function checkNonExistentKey(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Only test if key doesn't exist
        if (_ghostKeyExists[account][keyId]) return;

        IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);

        // TEMPO-KEY12: Non-existent key returns defaults
        assertEq(info.keyId, address(0), "TEMPO-KEY12: KeyId should be 0");
        assertEq(info.expiry, 0, "TEMPO-KEY12: Expiry should be 0");
        assertFalse(info.enforceLimits, "TEMPO-KEY12: EnforceLimits should be false");

        // isRevoked should match ghost state
        assertEq(
            info.isRevoked, _ghostKeyRevoked[account][keyId], "TEMPO-KEY12: isRevoked should match"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    function invariant_globalInvariants() public view {
        _invariantKeyConsistency();
        _invariantSpendingLimitConsistency();
        _invariantRevokedKeyState();
    }

    /// @notice TEMPO-KEY13: Key data matches ghost state for all tracked keys
    function _invariantKeyConsistency() internal view {
        for (uint256 a = 0; a < _actors.length; a++) {
            address account = _actors[a];
            address[] memory keys = _accountKeys[account];

            for (uint256 k = 0; k < keys.length; k++) {
                address keyId = keys[k];
                IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);

                if (_ghostKeyRevoked[account][keyId]) {
                    // Revoked key should show isRevoked=true
                    assertTrue(info.isRevoked, "TEMPO-KEY13: Revoked key should show isRevoked");
                    assertEq(info.keyId, address(0), "TEMPO-KEY13: Revoked key keyId should be 0");
                } else if (_ghostKeyExists[account][keyId]) {
                    // Active key should match ghost state
                    assertEq(info.keyId, keyId, "TEMPO-KEY13: Active key keyId should match");
                    assertEq(
                        info.expiry,
                        _ghostKeyExpiry[account][keyId],
                        "TEMPO-KEY13: Expiry should match"
                    );
                    assertEq(
                        info.enforceLimits,
                        _ghostKeyEnforceLimits[account][keyId],
                        "TEMPO-KEY13: EnforceLimits should match"
                    );
                    assertFalse(info.isRevoked, "TEMPO-KEY13: Active key should not be revoked");
                }
            }
        }
    }

    /// @notice TEMPO-KEY14: Spending limits match ghost state
    function _invariantSpendingLimitConsistency() internal view {
        for (uint256 a = 0; a < _actors.length; a++) {
            address account = _actors[a];
            address[] memory keys = _accountKeys[account];

            for (uint256 k = 0; k < keys.length; k++) {
                address keyId = keys[k];

                // Only check active (non-revoked) keys with limits
                if (!_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) continue;
                if (!_ghostKeyEnforceLimits[account][keyId]) continue;

                for (uint256 t = 0; t < _tokens.length; t++) {
                    address token = address(_tokens[t]);
                    uint256 expected = _ghostSpendingLimits[account][keyId][token];
                    uint256 actual = keychain.getRemainingLimit(account, keyId, token);
                    assertEq(
                        actual, expected, "TEMPO-KEY14: Spending limit should match ghost state"
                    );
                }
            }
        }
    }

    /// @notice TEMPO-KEY15: Revoked keys stay revoked
    function _invariantRevokedKeyState() internal view {
        for (uint256 a = 0; a < _actors.length; a++) {
            address account = _actors[a];
            address[] memory keys = _accountKeys[account];

            for (uint256 k = 0; k < keys.length; k++) {
                address keyId = keys[k];

                if (_ghostKeyRevoked[account][keyId]) {
                    IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);
                    assertTrue(info.isRevoked, "TEMPO-KEY15: Revoked key must stay revoked");
                }
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Checks if an error is known/expected for AccountKeychain
    function _assertKnownKeychainError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnown = selector == IAccountKeychain.KeyAlreadyExists.selector
            || selector == IAccountKeychain.KeyNotFound.selector
            || selector == IAccountKeychain.KeyInactive.selector
            || selector == IAccountKeychain.KeyExpired.selector
            || selector == IAccountKeychain.KeyAlreadyRevoked.selector
            || selector == IAccountKeychain.SpendingLimitExceeded.selector
            || selector == IAccountKeychain.InvalidSignatureType.selector
            || selector == IAccountKeychain.ZeroPublicKey.selector
            || selector == IAccountKeychain.UnauthorizedCaller.selector;
        assertTrue(isKnown, "Unknown error encountered");
    }

}
