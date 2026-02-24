// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { IAccountKeychain } from "../../src/interfaces/IAccountKeychain.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title AccountKeychain Invariant Tests
/// @notice Fuzz-based invariant tests for the AccountKeychain precompile
/// @dev Tests invariants TEMPO-KEY1 through TEMPO-KEY19 for access key management
///      Note: TEMPO-KEY20/21 require integration tests (transient storage for transaction_key)
contract AccountKeychainInvariantTest is InvariantBaseTest {

    /// @dev Starting offset for key ID address pool (distinct from zero address)
    uint256 private constant KEY_ID_POOL_OFFSET = 1;

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
        (_actors,) = _buildActors(10);
        _potentialKeyIds = _buildAddressPool(20, KEY_ID_POOL_OFFSET);

        // Seed each actor with an initial key to ensure handlers have keys to work with
        _seedInitialKeys();
    }

    /// @dev Seeds each actor with one initial key to bootstrap the fuzzer state
    function _seedInitialKeys() internal {
        for (uint256 a = 0; a < _actors.length; a++) {
            address account = _actors[a];
            // Use a deterministic key for each actor (offset by actor index)
            address keyId = _potentialKeyIds[a % _potentialKeyIds.length];
            _createKeyInternal(account, keyId);
        }
    }

    /// @dev Selects a potential key ID based on seed
    function _selectKeyId(uint256 seed) internal view returns (address) {
        return _selectFromPool(_potentialKeyIds, seed);
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
                         CORE CREATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Core key authorization with ghost state updates. Does NOT include assertions.
    /// @param account The account to authorize the key for
    /// @param keyId The key ID to authorize
    function _createKeyInternal(address account, address keyId) internal {
        uint64 expiry = _generateExpiry(uint256(keccak256(abi.encode(account, keyId))));
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        vm.startPrank(account);
        keychain.authorizeKey(
            keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, false, limits
        );
        vm.stopPrank();

        _totalKeysAuthorized++;
        _ghostKeyExists[account][keyId] = true;
        _ghostKeyExpiry[account][keyId] = expiry;
        _ghostKeyEnforceLimits[account][keyId] = false;
        _ghostKeySignatureType[account][keyId] = 0;

        if (!_keyUsed[account][keyId]) {
            _keyUsed[account][keyId] = true;
            _accountKeys[account].push(keyId);
        }
    }

    /// @dev Find an existing active (non-revoked) key for an account
    /// @param account The account to search
    /// @param seed Random seed for selection
    /// @return keyId The found key ID (address(0) if not found)
    /// @return found Whether a matching key was found
    function _findActiveKey(
        address account,
        uint256 seed
    )
        internal
        view
        returns (address keyId, bool found)
    {
        address[] memory keys = _accountKeys[account];
        if (keys.length == 0) return (address(0), false);

        uint256 startIdx = seed % keys.length;
        for (uint256 i = 0; i < keys.length; i++) {
            // Use modulo directly to avoid overflow when startIdx + i wraps
            uint256 idx = addmod(startIdx, i, keys.length);
            address candidate = keys[idx];
            if (_ghostKeyExists[account][candidate] && !_ghostKeyRevoked[account][candidate]) {
                return (candidate, true);
            }
        }
        return (address(0), false);
    }

    /// @dev Find an actor with an active key, or create one as fallback if none exist
    /// @param actorSeed Random seed for actor selection
    /// @param keyIdSeed Random seed for key selection
    /// @return account The actor with an active key
    /// @return keyId The active key ID
    /// @return skip True if no active key could be found or created
    function _ensureActorWithActiveKey(
        uint256 actorSeed,
        uint256 keyIdSeed
    )
        internal
        returns (address account, address keyId, bool skip)
    {
        // First, iterate over actors to find one with an existing active key
        uint256 startActorIdx = actorSeed % _actors.length;
        for (uint256 a = 0; a < _actors.length; a++) {
            // Use addmod to avoid overflow when startActorIdx + a wraps
            uint256 idx = addmod(startActorIdx, a, _actors.length);
            address candidate = _actors[idx];
            bool found;
            (keyId, found) = _findActiveKey(candidate, keyIdSeed);
            if (found) {
                return (candidate, keyId, false);
            }
        }

        // No actor has an active key - create one as fallback
        account = _selectActor(actorSeed);
        uint256 startKeyIdx = keyIdSeed % _potentialKeyIds.length;
        for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
            // Use addmod to avoid overflow when startKeyIdx + i wraps
            uint256 idx = addmod(startKeyIdx, i, _potentialKeyIds.length);
            address candidateKey = _potentialKeyIds[idx];
            // Can't reauthorize revoked keys (TEMPO-KEY4)
            if (!_ghostKeyRevoked[account][candidateKey]) {
                _createKeyInternal(account, candidateKey);
                return (account, candidateKey, false);
            }
        }

        // All keyIds revoked for this account - extremely rare, skip
        return (address(0), address(0), true);
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
    )
        external
    {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Skip if key already exists or was revoked for this account
        if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) {
            return;
        }

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
            assertEq(
                uint8(info.signatureType), uint8(sigType), "TEMPO-KEY1: SignatureType should match"
            );
            assertFalse(info.isRevoked, "TEMPO-KEY1: Should not be revoked");
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownKeychainError(reason);
        }
    }

    /// @notice Handler for revoking a key
    /// @dev Tests TEMPO-KEY3 (key revocation), TEMPO-KEY4 (revocation prevents reauthorization)
    function revokeKey(uint256 accountSeed, uint256 keyIdSeed) external {
        // Find an actor with an active key, or create one as fallback
        (address account, address keyId, bool skip) =
            _ensureActorWithActiveKey(accountSeed, keyIdSeed);
        if (skip) {
            return;
        }

        vm.startPrank(account);
        try keychain.revokeKey(keyId) {
            vm.stopPrank();

            _totalKeysRevoked++;

            // Update ghost state - clear all fields on revoke for consistency
            _ghostKeyExists[account][keyId] = false;
            _ghostKeyRevoked[account][keyId] = true;
            _ghostKeyExpiry[account][keyId] = 0;
            _ghostKeyEnforceLimits[account][keyId] = false;
            _ghostKeySignatureType[account][keyId] = 0;
            // Clear spending limits for all tokens
            for (uint256 t = 0; t < _tokens.length; t++) {
                _ghostSpendingLimits[account][keyId][address(_tokens[t])] = 0;
            }

            // TEMPO-KEY3: Verify key is revoked
            IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);
            assertTrue(info.isRevoked, "TEMPO-KEY3: Key should be marked as revoked");
            assertEq(info.expiry, 0, "TEMPO-KEY3: Expiry should be cleared");
            assertEq(info.keyId, address(0), "TEMPO-KEY3: KeyId should return 0 for revoked");
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownKeychainError(reason);
        }
    }

    /// @notice Handler for attempting to reauthorize a revoked key
    /// @dev Tests TEMPO-KEY4 (revoked keys cannot be reauthorized)
    function tryReauthorizeRevokedKey(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);

        // Find a revoked key across all actors (not just the selected account)
        address keyId = address(0);
        address keyOwner = address(0);
        uint256 startActorIdx = accountSeed % _actors.length;
        for (uint256 a = 0; a < _actors.length && keyId == address(0); a++) {
            // Use addmod to avoid overflow
            uint256 actorIdx = addmod(startActorIdx, a, _actors.length);
            address candidate = _actors[actorIdx];
            address[] memory keys = _accountKeys[candidate];
            if (keys.length == 0) continue;
            uint256 startKeyIdx = keyIdSeed % keys.length;
            for (uint256 k = 0; k < keys.length; k++) {
                // Use addmod to avoid overflow
                uint256 keyIdx = addmod(startKeyIdx, k, keys.length);
                address potentialKey = keys[keyIdx];
                if (_ghostKeyRevoked[candidate][potentialKey]) {
                    keyId = potentialKey;
                    keyOwner = candidate;
                    break;
                }
            }
        }

        if (keyId == address(0)) {
            // No revoked key found - create and revoke one as fallback
            account = _selectActor(accountSeed);
            // Find an unused keyId for this account
            uint256 startKeyIdx = keyIdSeed % _potentialKeyIds.length;
            for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
                // Use addmod to avoid overflow
                uint256 idx = addmod(startKeyIdx, i, _potentialKeyIds.length);
                address candidateKey = _potentialKeyIds[idx];
                if (
                    !_ghostKeyExists[account][candidateKey]
                        && !_ghostKeyRevoked[account][candidateKey]
                ) {
                    keyId = candidateKey;
                    break;
                }
            }
            if (keyId == address(0)) {
                return;
            }
            // Create and immediately revoke the key
            _createKeyInternal(account, keyId);
            vm.prank(account);
            keychain.revokeKey(keyId);
            _totalKeysRevoked++;
            _ghostKeyExists[account][keyId] = false;
            _ghostKeyRevoked[account][keyId] = true;
            _ghostKeyExpiry[account][keyId] = 0;
            _ghostKeyEnforceLimits[account][keyId] = false;
            _ghostKeySignatureType[account][keyId] = 0;
        } else {
            account = keyOwner;
        }

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
    }

    /// @notice Handler for updating spending limits
    /// @dev Tests TEMPO-KEY5 (limit update), TEMPO-KEY6 (enables limits on unlimited key)
    function updateSpendingLimit(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        // Need tokens for spending limits
        if (_tokens.length == 0) {
            return;
        }

        // Find an actor with an active key, or create one as fallback
        (address account, address keyId, bool skip) =
            _ensureActorWithActiveKey(accountSeed, keyIdSeed);
        if (skip) {
            return;
        }

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
    }

    /// @notice Handler for authorizing duplicate key (should fail)
    /// @dev Tests TEMPO-KEY8 (duplicate key rejection)
    function tryAuthorizeDuplicateKey(uint256 accountSeed, uint256 keyIdSeed) external {
        // Find an actor with an active key, or create one as fallback (skip if all keys are revoked)
        (address account, address keyId, bool skip) =
            _ensureActorWithActiveKey(accountSeed, keyIdSeed);
        if (skip) {
            return;
        }

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
    }

    /// @notice Handler for revoking non-existent key (should fail)
    /// @dev Tests TEMPO-KEY9 (revoke non-existent key returns KeyNotFound)
    function tryRevokeNonExistentKey(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Skip if key exists (not revoked)
        if (_ghostKeyExists[account][keyId]) {
            return;
        }

        // Both never-existed and already-revoked keys should return KeyNotFound
        bool wasRevoked = _ghostKeyRevoked[account][keyId];

        vm.startPrank(account);
        try keychain.revokeKey(keyId) {
            vm.stopPrank();
            revert("TEMPO-KEY9: Revoking non-existent/revoked key should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyNotFound.selector,
                "TEMPO-KEY9: Should revert with KeyNotFound"
            );
        }
    }

    /// @notice Handler for verifying account isolation
    /// @dev Tests TEMPO-KEY10 (keys are isolated per account)
    function verifyAccountIsolation(
        uint256 account1Seed,
        uint256 account2Seed,
        uint256 keyIdSeed
    )
        external
    {
        address account1 = _selectActor(account1Seed);
        address account2 = _selectActorExcluding(account2Seed, account1);

        address keyId = _selectKeyId(keyIdSeed);

        // Skip if either account has this key already
        if (_ghostKeyExists[account1][keyId] || _ghostKeyRevoked[account1][keyId]) {
            return;
        }
        if (_ghostKeyExists[account2][keyId] || _ghostKeyRevoked[account2][keyId]) {
            return;
        }

        // Need at least one token for limits
        if (_tokens.length == 0) {
            return;
        }

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
        if (_ghostKeyExists[account][keyId]) {
            return;
        }

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

    /// @notice Handler for testing expiry boundary condition
    /// @dev Tests TEMPO-KEY17 (expiry == block.timestamp counts as expired)
    ///      Rust uses timestamp >= expiry, so expiry == now is already expired
    function testExpiryBoundary(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Skip if key already exists or was revoked
        if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) {
            return;
        }
        if (_tokens.length == 0) {
            return;
        }

        // Create a key with expiry 1 second in the future (valid at creation)
        uint64 expiry = uint64(block.timestamp + 1);

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        vm.startPrank(account);
        try keychain.authorizeKey(
            keyId, IAccountKeychain.SignatureType.Secp256k1, expiry, false, limits
        ) {
            vm.stopPrank();

            // Key was created, update ghost state
            _ghostKeyExists[account][keyId] = true;
            _ghostKeyExpiry[account][keyId] = expiry;
            _ghostKeySignatureType[account][keyId] = 0;

            if (!_keyUsed[account][keyId]) {
                _keyUsed[account][keyId] = true;
                _accountKeys[account].push(keyId);
            }

            _totalKeysAuthorized++;

            // Warp to exactly the expiry timestamp
            // TEMPO-KEY17: timestamp >= expiry means equality counts as expired
            vm.warp(expiry);

            vm.startPrank(account);
            try keychain.updateSpendingLimit(keyId, address(_tokens[0]), 1000e6) {
                vm.stopPrank();
                revert("TEMPO-KEY17: Operation at expiry timestamp should fail with KeyExpired");
            } catch (bytes memory reason) {
                vm.stopPrank();
                assertEq(
                    bytes4(reason),
                    IAccountKeychain.KeyExpired.selector,
                    "TEMPO-KEY17: Should revert with KeyExpired when timestamp == expiry"
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            // ExpiryInPast is acceptable if expiry <= block.timestamp at creation
            _assertKnownKeychainError(reason);
        }
    }

    /// @notice Handler for testing operations on expired keys
    /// @dev Tests TEMPO-KEY18 (operations on expired keys fail with KeyExpired)
    function testExpiredKeyOperations(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 warpAmount
    )
        external
    {
        if (_tokens.length == 0) {
            return;
        }

        // Find an actor with an active key, or create one as fallback
        (address account, address keyId, bool skip) =
            _ensureActorWithActiveKey(accountSeed, keyIdSeed);
        if (skip) {
            return;
        }

        uint64 expiry = _ghostKeyExpiry[account][keyId];

        // Skip if already expired or expiry is max (never expires)
        if (block.timestamp >= expiry || expiry == type(uint64).max) {
            return;
        }

        // Warp past expiry (1 second to 1 day past)
        uint256 warpTo = expiry + 1 + (warpAmount % 1 days);
        vm.warp(warpTo);

        // TEMPO-KEY18: Operations on expired keys should fail with KeyExpired
        vm.startPrank(account);
        try keychain.updateSpendingLimit(keyId, address(_tokens[0]), 1000e6) {
            vm.stopPrank();
            revert("TEMPO-KEY18: Operation on expired key should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyExpired.selector,
                "TEMPO-KEY18: Should revert with KeyExpired"
            );
        }
    }

    /// @notice Handler for testing invalid signature type
    /// @dev Tests TEMPO-KEY19 (invalid enum values >= 3 are rejected with InvalidSignatureType)
    function testInvalidSignatureType(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint8 badType
    )
        external
    {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Skip if key already exists or was revoked
        if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) return;

        // Only test with values >= 3 (invalid enum values)
        badType = uint8(bound(badType, 3, 255));

        uint64 expiry = uint64(block.timestamp + 1 days);
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        // Use low-level call to bypass Solidity's enum type checking
        // This allows us to pass an invalid uint8 value for signatureType
        bytes memory callData = abi.encodeWithSelector(
            IAccountKeychain.authorizeKey.selector,
            keyId,
            badType, // Raw uint8 instead of enum
            expiry,
            false,
            limits
        );

        vm.startPrank(account);
        (bool success, bytes memory returnData) = address(keychain).call(callData);
        vm.stopPrank();

        // TEMPO-KEY19: Invalid signature type should be rejected
        assertFalse(success, "TEMPO-KEY19: Invalid signature type should revert");
        // If revert data is provided, verify it's the expected error
        // (Empty revert data is acceptable - ABI-level rejection for invalid enum)
        if (returnData.length >= 4) {
            assertEq(
                bytes4(returnData),
                IAccountKeychain.InvalidSignatureType.selector,
                "TEMPO-KEY19: Should revert with InvalidSignatureType"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks in a single pass over actors
    /// @dev Consolidates TEMPO-KEY13, KEY14, KEY15, KEY16 into unified loops
    function invariant_globalInvariants() public view {
        // Single pass over all actors and their keys
        for (uint256 a = 0; a < _actors.length; a++) {
            address account = _actors[a];
            address[] memory keys = _accountKeys[account];

            for (uint256 k = 0; k < keys.length; k++) {
                address keyId = keys[k];
                IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);

                if (_ghostKeyRevoked[account][keyId]) {
                    // TEMPO-KEY13: Revoked key should show isRevoked=true and other fields defaulted
                    assertTrue(info.isRevoked, "TEMPO-KEY13: Revoked key should show isRevoked");
                    assertEq(info.keyId, address(0), "TEMPO-KEY13: Revoked key keyId should be 0");
                    assertEq(info.expiry, 0, "TEMPO-KEY13: Revoked key expiry should be 0");
                    assertFalse(
                        info.enforceLimits, "TEMPO-KEY13: Revoked key enforceLimits should be false"
                    );
                    assertEq(
                        uint8(info.signatureType),
                        0,
                        "TEMPO-KEY13: Revoked key signatureType should be 0"
                    );
                    // TEMPO-KEY15: Revoked keys stay revoked (already checked via isRevoked above)
                } else if (_ghostKeyExists[account][keyId]) {
                    // TEMPO-KEY13: Active key should match ghost state
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
                    // TEMPO-KEY16: Signature type must match ghost state for all active keys
                    assertEq(
                        uint8(info.signatureType),
                        _ghostKeySignatureType[account][keyId],
                        "TEMPO-KEY16: SignatureType must match ghost state"
                    );
                    assertFalse(info.isRevoked, "TEMPO-KEY13: Active key should not be revoked");

                    // TEMPO-KEY14: Check spending limits for active keys with limits enforced
                    if (_ghostKeyEnforceLimits[account][keyId]) {
                        uint64 expiry = _ghostKeyExpiry[account][keyId];
                        bool isExpired = expiry != type(uint64).max && block.timestamp >= expiry;
                        if (!isExpired) {
                            for (uint256 t = 0; t < _tokens.length; t++) {
                                address token = address(_tokens[t]);
                                uint256 expected = _ghostSpendingLimits[account][keyId][token];
                                uint256 actual = keychain.getRemainingLimit(account, keyId, token);
                                assertEq(
                                    actual,
                                    expected,
                                    "TEMPO-KEY14: Spending limit should match ghost state"
                                );
                            }
                        }
                    }
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
            || selector == IAccountKeychain.ExpiryInPast.selector
            || selector == IAccountKeychain.UnauthorizedCaller.selector;
        assertTrue(isKnown, "Unknown error encountered");
    }

}
