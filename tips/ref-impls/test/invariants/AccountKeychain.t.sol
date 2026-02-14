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

    /// @dev Mode of token limits generated for authorizeKey fuzzing
    enum LimitMode {
        None,
        Single,
        TwoDistinct,
        TwoDuplicate
    }

    /// @dev Seed bundle for authorizeKey limit generation
    struct LimitSeeds {
        uint256 modeSeed;
        uint256 token0Seed;
        uint256 amount0Seed;
        uint256 token1Seed;
        uint256 amount1Seed;
    }

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
    function _generateValidAuthorizeExpiry(uint256 seed) internal view returns (uint64) {
        return uint64(block.timestamp + 1 + (seed % 365 days));
    }

    /// @dev Generates an invalid expiry timestamp for authorizeKey (expiry <= block.timestamp)
    function _generateInvalidAuthorizeExpiry(uint256 seed) internal view returns (uint64) {
        return uint64(bound(seed, 0, block.timestamp));
    }

    /// @dev Generates a signature type (0-2)
    function _generateSignatureType(uint256 seed)
        internal
        pure
        returns (IAccountKeychain.SignatureType)
    {
        return IAccountKeychain.SignatureType(seed % 3);
    }

    /// @dev Builds token limit inputs for authorizeKey fuzzing
    /// @dev Can generate empty, single-token, distinct-two-token, or duplicate-token limits
    function _buildAuthorizeLimits(LimitSeeds memory seeds)
        internal
        view
        returns (IAccountKeychain.TokenLimit[] memory limits)
    {
        if (_tokens.length == 0) {
            return new IAccountKeychain.TokenLimit[](0);
        }

        LimitMode mode = LimitMode(seeds.modeSeed % 4);
        uint256 limitCount = mode == LimitMode.None ? 0 : (mode == LimitMode.Single ? 1 : 2);
        limits = new IAccountKeychain.TokenLimit[](limitCount);
        if (limitCount == 0) {
            return limits;
        }

        address token0 = address(_selectBaseToken(seeds.token0Seed));
        uint256 amount0 = (seeds.amount0Seed % 1_000_000) * 1e6;
        limits[0] = IAccountKeychain.TokenLimit({
            token: token0, amount: amount0
        });

        if (limitCount == 1) {
            return limits;
        }

        address token1 = address(_selectBaseToken(seeds.token1Seed));
        if (mode == LimitMode.TwoDuplicate) {
            token1 = token0;
        } else if (mode == LimitMode.TwoDistinct && _tokens.length > 1 && token1 == token0) {
            token1 = address(_tokens[addmod(seeds.token1Seed, 1, _tokens.length)]);
        }
        uint256 amount1 = (seeds.amount1Seed % 1_000_000) * 1e6;

        limits[1] = IAccountKeychain.TokenLimit({
            token: token1, amount: amount1
        });
    }

    /// @dev Computes expected stored limit for a token from authorizeKey inputs
    /// @dev When duplicate token entries exist, last write wins
    function _expectedLimitForToken(
        IAccountKeychain.TokenLimit[] memory limits,
        bool enforceLimits,
        address token
    )
        internal
        pure
        returns (uint256 expected)
    {
        if (!enforceLimits) return 0;

        for (uint256 i = 0; i < limits.length; i++) {
            if (limits[i].token == token) {
                expected = limits[i].amount;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         CORE CREATION HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Core key authorization with ghost state updates. Does NOT include assertions.
    /// @param account The account to authorize the key for
    /// @param keyId The key ID to authorize
    function _createKeyInternal(address account, address keyId) internal {
        uint64 expiry = _generateValidAuthorizeExpiry(uint256(keccak256(abi.encode(account, keyId))));
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

    /// @dev Find an active and non-expired key for an account
    /// @param account The account to search
    /// @param seed Random seed for selection
    /// @return keyId The found key ID (address(0) if not found)
    /// @return found Whether a matching key was found
    function _findUpdatableKey(
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
            uint256 idx = addmod(startIdx, i, keys.length);
            address candidate = keys[idx];
            if (!_ghostKeyExists[account][candidate] || _ghostKeyRevoked[account][candidate]) {
                continue;
            }

            uint64 expiry = _ghostKeyExpiry[account][candidate];
            if (expiry == type(uint64).max || block.timestamp < expiry) {
                return (candidate, true);
            }
        }
        return (address(0), false);
    }

    /// @dev Find an actor with an active, non-expired key, or create one as fallback
    /// @param actorSeed Random seed for actor selection
    /// @param keyIdSeed Random seed for key selection
    /// @return account The actor with an updatable key
    /// @return keyId The updatable key ID
    /// @return skip True if no updatable key could be found or created
    function _ensureActorWithUpdatableKey(
        uint256 actorSeed,
        uint256 keyIdSeed
    )
        internal
        returns (address account, address keyId, bool skip)
    {
        // First, iterate over actors to find an existing non-expired key
        uint256 startActorIdx = actorSeed % _actors.length;
        for (uint256 a = 0; a < _actors.length; a++) {
            uint256 idx = addmod(startActorIdx, a, _actors.length);
            address candidate = _actors[idx];
            bool found;
            (keyId, found) = _findUpdatableKey(candidate, keyIdSeed);
            if (found) {
                return (candidate, keyId, false);
            }
        }

        // No actor has a non-expired key - create one as fallback
        account = _selectActor(actorSeed);
        uint256 startKeyIdx = keyIdSeed % _potentialKeyIds.length;
        for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
            uint256 idx = addmod(startKeyIdx, i, _potentialKeyIds.length);
            address candidateKey = _potentialKeyIds[idx];
            if (
                !_ghostKeyExists[account][candidateKey]
                    && !_ghostKeyRevoked[account][candidateKey]
            ) {
                _createKeyInternal(account, candidateKey);
                return (account, candidateKey, false);
            }
        }

        // All keyIds consumed/revoked for this account - extremely rare, skip
        return (address(0), address(0), true);
    }

    /// @dev Select token input for updateSpendingLimit fuzzing (includes edge addresses)
    function _selectUpdateLimitToken(
        uint256 tokenSeed,
        address account,
        address keyId
    )
        internal
        view
        returns (address)
    {
        if (_tokens.length == 0) return address(0);

        uint256 mode = tokenSeed % 10;
        if (mode == 0) return address(0);
        if (mode == 1) return account;
        if (mode == 2) return keyId;
        if (mode == 3) return _selectKeyId(tokenSeed);
        if (mode == 4) return address(pathUSD);
        return address(_tokens[tokenSeed % _tokens.length]);
    }

    /// @dev Derives new limit input to exercise edge values and arbitrary uint256 values
    function _deriveUpdateLimit(uint256 seed) internal pure returns (uint256) {
        uint256 mode = seed % 8;
        if (mode == 0) return 0;
        if (mode == 1) return 1;
        if (mode == 2) return 1e6;
        if (mode == 3) return type(uint256).max;
        return seed;
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for authorizing a new key
    /// @dev Tests TEMPO-KEY1 (key authorization), TEMPO-KEY2 (spending limits)
    function handler_authorizeKey(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 sigTypeSeed,
        uint256 expirySeed,
        bool enforceLimits,
        LimitSeeds calldata limitSeeds
    )
        external
    {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Skip if key already exists or was revoked for this account
        if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) {
            return;
        }

        uint64 expiry = _generateValidAuthorizeExpiry(expirySeed);
        IAccountKeychain.SignatureType sigType = _generateSignatureType(sigTypeSeed);

        // Generate limit inputs independently from enforceLimits to exercise
        // "limits ignored when enforceLimits=false" behavior.
        IAccountKeychain.TokenLimit[] memory limits = _buildAuthorizeLimits(limitSeeds);

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
                for (uint256 i = 0; i < limits.length; i++) {
                    _ghostSpendingLimits[account][keyId][limits[i].token] = limits[i].amount;
                }
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

            // TEMPO-KEY2: Verify all limit writes from authorizeKey.
            // Covers: empty/single/multi limits, duplicate token entries, and
            // enforceLimits=false with non-empty limits (limits must remain zero).
            for (uint256 t = 0; t < _tokens.length; t++) {
                address token = address(_tokens[t]);
                uint256 expectedLimit = _expectedLimitForToken(limits, enforceLimits, token);
                uint256 actualLimit = keychain.getRemainingLimit(account, keyId, token);
                assertEq(
                    actualLimit, expectedLimit, "TEMPO-KEY2: Stored limit should match input state"
                );
            }
        } catch {
            vm.stopPrank();
            revert("TEMPO-KEY1: Valid authorizeKey call should not revert");
        }
    }

    /// @notice Handler for authorizing with expiry in the past/boundary (should fail)
    /// @dev Exercises authorizeKey expiry validation with expiry <= block.timestamp
    function handler_tryAuthorizeKeyExpiryInPast(
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

        uint64 badExpiry = _generateInvalidAuthorizeExpiry(expirySeed);
        IAccountKeychain.SignatureType sigType = _generateSignatureType(sigTypeSeed);

        LimitSeeds memory limitSeeds = LimitSeeds({
            modeSeed: expirySeed,
            token0Seed: accountSeed,
            amount0Seed: keyIdSeed,
            token1Seed: sigTypeSeed,
            amount1Seed: limitAmountSeed
        });
        IAccountKeychain.TokenLimit[] memory limits = _buildAuthorizeLimits(limitSeeds);

        vm.startPrank(account);
        try keychain.authorizeKey(keyId, sigType, badExpiry, enforceLimits, limits) {
            vm.stopPrank();
            revert("TEMPO-KEY1: authorizeKey with expiry <= now should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(reason.length >= 4, "TEMPO-KEY1: Missing revert selector");
            assertEq(
                bytes4(reason),
                IAccountKeychain.ExpiryInPast.selector,
                "TEMPO-KEY1: Past/boundary expiry should revert with ExpiryInPast"
            );
        }
    }

    /// @notice Handler for revoking a key
    /// @dev Tests TEMPO-KEY3 (key revocation), TEMPO-KEY4 (revocation prevents reauthorization),
    ///      and TEMPO-KEY25 (revoked key limits are inaccessible)
    function handler_revokeKey(uint256 accountSeed, uint256 keyIdSeed) external {
        // Find an actor with an active key, or create one as fallback
        (address account, address keyId, bool skip) =
            _ensureActorWithActiveKey(accountSeed, keyIdSeed);
        if (skip) {
            return;
        }

        bool hadNonZeroLimit;
        for (uint256 t = 0; t < _tokens.length; t++) {
            if (keychain.getRemainingLimit(account, keyId, address(_tokens[t])) > 0) {
                hadNonZeroLimit = true;
            }
        }

        vm.prank(account);
        keychain.revokeKey(keyId);

        _totalKeysRevoked++;

        // Update ghost state - key metadata is cleared but revocation is sticky.
        _ghostKeyExists[account][keyId] = false;
        _ghostKeyRevoked[account][keyId] = true;
        _ghostKeyExpiry[account][keyId] = 0;
        _ghostKeyEnforceLimits[account][keyId] = false;
        _ghostKeySignatureType[account][keyId] = 0;

        // TEMPO-KEY3: Verify key is revoked and all fields match Rust Default
        IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);
        assertTrue(info.isRevoked, "TEMPO-KEY3: Key should be marked as revoked");
        assertEq(info.expiry, 0, "TEMPO-KEY3: Expiry should be cleared");
        assertEq(info.keyId, address(0), "TEMPO-KEY3: KeyId should return 0 for revoked");
        assertFalse(info.enforceLimits, "TEMPO-KEY3: EnforceLimits should be cleared");
        assertEq(
            uint8(info.signatureType),
            uint8(IAccountKeychain.SignatureType.Secp256k1),
            "TEMPO-KEY3: SignatureType should be cleared to default"
        );

        // TEMPO-KEY25 (T2+): Revoked key limits are inaccessible.
        for (uint256 t = 0; t < _tokens.length; t++) {
            assertEq(
                keychain.getRemainingLimit(account, keyId, address(_tokens[t])),
                0,
                "TEMPO-KEY25: Revoked key limit should read as 0"
            );
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
    /// @dev Tests TEMPO-KEY5 (limit update), TEMPO-KEY6 (enables limits on unlimited key),
    ///      TEMPO-KEY24 (enforceLimits one-way ratchet), and TEMPO-KEY28 (token independence)
    function handler_updateSpendingLimit(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        // Find an actor with an active, non-expired key, or create one as fallback
        (address account, address keyId, bool skip) =
            _ensureActorWithUpdatableKey(accountSeed, keyIdSeed);
        if (skip) {
            return;
        }

        address token = _selectUpdateLimitToken(tokenSeed, account, keyId);
        uint256 newLimit = _deriveUpdateLimit(newLimitSeed);

        IAccountKeychain.KeyInfo memory infoBefore = keychain.getKey(account, keyId);

        // Build a watch list of token addresses to check for independence (TEMPO-KEY28).
        // Includes all base tokens, pathUSD, address(0), and the selected token itself
        // (which may be an arbitrary address like account or keyId).
        uint256 watchLen = _tokens.length + 3;
        address[] memory watchTokens = new address[](watchLen);
        for (uint256 t = 0; t < _tokens.length; t++) {
            watchTokens[t] = address(_tokens[t]);
        }
        watchTokens[_tokens.length] = address(pathUSD);
        watchTokens[_tokens.length + 1] = address(0);
        watchTokens[_tokens.length + 2] = token;

        uint256[] memory watchLimitsBefore = new uint256[](watchTokens.length);
        for (uint256 t = 0; t < watchTokens.length; t++) {
            watchLimitsBefore[t] = keychain.getRemainingLimit(account, keyId, watchTokens[t]);
        }
        uint256 selectedLimitBefore = keychain.getRemainingLimit(account, keyId, token);

        vm.prank(account);
        keychain.updateSpendingLimit(keyId, token, newLimit);

        _totalLimitUpdates++;

        // Update ghost state
        _ghostSpendingLimits[account][keyId][token] = newLimit;
        _ghostKeyEnforceLimits[account][keyId] = true; // Always enables limits

        // TEMPO-KEY5: selected token limit should be updated to newLimit
        uint256 storedLimit = keychain.getRemainingLimit(account, keyId, token);
        assertEq(storedLimit, newLimit, "TEMPO-KEY5: selected token limit should equal newLimit");

        // TEMPO-KEY6 / KEY24: enforceLimits should be true and remain a one-way ratchet
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(account, keyId);
        assertTrue(infoAfter.enforceLimits, "TEMPO-KEY6: enforceLimits should be true after update");
        assertEq(infoAfter.keyId, infoBefore.keyId, "TEMPO-KEY5: keyId should remain unchanged");
        assertEq(infoAfter.expiry, infoBefore.expiry, "TEMPO-KEY5: expiry should remain unchanged");
        assertEq(
            uint8(infoAfter.signatureType),
            uint8(infoBefore.signatureType),
            "TEMPO-KEY5: signature type should remain unchanged"
        );
        assertEq(
            infoAfter.isRevoked, infoBefore.isRevoked, "TEMPO-KEY5: revoked flag should remain unchanged"
        );

        // TEMPO-KEY28: updating one token must not mutate limits for other tokens.
        for (uint256 t = 0; t < watchTokens.length; t++) {
            uint256 expected = watchTokens[t] == token ? newLimit : watchLimitsBefore[t];
            assertEq(
                keychain.getRemainingLimit(account, keyId, watchTokens[t]),
                expected,
                "TEMPO-KEY28: unrelated token limits should remain unchanged"
            );
        }

    }

    /// @notice Handler for updating spending limit on a never-authorized key (should fail)
    /// @dev Tests KeyNotFound branch for updateSpendingLimit
    function handler_tryUpdateSpendingLimitNonExistentKey(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        address account = _selectActor(accountSeed);
        address keyId = address(0);

        // Sample keyId=0 as explicit edge case; otherwise pick a never-authorized pool key.
        if (keyIdSeed % 8 != 0) {
            uint256 startPoolIdx = keyIdSeed % _potentialKeyIds.length;
            for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
                uint256 idx = addmod(startPoolIdx, i, _potentialKeyIds.length);
                address candidate = _potentialKeyIds[idx];
                if (!_ghostKeyExists[account][candidate] && !_ghostKeyRevoked[account][candidate]) {
                    keyId = candidate;
                    break;
                }
            }
        }

        if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) {
            return;
        }

        address token = _selectUpdateLimitToken(tokenSeed, account, keyId);
        uint256 newLimit = _deriveUpdateLimit(newLimitSeed);

        IAccountKeychain.KeyInfo memory infoBefore = keychain.getKey(account, keyId);
        uint256 limitBefore = keychain.getRemainingLimit(account, keyId, token);

        vm.startPrank(account);
        try keychain.updateSpendingLimit(keyId, token, newLimit) {
            vm.stopPrank();
            revert("TEMPO-KEY5: Updating non-existent key should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyNotFound.selector,
                "TEMPO-KEY5: non-existent key should revert with KeyNotFound"
            );
        }

        // Failed update should not mutate key or limit view state.
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(account, keyId);
        assertEq(infoAfter.keyId, infoBefore.keyId, "TEMPO-KEY5: keyId should remain unchanged");
        assertEq(infoAfter.expiry, infoBefore.expiry, "TEMPO-KEY5: expiry should remain unchanged");
        assertEq(
            infoAfter.enforceLimits,
            infoBefore.enforceLimits,
            "TEMPO-KEY5: enforceLimits should remain unchanged"
        );
        assertEq(
            uint8(infoAfter.signatureType),
            uint8(infoBefore.signatureType),
            "TEMPO-KEY5: signature type should remain unchanged"
        );
        assertEq(
            infoAfter.isRevoked, infoBefore.isRevoked, "TEMPO-KEY5: revoked flag should remain unchanged"
        );
        assertEq(
            keychain.getRemainingLimit(account, keyId, token),
            limitBefore,
            "TEMPO-KEY5: failed update should not mutate limit"
        );

    }

    /// @notice Handler for updating spending limit on a revoked key (should fail)
    /// @dev Tests KeyAlreadyRevoked branch for updateSpendingLimit
    function handler_tryUpdateSpendingLimitRevokedKey(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        address account = _selectActor(accountSeed);
        address keyId = address(0);

        // Prefer an already revoked key for this account.
        address[] memory keys = _accountKeys[account];
        if (keys.length > 0) {
            uint256 startKeyIdx = keyIdSeed % keys.length;
            for (uint256 k = 0; k < keys.length; k++) {
                uint256 idx = addmod(startKeyIdx, k, keys.length);
                address candidate = keys[idx];
                if (_ghostKeyRevoked[account][candidate]) {
                    keyId = candidate;
                    break;
                }
            }
        }

        // Fallback: create+revoke to guarantee this path is exercised.
        if (keyId == address(0)) {
            uint256 startPoolIdx = keyIdSeed % _potentialKeyIds.length;
            for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
                uint256 idx = addmod(startPoolIdx, i, _potentialKeyIds.length);
                address candidate = _potentialKeyIds[idx];
                if (!_ghostKeyExists[account][candidate] && !_ghostKeyRevoked[account][candidate]) {
                    keyId = candidate;
                    break;
                }
            }
            if (keyId == address(0)) return;

            _createKeyInternal(account, keyId);
            vm.prank(account);
            keychain.revokeKey(keyId);

            _totalKeysRevoked++;
            _ghostKeyExists[account][keyId] = false;
            _ghostKeyRevoked[account][keyId] = true;
            _ghostKeyExpiry[account][keyId] = 0;
            _ghostKeyEnforceLimits[account][keyId] = false;
            _ghostKeySignatureType[account][keyId] = 0;
        }

        if (!_ghostKeyRevoked[account][keyId]) return;

        address token = _selectUpdateLimitToken(tokenSeed, account, keyId);
        uint256 newLimit = _deriveUpdateLimit(newLimitSeed);

        IAccountKeychain.KeyInfo memory infoBefore = keychain.getKey(account, keyId);
        uint256 limitBefore = keychain.getRemainingLimit(account, keyId, token);

        vm.startPrank(account);
        try keychain.updateSpendingLimit(keyId, token, newLimit) {
            vm.stopPrank();
            revert("TEMPO-KEY5: Updating revoked key should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyAlreadyRevoked.selector,
                "TEMPO-KEY5: revoked key should revert with KeyAlreadyRevoked"
            );
        }

        // Failed update should not mutate revoked key state.
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(account, keyId);
        assertEq(infoAfter.keyId, infoBefore.keyId, "TEMPO-KEY5: keyId should remain unchanged");
        assertEq(infoAfter.expiry, infoBefore.expiry, "TEMPO-KEY5: expiry should remain unchanged");
        assertEq(
            infoAfter.enforceLimits,
            infoBefore.enforceLimits,
            "TEMPO-KEY5: enforceLimits should remain unchanged"
        );
        assertEq(
            uint8(infoAfter.signatureType),
            uint8(infoBefore.signatureType),
            "TEMPO-KEY5: signature type should remain unchanged"
        );
        assertEq(
            infoAfter.isRevoked, infoBefore.isRevoked, "TEMPO-KEY5: revoked flag should remain unchanged"
        );
        assertEq(
            keychain.getRemainingLimit(account, keyId, token),
            limitBefore,
            "TEMPO-KEY5: failed update should not mutate limit"
        );

    }

    /// @notice Handler for updating another account's key (should fail)
    /// @dev Tests account isolation for updateSpendingLimit
    function handler_tryUpdateSpendingLimitOtherAccountsKey(
        uint256 ownerSeed,
        uint256 callerSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        address owner = _selectActor(ownerSeed);
        address caller = _selectActorExcluding(callerSeed, owner);
        address keyId = address(0);

        // Prefer an owner-active key that caller does not have.
        address[] memory ownerKeys = _accountKeys[owner];
        if (ownerKeys.length > 0) {
            uint256 startKeyIdx = keyIdSeed % ownerKeys.length;
            for (uint256 k = 0; k < ownerKeys.length; k++) {
                uint256 idx = addmod(startKeyIdx, k, ownerKeys.length);
                address candidate = ownerKeys[idx];
                if (
                    _ghostKeyExists[owner][candidate] && !_ghostKeyRevoked[owner][candidate]
                        && !_ghostKeyExists[caller][candidate] && !_ghostKeyRevoked[caller][candidate]
                ) {
                    keyId = candidate;
                    break;
                }
            }
        }

        // Fallback: create fresh owner key that is absent for caller.
        if (keyId == address(0)) {
            uint256 startPoolIdx = keyIdSeed % _potentialKeyIds.length;
            for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
                uint256 idx = addmod(startPoolIdx, i, _potentialKeyIds.length);
                address candidate = _potentialKeyIds[idx];
                if (
                    !_ghostKeyExists[owner][candidate] && !_ghostKeyRevoked[owner][candidate]
                        && !_ghostKeyExists[caller][candidate] && !_ghostKeyRevoked[caller][candidate]
                ) {
                    keyId = candidate;
                    break;
                }
            }
            if (keyId == address(0)) return;
            _createKeyInternal(owner, keyId);
        }

        if (!_ghostKeyExists[owner][keyId] || _ghostKeyRevoked[owner][keyId]) return;
        if (_ghostKeyExists[caller][keyId] || _ghostKeyRevoked[caller][keyId]) return;

        address token = _selectUpdateLimitToken(tokenSeed, owner, keyId);
        uint256 newLimit = _deriveUpdateLimit(newLimitSeed);

        IAccountKeychain.KeyInfo memory ownerBefore = keychain.getKey(owner, keyId);
        uint256 ownerLimitBefore = keychain.getRemainingLimit(owner, keyId, token);

        vm.startPrank(caller);
        try keychain.updateSpendingLimit(keyId, token, newLimit) {
            vm.stopPrank();
            revert("TEMPO-KEY5: Caller should not update another account's key");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyNotFound.selector,
                "TEMPO-KEY5: foreign key update should revert with KeyNotFound"
            );
        }

        // Failed foreign update must not mutate owner's key state.
        IAccountKeychain.KeyInfo memory ownerAfter = keychain.getKey(owner, keyId);
        assertEq(ownerAfter.keyId, ownerBefore.keyId, "TEMPO-KEY5: owner keyId should remain unchanged");
        assertEq(ownerAfter.expiry, ownerBefore.expiry, "TEMPO-KEY5: owner expiry should remain unchanged");
        assertEq(
            ownerAfter.enforceLimits,
            ownerBefore.enforceLimits,
            "TEMPO-KEY5: owner enforceLimits should remain unchanged"
        );
        assertEq(
            uint8(ownerAfter.signatureType),
            uint8(ownerBefore.signatureType),
            "TEMPO-KEY5: owner signature type should remain unchanged"
        );
        assertEq(
            ownerAfter.isRevoked, ownerBefore.isRevoked, "TEMPO-KEY5: owner revoked flag should remain unchanged"
        );
        assertEq(
            keychain.getRemainingLimit(owner, keyId, token),
            ownerLimitBefore,
            "TEMPO-KEY5: failed foreign update should not mutate owner limit"
        );

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

    /// @notice Handler for revoking a never-authorized key (should fail)
    /// @dev Tests TEMPO-KEY9 (revoke non-existent key returns KeyNotFound)
    function handler_tryRevokeNonExistentKey(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);
        address keyId = address(0);

        // Sample keyId=0 as explicit edge case; otherwise pick a never-authorized pool key.
        if (keyIdSeed % 8 != 0) {
            uint256 startPoolIdx = keyIdSeed % _potentialKeyIds.length;
            for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
                uint256 idx = addmod(startPoolIdx, i, _potentialKeyIds.length);
                address candidate = _potentialKeyIds[idx];
                if (!_ghostKeyExists[account][candidate] && !_ghostKeyRevoked[account][candidate]) {
                    keyId = candidate;
                    break;
                }
            }
        }

        // Sanity: ensure this is truly never-authorized for this account.
        assertFalse(_ghostKeyExists[account][keyId], "TEMPO-KEY9: target key must not be active");
        assertFalse(_ghostKeyRevoked[account][keyId], "TEMPO-KEY9: target key must not be revoked");

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

    }

    /// @notice Handler for revoking an already-revoked key (should fail)
    /// @dev Tests TEMPO-KEY9 replay branch (double revoke returns KeyNotFound)
    function handler_tryRevokeAlreadyRevokedKey(uint256 accountSeed, uint256 keyIdSeed) external {
        address account = _selectActor(accountSeed);
        address keyId = address(0);

        // Prefer an already revoked key for this account.
        address[] memory keys = _accountKeys[account];
        if (keys.length > 0) {
            uint256 startKeyIdx = keyIdSeed % keys.length;
            for (uint256 k = 0; k < keys.length; k++) {
                uint256 idx = addmod(startKeyIdx, k, keys.length);
                address candidate = keys[idx];
                if (_ghostKeyRevoked[account][candidate]) {
                    keyId = candidate;
                    break;
                }
            }
        }

        // Fallback: create+revoke to ensure this path is exercised.
        if (keyId == address(0)) {
            uint256 startPoolIdx = keyIdSeed % _potentialKeyIds.length;
            for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
                uint256 idx = addmod(startPoolIdx, i, _potentialKeyIds.length);
                address candidate = _potentialKeyIds[idx];
                if (!_ghostKeyExists[account][candidate] && !_ghostKeyRevoked[account][candidate]) {
                    keyId = candidate;
                    break;
                }
            }
            if (keyId == address(0)) return;

            _createKeyInternal(account, keyId);
            vm.prank(account);
            keychain.revokeKey(keyId);

            _totalKeysRevoked++;
            _ghostKeyExists[account][keyId] = false;
            _ghostKeyRevoked[account][keyId] = true;
            _ghostKeyExpiry[account][keyId] = 0;
            _ghostKeyEnforceLimits[account][keyId] = false;
            _ghostKeySignatureType[account][keyId] = 0;
        }

        // Sanity: key should be in revoked state before attempting second revoke.
        assertFalse(_ghostKeyExists[account][keyId], "TEMPO-KEY9: target key must not be active");
        assertTrue(_ghostKeyRevoked[account][keyId], "TEMPO-KEY9: target key must be revoked");

        IAccountKeychain.KeyInfo memory infoBefore = keychain.getKey(account, keyId);
        uint256[] memory limitsBefore = new uint256[](_tokens.length);
        for (uint256 t = 0; t < _tokens.length; t++) {
            limitsBefore[t] = keychain.getRemainingLimit(account, keyId, address(_tokens[t]));
        }

        vm.startPrank(account);
        try keychain.revokeKey(keyId) {
            vm.stopPrank();
            revert("TEMPO-KEY9: Revoking already-revoked key should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyNotFound.selector,
                "TEMPO-KEY9: Should revert with KeyNotFound"
            );
        }

        // Failed double-revoke must not mutate key state.
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(account, keyId);
        assertEq(infoAfter.keyId, infoBefore.keyId, "TEMPO-KEY9: keyId should remain unchanged");
        assertEq(infoAfter.expiry, infoBefore.expiry, "TEMPO-KEY9: expiry should remain unchanged");
        assertEq(
            infoAfter.enforceLimits,
            infoBefore.enforceLimits,
            "TEMPO-KEY9: enforceLimits should remain unchanged"
        );
        assertEq(
            uint8(infoAfter.signatureType),
            uint8(infoBefore.signatureType),
            "TEMPO-KEY9: signature type should remain unchanged"
        );
        assertEq(
            infoAfter.isRevoked, infoBefore.isRevoked, "TEMPO-KEY9: revoked flag should remain unchanged"
        );

        for (uint256 t = 0; t < _tokens.length; t++) {
            assertEq(
                keychain.getRemainingLimit(account, keyId, address(_tokens[t])),
                limitsBefore[t],
                "TEMPO-KEY9: failed double-revoke should not mutate limits"
            );
        }

    }

    /// @notice Handler for revoking another account's active key (should fail)
    /// @dev Tests account isolation branch for revoke: caller cannot revoke owner's key
    function handler_tryRevokeOtherAccountsKey(
        uint256 ownerSeed,
        uint256 callerSeed,
        uint256 keyIdSeed
    )
        external
    {
        address owner = _selectActor(ownerSeed);
        address caller = _selectActorExcluding(callerSeed, owner);
        address keyId = address(0);

        // Prefer an owner-active key that is absent for caller.
        address[] memory ownerKeys = _accountKeys[owner];
        if (ownerKeys.length > 0) {
            uint256 startKeyIdx = keyIdSeed % ownerKeys.length;
            for (uint256 k = 0; k < ownerKeys.length; k++) {
                uint256 idx = addmod(startKeyIdx, k, ownerKeys.length);
                address candidate = ownerKeys[idx];
                if (
                    _ghostKeyExists[owner][candidate] && !_ghostKeyRevoked[owner][candidate]
                        && !_ghostKeyExists[caller][candidate] && !_ghostKeyRevoked[caller][candidate]
                ) {
                    keyId = candidate;
                    break;
                }
            }
        }

        // Fallback: create a fresh owner key that caller doesn't have.
        if (keyId == address(0)) {
            uint256 startPoolIdx = keyIdSeed % _potentialKeyIds.length;
            for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
                uint256 idx = addmod(startPoolIdx, i, _potentialKeyIds.length);
                address candidate = _potentialKeyIds[idx];
                if (
                    !_ghostKeyExists[owner][candidate] && !_ghostKeyRevoked[owner][candidate]
                        && !_ghostKeyExists[caller][candidate] && !_ghostKeyRevoked[caller][candidate]
                ) {
                    keyId = candidate;
                    break;
                }
            }
            if (keyId == address(0)) return;
            _createKeyInternal(owner, keyId);
        }

        // Sanity: key is active for owner and missing for caller.
        assertTrue(_ghostKeyExists[owner][keyId], "TEMPO-KEY10: owner should have active key");
        assertFalse(_ghostKeyRevoked[owner][keyId], "TEMPO-KEY10: owner key should not be revoked");
        assertFalse(_ghostKeyExists[caller][keyId], "TEMPO-KEY10: caller should not have this key");
        assertFalse(_ghostKeyRevoked[caller][keyId], "TEMPO-KEY10: caller key should not be revoked");

        IAccountKeychain.KeyInfo memory ownerInfoBefore = keychain.getKey(owner, keyId);

        vm.startPrank(caller);
        try keychain.revokeKey(keyId) {
            vm.stopPrank();
            revert("TEMPO-KEY10: Caller should not be able to revoke another account's key");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IAccountKeychain.KeyNotFound.selector,
                "TEMPO-KEY10: Should revert with KeyNotFound for foreign key"
            );
        }

        // Failed foreign revoke must not mutate owner's key.
        IAccountKeychain.KeyInfo memory ownerInfoAfter = keychain.getKey(owner, keyId);
        assertEq(ownerInfoAfter.keyId, ownerInfoBefore.keyId, "TEMPO-KEY10: owner keyId should persist");
        assertEq(ownerInfoAfter.expiry, ownerInfoBefore.expiry, "TEMPO-KEY10: owner expiry should persist");
        assertEq(
            ownerInfoAfter.enforceLimits,
            ownerInfoBefore.enforceLimits,
            "TEMPO-KEY10: owner enforceLimits should persist"
        );
        assertEq(
            uint8(ownerInfoAfter.signatureType),
            uint8(ownerInfoBefore.signatureType),
            "TEMPO-KEY10: owner signature type should persist"
        );
        assertEq(
            ownerInfoAfter.isRevoked, ownerInfoBefore.isRevoked, "TEMPO-KEY10: owner revoked flag should persist"
        );

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
    function checkTransactionKey() external view {
        // TEMPO-KEY11: When called directly, should return address(0)
        address txKey = keychain.getTransactionKey();
        assertEq(txKey, address(0), "TEMPO-KEY11: Transaction key should be 0 outside tx context");
    }

    /// @notice Handler for getting key info on non-existent key
    /// @dev Tests TEMPO-KEY12 (non-existent key returns defaults)
    function checkNonExistentKey(uint256 accountSeed, uint256 keyIdSeed) external view {
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
