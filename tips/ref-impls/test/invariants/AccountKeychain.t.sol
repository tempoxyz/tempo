// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { IAccountKeychain } from "../../src/interfaces/IAccountKeychain.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title AccountKeychain Invariant Tests
/// @notice Fuzz-based invariant tests for the AccountKeychain precompile
/// @dev Tests invariants TEMPO-KEY1 through TEMPO-KEY27 (see README.md for mapping)
///      Note: TEMPO-KEY20/21 require integration tests (transient storage for transaction_key)
contract AccountKeychainInvariantTest is InvariantBaseTest {

    /// @dev Starting offset for key ID address pool (distinct from zero address)
    uint256 private constant KEY_ID_POOL_OFFSET = 1;

    /// @dev Type of token limits generated for authorizeKey fuzzing
    enum LimitScenario {
        None,
        Single,
        TwoDistinct,
        TwoDuplicate
    }

    /// @dev Seed bundle for authorizeKey limit generation
    struct LimitSeeds {
        uint256 scenarioSeed;
        uint256 token0Seed;
        uint256 amount0Seed;
        uint256 token1Seed;
        uint256 amount1Seed;
    }

    /// @dev Revert scenario for authorizeKey consolidated handler
    enum AuthorizeKeyRevertScenario {
        ZeroPublicKey,
        KeyAlreadyExists,
        ExpiryInPast,
        KeyAlreadyRevoked
    }

    /// @dev Revert scenario for revokeKey consolidated handler
    enum RevokeKeyRevertScenario {
        NeverAuthorized,
        AlreadyRevoked,
        OtherAccount
    }

    /// @dev Revert scenario for updateSpendingLimit consolidated handler
    enum UpdateLimitRevertScenario {
        NonExistent,
        Revoked,
        OtherAccount
    }

    /// @dev Snapshot of key state for immutability checks
    struct KeySnapshot {
        IAccountKeychain.KeyInfo info;
        address[] tokens;
        uint256[] limits;
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

    /// @dev Track tokens that have been written for a (account, keyId) pair
    /// account => keyId => list of tokens ever written
    mapping(address => mapping(address => address[])) private _ghostLimitTokens;

    /// @dev Dedup guard for _ghostLimitTokens
    /// account => keyId => token => seen
    mapping(address => mapping(address => mapping(address => bool))) private _ghostLimitTokenSeen;

    /// @dev Track all keys created per account
    mapping(address => address[]) private _accountKeys;

    /// @dev Track if a key has been used for an account
    mapping(address => mapping(address => bool)) private _keyUsed;

    /// @dev Counters
    uint256 private _totalKeysAuthorized;
    uint256 private _totalKeysRevoked;
    uint256 private _totalLimitUpdates;
    uint256 private _totalViewChecks;

    /// @dev Coverage log file path

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

        LimitScenario scenario = LimitScenario(seeds.scenarioSeed % 4);
        uint256 limitCount =
            scenario == LimitScenario.None ? 0 : (scenario == LimitScenario.Single ? 1 : 2);
        limits = new IAccountKeychain.TokenLimit[](limitCount);
        if (limitCount == 0) {
            return limits;
        }

        address token0 = address(_selectBaseToken(seeds.token0Seed));
        uint256 amount0 = (seeds.amount0Seed % 1_000_000) * 1e6;
        limits[0] = IAccountKeychain.TokenLimit({ token: token0, amount: amount0 });

        if (limitCount == 1) {
            return limits;
        }

        address token1 = address(_selectBaseToken(seeds.token1Seed));
        if (scenario == LimitScenario.TwoDuplicate) {
            token1 = token0;
        } else if (scenario == LimitScenario.TwoDistinct && _tokens.length > 1 && token1 == token0)
        {
            token1 = address(_tokens[addmod(seeds.token1Seed, 1, _tokens.length)]);
        }
        uint256 amount1 = (seeds.amount1Seed % 1_000_000) * 1e6;

        limits[1] = IAccountKeychain.TokenLimit({ token: token1, amount: amount1 });
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
        uint64 expiry =
            _generateValidAuthorizeExpiry(uint256(keccak256(abi.encode(account, keyId))));
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
            if (!_ghostKeyExists[account][candidateKey] && !_ghostKeyRevoked[account][candidateKey])
            {
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
                    _trackLimitToken(account, keyId, limits[i].token);
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

    /// @notice Revert handler for authorizeKey (internal, dispatched by per-scenario wrappers)
    /// @dev Tests TEMPO-KEY1 (ExpiryInPast), KEY4 (KeyAlreadyRevoked), KEY7 (ZeroPublicKey),
    ///      KEY8 (KeyAlreadyExists)
    function _tryAuthorizeKeyRevert(
        AuthorizeKeyRevertScenario scenario,
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 sigTypeSeed,
        uint256 expirySeed,
        bool enforceLimits,
        LimitSeeds calldata limitSeeds
    )
        internal
    {
        if (scenario == AuthorizeKeyRevertScenario.ZeroPublicKey) {
            address account = _selectActor(accountSeed);
            IAccountKeychain.SignatureType sigType = _generateSignatureType(sigTypeSeed);
            uint64 expiry = _generateValidAuthorizeExpiry(expirySeed);
            IAccountKeychain.TokenLimit[] memory limits = _buildAuthorizeLimits(limitSeeds);

            _expectAuthorizeKeyRevert(
                account,
                address(0),
                sigType,
                expiry,
                enforceLimits,
                limits,
                IAccountKeychain.ZeroPublicKey.selector,
                "TEMPO-KEY7"
            );

        } else if (scenario == AuthorizeKeyRevertScenario.KeyAlreadyExists) {
            (address account, address keyId, bool skip) =
                _ensureActorWithActiveKey(accountSeed, keyIdSeed);
            if (skip) return;
            if (!_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) return;

            IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

            _expectAuthorizeKeyRevert(
                account,
                keyId,
                IAccountKeychain.SignatureType.Secp256k1,
                uint64(block.timestamp + 1 days),
                false,
                limits,
                IAccountKeychain.KeyAlreadyExists.selector,
                "TEMPO-KEY8"
            );

        } else if (scenario == AuthorizeKeyRevertScenario.ExpiryInPast) {
            address account = _selectActor(accountSeed);
            address keyId = _selectKeyId(keyIdSeed);
            if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) return;

            uint64 badExpiry = _generateInvalidAuthorizeExpiry(expirySeed);
            IAccountKeychain.SignatureType sigType = _generateSignatureType(sigTypeSeed);
            IAccountKeychain.TokenLimit[] memory limits = _buildAuthorizeLimits(limitSeeds);

            _expectAuthorizeKeyRevert(
                account,
                keyId,
                sigType,
                badExpiry,
                enforceLimits,
                limits,
                IAccountKeychain.ExpiryInPast.selector,
                "TEMPO-KEY1"
            );

        } else {
            // TEMPO-KEY4: KeyAlreadyRevoked
            address account = _selectActor(accountSeed);

            (address keyId, bool skip) = _ensureRevokedKey(account, keyIdSeed);
            if (skip) return;

            assertFalse(
                _ghostKeyExists[account][keyId], "TEMPO-KEY4: revoked key should not be active"
            );
            assertTrue(_ghostKeyRevoked[account][keyId], "TEMPO-KEY4: key should be marked revoked");

            IAccountKeychain.SignatureType sigType = _generateSignatureType(sigTypeSeed);
            uint64 expiry = _generateValidAuthorizeExpiry(expirySeed);
            IAccountKeychain.TokenLimit[] memory limits = _buildAuthorizeLimits(limitSeeds);

            _expectAuthorizeKeyRevert(
                account,
                keyId,
                sigType,
                expiry,
                enforceLimits,
                limits,
                IAccountKeychain.KeyAlreadyRevoked.selector,
                "TEMPO-KEY4"
            );

        }
    }

    function handler_tryAuthorizeKeyRevert_ZeroPublicKey(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 sigTypeSeed,
        uint256 expirySeed,
        bool enforceLimits,
        LimitSeeds calldata limitSeeds
    )
        external
    {
        _tryAuthorizeKeyRevert(
            AuthorizeKeyRevertScenario.ZeroPublicKey,
            accountSeed,
            keyIdSeed,
            sigTypeSeed,
            expirySeed,
            enforceLimits,
            limitSeeds
        );
    }

    function handler_tryAuthorizeKeyRevert_KeyAlreadyExists(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 sigTypeSeed,
        uint256 expirySeed,
        bool enforceLimits,
        LimitSeeds calldata limitSeeds
    )
        external
    {
        _tryAuthorizeKeyRevert(
            AuthorizeKeyRevertScenario.KeyAlreadyExists,
            accountSeed,
            keyIdSeed,
            sigTypeSeed,
            expirySeed,
            enforceLimits,
            limitSeeds
        );
    }

    function handler_tryAuthorizeKeyRevert_ExpiryInPast(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 sigTypeSeed,
        uint256 expirySeed,
        bool enforceLimits,
        LimitSeeds calldata limitSeeds
    )
        external
    {
        _tryAuthorizeKeyRevert(
            AuthorizeKeyRevertScenario.ExpiryInPast,
            accountSeed,
            keyIdSeed,
            sigTypeSeed,
            expirySeed,
            enforceLimits,
            limitSeeds
        );
    }

    function handler_tryAuthorizeKeyRevert_KeyAlreadyRevoked(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 sigTypeSeed,
        uint256 expirySeed,
        bool enforceLimits,
        LimitSeeds calldata limitSeeds
    )
        external
    {
        _tryAuthorizeKeyRevert(
            AuthorizeKeyRevertScenario.KeyAlreadyRevoked,
            accountSeed,
            keyIdSeed,
            sigTypeSeed,
            expirySeed,
            enforceLimits,
            limitSeeds
        );
    }

    /// @notice Handler for revoking a key
    /// @dev Tests TEMPO-KEY3 (key revocation), TEMPO-KEY4 (revocation prevents reauthorization),
    ///      and TEMPO-KEY23 (revoked key limits are inaccessible)
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

        _revokeKey(account, keyId);

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

        // TEMPO-KEY23 (T2+): Revoked key limits are inaccessible for all known tokens.
        _assertAllLimitsZero(account, keyId, "TEMPO-KEY23");

    }

    /// @notice Handler for updating spending limits
    /// @dev Tests TEMPO-KEY5 (limit update), TEMPO-KEY6 (enables limits on unlimited key),
    ///      TEMPO-KEY22 (enforceLimits one-way ratchet), and TEMPO-KEY24 (token independence)
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

        // Build a watch list of token addresses to check for independence (TEMPO-KEY24).
        address[] memory watchTokens = _watchTokens(token);

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
        _trackLimitToken(account, keyId, token);

        // TEMPO-KEY5: selected token limit should be updated to newLimit
        uint256 storedLimit = keychain.getRemainingLimit(account, keyId, token);
        assertEq(storedLimit, newLimit, "TEMPO-KEY5: selected token limit should equal newLimit");

        // TEMPO-KEY6 / KEY22: enforceLimits should be true and remain a one-way ratchet
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(account, keyId);
        assertTrue(infoAfter.enforceLimits, "TEMPO-KEY6: enforceLimits should be true after update");
        _assertKeyMetadataUnchanged(infoBefore, account, keyId, "TEMPO-KEY5");

        // TEMPO-KEY24: updating one token must not mutate limits for other tokens.
        for (uint256 t = 0; t < watchTokens.length; t++) {
            uint256 expected = watchTokens[t] == token ? newLimit : watchLimitsBefore[t];
            assertEq(
                keychain.getRemainingLimit(account, keyId, watchTokens[t]),
                expected,
                "TEMPO-KEY24: unrelated token limits should remain unchanged"
            );
        }

    }

    /// @notice Revert handler for updateSpendingLimit (internal, dispatched by per-scenario wrappers)
    /// @dev Tests TEMPO-KEY5 (KeyNotFound: non-existent, KeyAlreadyRevoked: revoked)
    ///      and cross-account isolation (KeyNotFound: foreign key)
    function _tryUpdateSpendingLimitRevert(
        UpdateLimitRevertScenario scenario,
        uint256 accountSeed,
        uint256 callerSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        internal
    {
        if (scenario == UpdateLimitRevertScenario.NonExistent) {
            address account = _selectActor(accountSeed);
            address keyId = address(0);

            if (keyIdSeed % 8 != 0) {
                bool found;
                (keyId, found) = _findFreshKeyIdForAccount(account, keyIdSeed);
                if (!found) keyId = address(0);
            }

            if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) return;

            address token = _selectUpdateLimitToken(tokenSeed, account, keyId);
            uint256 newLimit = _deriveUpdateLimit(newLimitSeed);

            _expectUpdateLimitRevert(
                account,
                account,
                keyId,
                token,
                newLimit,
                IAccountKeychain.KeyNotFound.selector,
                "TEMPO-KEY5"
            );

        } else if (scenario == UpdateLimitRevertScenario.Revoked) {
            address account = _selectActor(accountSeed);

            (address keyId, bool skip) = _ensureRevokedKey(account, keyIdSeed);
            if (skip) return;
            if (!_ghostKeyRevoked[account][keyId]) return;

            address token = _selectUpdateLimitToken(tokenSeed, account, keyId);
            uint256 newLimit = _deriveUpdateLimit(newLimitSeed);

            _expectUpdateLimitRevert(
                account,
                account,
                keyId,
                token,
                newLimit,
                IAccountKeychain.KeyAlreadyRevoked.selector,
                "TEMPO-KEY5"
            );

        } else {
            // Cross-account (caller tries to update owner's key)
            address owner = _selectActor(accountSeed);
            address caller = _selectActorExcluding(callerSeed, owner);

            (address keyId, bool skip) = _ensureActiveKeyOwnedByOther(owner, caller, keyIdSeed);
            if (skip) return;

            if (!_ghostKeyExists[owner][keyId] || _ghostKeyRevoked[owner][keyId]) return;
            if (_ghostKeyExists[caller][keyId] || _ghostKeyRevoked[caller][keyId]) return;

            address token = _selectUpdateLimitToken(tokenSeed, owner, keyId);
            uint256 newLimit = _deriveUpdateLimit(newLimitSeed);

            _expectUpdateLimitRevert(
                caller,
                owner,
                keyId,
                token,
                newLimit,
                IAccountKeychain.KeyNotFound.selector,
                "TEMPO-KEY5"
            );

        }
    }

    function handler_tryUpdateSpendingLimitRevert_NonExistent(
        uint256 accountSeed,
        uint256 callerSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        _tryUpdateSpendingLimitRevert(
            UpdateLimitRevertScenario.NonExistent,
            accountSeed,
            callerSeed,
            keyIdSeed,
            tokenSeed,
            newLimitSeed
        );
    }

    function handler_tryUpdateSpendingLimitRevert_Revoked(
        uint256 accountSeed,
        uint256 callerSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        _tryUpdateSpendingLimitRevert(
            UpdateLimitRevertScenario.Revoked,
            accountSeed,
            callerSeed,
            keyIdSeed,
            tokenSeed,
            newLimitSeed
        );
    }

    function handler_tryUpdateSpendingLimitRevert_OtherAccount(
        uint256 accountSeed,
        uint256 callerSeed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        _tryUpdateSpendingLimitRevert(
            UpdateLimitRevertScenario.OtherAccount,
            accountSeed,
            callerSeed,
            keyIdSeed,
            tokenSeed,
            newLimitSeed
        );
    }

    /// @notice Revert handler for revokeKey (internal, dispatched by per-scenario wrappers)
    /// @dev Tests TEMPO-KEY9 (KeyNotFound: never-authorized, already-revoked) and
    ///      TEMPO-KEY10 (KeyNotFound: cross-account isolation)
    function _tryRevokeKeyRevert(
        RevokeKeyRevertScenario scenario,
        uint256 accountSeed,
        uint256 callerSeed,
        uint256 keyIdSeed
    )
        internal
    {
        if (scenario == RevokeKeyRevertScenario.NeverAuthorized) {
            address account = _selectActor(accountSeed);
            address keyId = address(0);

            if (keyIdSeed % 8 != 0) {
                bool found;
                (keyId, found) = _findFreshKeyIdForAccount(account, keyIdSeed);
                if (!found) keyId = address(0);
            }

            assertFalse(
                _ghostKeyExists[account][keyId], "TEMPO-KEY9: target key must not be active"
            );
            assertFalse(
                _ghostKeyRevoked[account][keyId], "TEMPO-KEY9: target key must not be revoked"
            );

            _expectRevokeKeyRevert(
                account, account, keyId, IAccountKeychain.KeyNotFound.selector, "TEMPO-KEY9"
            );

        } else if (scenario == RevokeKeyRevertScenario.AlreadyRevoked) {
            address account = _selectActor(accountSeed);

            (address keyId, bool skip) = _ensureRevokedKey(account, keyIdSeed);
            if (skip) return;

            assertFalse(
                _ghostKeyExists[account][keyId], "TEMPO-KEY9: target key must not be active"
            );
            assertTrue(_ghostKeyRevoked[account][keyId], "TEMPO-KEY9: target key must be revoked");

            _expectRevokeKeyRevert(
                account, account, keyId, IAccountKeychain.KeyNotFound.selector, "TEMPO-KEY9"
            );

        } else {
            // TEMPO-KEY10: Revoke another account's key (cross-account isolation)
            address owner = _selectActor(accountSeed);
            address caller = _selectActorExcluding(callerSeed, owner);

            (address keyId, bool skip) = _ensureActiveKeyOwnedByOther(owner, caller, keyIdSeed);
            if (skip) return;

            assertTrue(_ghostKeyExists[owner][keyId], "TEMPO-KEY10: owner should have active key");
            assertFalse(
                _ghostKeyRevoked[owner][keyId], "TEMPO-KEY10: owner key should not be revoked"
            );
            assertFalse(
                _ghostKeyExists[caller][keyId], "TEMPO-KEY10: caller should not have this key"
            );

            _expectRevokeKeyRevert(
                caller, owner, keyId, IAccountKeychain.KeyNotFound.selector, "TEMPO-KEY10"
            );

        }
    }

    function handler_tryRevokeKeyRevert_NeverAuthorized(
        uint256 accountSeed,
        uint256 callerSeed,
        uint256 keyIdSeed
    )
        external
    {
        _tryRevokeKeyRevert(
            RevokeKeyRevertScenario.NeverAuthorized, accountSeed, callerSeed, keyIdSeed
        );
    }

    function handler_tryRevokeKeyRevert_AlreadyRevoked(
        uint256 accountSeed,
        uint256 callerSeed,
        uint256 keyIdSeed
    )
        external
    {
        _tryRevokeKeyRevert(
            RevokeKeyRevertScenario.AlreadyRevoked, accountSeed, callerSeed, keyIdSeed
        );
    }

    function handler_tryRevokeKeyRevert_OtherAccount(
        uint256 accountSeed,
        uint256 callerSeed,
        uint256 keyIdSeed
    )
        external
    {
        _tryRevokeKeyRevert(
            RevokeKeyRevertScenario.OtherAccount, accountSeed, callerSeed, keyIdSeed
        );
    }

    /// @notice Handler for verifying account isolation
    /// @dev Tests TEMPO-KEY10 (keys are isolated per account)
    ///      Snapshots all actors' view state for a keyId, authorizes the key for two
    ///      actors with distinct settings, then asserts every other actor is unchanged.
    function handler_checkAccountIsolation(
        uint256 account1Seed,
        uint256 account2Seed,
        uint256 keyIdSeed,
        uint256 tokenSeed,
        uint256 limit1Seed,
        uint256 limit2Seed
    )
        external
    {
        address account1 = _selectActor(account1Seed);
        address account2 = _selectActorExcluding(account2Seed, account1);
        address keyId = _selectKeyId(keyIdSeed);

        if (_ghostKeyExists[account1][keyId] || _ghostKeyRevoked[account1][keyId]) return;
        if (_ghostKeyExists[account2][keyId] || _ghostKeyRevoked[account2][keyId]) return;
        if (_tokens.length == 0) return;

        address token = _selectToken(tokenSeed);

        uint256 initialLimit1 = bound(limit1Seed, 1, 1_000_000) * 1e6;
        uint256 initialLimit2 = bound(limit2Seed, 1, 1_000_000) * 1e6;
        if (initialLimit2 == initialLimit1) {
            initialLimit2 =
                initialLimit2 == 1_000_000 * 1e6 ? initialLimit2 - 1e6 : initialLimit2 + 1e6;
        }

        IAccountKeychain.SignatureType sigType1 = _generateSignatureType(limit1Seed);
        IAccountKeychain.SignatureType sigType2 =
            IAccountKeychain.SignatureType((uint8(sigType1) + 1) % 3);

        uint64 expiry1 = _generateValidAuthorizeExpiry(limit1Seed);
        uint64 expiry2 = _generateValidAuthorizeExpiry(limit2Seed);
        if (expiry2 == expiry1) expiry2 = expiry1 + 1;

        // Snapshot all actors' view state for this keyId before any mutations.
        IAccountKeychain.KeyInfo[] memory keysBefore =
            new IAccountKeychain.KeyInfo[](_actors.length);
        uint256[] memory limitsBefore = new uint256[](_actors.length);
        for (uint256 a = 0; a < _actors.length; a++) {
            keysBefore[a] = keychain.getKey(_actors[a], keyId);
            limitsBefore[a] = keychain.getRemainingLimit(_actors[a], keyId, token);
        }

        // Authorize key for account1.
        IAccountKeychain.TokenLimit[] memory limits1 = new IAccountKeychain.TokenLimit[](1);
        limits1[0] = IAccountKeychain.TokenLimit({ token: token, amount: initialLimit1 });

        vm.prank(account1);
        keychain.authorizeKey(keyId, sigType1, expiry1, true, limits1);

        _totalKeysAuthorized++;
        _ghostKeyExists[account1][keyId] = true;
        _ghostKeyExpiry[account1][keyId] = expiry1;
        _ghostKeyEnforceLimits[account1][keyId] = true;
        _ghostKeySignatureType[account1][keyId] = uint8(sigType1);
        _ghostSpendingLimits[account1][keyId][token] = initialLimit1;
        _trackLimitToken(account1, keyId, token);

        if (!_keyUsed[account1][keyId]) {
            _keyUsed[account1][keyId] = true;
            _accountKeys[account1].push(keyId);
        }

        // Authorize same keyId for account2 with different settings.
        IAccountKeychain.TokenLimit[] memory limits2 = new IAccountKeychain.TokenLimit[](1);
        limits2[0] = IAccountKeychain.TokenLimit({ token: token, amount: initialLimit2 });

        vm.prank(account2);
        keychain.authorizeKey(keyId, sigType2, expiry2, true, limits2);

        _totalKeysAuthorized++;
        _ghostKeyExists[account2][keyId] = true;
        _ghostKeyExpiry[account2][keyId] = expiry2;
        _ghostKeyEnforceLimits[account2][keyId] = true;
        _ghostKeySignatureType[account2][keyId] = uint8(sigType2);
        _ghostSpendingLimits[account2][keyId][token] = initialLimit2;
        _trackLimitToken(account2, keyId, token);

        if (!_keyUsed[account2][keyId]) {
            _keyUsed[account2][keyId] = true;
            _accountKeys[account2].push(keyId);
        }

        // TEMPO-KEY10: Verify the two mutated accounts and assert all others unchanged.
        for (uint256 a = 0; a < _actors.length; a++) {
            address actor = _actors[a];
            IAccountKeychain.KeyInfo memory info = keychain.getKey(actor, keyId);
            uint256 limit = keychain.getRemainingLimit(actor, keyId, token);

            if (actor == account1) {
                assertEq(info.keyId, keyId, "TEMPO-KEY10: account1 keyId mismatch");
                assertEq(
                    uint8(info.signatureType),
                    uint8(sigType1),
                    "TEMPO-KEY10: account1 sigType mismatch"
                );
                assertEq(info.expiry, expiry1, "TEMPO-KEY10: account1 expiry mismatch");
                assertTrue(info.enforceLimits, "TEMPO-KEY10: account1 enforceLimits mismatch");
                assertFalse(info.isRevoked, "TEMPO-KEY10: account1 should not be revoked");
                assertEq(limit, initialLimit1, "TEMPO-KEY10: account1 limit mismatch");
            } else if (actor == account2) {
                assertEq(info.keyId, keyId, "TEMPO-KEY10: account2 keyId mismatch");
                assertEq(
                    uint8(info.signatureType),
                    uint8(sigType2),
                    "TEMPO-KEY10: account2 sigType mismatch"
                );
                assertEq(info.expiry, expiry2, "TEMPO-KEY10: account2 expiry mismatch");
                assertTrue(info.enforceLimits, "TEMPO-KEY10: account2 enforceLimits mismatch");
                assertFalse(info.isRevoked, "TEMPO-KEY10: account2 should not be revoked");
                assertEq(limit, initialLimit2, "TEMPO-KEY10: account2 limit mismatch");
            } else {
                assertEq(info.keyId, keysBefore[a].keyId, "TEMPO-KEY10: unexpected keyId changed");
                assertEq(
                    info.expiry, keysBefore[a].expiry, "TEMPO-KEY10: unexpected expiry changed"
                );
                assertEq(
                    uint8(info.signatureType),
                    uint8(keysBefore[a].signatureType),
                    "TEMPO-KEY10: unexpected sigType changed"
                );
                assertEq(
                    info.enforceLimits,
                    keysBefore[a].enforceLimits,
                    "TEMPO-KEY10: unexpected enforceLimits changed"
                );
                assertEq(
                    info.isRevoked,
                    keysBefore[a].isRevoked,
                    "TEMPO-KEY10: unexpected isRevoked changed"
                );
                assertEq(limit, limitsBefore[a], "TEMPO-KEY10: unexpected limit changed");
            }
        }

    }

    /// @notice Handler for checking getTransactionKey
    /// @dev Tests TEMPO-KEY11 (transaction key returns 0 when not in transaction)
    ///      Note: transient storage is never set in this harness, so this is a
    ///      smoke-test only. Real protocol-context validation (TEMPO-KEY20/21)
    ///      requires integration tests.
    function handler_checkTransactionKey() external {
        // Foundry invariant runner skips `view` functions; bump counter to keep non-view.
        _totalViewChecks++;

        // TEMPO-KEY11: When called directly, should return address(0)
        address txKey = keychain.getTransactionKey();
        assertEq(txKey, address(0), "TEMPO-KEY11: Transaction key should be 0 outside tx context");
    }

    /// @notice Handler for getting key info on non-existent key
    /// @dev Tests TEMPO-KEY12 (non-existent key returns defaults)
    ///      "Non-existent" includes never-authorized keys and revoked keys (expiry==0).
    function handler_checkNonExistentKey(uint256 accountSeed, uint256 keyIdSeed) external {
        // Foundry invariant runner skips `view` functions; bump counter to keep non-view.
        _totalViewChecks++;

        address account = _selectActor(accountSeed);

        // Occasionally test keyId == address(0) (rejected by authorizeKey, but getKey
        // must still return sane defaults).
        address keyId;
        if (keyIdSeed % 16 == 0) {
            keyId = address(0);
        } else {
            keyId = _selectKeyId(keyIdSeed);

            // If the selected key is active, search for a non-existent one to reduce skip rate.
            if (_ghostKeyExists[account][keyId]) {
                bool found = false;
                for (uint256 i = 0; i < 4; i++) {
                    address candidate = _selectKeyId(uint256(keccak256(abi.encode(keyIdSeed, i))));
                    if (!_ghostKeyExists[account][candidate]) {
                        keyId = candidate;
                        found = true;
                        break;
                    }
                }
                if (!found) return;
            }
        }

        IAccountKeychain.KeyInfo memory info = keychain.getKey(account, keyId);

        // TEMPO-KEY12: Non-existent key returns defaults
        assertEq(info.keyId, address(0), "TEMPO-KEY12: KeyId should be 0");
        assertEq(info.expiry, 0, "TEMPO-KEY12: Expiry should be 0");
        assertFalse(info.enforceLimits, "TEMPO-KEY12: EnforceLimits should be false");
        assertEq(
            uint8(info.signatureType),
            uint8(IAccountKeychain.SignatureType.Secp256k1),
            "TEMPO-KEY12: SignatureType should default to Secp256k1"
        );

        // isRevoked should match ghost state (revoked is sticky even after metadata is cleared)
        assertEq(
            info.isRevoked,
            _ghostKeyRevoked[account][keyId],
            "TEMPO-KEY12: isRevoked should match ghost"
        );

        // getRemainingLimit must return 0 for every token on a non-existent/revoked key
        for (uint256 t = 0; t < _tokens.length; t++) {
            assertEq(
                keychain.getRemainingLimit(account, keyId, address(_tokens[t])),
                0,
                "TEMPO-KEY12: RemainingLimit should be 0 for non-existent key"
            );
        }
        assertEq(
            keychain.getRemainingLimit(account, keyId, address(pathUSD)),
            0,
            "TEMPO-KEY12: RemainingLimit(pathUSD) should be 0"
        );
        assertEq(
            keychain.getRemainingLimit(account, keyId, address(0)),
            0,
            "TEMPO-KEY12: RemainingLimit(address(0)) should be 0"
        );
    }

    /// @notice Handler for testing expiry boundary condition
    /// @dev Tests TEMPO-KEY17 (expiry == block.timestamp counts as expired)
    ///      Rust uses timestamp >= expiry, so expiry == now is already expired
    function handler_testExpiryBoundary(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 sigTypeSeed,
        bool enforceLimits,
        LimitSeeds calldata limitSeeds,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Skip if key already exists or was revoked
        if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) {
            return;
        }

        // Create a key with expiry 1 second in the future (valid at creation).
        IAccountKeychain.SignatureType sigType = _generateSignatureType(sigTypeSeed);
        uint64 expiry = uint64(block.timestamp + 1);
        address token = _selectUpdateLimitToken(tokenSeed, account, keyId);
        uint256 newLimit = _deriveUpdateLimit(newLimitSeed);
        IAccountKeychain.TokenLimit[] memory limits = _buildAuthorizeLimits(limitSeeds);

        vm.startPrank(account);
        try keychain.authorizeKey(keyId, sigType, expiry, enforceLimits, limits) {
            vm.stopPrank();
        } catch {
            vm.stopPrank();
            revert("TEMPO-KEY17: authorizeKey setup unexpectedly reverted");
        }

        // Update ghost state for the newly created key.
        _totalKeysAuthorized++;
        _ghostKeyExists[account][keyId] = true;
        _ghostKeyExpiry[account][keyId] = expiry;
        _ghostKeyEnforceLimits[account][keyId] = enforceLimits;
        _ghostKeySignatureType[account][keyId] = uint8(sigType);
        if (enforceLimits && limits.length > 0) {
            for (uint256 i = 0; i < limits.length; i++) {
                _ghostSpendingLimits[account][keyId][limits[i].token] = limits[i].amount;
                _trackLimitToken(account, keyId, limits[i].token);
            }
        }

        if (!_keyUsed[account][keyId]) {
            _keyUsed[account][keyId] = true;
            _accountKeys[account].push(keyId);
        }

        address[] memory watchTokens = _watchTokens(token);
        KeySnapshot memory snap = _snapshotKey(account, keyId, watchTokens);
        // Warp to exactly the expiry timestamp.
        // TEMPO-KEY17: timestamp >= expiry means equality counts as expired.
        vm.warp(expiry);

        vm.startPrank(account);
        try keychain.updateSpendingLimit(keyId, token, newLimit) {
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

        // Failed boundary update must not mutate key metadata or limits.
        _assertKeyUnchanged(snap, account, keyId, "TEMPO-KEY17");

    }

    /// @notice Handler for testing operations on expired keys
    /// @dev Tests TEMPO-KEY18 (operations on expired keys fail with KeyExpired)
    function handler_testExpiredKeyOperations(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 warpAmount,
        uint256 tokenSeed,
        uint256 newLimitSeed
    )
        external
    {
        // Find an actor with an active, non-expired key, or create one as fallback.
        (address account, address keyId, bool skip) =
            _ensureActorWithUpdatableKey(accountSeed, keyIdSeed);
        if (skip) {
            return;
        }

        uint64 expiry = _ghostKeyExpiry[account][keyId];

        // Skip if already expired or expiry is max (never expires)
        if (block.timestamp >= expiry || expiry == type(uint64).max) {
            return;
        }

        address token = _selectUpdateLimitToken(tokenSeed, account, keyId);
        uint256 newLimit = _deriveUpdateLimit(newLimitSeed);

        address[] memory watchTokens = _watchTokens(token);
        KeySnapshot memory snap = _snapshotKey(account, keyId, watchTokens);
        // Warp past expiry (1 second to 1 day past)
        uint256 warpTo = expiry + 1 + (warpAmount % 1 days);
        vm.warp(warpTo);

        // TEMPO-KEY18: Operations on expired keys should fail with KeyExpired
        vm.startPrank(account);
        try keychain.updateSpendingLimit(keyId, token, newLimit) {
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

        // Failed update on an expired key must not mutate metadata or limits.
        _assertKeyUnchanged(snap, account, keyId, "TEMPO-KEY18");

    }

    /// @notice Handler for testing invalid signature type
    /// @dev Tests TEMPO-KEY19 (invalid enum values >= 3 are rejected with InvalidSignatureType)
    function handler_testInvalidSignatureType(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint8 badType,
        uint256 expirySeed,
        bool enforceLimits,
        LimitSeeds calldata limitSeeds
    )
        external
    {
        address account = _selectActor(accountSeed);
        address keyId = address(0);

        // Select a key that is neither active nor revoked for this account.
        if (keyIdSeed % 8 == 0) {
            keyId = address(0); // Explicit edge case for pre-validation ordering.
        } else {
            bool found;
            (keyId, found) = _findFreshKeyIdForAccount(account, keyIdSeed);
            if (!found) return;
        }

        // Only test with values >= 3 (invalid enum values)
        badType = uint8(bound(badType, 3, 255));

        // Keep expiry valid so signature validation is reached unless a stricter precheck
        // (like keyId=0) intentionally fires first.
        uint64 expiry = _generateValidAuthorizeExpiry(expirySeed);
        IAccountKeychain.TokenLimit[] memory limits = _buildAuthorizeLimits(limitSeeds);

        address[] memory watchTokens = _watchTokens(keyId);
        KeySnapshot memory snap = _snapshotKey(account, keyId, watchTokens);

        // Use low-level call to bypass Solidity's enum type checking
        // This allows us to pass an invalid uint8 value for signatureType
        bytes memory callData = abi.encodeWithSelector(
            IAccountKeychain.authorizeKey.selector,
            keyId,
            badType, // Raw uint8 instead of enum
            expiry,
            enforceLimits,
            limits
        );

        vm.startPrank(account);
        (bool success, bytes memory returnData) = address(keychain).call(callData);
        vm.stopPrank();

        // TEMPO-KEY19: Invalid signature type should be rejected
        assertFalse(success, "TEMPO-KEY19: Invalid signature type should revert");
        // Depending on decoder path and validation ordering, failure can surface as:
        // - InvalidSignatureType custom error (precompile validation path)
        // - ZeroPublicKey (keyId==0 is checked before sigType in authorizeKey)
        // - Panic(0x21) or empty revert data (ABI enum decode rejection path)
        if (returnData.length >= 4) {
            bytes4 selector = bytes4(returnData);
            if (selector == bytes4(0x4e487b71)) {
                assertEq(
                    keccak256(returnData),
                    keccak256(abi.encodeWithSelector(bytes4(0x4e487b71), uint256(0x21))),
                    "TEMPO-KEY19: Panic should be enum conversion panic (0x21)"
                );
            } else if (keyId == address(0)) {
                assertEq(
                    selector,
                    IAccountKeychain.ZeroPublicKey.selector,
                    "TEMPO-KEY19: keyId=0 should revert with ZeroPublicKey before sigType check"
                );
            } else {
                assertEq(
                    selector,
                    IAccountKeychain.InvalidSignatureType.selector,
                    "TEMPO-KEY19: Should revert with InvalidSignatureType"
                );
            }
        }

        // Failed authorize must not mutate state.
        _assertKeyUnchanged(snap, account, keyId, "TEMPO-KEY19");

    }

    /// @notice Handler for testing duplicate token limits (last write wins)
    /// @dev Tests TEMPO-KEY27 (when authorizeKey is called with duplicate token entries,
    ///      the last entry wins because limits are written sequentially)
    function handler_testDuplicateTokenLimitsLastWins(
        uint256 accountSeed,
        uint256 keyIdSeed,
        uint256 sigTypeSeed,
        uint256 expirySeed,
        uint256 amount0Seed,
        uint256 amount1Seed
    )
        external
    {
        address account = _selectActor(accountSeed);
        address keyId = _selectKeyId(keyIdSeed);

        // Need a fresh key and at least one token
        if (_ghostKeyExists[account][keyId] || _ghostKeyRevoked[account][keyId]) return;
        if (_tokens.length == 0) return;

        uint64 expiry = _generateValidAuthorizeExpiry(expirySeed);
        IAccountKeychain.SignatureType sigType = _generateSignatureType(sigTypeSeed);

        // Build limits with the same token appearing twice at different amounts
        address token = address(_selectBaseToken(amount0Seed));
        uint256 firstAmount = (amount0Seed % 1_000_000) * 1e6;
        uint256 secondAmount = (amount1Seed % 1_000_000) * 1e6;
        // Ensure amounts are distinct so we can tell which one won
        if (secondAmount == firstAmount) {
            secondAmount = firstAmount == 0 ? 1e6 : firstAmount - 1;
        }

        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](2);
        limits[0] = IAccountKeychain.TokenLimit({ token: token, amount: firstAmount });
        limits[1] = IAccountKeychain.TokenLimit({ token: token, amount: secondAmount });

        vm.startPrank(account);
        try keychain.authorizeKey(keyId, sigType, expiry, true, limits) {
            vm.stopPrank();
        } catch {
            vm.stopPrank();
            revert("TEMPO-KEY27: authorizeKey with duplicate limits should not revert");
        }

        _totalKeysAuthorized++;
        _ghostKeyExists[account][keyId] = true;
        _ghostKeyExpiry[account][keyId] = expiry;
        _ghostKeyEnforceLimits[account][keyId] = true;
        _ghostKeySignatureType[account][keyId] = uint8(sigType);
        _ghostSpendingLimits[account][keyId][token] = secondAmount;
        _trackLimitToken(account, keyId, token);

        if (!_keyUsed[account][keyId]) {
            _keyUsed[account][keyId] = true;
            _accountKeys[account].push(keyId);
        }

        // TEMPO-KEY27: The second (last) entry must win
        uint256 storedLimit = keychain.getRemainingLimit(account, keyId, token);
        assertEq(
            storedLimit, secondAmount, "TEMPO-KEY27: Duplicate token limit should use last entry"
        );
        assertTrue(
            storedLimit != firstAmount || firstAmount == secondAmount,
            "TEMPO-KEY27: First entry should NOT win when duplicates exist"
        );

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "DUPLICATE_LIMITS: account=",
                    _getActorIndex(account),
                    " keyId=",
                    vm.toString(keyId),
                    " token=",
                    vm.toString(token),
                    " first=",
                    vm.toString(firstAmount),
                    " second=",
                    vm.toString(secondAmount),
                    " stored=",
                    vm.toString(storedLimit)
                )
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks in a single pass over actors
    /// @dev Consolidates TEMPO-KEY13, KEY14, KEY15, KEY16, KEY23, KEY25, KEY26
    function invariant_globalInvariants() public view {
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

                    // TEMPO-KEY23: Revoked key limits must read as 0 for all known tokens
                    _assertAllLimitsZero(account, keyId, "TEMPO-KEY23");
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
                    assertFalse(info.isRevoked, "TEMPO-KEY13: Active key should not be revoked");

                    // TEMPO-KEY16: Signature type must match ghost state for all active keys
                    assertEq(
                        uint8(info.signatureType),
                        _ghostKeySignatureType[account][keyId],
                        "TEMPO-KEY16: SignatureType must match ghost state"
                    );

                    // TEMPO-KEY26: Stored signature type must be bounded to valid enum range
                    assertLe(
                        uint8(info.signatureType),
                        2,
                        "TEMPO-KEY26: SignatureType must be in {0,1,2}"
                    );

                    uint64 expiry = _ghostKeyExpiry[account][keyId];
                    bool isExpired = expiry != type(uint64).max && block.timestamp >= expiry;

                    if (_ghostKeyEnforceLimits[account][keyId]) {
                        // TEMPO-KEY14: Spending limits must match ghost state for all known tokens
                        if (!isExpired) {
                            _assertAllLimitsMatchGhost(account, keyId, "TEMPO-KEY14");
                        }
                    } else {
                        // TEMPO-KEY25: enforceLimits=false → all limits must read as 0
                        if (!isExpired) {
                            _assertAllLimitsZero(account, keyId, "TEMPO-KEY25");
                        }
                    }
                }
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Registers a token as having been written for a (account, keyId) pair
    function _trackLimitToken(address account, address keyId, address token) internal {
        if (_ghostLimitTokenSeen[account][keyId][token]) return;
        _ghostLimitTokenSeen[account][keyId][token] = true;
        _ghostLimitTokens[account][keyId].push(token);
    }

    /// @dev Asserts getRemainingLimit matches ghost state for all known tokens on a key.
    ///      "Known tokens" = base _tokens + pathUSD + address(0) + all tokens ever written
    ///      for this (account, keyId) pair via _trackLimitToken.
    function _assertAllLimitsMatchGhost(
        address account,
        address keyId,
        string memory tag
    )
        internal
        view
    {
        // Check base tokens
        for (uint256 t = 0; t < _tokens.length; t++) {
            address token = address(_tokens[t]);
            assertEq(
                keychain.getRemainingLimit(account, keyId, token),
                _ghostSpendingLimits[account][keyId][token],
                string.concat(tag, ": limit mismatch for base token")
            );
        }
        // Check pathUSD and address(0)
        assertEq(
            keychain.getRemainingLimit(account, keyId, address(pathUSD)),
            _ghostSpendingLimits[account][keyId][address(pathUSD)],
            string.concat(tag, ": limit mismatch for pathUSD")
        );
        assertEq(
            keychain.getRemainingLimit(account, keyId, address(0)),
            _ghostSpendingLimits[account][keyId][address(0)],
            string.concat(tag, ": limit mismatch for address(0)")
        );
        // Check all tokens ever written for this key
        address[] memory tracked = _ghostLimitTokens[account][keyId];
        for (uint256 t = 0; t < tracked.length; t++) {
            assertEq(
                keychain.getRemainingLimit(account, keyId, tracked[t]),
                _ghostSpendingLimits[account][keyId][tracked[t]],
                string.concat(tag, ": limit mismatch for tracked token")
            );
        }
    }

    /// @dev Asserts getRemainingLimit is 0 for all known tokens on a key.
    ///      Used for revoked keys (KEY25) and enforceLimits=false keys (KEY30).
    function _assertAllLimitsZero(address account, address keyId, string memory tag) internal view {
        // Check base tokens
        for (uint256 t = 0; t < _tokens.length; t++) {
            assertEq(
                keychain.getRemainingLimit(account, keyId, address(_tokens[t])),
                0,
                string.concat(tag, ": limit should be 0 for base token")
            );
        }
        // Check pathUSD and address(0)
        assertEq(
            keychain.getRemainingLimit(account, keyId, address(pathUSD)),
            0,
            string.concat(tag, ": limit should be 0 for pathUSD")
        );
        assertEq(
            keychain.getRemainingLimit(account, keyId, address(0)),
            0,
            string.concat(tag, ": limit should be 0 for address(0)")
        );
        // Check all tokens ever written for this key
        address[] memory tracked = _ghostLimitTokens[account][keyId];
        for (uint256 t = 0; t < tracked.length; t++) {
            assertEq(
                keychain.getRemainingLimit(account, keyId, tracked[t]),
                0,
                string.concat(tag, ": limit should be 0 for tracked token")
            );
        }
    }

    /// @dev Builds the standard watch-token list: all _tokens + pathUSD + address(0) + selected
    function _watchTokens(address selected) internal view returns (address[] memory tokens) {
        uint256 len = _tokens.length + 3;
        tokens = new address[](len);
        for (uint256 t = 0; t < _tokens.length; t++) {
            tokens[t] = address(_tokens[t]);
        }
        tokens[_tokens.length] = address(pathUSD);
        tokens[_tokens.length + 1] = address(0);
        tokens[_tokens.length + 2] = selected;
    }

    /// @dev Revokes a key and updates ghost state (no assertions)
    function _revokeKey(address account, address keyId) internal {
        vm.prank(account);
        keychain.revokeKey(keyId);

        _totalKeysRevoked++;
        _ghostKeyExists[account][keyId] = false;
        _ghostKeyRevoked[account][keyId] = true;
        _ghostKeyExpiry[account][keyId] = 0;
        _ghostKeyEnforceLimits[account][keyId] = false;
        _ghostKeySignatureType[account][keyId] = 0;
    }

    /// @dev Finds a keyId from the pool that is neither active nor revoked for an account
    function _findFreshKeyIdForAccount(
        address account,
        uint256 seed
    )
        internal
        view
        returns (address keyId, bool found)
    {
        uint256 start = seed % _potentialKeyIds.length;
        for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
            address candidate = _potentialKeyIds[addmod(start, i, _potentialKeyIds.length)];
            if (!_ghostKeyExists[account][candidate] && !_ghostKeyRevoked[account][candidate]) {
                return (candidate, true);
            }
        }
        return (address(0), false);
    }

    /// @dev Finds an existing revoked key for an account, or creates and revokes one
    function _ensureRevokedKey(
        address account,
        uint256 keyIdSeed
    )
        internal
        returns (address keyId, bool skip)
    {
        // Prefer an existing revoked key.
        address[] memory keys = _accountKeys[account];
        if (keys.length > 0) {
            uint256 start = keyIdSeed % keys.length;
            for (uint256 i = 0; i < keys.length; i++) {
                address candidate = keys[addmod(start, i, keys.length)];
                if (_ghostKeyRevoked[account][candidate]) {
                    return (candidate, false);
                }
            }
        }

        // Fallback: create and revoke a fresh key.
        bool found;
        (keyId, found) = _findFreshKeyIdForAccount(account, keyIdSeed);
        if (!found) return (address(0), true);

        _createKeyInternal(account, keyId);
        _revokeKey(account, keyId);
        return (keyId, false);
    }

    /// @dev Finds or creates a key that is active for owner but unused by another account
    function _ensureActiveKeyOwnedByOther(
        address owner,
        address other,
        uint256 keyIdSeed
    )
        internal
        returns (address keyId, bool skip)
    {
        // Prefer an existing owner key that is active and unused by other.
        address[] memory keys = _accountKeys[owner];
        if (keys.length > 0) {
            uint256 start = keyIdSeed % keys.length;
            for (uint256 i = 0; i < keys.length; i++) {
                address candidate = keys[addmod(start, i, keys.length)];
                if (
                    _ghostKeyExists[owner][candidate] && !_ghostKeyRevoked[owner][candidate]
                        && !_ghostKeyExists[other][candidate] && !_ghostKeyRevoked[other][candidate]
                ) {
                    return (candidate, false);
                }
            }
        }

        // Fallback: create a fresh key for the owner.
        uint256 startPool = keyIdSeed % _potentialKeyIds.length;
        for (uint256 i = 0; i < _potentialKeyIds.length; i++) {
            address candidate = _potentialKeyIds[addmod(startPool, i, _potentialKeyIds.length)];
            if (
                !_ghostKeyExists[owner][candidate] && !_ghostKeyRevoked[owner][candidate]
                    && !_ghostKeyExists[other][candidate] && !_ghostKeyRevoked[other][candidate]
            ) {
                _createKeyInternal(owner, candidate);
                return (candidate, false);
            }
        }

        return (address(0), true);
    }

    /// @dev Snapshots KeyInfo + token limits for immutability checks
    function _snapshotKey(
        address account,
        address keyId,
        address[] memory tokens
    )
        internal
        view
        returns (KeySnapshot memory snap)
    {
        snap.info = keychain.getKey(account, keyId);
        snap.tokens = tokens;
        snap.limits = new uint256[](tokens.length);
        for (uint256 t = 0; t < tokens.length; t++) {
            snap.limits[t] = keychain.getRemainingLimit(account, keyId, tokens[t]);
        }
    }

    /// @dev Asserts all KeyInfo fields and token limits are unchanged from snapshot
    function _assertKeyUnchanged(
        KeySnapshot memory before,
        address account,
        address keyId,
        string memory tag
    )
        internal
        view
    {
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(account, keyId);
        assertEq(
            infoAfter.keyId,
            before.info.keyId,
            string.concat(tag, ": keyId should remain unchanged")
        );
        assertEq(
            infoAfter.expiry,
            before.info.expiry,
            string.concat(tag, ": expiry should remain unchanged")
        );
        assertEq(
            infoAfter.enforceLimits,
            before.info.enforceLimits,
            string.concat(tag, ": enforceLimits should remain unchanged")
        );
        assertEq(
            uint8(infoAfter.signatureType),
            uint8(before.info.signatureType),
            string.concat(tag, ": signature type should remain unchanged")
        );
        assertEq(
            infoAfter.isRevoked,
            before.info.isRevoked,
            string.concat(tag, ": revoked flag should remain unchanged")
        );
        for (uint256 t = 0; t < before.tokens.length; t++) {
            assertEq(
                keychain.getRemainingLimit(account, keyId, before.tokens[t]),
                before.limits[t],
                string.concat(tag, ": token limit should remain unchanged")
            );
        }
    }

    /// @dev Attempts authorizeKey and asserts it reverts with the expected selector
    function _expectAuthorizeKeyRevert(
        address caller,
        address keyId,
        IAccountKeychain.SignatureType sigType,
        uint64 expiry,
        bool enforceLimits,
        IAccountKeychain.TokenLimit[] memory limits,
        bytes4 expectedSelector,
        string memory tag
    )
        internal
    {
        address[] memory watchTokens = _watchTokens(keyId);
        KeySnapshot memory snap = _snapshotKey(caller, keyId, watchTokens);

        vm.startPrank(caller);
        try keychain.authorizeKey(keyId, sigType, expiry, enforceLimits, limits) {
            vm.stopPrank();
            revert(string.concat(tag, ": should have reverted"));
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(bytes4(reason), expectedSelector, string.concat(tag, ": wrong error selector"));
        }

        _assertKeyUnchanged(snap, caller, keyId, tag);
    }

    /// @dev Attempts revokeKey and asserts it reverts with the expected selector
    function _expectRevokeKeyRevert(
        address caller,
        address snapshotAccount,
        address keyId,
        bytes4 expectedSelector,
        string memory tag
    )
        internal
    {
        address[] memory watchTokens = _watchTokens(keyId);
        KeySnapshot memory snap = _snapshotKey(snapshotAccount, keyId, watchTokens);

        vm.startPrank(caller);
        try keychain.revokeKey(keyId) {
            vm.stopPrank();
            revert(string.concat(tag, ": should have reverted"));
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(bytes4(reason), expectedSelector, string.concat(tag, ": wrong error selector"));
        }

        _assertKeyUnchanged(snap, snapshotAccount, keyId, tag);
    }

    /// @dev Attempts updateSpendingLimit and asserts it reverts with the expected selector
    function _expectUpdateLimitRevert(
        address caller,
        address snapshotAccount,
        address keyId,
        address token,
        uint256 newLimit,
        bytes4 expectedSelector,
        string memory tag
    )
        internal
    {
        address[] memory watchTokens = _watchTokens(token);
        KeySnapshot memory snap = _snapshotKey(snapshotAccount, keyId, watchTokens);

        vm.startPrank(caller);
        try keychain.updateSpendingLimit(keyId, token, newLimit) {
            vm.stopPrank();
            revert(string.concat(tag, ": should have reverted"));
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(bytes4(reason), expectedSelector, string.concat(tag, ": wrong error selector"));
        }

        _assertKeyUnchanged(snap, snapshotAccount, keyId, tag);
    }

    /// @dev Asserts KeyInfo fields (not limits) are unchanged from snapshot
    function _assertKeyMetadataUnchanged(
        IAccountKeychain.KeyInfo memory infoBefore,
        address account,
        address keyId,
        string memory tag
    )
        internal
        view
    {
        IAccountKeychain.KeyInfo memory infoAfter = keychain.getKey(account, keyId);
        assertEq(
            infoAfter.keyId, infoBefore.keyId, string.concat(tag, ": keyId should remain unchanged")
        );
        assertEq(
            infoAfter.expiry,
            infoBefore.expiry,
            string.concat(tag, ": expiry should remain unchanged")
        );
        assertEq(
            uint8(infoAfter.signatureType),
            uint8(infoBefore.signatureType),
            string.concat(tag, ": signature type should remain unchanged")
        );
        assertEq(
            infoAfter.isRevoked,
            infoBefore.isRevoked,
            string.concat(tag, ": revoked flag should remain unchanged")
        );
    }

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
