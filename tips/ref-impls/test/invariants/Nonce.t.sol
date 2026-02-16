// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { INonce } from "../../src/interfaces/INonce.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title Nonce Invariant Tests
/// @notice Fuzz-based invariant tests for the Nonce precompile
/// @dev Tests invariants TEMPO-NON1 through TEMPO-NON11 for the 2D nonce system
contract NonceInvariantTest is InvariantBaseTest {

    /// @dev Storage slot for nonces mapping (slot 0)
    uint256 private constant NONCES_SLOT = 0;

    /// @dev Maximum nonce key used by normal handlers (1 to MAX_NORMAL_NONCE_KEY)
    uint256 private constant MAX_NORMAL_NONCE_KEY = 1000;

    /// @dev Ghost variables for tracking nonce state
    /// Maps account => nonceKey => expected nonce value
    mapping(address => mapping(uint256 => uint64)) private _ghostNonces;

    /// @dev Track all nonce keys used per account
    mapping(address => uint256[]) private _accountNonceKeys;

    /// @dev Track if a nonce key has been used by an account
    mapping(address => mapping(uint256 => bool)) private _nonceKeyUsed;

    /// @dev Track last-seen nonce values for decrease detection
    /// account => nonceKey => lastSeenNonce
    mapping(address => mapping(uint256 => uint64)) private _lastSeenNonces;

    /// @dev Total increments performed
    uint256 private _totalIncrements;

    /// @dev Total reads performed
    uint256 private _totalReads;

    /// @dev Total protocol nonce rejections (key 0 reads)
    uint256 private _totalProtocolNonceRejections;

    /// @dev Total account independence checks
    uint256 private _totalAccountIndependenceChecks;

    /// @dev Total key independence checks
    uint256 private _totalKeyIndependenceChecks;

    /// @dev Total large key tests
    uint256 private _totalLargeKeyTests;

    /// @dev Total multiple increment operations
    uint256 private _totalMultipleIncrements;

    /// @dev Total overflow tests
    uint256 private _totalOverflowTests;

    /// @dev Total invalid key increment rejections
    uint256 private _totalInvalidKeyRejections;

    /// @dev Total reserved expiring key tests
    uint256 private _totalReservedKeyTests;

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets up the test environment
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        // Exclude helper functions from fuzzing - only target actual handlers
        bytes4[] memory selectors = new bytes4[](10);
        selectors[0] = this.incrementNonce.selector;
        selectors[1] = this.readNonce.selector;
        selectors[2] = this.tryProtocolNonce.selector;
        selectors[3] = this.verifyAccountIndependence.selector;
        selectors[4] = this.verifyKeyIndependence.selector;
        selectors[5] = this.testLargeNonceKey.selector;
        selectors[6] = this.multipleIncrements.selector;
        selectors[7] = this.testNonceOverflow.selector;
        selectors[8] = this.testInvalidNonceKeyIncrement.selector;
        selectors[9] = this.testReservedExpiringNonceKey.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));

        _setupInvariantBase();
        _actors = _buildActors(10);
    }

    /// @dev Gets a valid nonce key (1 to MAX_NORMAL_NONCE_KEY)
    function _selectNonceKey(uint256 seed) internal pure returns (uint256) {
        return (seed % MAX_NORMAL_NONCE_KEY) + 1;
    }

    /// @dev Selects a nonce key that is NOT the excluded key, using bound to avoid discards
    /// @param seed Random seed
    /// @param excluded Key to exclude from selection
    /// @return Selected nonce key (guaranteed != excluded)
    function _selectNonceKeyExcluding(
        uint256 seed,
        uint256 excluded
    )
        internal
        pure
        returns (uint256)
    {
        uint256 idx = bound(seed, 0, MAX_NORMAL_NONCE_KEY - 2);
        uint256 key = idx + 1;
        if (key >= excluded) {
            key += 1;
        }
        return key;
    }

    /// @dev Tracks a nonce key for an actor in ghost state (for invariant iteration)
    /// @param actor The actor address
    /// @param nonceKey The nonce key to track
    function _trackNonceKey(address actor, uint256 nonceKey) internal {
        if (!_nonceKeyUsed[actor][nonceKey]) {
            _nonceKeyUsed[actor][nonceKey] = true;
            _accountNonceKeys[actor].push(nonceKey);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          STORAGE HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Calculate storage slot for nonces[account][nonceKey]
    function _getNonceSlot(address account, uint256 nonceKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(nonceKey, keccak256(abi.encode(account, NONCES_SLOT))));
    }

    /// @dev Increment nonce via direct storage manipulation (simulates protocol behavior)
    /// @dev Uses INonce custom errors to align with protocol error semantics
    function _incrementNonceViaStorage(
        address account,
        uint256 nonceKey
    )
        internal
        returns (uint64 newNonce)
    {
        if (nonceKey == 0) revert INonce.InvalidNonceKey();

        bytes32 slot = _getNonceSlot(account, nonceKey);
        uint64 current = uint64(uint256(vm.load(_NONCE, slot)));

        if (current == type(uint64).max) revert INonce.NonceOverflow();

        newNonce = current + 1;
        vm.store(_NONCE, slot, bytes32(uint256(newNonce)));

        return newNonce;
    }

    /// @dev External wrapper for testing reverts
    function externalIncrementNonceViaStorage(
        address account,
        uint256 nonceKey
    )
        external
        returns (uint64)
    {
        return _incrementNonceViaStorage(account, nonceKey);
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for incrementing nonces
    /// @dev Tests TEMPO-NON1 (monotonic increment), TEMPO-NON2 (sequential values)
    function incrementNonce(uint256 actorSeed, uint256 keySeed) external {
        address actor = _selectActor(actorSeed);
        uint256 nonceKey = _selectNonceKey(keySeed);

        uint64 expectedBefore = _ghostNonces[actor][nonceKey];
        uint64 actualBefore = nonce.getNonce(actor, nonceKey);

        // TEMPO-NON2: Ghost state should match actual state
        assertEq(actualBefore, expectedBefore, "TEMPO-NON2: Ghost nonce mismatch before increment");

        uint64 newNonce = _incrementNonceViaStorage(actor, nonceKey);
        _totalIncrements++;

        // Update ghost state
        _ghostNonces[actor][nonceKey] = newNonce;
        _lastSeenNonces[actor][nonceKey] = newNonce;

        // Track nonce key usage
        _trackNonceKey(actor, nonceKey);

        // TEMPO-NON1: Nonce should increment by exactly 1
        assertEq(newNonce, expectedBefore + 1, "TEMPO-NON1: Nonce should increment by 1");

        // TEMPO-NON3: New value should be readable
        uint64 actualAfter = nonce.getNonce(actor, nonceKey);
        assertEq(actualAfter, newNonce, "TEMPO-NON3: Stored nonce should match returned value");
    }

    /// @notice Handler for reading nonces
    /// @dev Tests TEMPO-NON3 (read consistency)
    function readNonce(uint256 actorSeed, uint256 keySeed) external {
        address actor = _selectActor(actorSeed);
        uint256 nonceKey = _selectNonceKey(keySeed);

        uint64 actual = nonce.getNonce(actor, nonceKey);
        uint64 expected = _ghostNonces[actor][nonceKey];

        _totalReads++;

        // TEMPO-NON3: Read should return correct value
        assertEq(actual, expected, "TEMPO-NON3: Read nonce should match ghost state");
    }

    /// @notice Handler for testing protocol nonce rejection
    /// @dev Tests TEMPO-NON4 (protocol nonce key 0 not supported)
    function tryProtocolNonce(uint256 actorSeed) external {
        address actor = _selectActor(actorSeed);

        // TEMPO-NON4: Key 0 should revert with ProtocolNonceNotSupported
        try nonce.getNonce(actor, 0) {
            revert("TEMPO-NON4: Protocol nonce (key 0) should revert");
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                INonce.ProtocolNonceNotSupported.selector,
                "TEMPO-NON4: Should revert with ProtocolNonceNotSupported"
            );
        }

        _totalProtocolNonceRejections++;
    }

    /// @notice Handler for verifying account independence
    /// @dev Tests TEMPO-NON5 (different accounts have independent nonces)
    function verifyAccountIndependence(
        uint256 actor1Seed,
        uint256 actor2Seed,
        uint256 keySeed
    )
        external
    {
        address actor1 = _selectActor(actor1Seed);
        address actor2 = _selectActorExcluding(actor2Seed, actor1);
        uint256 nonceKey = _selectNonceKey(keySeed);

        uint64 nonce2Before = nonce.getNonce(actor2, nonceKey);

        // Increment actor1's nonce
        uint64 newNonce1 = _incrementNonceViaStorage(actor1, nonceKey);
        _ghostNonces[actor1][nonceKey] = newNonce1;
        _lastSeenNonces[actor1][nonceKey] = newNonce1;
        _trackNonceKey(actor1, nonceKey);

        // TEMPO-NON5: Actor2's nonce should be unchanged
        uint64 nonce2After = nonce.getNonce(actor2, nonceKey);
        assertEq(nonce2After, nonce2Before, "TEMPO-NON5: Other account nonce should be unchanged");

        _totalAccountIndependenceChecks++;
    }

    /// @notice Handler for verifying key independence
    /// @dev Tests TEMPO-NON6 (different keys have independent nonces)
    function verifyKeyIndependence(uint256 actorSeed, uint256 key1Seed, uint256 key2Seed) external {
        address actor = _selectActor(actorSeed);
        uint256 key1 = _selectNonceKey(key1Seed);
        uint256 key2 = _selectNonceKeyExcluding(key2Seed, key1);

        uint64 nonce2Before = nonce.getNonce(actor, key2);

        // Increment key1's nonce
        uint64 newNonce1 = _incrementNonceViaStorage(actor, key1);
        _ghostNonces[actor][key1] = newNonce1;
        _lastSeenNonces[actor][key1] = newNonce1;
        _trackNonceKey(actor, key1);

        // TEMPO-NON6: Key2's nonce should be unchanged
        uint64 nonce2After = nonce.getNonce(actor, key2);
        assertEq(nonce2After, nonce2Before, "TEMPO-NON6: Other key nonce should be unchanged");

        _totalKeyIndependenceChecks++;
    }

    /// @notice Handler for testing max nonce key
    /// @dev Tests TEMPO-NON7 (large nonce keys work)
    /// Note: type(uint256).max is reserved for TEMPO_EXPIRING_NONCE_KEY, so we use max-1
    function testLargeNonceKey(uint256 actorSeed) external {
        address actor = _selectActor(actorSeed);
        uint256 largeKey = type(uint256).max - 1;

        // Should work with large uint256 key
        uint64 result = nonce.getNonce(actor, largeKey);
        assertEq(result, _ghostNonces[actor][largeKey], "TEMPO-NON7: Large key should work");

        // Increment and verify
        uint64 newNonce = _incrementNonceViaStorage(actor, largeKey);
        _ghostNonces[actor][largeKey] = newNonce;
        _lastSeenNonces[actor][largeKey] = newNonce;
        _trackNonceKey(actor, largeKey);

        uint64 afterIncrement = nonce.getNonce(actor, largeKey);
        assertEq(afterIncrement, newNonce, "TEMPO-NON7: Large key should increment correctly");

        _totalLargeKeyTests++;
    }

    /// @notice Handler for multiple sequential increments
    /// @dev Tests TEMPO-NON8 (strict monotonicity over many increments)
    function multipleIncrements(uint256 actorSeed, uint256 keySeed, uint8 countSeed) external {
        address actor = _selectActor(actorSeed);
        uint256 nonceKey = _selectNonceKey(keySeed);
        uint256 count = (countSeed % 10) + 1; // 1-10 increments

        uint64 startNonce = nonce.getNonce(actor, nonceKey);

        for (uint256 i = 0; i < count; i++) {
            uint64 beforeIncrement = nonce.getNonce(actor, nonceKey);
            uint64 newNonce = _incrementNonceViaStorage(actor, nonceKey);
            _ghostNonces[actor][nonceKey] = newNonce;
            _lastSeenNonces[actor][nonceKey] = newNonce;

            // TEMPO-NON8: Each increment should be exactly +1
            assertEq(
                newNonce, beforeIncrement + 1, "TEMPO-NON8: Each increment should be exactly +1"
            );
        }

        _trackNonceKey(actor, nonceKey);

        uint64 endNonce = nonce.getNonce(actor, nonceKey);
        assertEq(endNonce, startNonce + uint64(count), "TEMPO-NON8: Total increment should match");

        _totalMultipleIncrements++;
    }

    /// @notice Handler for testing nonce overflow at u64::MAX
    /// @dev Tests TEMPO-NON9 (nonce overflow protection)
    /// Uses a small bounded key range to avoid conflicts and prevent unbounded key growth:
    /// - Normal handlers (1 to MAX_NORMAL_NONCE_KEY)
    /// - testLargeNonceKey (max-1)
    /// - Reserved TEMPO_EXPIRING_NONCE_KEY (max)
    function testNonceOverflow(uint256 actorSeed, uint256 keySeed) external {
        address actor = _selectActor(actorSeed);
        // Use a small bounded range to prevent unbounded _accountNonceKeys growth
        uint256 nonceKey = bound(keySeed, MAX_NORMAL_NONCE_KEY + 1, MAX_NORMAL_NONCE_KEY + 100);

        // Set nonce to max value via direct storage manipulation
        bytes32 slot = _getNonceSlot(actor, nonceKey);
        vm.store(_NONCE, slot, bytes32(uint256(type(uint64).max)));

        // Verify the nonce is at max
        uint64 currentNonce = nonce.getNonce(actor, nonceKey);
        assertEq(currentNonce, type(uint64).max, "TEMPO-NON9: Nonce should be at max");

        // Update ghost state to reflect the storage manipulation
        _ghostNonces[actor][nonceKey] = type(uint64).max;
        _lastSeenNonces[actor][nonceKey] = type(uint64).max;
        _trackNonceKey(actor, nonceKey);

        // TEMPO-NON9: Attempting to increment at max should revert with NonceOverflow
        vm.expectRevert(INonce.NonceOverflow.selector);
        this.externalIncrementNonceViaStorage(actor, nonceKey);

        _totalOverflowTests++;
    }

    /// @notice Handler for testing invalid nonce key (key 0) increment rejection
    /// @dev Tests TEMPO-NON10 (InvalidNonceKey for key 0 increment)
    /// Note: Rust distinguishes between:
    /// - get_nonce(key=0) -> ProtocolNonceNotSupported
    /// - increment_nonce(key=0) -> InvalidNonceKey
    function testInvalidNonceKeyIncrement(uint256 actorSeed) external {
        address actor = _selectActor(actorSeed);

        // TEMPO-NON10: Increment with key 0 should revert with InvalidNonceKey
        vm.expectRevert(INonce.InvalidNonceKey.selector);
        this.externalIncrementNonceViaStorage(actor, 0);

        _totalInvalidKeyRejections++;
    }

    /// @notice Handler for testing reserved TEMPO_EXPIRING_NONCE_KEY readability
    /// @dev Tests TEMPO-NON11 (reserved key type(uint256).max is readable via getNonce)
    /// @dev Expiring nonces use tx-hash-based replay protection (separate storage). This
    ///      test verifies the key is accessible and returns 0 for uninitialized accounts.
    function testReservedExpiringNonceKey(uint256 actorSeed) external {
        address actor = _selectActor(actorSeed);
        uint256 reservedKey = type(uint256).max;

        // TEMPO-NON11: Reserved key should be readable (returns 0 for uninitialized)
        // The key is reserved for expiring nonces but reading it works
        uint64 result = nonce.getNonce(actor, reservedKey);

        // For uninitialized, it should return 0
        // (We don't track this in ghost state since it's reserved)
        assertEq(result, 0, "TEMPO-NON11: Reserved key should return 0 for uninitialized");

        _totalReservedKeyTests++;
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks in a single unified loop
    /// @dev Combines TEMPO-NON1 (never decrease) and TEMPO-NON2 (ghost consistency) checks
    ///      Caches nonce.getNonce() result to avoid duplicate external calls
    function invariant_globalInvariants() public view {
        for (uint256 a = 0; a < _actors.length; a++) {
            address actor = _actors[a];
            uint256[] storage keys = _accountNonceKeys[actor];
            uint256 keysLength = keys.length;

            for (uint256 k = 0; k < keysLength; k++) {
                uint256 nonceKey = keys[k];
                uint64 actual = nonce.getNonce(actor, nonceKey);

                // TEMPO-NON2: Ghost state should match actual state
                uint64 expected = _ghostNonces[actor][nonceKey];
                assertEq(actual, expected, "TEMPO-NON2: Ghost state should match actual state");

                // TEMPO-NON1: Nonces should never decrease
                uint64 lastSeen = _lastSeenNonces[actor][nonceKey];
                assertGe(actual, lastSeen, "TEMPO-NON1: Nonce decreased from last seen value");
            }
        }
    }

}
