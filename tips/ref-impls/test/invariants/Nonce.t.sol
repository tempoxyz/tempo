// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { INonce } from "../../src/interfaces/INonce.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title Nonce Invariant Tests
/// @notice Fuzz-based invariant tests for Nonce precompile storage layout and view behavior
/// @dev Tests invariants TEMPO-NON1 through TEMPO-NON11 for the 2D nonce system.
///      Uses direct storage manipulation (vm.store/vm.load) to simulate nonce increments
///      against the deployed Solidity reference contract. This validates storage slot layout,
///      getNonce view correctness, and ghost state consistency. Real precompile execution
///      (increment_nonce via Rust) is covered by TempoTransactionInvariant.t.sol.
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

    /// @dev Snapshot of expiringNonceRingPtr (slot 3) at setUp, for isolation checks
    bytes32 private _expiringNonceRingPtrInit;

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets up the test environment
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        // Exclude helper functions from fuzzing - only target actual handlers
        bytes4[] memory selectors = new bytes4[](11);
        selectors[0] = this.handler_incrementNonce.selector;
        selectors[1] = this.handler_readNonce.selector;
        selectors[2] = this.handler_tryProtocolNonce.selector;
        selectors[3] = this.handler_verifyAccountIndependence.selector;
        selectors[4] = this.handler_verifyKeyIndependence.selector;
        selectors[5] = this.handler_testLargeNonceKey.selector;
        selectors[6] = this.handler_multipleIncrements.selector;
        selectors[7] = this.handler_nonceOverflow.selector;
        selectors[8] = this.handler_invalidNonceKeyIncrement.selector;
        selectors[9] = this.handler_testReservedExpiringNonceKey.selector;
        selectors[10] = this.handler_protocolNonceWithStorage.selector;
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));

        _setupInvariantBase();
        _actors = _buildActors(10);

        // Snapshot expiringNonceRingPtr (slot 3) for isolation invariant.
        _expiringNonceRingPtrInit = vm.load(_NONCE, bytes32(uint256(3)));
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

    /// @dev Number of interesting large nonce keys
    uint256 private constant NUM_LARGE_KEYS = 8;

    /// @dev Selects from a bounded set of interesting large nonce keys
    /// Exercises storage slot derivation at extreme uint256 values without unbounded key growth.
    /// Avoids type(uint256).max which is reserved for TEMPO_EXPIRING_NONCE_KEY.
    function _selectLargeNonceKey(uint256 seed) internal pure returns (uint256) {
        uint256 idx = seed % NUM_LARGE_KEYS;
        if (idx == 0) return type(uint256).max - 1;
        if (idx == 1) return type(uint256).max - 2;
        if (idx == 2) return 1 << 255;
        if (idx == 3) return (1 << 255) + 123;
        if (idx == 4) return 1 << 128;
        if (idx == 5) return (1 << 128) + 456;
        if (idx == 6) return type(uint256).max / 2;
        return type(uint256).max - 10_000;
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

    /// @dev Selects an account, occasionally injecting edge-case addresses
    function _selectAccount(uint256 seed) internal view returns (address) {
        uint256 branch = seed % 8;
        if (branch == 0) return address(0);
        if (branch == 1) return address(this);
        if (branch == 2) return _NONCE;
        return _selectActor(seed);
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
    /// @dev Tests TEMPO-NON1 (monotonic increment), TEMPO-NON2 (sequential values),
    ///      TEMPO-NON3 (read-back consistency)
    function handler_incrementNonce(uint256 actorSeed, uint256 keySeed) external {
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
        _trackNonceKey(actor, nonceKey);

        // TEMPO-NON1: Nonce should increment by exactly 1
        assertEq(newNonce, expectedBefore + 1, "TEMPO-NON1: Nonce should increment by 1");

        // TEMPO-NON3: New value should be readable via getNonce
        uint64 actualAfter = nonce.getNonce(actor, nonceKey);
        assertEq(actualAfter, newNonce, "TEMPO-NON3: Stored nonce should match returned value");
    }

    /// @notice Handler for reading nonces
    /// @dev Tests TEMPO-NON3 (read consistency)
    function handler_readNonce(uint256 actorSeed, uint256 keySeed) external {
        address actor = _selectActor(actorSeed);
        uint256 nonceKey = _selectNonceKey(keySeed);

        uint64 actual = nonce.getNonce(actor, nonceKey);
        uint64 expected = _ghostNonces[actor][nonceKey];

        _totalReads++;

        // TEMPO-NON3: Read should return correct value
        assertEq(actual, expected, "TEMPO-NON3: Read nonce should match ghost state");

        // TEMPO-NON1: Fail immediately if nonce decreased from last observation
        uint64 lastSeen = _lastSeenNonces[actor][nonceKey];
        assertGe(actual, lastSeen, "TEMPO-NON1: Nonce decreased since last seen");

        _lastSeenNonces[actor][nonceKey] = actual;
    }

    /// @notice Handler for testing protocol nonce rejection
    /// @dev Tests TEMPO-NON4 (protocol nonce key 0 not supported)
    function handler_tryProtocolNonce(uint256 actorSeed) external {
        address account = _selectAccount(actorSeed);

        // TEMPO-NON4: Key 0 should revert with ProtocolNonceNotSupported
        try nonce.getNonce(account, 0) {
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
    function handler_verifyAccountIndependence(
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

        // Skip if actor1 is at max (overflow tested by handler_nonceOverflow)
        if (_ghostNonces[actor1][nonceKey] == type(uint64).max) return;

        // Increment actor1's nonce
        uint64 newNonce1 = _incrementNonceViaStorage(actor1, nonceKey);
        _ghostNonces[actor1][nonceKey] = newNonce1;
        _lastSeenNonces[actor1][nonceKey] = newNonce1;
        _trackNonceKey(actor1, nonceKey);
        _totalIncrements++;

        // TEMPO-NON5: Actor2's nonce should be unchanged
        uint64 nonce2After = nonce.getNonce(actor2, nonceKey);
        assertEq(nonce2After, nonce2Before, "TEMPO-NON5: Other account nonce should be unchanged");

        // Track actor2's key so global invariant covers it
        _trackNonceKey(actor2, nonceKey);

        _totalAccountIndependenceChecks++;
    }

    /// @notice Handler for verifying key independence
    /// @dev Tests TEMPO-NON6 (different keys have independent nonces for the same account)
    function handler_verifyKeyIndependence(
        uint256 actorSeed,
        uint256 key1Seed,
        uint256 key2Seed
    )
        external
    {
        address actor = _selectActor(actorSeed);
        uint256 key1 = _selectNonceKey(key1Seed);
        uint256 key2 = _selectNonceKeyExcluding(key2Seed, key1);

        uint64 nonce2Before = nonce.getNonce(actor, key2);

        // Skip if key1 is at max (overflow tested by handler_nonceOverflow)
        if (_ghostNonces[actor][key1] == type(uint64).max) return;

        // Increment key1's nonce
        uint64 newNonce1 = _incrementNonceViaStorage(actor, key1);
        _ghostNonces[actor][key1] = newNonce1;
        _lastSeenNonces[actor][key1] = newNonce1;
        _trackNonceKey(actor, key1);
        _totalIncrements++;

        // TEMPO-NON6: Key2's nonce should be unchanged
        uint64 nonce2After = nonce.getNonce(actor, key2);
        assertEq(nonce2After, nonce2Before, "TEMPO-NON6: Other key nonce should be unchanged");

        // Track key2 so global invariant covers it
        _trackNonceKey(actor, key2);

        _totalKeyIndependenceChecks++;
    }

    /// @notice Handler for testing large nonce keys
    /// @dev Tests TEMPO-NON7 (large nonce keys work correctly)
    /// Selects from a bounded set of interesting large keys to exercise storage slot
    /// derivation at extreme uint256 values without unbounded key growth.
    /// Note: type(uint256).max is reserved for TEMPO_EXPIRING_NONCE_KEY.
    function handler_testLargeNonceKey(uint256 actorSeed, uint256 keySeed) external {
        address actor = _selectActor(actorSeed);
        uint256 largeKey = _selectLargeNonceKey(keySeed);

        uint64 expectedBefore = _ghostNonces[actor][largeKey];
        uint64 actualBefore = nonce.getNonce(actor, largeKey);

        // TEMPO-NON7: Ghost state should match actual state before increment
        assertEq(actualBefore, expectedBefore, "TEMPO-NON7: Ghost nonce mismatch before increment");

        // Increment and verify
        uint64 newNonce = _incrementNonceViaStorage(actor, largeKey);
        _ghostNonces[actor][largeKey] = newNonce;
        _lastSeenNonces[actor][largeKey] = newNonce;
        _trackNonceKey(actor, largeKey);
        _totalIncrements++;
        _totalLargeKeyTests++;

        // TEMPO-NON7: Large key should increment correctly
        uint64 afterIncrement = nonce.getNonce(actor, largeKey);
        assertEq(afterIncrement, newNonce, "TEMPO-NON7: Large key should increment correctly");
    }

    /// @notice Handler for multiple sequential increments
    /// @dev Tests TEMPO-NON8 (strict monotonicity over many increments)
    function handler_multipleIncrements(
        uint256 actorSeed,
        uint256 keySeed,
        uint8 countSeed
    )
        external
    {
        address actor = _selectActor(actorSeed);
        uint256 nonceKey = _selectNonceKey(keySeed);
        uint256 count = bound(countSeed, 1, 32);

        uint64 startNonce = nonce.getNonce(actor, nonceKey);

        // Clamp count to avoid overflow
        uint256 maxSteps = uint256(type(uint64).max) - uint256(startNonce);
        if (count > maxSteps) {
            count = maxSteps;
        }
        if (count == 0) return;

        _trackNonceKey(actor, nonceKey);

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

        uint64 endNonce = nonce.getNonce(actor, nonceKey);
        assertEq(endNonce, startNonce + uint64(count), "TEMPO-NON8: Total increment should match");

        _totalMultipleIncrements++;
        _totalIncrements += count;
    }

    /// @notice Handler for testing nonce overflow at u64::MAX
    /// @dev Tests TEMPO-NON9 (nonce overflow protection)
    /// Uses a small bounded key range to avoid conflicts and prevent unbounded key growth.
    /// Tests the boundary in two steps:
    /// 1. Set nonce to max-1, increment once (should succeed, reaching max)
    /// 2. Attempt to increment again at max (should revert with NonceOverflow)
    function handler_nonceOverflow(uint256 actorSeed, uint256 keySeed) external {
        address actor = _selectActor(actorSeed);
        uint256 nonceKey = bound(keySeed, MAX_NORMAL_NONCE_KEY + 1, MAX_NORMAL_NONCE_KEY + 100);

        bytes32 slot = _getNonceSlot(actor, nonceKey);

        // Step 1: Set nonce to max-1 and increment once (should succeed)
        vm.store(_NONCE, slot, bytes32(uint256(type(uint64).max - 1)));

        uint64 newNonce = _incrementNonceViaStorage(actor, nonceKey);
        assertEq(newNonce, type(uint64).max, "TEMPO-NON9: Increment from max-1 should reach max");
        assertEq(
            nonce.getNonce(actor, nonceKey),
            type(uint64).max,
            "TEMPO-NON9: getNonce should return max after increment from max-1"
        );

        // Update ghost state
        _ghostNonces[actor][nonceKey] = type(uint64).max;
        _lastSeenNonces[actor][nonceKey] = type(uint64).max;
        _trackNonceKey(actor, nonceKey);

        // Step 2: Attempt to increment at max (should revert)
        try this.externalIncrementNonceViaStorage(actor, nonceKey) {
            revert("TEMPO-NON9: Increment at max should revert");
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                INonce.NonceOverflow.selector,
                "TEMPO-NON9: Should revert with NonceOverflow"
            );
        }

        // Verify nonce is still at max after revert
        assertEq(
            nonce.getNonce(actor, nonceKey),
            type(uint64).max,
            "TEMPO-NON9: getNonce must still return max after overflow revert"
        );

        _totalOverflowTests++;
    }

    /// @notice Handler for testing invalid nonce key (key 0) increment rejection
    /// @dev Tests TEMPO-NON10 (InvalidNonceKey for key 0 increment)
    /// Note: Rust distinguishes between:
    /// - get_nonce(key=0) -> ProtocolNonceNotSupported
    /// - increment_nonce(key=0) -> InvalidNonceKey
    function handler_invalidNonceKeyIncrement(uint256 accountSeed) external {
        address account = _selectAccount(accountSeed);

        // TEMPO-NON10: Increment with key 0 should revert with InvalidNonceKey
        try this.externalIncrementNonceViaStorage(account, 0) {
            revert("TEMPO-NON10: Increment with key 0 should revert");
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                INonce.InvalidNonceKey.selector,
                "TEMPO-NON10: Should revert with InvalidNonceKey"
            );
        }

        _totalInvalidKeyRejections++;
    }

    /// @notice Handler for testing reserved TEMPO_EXPIRING_NONCE_KEY readability
    /// @dev Tests TEMPO-NON11 (reserved key type(uint256).max is readable via getNonce)
    /// @dev Expiring nonces use tx-hash-based replay protection (separate storage). This
    ///      test verifies the key is accessible and returns the expected value.
    function handler_testReservedExpiringNonceKey(uint256 actorSeed) external {
        address account = _selectAccount(actorSeed);
        uint256 reservedKey = type(uint256).max;

        // TEMPO-NON11: Reserved key should be readable
        uint64 result = nonce.getNonce(account, reservedKey);
        uint64 expected = _ghostNonces[account][reservedKey];

        assertEq(result, expected, "TEMPO-NON11: Reserved key should match ghost state");

        // Uninitialized accounts should return 0
        if (!_nonceKeyUsed[account][reservedKey]) {
            assertEq(result, 0, "TEMPO-NON11: Uninitialized reserved key should be zero");
        }

        _totalReservedKeyTests++;
    }

    /// @notice Handler for testing that key 0 reverts even when storage is non-zero
    /// @dev Tests TEMPO-NON4 semantically: the key-0 guard is checked before reading storage,
    ///      so even if someone writes a value to the key-0 slot, getNonce must still revert.
    function handler_protocolNonceWithStorage(uint256 actorSeed) external {
        address actor = _selectActor(actorSeed);

        // Write a non-zero value into the key-0 storage slot
        bytes32 slot = _getNonceSlot(actor, 0);
        vm.store(_NONCE, slot, bytes32(uint256(123)));

        // TEMPO-NON4: getNonce(actor, 0) must still revert despite non-zero storage
        try nonce.getNonce(actor, 0) {
            revert("TEMPO-NON4: getNonce(actor, 0) must revert even with non-zero storage");
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                INonce.ProtocolNonceNotSupported.selector,
                "TEMPO-NON4: Should revert with ProtocolNonceNotSupported"
            );
        }

        // Clean up: restore slot to zero so we don't pollute isolation checks
        vm.store(_NONCE, slot, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks in a single unified loop
    /// @dev Combines TEMPO-NON1 (never decrease), TEMPO-NON2 (ghost consistency),
    ///      and raw storage canonical checks across all tracked (actor, nonceKey) pairs.
    ///      Raw storage checks catch high-bit corruption that getNonce's uint64 return
    ///      would mask — important for validating the precompile's storage layout.
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

                // Raw storage canonical: no dirty high bits.
                // getNonce returns uint64, which would mask corruption in the upper
                // 192 bits. Checking raw storage catches layout regressions.
                bytes32 slot = _getNonceSlot(actor, nonceKey);
                bytes32 raw = vm.load(_NONCE, slot);
                assertEq(
                    raw, bytes32(uint256(actual)), "TEMPO-NON2: Raw storage has dirty high bits"
                );
            }
        }
    }

    /// @notice Protocol nonce key 0 must always revert, regardless of state mutations
    /// @dev Tests TEMPO-NON4 globally: getNonce(account, 0) must revert with
    ///      ProtocolNonceNotSupported for all actors and edge-case addresses.
    ///      Ensures no handler accidentally makes key 0 readable.
    function invariant_protocolNonceAlwaysReverts() public {
        for (uint256 a = 0; a < _actors.length; a++) {
            try nonce.getNonce(_actors[a], 0) {
                revert("TEMPO-NON4: getNonce(actor, 0) must revert");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    INonce.ProtocolNonceNotSupported.selector,
                    "TEMPO-NON4: Should revert with ProtocolNonceNotSupported"
                );
            }
        }

        // Edge-case addresses: key 0 rejection must be account-independent
        address[3] memory edgeAccounts = [address(0), address(this), _NONCE];
        for (uint256 i = 0; i < edgeAccounts.length; i++) {
            try nonce.getNonce(edgeAccounts[i], 0) {
                revert("TEMPO-NON4: getNonce(edgeAddr, 0) must revert");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    INonce.ProtocolNonceNotSupported.selector,
                    "TEMPO-NON4: Should revert with ProtocolNonceNotSupported"
                );
            }
        }
    }

    /// @notice 2D nonce operations must never mutate expiring nonce storage (slots 1-3)
    /// @dev Tests storage isolation between the 2D nonce system (slot 0 mapping) and
    ///      the expiring nonce system (slots 1-3). For each tracked (actor, nonceKey) pair,
    ///      verifies that wrong-base-slot derived locations (slots 1 and 2) are still zero.
    function invariant_expiringNonceStorageIsolation() public view {
        // Base scalar slots 1 and 2 must remain zero (mapping base slots are never written).
        // Catches direct-slot clobbering that derived-slot checks alone would miss.
        assertEq(
            vm.load(_NONCE, bytes32(uint256(1))),
            bytes32(0),
            "Storage isolation: base slot 1 (expiringNonceSeen) is non-zero"
        );
        assertEq(
            vm.load(_NONCE, bytes32(uint256(2))),
            bytes32(0),
            "Storage isolation: base slot 2 (expiringNonceRing) is non-zero"
        );

        // Slot 3: expiringNonceRingPtr (scalar)
        assertEq(
            vm.load(_NONCE, bytes32(uint256(3))),
            _expiringNonceRingPtrInit,
            "Storage isolation: expiringNonceRingPtr (slot 3) mutated by 2D nonce operation"
        );

        // For each tracked (actor, nonceKey), verify wrong-base-slot locations are zero.
        // If the 2D nonce base slot (0) accidentally changed to 1 or 2, writes would
        // land at these derived locations instead. They must remain untouched.
        for (uint256 a = 0; a < _actors.length; a++) {
            address actor = _actors[a];
            uint256[] storage keys = _accountNonceKeys[actor];
            uint256 keysLength = keys.length;

            for (uint256 k = 0; k < keysLength; k++) {
                uint256 nonceKey = keys[k];

                // Slot that would be written if base slot were 1 (expiringNonceSeen)
                bytes32 wrongSlot1 =
                    keccak256(abi.encode(nonceKey, keccak256(abi.encode(actor, uint256(1)))));
                assertEq(
                    vm.load(_NONCE, wrongSlot1),
                    bytes32(0),
                    "Storage isolation: wrong-base-slot 1 location is non-zero"
                );

                // Slot that would be written if base slot were 2 (expiringNonceRing)
                bytes32 wrongSlot2 =
                    keccak256(abi.encode(nonceKey, keccak256(abi.encode(actor, uint256(2)))));
                assertEq(
                    vm.load(_NONCE, wrongSlot2),
                    bytes32(0),
                    "Storage isolation: wrong-base-slot 2 location is non-zero"
                );
            }
        }
    }

}
