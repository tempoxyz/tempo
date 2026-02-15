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

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets up the test environment
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        // Exclude helper functions from fuzzing - only target actual handlers
        bytes4[] memory selectors = new bytes4[](10);
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
        targetSelector(FuzzSelector({ addr: address(this), selectors: selectors }));

        _setupInvariantBase();
        _actors = _buildActors(10);

        _initLogFile("nonce.log", "Nonce Invariant Test Log");
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
    function handler_incrementNonce(uint256 actorSeed, uint256 keySeed) external {
        address actor = _selectActor(actorSeed);
        uint256 nonceKey = _selectNonceKey(keySeed);

        uint64 expectedBefore = _ghostNonces[actor][nonceKey];
        uint64 actualBefore = nonce.getNonce(actor, nonceKey);

        // TEMPO-NON2: Ghost state should match actual state before increment
        assertEq(actualBefore, expectedBefore, "TEMPO-NON2: Ghost nonce mismatch before increment");

        // Verify raw storage matches before increment (catches high-bit corruption
        // that getNonce's uint64 return would mask)
        bytes32 slot = _getNonceSlot(actor, nonceKey);
        bytes32 rawBefore = vm.load(_NONCE, slot);
        assertEq(
            rawBefore,
            bytes32(uint256(expectedBefore)),
            "TEMPO-NON2: Raw storage mismatch before increment"
        );

        // Snapshot an adjacent key's slot to verify it is untouched after increment
        uint256 otherKey = _selectNonceKeyExcluding(keySeed ^ 0xBEEF, nonceKey);
        bytes32 otherSlot = _getNonceSlot(actor, otherKey);
        bytes32 otherBefore = vm.load(_NONCE, otherSlot);

        // Compute expected value independently of the storage helper
        uint64 expectedAfter = expectedBefore + 1;

        uint64 newNonce = _incrementNonceViaStorage(actor, nonceKey);
        _totalIncrements++;

        // TEMPO-NON1: Nonce should increment by exactly 1
        assertEq(newNonce, expectedAfter, "TEMPO-NON1: Nonce should increment by 1");

        // Verify raw storage after increment (catches high-bit corruption)
        bytes32 rawAfter = vm.load(_NONCE, slot);
        assertEq(
            rawAfter,
            bytes32(uint256(expectedAfter)),
            "TEMPO-NON1: Raw storage mismatch after increment"
        );

        // Verify adjacent key slot was not modified
        assertEq(
            vm.load(_NONCE, otherSlot),
            otherBefore,
            "TEMPO-NON6: Increment wrote to adjacent key slot"
        );

        // Update ghost state from independently computed expected value (not helper return)
        _ghostNonces[actor][nonceKey] = expectedAfter;
        _lastSeenNonces[actor][nonceKey] = expectedAfter;

        // Track nonce key usage
        _trackNonceKey(actor, nonceKey);

        // TEMPO-NON3: New value should be readable via getNonce
        uint64 actualAfter = nonce.getNonce(actor, nonceKey);
        assertEq(actualAfter, expectedAfter, "TEMPO-NON3: Stored nonce should match expected value");

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "INCREMENT: ",
                    _getActorIndex(actor),
                    " key=",
                    vm.toString(nonceKey),
                    " ",
                    vm.toString(expectedBefore),
                    " -> ",
                    vm.toString(expectedAfter)
                )
            );
        }
    }

    /// @notice Handler for reading nonces
    /// @dev Tests TEMPO-NON3 (read consistency), TEMPO-NON1 (monotonicity on read)
    function handler_readNonce(uint256 actorSeed, uint256 keySeed) external {
        address actor = _selectActor(actorSeed);
        uint256 nonceKey = _selectNonceKey(keySeed);

        uint64 expected = _ghostNonces[actor][nonceKey];
        bytes32 slot = _getNonceSlot(actor, nonceKey);

        // Snapshot raw storage before reads
        bytes32 rawBefore = vm.load(_NONCE, slot);

        // Read twice to verify idempotency (view should have no side effects)
        uint64 v1 = nonce.getNonce(actor, nonceKey);
        uint64 v2 = nonce.getNonce(actor, nonceKey);

        _totalReads++;

        // TEMPO-NON3: Reads should be idempotent
        assertEq(v1, v2, "TEMPO-NON3: Read should be idempotent");

        // TEMPO-NON3: Read should return correct value
        assertEq(v1, expected, "TEMPO-NON3: Read nonce should match ghost state");

        // TEMPO-NON3: Raw storage should match ghost (catches high-bit corruption
        // that getNonce's uint64 return would mask)
        assertEq(
            rawBefore,
            bytes32(uint256(expected)),
            "TEMPO-NON3: Raw storage mismatch / dirty high bits"
        );

        // TEMPO-NON3: Read should not mutate storage
        assertEq(
            vm.load(_NONCE, slot),
            rawBefore,
            "TEMPO-NON3: Read should not mutate storage"
        );

        // TEMPO-NON1: Nonce should never decrease from last seen value
        uint64 lastSeen = _lastSeenNonces[actor][nonceKey];
        assertGe(v1, lastSeen, "TEMPO-NON1: Nonce decreased since last seen");
        _lastSeenNonces[actor][nonceKey] = v1;

        // Explicit uninitialized-key check
        if (!_nonceKeyUsed[actor][nonceKey]) {
            assertEq(v1, 0, "TEMPO-NON3: Uninitialized nonce should be zero");
        }

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "READ: ",
                    _getActorIndex(actor),
                    " key=",
                    vm.toString(nonceKey),
                    " value=",
                    vm.toString(v1)
                )
            );
        }
    }

    /// @notice Handler for testing protocol nonce rejection
    /// @dev Tests TEMPO-NON4 (protocol nonce key 0 not supported)
    function handler_tryProtocolNonce(uint256 actorSeed) external {
        // Broaden the account domain beyond _actors to verify key-0 rejection
        // is account-independent. Use actorSeed to occasionally inject edge-case addresses.
        address account;
        uint256 branch = actorSeed % 8;
        if (branch == 0) {
            account = address(0);
        } else if (branch == 1) {
            account = address(this);
        } else if (branch == 2) {
            account = _NONCE;
        } else {
            account = _selectActor(actorSeed);
        }

        // Snapshot sampled storage slots to verify no side effects
        uint256 k1 = _selectNonceKey(actorSeed ^ 0xA1);
        uint256 k2 = _selectNonceKeyExcluding(actorSeed ^ 0xA2, k1);
        bytes32 slot1 = _getNonceSlot(account, k1);
        bytes32 slot2 = _getNonceSlot(account, k2);
        bytes32 snap1 = vm.load(_NONCE, slot1);
        bytes32 snap2 = vm.load(_NONCE, slot2);

        // Also snapshot the key-0 slot itself to detect accidental writes to key 0
        bytes32 slot0 = _getNonceSlot(account, 0);
        bytes32 snap0 = vm.load(_NONCE, slot0);

        // TEMPO-NON4: Key 0 should revert with ProtocolNonceNotSupported
        bytes memory expectedRevert =
            abi.encodeWithSelector(INonce.ProtocolNonceNotSupported.selector);

        try nonce.getNonce(account, 0) {
            revert("TEMPO-NON4: Protocol nonce (key 0) should revert");
        } catch (bytes memory reason) {
            // Assert exact revert payload, not just selector (catches malformed revert data)
            assertEq(reason.length, 4, "TEMPO-NON4: Revert data should be exactly 4 bytes");
            assertEq(reason, expectedRevert, "TEMPO-NON4: Should revert with ProtocolNonceNotSupported");
        }

        // Assert statelessness: a second call should revert identically
        try nonce.getNonce(account, 0) {
            revert("TEMPO-NON4: Protocol nonce (key 0) should revert on repeat call");
        } catch (bytes memory reason2) {
            assertEq(reason2, expectedRevert, "TEMPO-NON4: Repeat call should revert identically");
        }

        // Verify no side effects on sampled storage slots
        assertEq(vm.load(_NONCE, slot0), snap0, "TEMPO-NON4: Key-0 slot modified by rejected read");
        assertEq(vm.load(_NONCE, slot1), snap1, "TEMPO-NON4: Adjacent key slot modified by rejected read");
        assertEq(vm.load(_NONCE, slot2), snap2, "TEMPO-NON4: Adjacent key slot modified by rejected read");

        _totalProtocolNonceRejections++;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRY_PROTOCOL_NONCE: account=",
                    vm.toString(account),
                    " correctly rejected"
                )
            );
        }
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

        // --- actor1 before: view + ghost + raw ---
        uint64 expected1Before = _ghostNonces[actor1][nonceKey];
        assertEq(
            nonce.getNonce(actor1, nonceKey),
            expected1Before,
            "TEMPO-NON2: actor1 ghost mismatch before increment"
        );
        bytes32 slot1 = _getNonceSlot(actor1, nonceKey);
        assertEq(
            vm.load(_NONCE, slot1),
            bytes32(uint256(expected1Before)),
            "TEMPO-NON2: actor1 raw storage mismatch before increment"
        );

        // --- actor2 before: view + ghost + raw ---
        uint64 expected2Before = _ghostNonces[actor2][nonceKey];
        uint64 nonce2Before = nonce.getNonce(actor2, nonceKey);
        assertEq(nonce2Before, expected2Before, "TEMPO-NON5: actor2 ghost mismatch before increment");
        bytes32 slot2 = _getNonceSlot(actor2, nonceKey);
        bytes32 raw2Before = vm.load(_NONCE, slot2);
        assertEq(
            raw2Before,
            bytes32(uint256(expected2Before)),
            "TEMPO-NON5: actor2 raw storage mismatch before increment"
        );

        // Skip if actor1 is at max (overflow tested by testNonceOverflow)
        if (expected1Before == type(uint64).max) return;

        // Compute expected value independently of the storage helper
        uint64 expected1After = expected1Before + 1;

        // Increment actor1's nonce
        uint64 newNonce1 = _incrementNonceViaStorage(actor1, nonceKey);

        // TEMPO-NON1: Verify helper returned the independently computed value
        assertEq(newNonce1, expected1After, "TEMPO-NON1: actor1 increment returned wrong value");

        // Verify actor1 raw storage after increment (catches high-bit corruption)
        assertEq(
            vm.load(_NONCE, slot1),
            bytes32(uint256(expected1After)),
            "TEMPO-NON1: actor1 raw storage mismatch after increment"
        );

        // Update ghost state from independently computed value (not helper return)
        assertGe(
            expected1After,
            _lastSeenNonces[actor1][nonceKey],
            "TEMPO-NON1: actor1 lastSeen would decrease"
        );
        _ghostNonces[actor1][nonceKey] = expected1After;
        _lastSeenNonces[actor1][nonceKey] = expected1After;
        _trackNonceKey(actor1, nonceKey);

        // --- actor2 after: view + raw unchanged ---
        uint64 nonce2After = nonce.getNonce(actor2, nonceKey);
        assertEq(nonce2After, nonce2Before, "TEMPO-NON5: actor2 view changed after actor1 increment");
        assertEq(
            vm.load(_NONCE, slot2),
            raw2Before,
            "TEMPO-NON5: actor2 raw slot changed after actor1 increment"
        );

        // Track actor2's key so global invariant covers it going forward
        _trackNonceKey(actor2, nonceKey);

        _totalAccountIndependenceChecks++;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "ACCOUNT_INDEPENDENCE: ",
                    _getActorIndex(actor1),
                    " key=",
                    vm.toString(nonceKey),
                    " ",
                    vm.toString(expected1Before),
                    " -> ",
                    vm.toString(expected1After),
                    ", ",
                    _getActorIndex(actor2),
                    " unchanged at ",
                    vm.toString(nonce2After)
                )
            );
        }
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

        // --- key1 before: view + ghost + raw ---
        uint64 expected1Before = _ghostNonces[actor][key1];
        assertEq(
            nonce.getNonce(actor, key1),
            expected1Before,
            "TEMPO-NON2: key1 ghost mismatch before increment"
        );
        bytes32 slot1 = _getNonceSlot(actor, key1);
        assertEq(
            vm.load(_NONCE, slot1),
            bytes32(uint256(expected1Before)),
            "TEMPO-NON2: key1 raw storage mismatch before increment"
        );

        // --- key2 (witness) before: view + ghost + raw ---
        uint64 expected2Before = _ghostNonces[actor][key2];
        uint64 nonce2Before = nonce.getNonce(actor, key2);
        assertEq(nonce2Before, expected2Before, "TEMPO-NON6: key2 ghost mismatch before increment");
        bytes32 slot2 = _getNonceSlot(actor, key2);
        bytes32 raw2Before = vm.load(_NONCE, slot2);
        assertEq(
            raw2Before,
            bytes32(uint256(expected2Before)),
            "TEMPO-NON6: key2 raw storage mismatch before increment"
        );

        // Skip if key1 is at max (overflow tested by testNonceOverflow)
        if (expected1Before == type(uint64).max) return;

        // Compute expected value independently of the storage helper
        uint64 expected1After = expected1Before + 1;

        // Increment key1's nonce
        uint64 newNonce1 = _incrementNonceViaStorage(actor, key1);

        // TEMPO-NON1: Verify helper returned the independently computed value
        assertEq(newNonce1, expected1After, "TEMPO-NON1: key1 increment returned wrong value");

        // Verify key1 raw storage after increment (catches high-bit corruption)
        assertEq(
            vm.load(_NONCE, slot1),
            bytes32(uint256(expected1After)),
            "TEMPO-NON1: key1 raw storage mismatch after increment"
        );

        // Update ghost state from independently computed value (not helper return)
        assertGe(
            expected1After,
            _lastSeenNonces[actor][key1],
            "TEMPO-NON1: key1 lastSeen would decrease"
        );
        _ghostNonces[actor][key1] = expected1After;
        _lastSeenNonces[actor][key1] = expected1After;
        _trackNonceKey(actor, key1);

        // --- key2 (witness) after: view + raw unchanged ---
        uint64 nonce2After = nonce.getNonce(actor, key2);
        assertEq(nonce2After, nonce2Before, "TEMPO-NON6: key2 view changed after key1 increment");
        assertEq(
            vm.load(_NONCE, slot2),
            raw2Before,
            "TEMPO-NON6: key2 raw slot changed after key1 increment"
        );

        // Track key2 so global invariant covers it going forward
        _trackNonceKey(actor, key2);

        _totalKeyIndependenceChecks++;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "KEY_INDEPENDENCE: ",
                    _getActorIndex(actor),
                    " key=",
                    vm.toString(key1),
                    " ",
                    vm.toString(expected1Before),
                    " -> ",
                    vm.toString(expected1After),
                    ", key=",
                    vm.toString(key2),
                    " unchanged at ",
                    vm.toString(nonce2After)
                )
            );
        }
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

        // Verify raw storage matches before increment (catches high-bit corruption
        // that getNonce's uint64 return would mask)
        bytes32 slot = _getNonceSlot(actor, largeKey);
        bytes32 rawBefore = vm.load(_NONCE, slot);
        assertEq(
            rawBefore,
            bytes32(uint256(expectedBefore)),
            "TEMPO-NON7: Raw storage mismatch before increment"
        );

        // Snapshot reserved key slot to verify it is untouched after increment
        bytes32 reservedSlot = _getNonceSlot(actor, type(uint256).max);
        bytes32 reservedBefore = vm.load(_NONCE, reservedSlot);

        // Snapshot a normal-range key slot to verify cross-range isolation
        uint256 normalKey = _selectNonceKey(keySeed ^ 0xBEEF);
        bytes32 normalSlot = _getNonceSlot(actor, normalKey);
        bytes32 normalBefore = vm.load(_NONCE, normalSlot);

        // Snapshot same large key on a different actor for cross-account isolation
        address otherActor = _selectActor(actorSeed ^ 0xDEAD);
        bytes32 otherActorSlot = _getNonceSlot(otherActor, largeKey);
        bytes32 otherActorBefore = vm.load(_NONCE, otherActorSlot);

        // Compute expected value independently of the storage helper
        uint64 expectedAfter = expectedBefore + 1;

        uint64 newNonce = _incrementNonceViaStorage(actor, largeKey);
        _totalIncrements++;
        _totalLargeKeyTests++;

        // TEMPO-NON7: Nonce should increment by exactly 1
        assertEq(newNonce, expectedAfter, "TEMPO-NON7: Large key nonce should increment by 1");

        // Verify raw storage after increment (catches high-bit corruption)
        bytes32 rawAfter = vm.load(_NONCE, slot);
        assertEq(
            rawAfter,
            bytes32(uint256(expectedAfter)),
            "TEMPO-NON7: Raw storage mismatch after increment"
        );

        // Verify reserved key slot was not modified
        assertEq(
            vm.load(_NONCE, reservedSlot),
            reservedBefore,
            "TEMPO-NON7: Increment wrote to reserved key (MAX) slot"
        );

        // Verify normal-range key slot was not modified
        assertEq(
            vm.load(_NONCE, normalSlot),
            normalBefore,
            "TEMPO-NON7: Increment wrote to normal-range key slot"
        );

        // Verify same large key on different actor was not modified
        assertEq(
            vm.load(_NONCE, otherActorSlot),
            otherActorBefore,
            "TEMPO-NON7: Increment wrote to other actor's slot"
        );

        // Update ghost state from independently computed expected value (not helper return)
        _ghostNonces[actor][largeKey] = expectedAfter;
        _lastSeenNonces[actor][largeKey] = expectedAfter;

        // Track nonce key usage
        _trackNonceKey(actor, largeKey);

        // TEMPO-NON7: New value should be readable via getNonce
        uint64 actualAfter = nonce.getNonce(actor, largeKey);
        assertEq(
            actualAfter, expectedAfter, "TEMPO-NON7: Large key stored nonce should match expected"
        );

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "LARGE_KEY: ",
                    _getActorIndex(actor),
                    " key=",
                    vm.toString(largeKey),
                    " ",
                    vm.toString(expectedBefore),
                    " -> ",
                    vm.toString(expectedAfter)
                )
            );
        }
    }

    /// @notice Handler for multiple sequential increments
    /// @dev Tests TEMPO-NON8 (strict monotonicity over many increments)
    ///      Mirrors handler_incrementNonce rigor: ghost consistency, raw storage,
    ///      key/account isolation, and independently computed expected values.
    ///      Event emission (NonceIncremented) is not verifiable here because this
    ///      suite uses vm.store; event checks are covered by TempoTransactionInvariant.t.sol.
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

        // --- Pre-loop: verify ghost consistency and snapshot isolation targets ---

        uint64 expectedBefore = _ghostNonces[actor][nonceKey];
        uint64 actualBefore = nonce.getNonce(actor, nonceKey);

        // TEMPO-NON2: Ghost must match actual before we begin
        assertEq(
            actualBefore, expectedBefore, "TEMPO-NON2: Ghost nonce mismatch before multi-increment"
        );

        // Raw storage check (catches high-bit corruption that uint64 return would mask)
        bytes32 slot = _getNonceSlot(actor, nonceKey);
        bytes32 rawBefore = vm.load(_NONCE, slot);
        assertEq(
            rawBefore,
            bytes32(uint256(expectedBefore)),
            "TEMPO-NON2: Raw storage mismatch before multi-increment"
        );

        // Snapshot adjacent key for isolation (TEMPO-NON6)
        uint256 otherKey = _selectNonceKeyExcluding(keySeed ^ 0xBEEF, nonceKey);
        bytes32 otherSlot = _getNonceSlot(actor, otherKey);
        bytes32 otherKeyBefore = vm.load(_NONCE, otherSlot);

        // Snapshot other actor same key for account isolation (TEMPO-NON5)
        address otherActor = _selectActorExcluding(actorSeed ^ 0xDEAD, actor);
        bytes32 otherActorSlot = _getNonceSlot(otherActor, nonceKey);
        bytes32 otherActorBefore = vm.load(_NONCE, otherActorSlot);

        // Clamp count to avoid overflow in the helper (and in test arithmetic)
        uint256 maxSteps = uint256(type(uint64).max) - uint256(expectedBefore);
        if (count > maxSteps) {
            count = maxSteps;
        }
        if (count == 0) return;

        // Track key before loop so it's recorded even on early return paths
        _trackNonceKey(actor, nonceKey);

        // --- Loop: per-iteration assertions with independently computed expected values ---

        uint64 expected = expectedBefore;

        for (uint256 i = 0; i < count; i++) {
            uint64 expectedAfter = expected + 1;

            uint64 newNonce = _incrementNonceViaStorage(actor, nonceKey);

            // TEMPO-NON8: Helper return must match independently computed expected
            assertEq(
                newNonce,
                expectedAfter,
                "TEMPO-NON8: Each increment should be exactly +1"
            );

            // TEMPO-NON3: Read-back via getNonce must agree
            assertEq(
                nonce.getNonce(actor, nonceKey),
                expectedAfter,
                "TEMPO-NON3: getNonce mismatch after increment in multi-increment"
            );

            // Raw storage must match (catches high-bit corruption)
            assertEq(
                vm.load(_NONCE, slot),
                bytes32(uint256(expectedAfter)),
                "TEMPO-NON8: Raw storage mismatch after increment in multi-increment"
            );

            // Update ghost from independently computed value (not helper return)
            _ghostNonces[actor][nonceKey] = expectedAfter;
            _lastSeenNonces[actor][nonceKey] = expectedAfter;

            expected = expectedAfter;
        }

        // --- Post-loop: final consistency and isolation checks ---

        uint64 endNonce = nonce.getNonce(actor, nonceKey);
        assertEq(
            endNonce,
            expectedBefore + uint64(count),
            "TEMPO-NON8: Total increment should match count"
        );

        // TEMPO-NON6: Adjacent key must be untouched
        assertEq(
            vm.load(_NONCE, otherSlot),
            otherKeyBefore,
            "TEMPO-NON6: Multi-increment wrote to adjacent key slot"
        );

        // TEMPO-NON5: Other actor same key must be untouched
        assertEq(
            vm.load(_NONCE, otherActorSlot),
            otherActorBefore,
            "TEMPO-NON5: Multi-increment wrote to other actor's slot"
        );

        _totalMultipleIncrements++;
        _totalIncrements += count;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "MULTI_INCREMENT: ",
                    _getActorIndex(actor),
                    " key=",
                    vm.toString(nonceKey),
                    " count=",
                    vm.toString(count),
                    " ",
                    vm.toString(uint256(expectedBefore)),
                    " -> ",
                    vm.toString(uint256(endNonce))
                )
            );
        }
    }

    /// @notice Handler for testing nonce overflow at u64::MAX
    /// @dev Tests TEMPO-NON9 (nonce overflow protection)
    /// Uses a small bounded key range to avoid conflicts and prevent unbounded key growth:
    /// - Normal handlers use keys (1 to MAX_NORMAL_NONCE_KEY)
    /// - testLargeNonceKey uses extreme uint256 values
    /// - Reserved TEMPO_EXPIRING_NONCE_KEY uses type(uint256).max
    /// - This handler uses keys (MAX_NORMAL_NONCE_KEY + 1 to MAX_NORMAL_NONCE_KEY + 100)
    ///
    /// Tests the boundary in two steps:
    /// 1. Set nonce to max-1, increment once (should succeed, reaching max)
    /// 2. Attempt to increment again at max (should revert with NonceOverflow)
    /// Verifies raw storage immutability on revert, adjacent key isolation, and ghost consistency.
    function handler_nonceOverflow(uint256 actorSeed, uint256 keySeed) external {
        address actor = _selectActor(actorSeed);
        // Use a small bounded range to prevent unbounded _accountNonceKeys growth
        uint256 nonceKey = bound(keySeed, MAX_NORMAL_NONCE_KEY + 1, MAX_NORMAL_NONCE_KEY + 100);

        bytes32 slot = _getNonceSlot(actor, nonceKey);

        // Snapshot an adjacent key's slot to verify isolation after overflow attempt
        uint256 otherKey = _selectNonceKeyExcluding(keySeed ^ 0xBEEF, nonceKey);
        bytes32 otherSlot = _getNonceSlot(actor, otherKey);
        bytes32 otherBefore = vm.load(_NONCE, otherSlot);

        // Snapshot another actor's same key slot to verify cross-actor isolation
        address otherActor = _selectActorExcluding(actorSeed ^ 0xDEAD, actor);
        bytes32 otherActorSlot = _getNonceSlot(otherActor, nonceKey);
        bytes32 otherActorBefore = vm.load(_NONCE, otherActorSlot);

        // --- Step 1: Boundary test at max-1 (should succeed) ---

        // Set nonce to max-1 via direct storage manipulation
        vm.store(_NONCE, slot, bytes32(uint256(type(uint64).max - 1)));

        // Verify raw storage is canonical (no high-bit corruption from vm.store)
        assertEq(
            vm.load(_NONCE, slot),
            bytes32(uint256(type(uint64).max - 1)),
            "TEMPO-NON9: Raw storage should be canonical after vm.store"
        );

        // Verify getNonce reads the expected value
        assertEq(
            nonce.getNonce(actor, nonceKey),
            type(uint64).max - 1,
            "TEMPO-NON9: getNonce should return max-1"
        );

        // Increment from max-1: should succeed and reach max
        uint64 newNonce = _incrementNonceViaStorage(actor, nonceKey);
        assertEq(newNonce, type(uint64).max, "TEMPO-NON9: Increment from max-1 should reach max");

        // Verify raw storage after successful increment
        assertEq(
            vm.load(_NONCE, slot),
            bytes32(uint256(type(uint64).max)),
            "TEMPO-NON9: Raw storage should be max after increment from max-1"
        );

        // Verify getNonce after successful increment
        assertEq(
            nonce.getNonce(actor, nonceKey),
            type(uint64).max,
            "TEMPO-NON9: getNonce should return max after increment from max-1"
        );

        // Update ghost state to reflect the successful increment
        _ghostNonces[actor][nonceKey] = type(uint64).max;
        _lastSeenNonces[actor][nonceKey] = type(uint64).max;
        _trackNonceKey(actor, nonceKey);

        // --- Step 2: Overflow test at max (should revert) ---

        // Snapshot raw storage before the overflow attempt
        bytes32 rawBeforeOverflow = vm.load(_NONCE, slot);

        // TEMPO-NON9: Attempting to increment at max should revert with NonceOverflow
        vm.expectRevert(INonce.NonceOverflow.selector);
        this.externalIncrementNonceViaStorage(actor, nonceKey);

        // Verify raw storage was NOT modified by the reverted call
        assertEq(
            vm.load(_NONCE, slot),
            rawBeforeOverflow,
            "TEMPO-NON9: Raw storage must not change on overflow revert"
        );

        // Verify getNonce still returns max after the reverted overflow attempt
        assertEq(
            nonce.getNonce(actor, nonceKey),
            type(uint64).max,
            "TEMPO-NON9: getNonce must still return max after overflow revert"
        );

        // Verify ghost state is still consistent
        assertEq(
            _ghostNonces[actor][nonceKey],
            type(uint64).max,
            "TEMPO-NON9: Ghost state must remain max after overflow revert"
        );
        assertEq(
            _lastSeenNonces[actor][nonceKey],
            type(uint64).max,
            "TEMPO-NON9: Last seen must remain max after overflow revert"
        );

        // Verify adjacent key slot was not modified by the overflow attempt
        assertEq(
            vm.load(_NONCE, otherSlot),
            otherBefore,
            "TEMPO-NON6: Overflow attempt wrote to adjacent key slot"
        );

        // Verify other actor's same key slot was not modified
        assertEq(
            vm.load(_NONCE, otherActorSlot),
            otherActorBefore,
            "TEMPO-NON5: Overflow attempt wrote to other actor's slot"
        );

        _totalOverflowTests++;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "NONCE_OVERFLOW: ",
                    _getActorIndex(actor),
                    " key=",
                    vm.toString(nonceKey),
                    " max-1 -> max succeeded, max -> max+1 correctly reverted"
                )
            );
        }
    }

    /// @notice Handler for testing invalid nonce key (key 0) increment rejection
    /// @dev Tests TEMPO-NON10 (InvalidNonceKey for key 0 increment)
    /// Note: Rust distinguishes between:
    /// - get_nonce(key=0) -> ProtocolNonceNotSupported
    /// - increment_nonce(key=0) -> InvalidNonceKey
    function handler_invalidNonceKeyIncrement(
        uint256 accountSeed,
        uint256 otherKeySeed,
        uint256 otherActorSeed
    )
        external
    {
        // Broaden the account domain beyond _actors to verify key-0 rejection
        // is account-independent. Use accountSeed to occasionally inject edge-case addresses.
        address account;
        uint256 branch = accountSeed % 8;
        if (branch == 0) {
            account = address(0);
        } else if (branch == 1) {
            account = address(this);
        } else if (branch == 2) {
            account = _NONCE;
        } else {
            account = _selectActor(accountSeed);
        }

        uint256 otherKey = _selectNonceKey(otherKeySeed);

        // --- Snapshot storage before the rejected increment ---

        // Key-0 slot itself (should never be written)
        bytes32 slot0 = _getNonceSlot(account, 0);
        bytes32 snap0 = vm.load(_NONCE, slot0);

        // Adjacent key slot
        bytes32 otherSlot = _getNonceSlot(account, otherKey);
        bytes32 snapOther = vm.load(_NONCE, otherSlot);

        // Cross-account slot (if account is from _actors, pick a different actor)
        address otherActor;
        if (branch >= 3) {
            otherActor = _selectActorExcluding(otherActorSeed, account);
        } else {
            otherActor = _selectActor(otherActorSeed);
        }
        bytes32 crossSlot = _getNonceSlot(otherActor, otherKey);
        bytes32 snapCross = vm.load(_NONCE, crossSlot);

        // Snapshot ghost state for the adjacent key (should not change)
        uint64 ghostOtherBefore = _ghostNonces[account][otherKey];

        // Snapshot the increment counter (should not change)
        uint256 incrementsBefore = _totalIncrements;

        // --- TEMPO-NON10: Increment with key 0 should revert with InvalidNonceKey ---

        bytes memory expectedRevert = abi.encodeWithSelector(INonce.InvalidNonceKey.selector);

        try this.externalIncrementNonceViaStorage(account, 0) {
            revert("TEMPO-NON10: Increment with key 0 should revert");
        } catch (bytes memory reason) {
            // Assert exact revert payload (4 bytes, exact match)
            assertEq(reason.length, 4, "TEMPO-NON10: Revert data should be exactly 4 bytes");
            assertEq(reason, expectedRevert, "TEMPO-NON10: Should revert with InvalidNonceKey");
        }

        // --- Assert statelessness: a second call should revert identically ---

        try this.externalIncrementNonceViaStorage(account, 0) {
            revert("TEMPO-NON10: Repeat increment with key 0 should revert");
        } catch (bytes memory reason2) {
            assertEq(
                reason2, expectedRevert, "TEMPO-NON10: Repeat call should revert identically"
            );
        }

        // --- Assert no side effects on storage ---

        // Key-0 slot unchanged
        assertEq(
            vm.load(_NONCE, slot0), snap0, "TEMPO-NON10: Key-0 slot modified by rejected increment"
        );

        // Adjacent key slot unchanged
        assertEq(
            vm.load(_NONCE, otherSlot),
            snapOther,
            "TEMPO-NON10: Adjacent key slot modified by rejected increment"
        );

        // Cross-account slot unchanged
        assertEq(
            vm.load(_NONCE, crossSlot),
            snapCross,
            "TEMPO-NON10: Cross-account slot modified by rejected increment"
        );

        // --- Assert no side effects on ghost state ---

        assertEq(
            _ghostNonces[account][otherKey],
            ghostOtherBefore,
            "TEMPO-NON10: Ghost state modified by rejected increment"
        );

        // Increment counter should not have changed
        assertEq(
            _totalIncrements,
            incrementsBefore,
            "TEMPO-NON10: Increment counter modified by rejected increment"
        );

        _totalInvalidKeyRejections++;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "INVALID_KEY_INCREMENT: account=",
                    vm.toString(account),
                    " key=0 correctly reverted"
                )
            );
        }
    }

    /// @notice Handler for testing reserved TEMPO_EXPIRING_NONCE_KEY behavior
    /// @dev Tests TEMPO-NON11 (reserved key type(uint256).max):
    ///      - Readable via getNonce (returns value from 2D nonce mapping)
    ///      - Reads are idempotent (no side effects)
    ///      - Reading does not touch expiring nonce storage (slots 1-3)
    ///      - Reading does not touch adjacent keys or other accounts
    ///      - Raw storage consistency (no dirty high bits)
    ///      - Ghost state consistency
    /// @dev Expiring nonces use tx-hash-based replay protection in separate storage
    ///      (expiringNonceSeen, expiringNonceRing, expiringNonceRingPtr). The 2D nonce
    ///      slot at nonces[account][uint256.max] is independent of that mechanism.
    function handler_testReservedExpiringNonceKey(
        uint256 actorSeed,
        uint256 normalKeySeed,
        uint256 otherActorSeed
    )
        external
    {
        // --- Select account: broaden domain beyond _actors ---
        address account;
        uint256 branch = actorSeed % 8;
        if (branch == 0) {
            account = address(0);
        } else if (branch == 1) {
            account = address(this);
        } else if (branch == 2) {
            account = _NONCE;
        } else {
            account = _selectActor(actorSeed);
        }

        uint256 reservedKey = type(uint256).max;

        // --- Snapshot reserved key: raw storage + ghost ---

        bytes32 reservedSlot = _getNonceSlot(account, reservedKey);
        bytes32 rawBefore = vm.load(_NONCE, reservedSlot);
        uint64 ghostBefore = _ghostNonces[account][reservedKey];

        // TEMPO-NON2: Raw storage must match ghost before read
        assertEq(
            rawBefore,
            bytes32(uint256(ghostBefore)),
            "TEMPO-NON11: Raw storage mismatch vs ghost before read"
        );

        // --- Snapshot adjacent/cross-account slots for isolation ---

        uint256 normalKey = _selectNonceKey(normalKeySeed);
        bytes32 normalSlot = _getNonceSlot(account, normalKey);
        bytes32 normalBefore = vm.load(_NONCE, normalSlot);

        // Adjacent large key (uint256.max - 1) for near-neighbor isolation
        bytes32 adjacentLargeSlot = _getNonceSlot(account, type(uint256).max - 1);
        bytes32 adjacentLargeBefore = vm.load(_NONCE, adjacentLargeSlot);

        // Cross-account: same reserved key on a different account
        address otherAccount;
        if (branch >= 3) {
            otherAccount = _selectActorExcluding(otherActorSeed, account);
        } else {
            otherAccount = _selectActor(otherActorSeed);
        }
        bytes32 crossSlot = _getNonceSlot(otherAccount, reservedKey);
        bytes32 crossBefore = vm.load(_NONCE, crossSlot);

        // --- Snapshot expiring nonce storage (slots 1-3) ---
        // These should never be touched by a getNonce read.

        // Slot 3: expiringNonceRingPtr (scalar at slot 3)
        bytes32 ptrSlot = bytes32(uint256(3));
        bytes32 ptrBefore = vm.load(_NONCE, ptrSlot);

        // Slot 1 sample: expiringNonceSeen[hash] for a deterministic hash
        bytes32 sampleTxHash = keccak256(abi.encodePacked(actorSeed, account));
        bytes32 seenSlot = keccak256(abi.encode(sampleTxHash, uint256(1)));
        bytes32 seenBefore = vm.load(_NONCE, seenSlot);

        // Slot 2 sample: expiringNonceRing[idx] for a deterministic index
        uint32 sampleIdx = uint32(actorSeed % 300_000);
        bytes32 ringSlot = keccak256(abi.encode(uint256(sampleIdx), uint256(2)));
        bytes32 ringBefore = vm.load(_NONCE, ringSlot);

        // --- Read reserved key twice (idempotency) ---

        uint64 v1 = nonce.getNonce(account, reservedKey);
        uint64 v2 = nonce.getNonce(account, reservedKey);

        // TEMPO-NON11: Reads must be idempotent
        assertEq(v1, v2, "TEMPO-NON11: Read should be idempotent");

        // TEMPO-NON11: Returned value must match raw storage
        assertEq(v1, uint64(uint256(rawBefore)), "TEMPO-NON11: Return value vs raw storage mismatch");

        // TEMPO-NON11: Raw storage should have no dirty high bits
        assertEq(
            rawBefore,
            bytes32(uint256(v1)),
            "TEMPO-NON11: Raw storage has dirty high bits"
        );

        // TEMPO-NON2: Returned value must match ghost state
        assertEq(v1, ghostBefore, "TEMPO-NON11: Return value vs ghost state mismatch");

        // Uninitialized-key check: if ghost is zero, value must be zero
        if (!_nonceKeyUsed[account][reservedKey]) {
            assertEq(v1, 0, "TEMPO-NON11: Uninitialized reserved key should be zero");
        }

        // --- Assert no side effects on 2D nonce storage ---

        // Reserved slot itself unchanged
        assertEq(
            vm.load(_NONCE, reservedSlot),
            rawBefore,
            "TEMPO-NON11: Read mutated reserved key slot"
        );

        // Normal key slot unchanged
        assertEq(
            vm.load(_NONCE, normalSlot),
            normalBefore,
            "TEMPO-NON11: Read mutated normal key slot"
        );

        // Adjacent large key slot unchanged
        assertEq(
            vm.load(_NONCE, adjacentLargeSlot),
            adjacentLargeBefore,
            "TEMPO-NON11: Read mutated adjacent large key slot"
        );

        // Cross-account reserved key slot unchanged
        assertEq(
            vm.load(_NONCE, crossSlot),
            crossBefore,
            "TEMPO-NON11: Read mutated cross-account reserved key slot"
        );

        // --- Assert no side effects on expiring nonce storage (slots 1-3) ---

        assertEq(
            vm.load(_NONCE, ptrSlot),
            ptrBefore,
            "TEMPO-NON11: Read mutated expiringNonceRingPtr (slot 3)"
        );

        assertEq(
            vm.load(_NONCE, seenSlot),
            seenBefore,
            "TEMPO-NON11: Read mutated expiringNonceSeen sample (slot 1)"
        );

        assertEq(
            vm.load(_NONCE, ringSlot),
            ringBefore,
            "TEMPO-NON11: Read mutated expiringNonceRing sample (slot 2)"
        );

        _totalReservedKeyTests++;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "RESERVED_EXPIRING_KEY: account=",
                    vm.toString(account),
                    " key=MAX_UINT256 readable, value=",
                    vm.toString(v1)
                )
            );
        }
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

    /*//////////////////////////////////////////////////////////////
                          AFTER INVARIANT
    //////////////////////////////////////////////////////////////*/

    /// @notice Logs final state summary after invariant run
    function afterInvariant() public {
        if (!_loggingEnabled) return;

        _log("");
        _log("--------------------------------------------------------------------------------");
        _log("                              Final State Summary");
        _log("--------------------------------------------------------------------------------");
        _log(string.concat("Total increments: ", vm.toString(_totalIncrements)));
        _log(string.concat("Total reads: ", vm.toString(_totalReads)));
        _log(
            string.concat(
                "Protocol nonce rejections (NON4): ", vm.toString(_totalProtocolNonceRejections)
            )
        );
        _log(
            string.concat(
                "Account independence checks (NON5): ", vm.toString(_totalAccountIndependenceChecks)
            )
        );
        _log(
            string.concat(
                "Key independence checks (NON6): ", vm.toString(_totalKeyIndependenceChecks)
            )
        );
        _log(string.concat("Large key tests (NON7): ", vm.toString(_totalLargeKeyTests)));
        _log(
            string.concat(
                "Multiple increment operations (NON8): ", vm.toString(_totalMultipleIncrements)
            )
        );
        _log(string.concat("Overflow tests (NON9): ", vm.toString(_totalOverflowTests)));
        _log(
            string.concat(
                "Invalid key rejections (NON10): ", vm.toString(_totalInvalidKeyRejections)
            )
        );
        _log(string.concat("Reserved key tests (NON11): ", vm.toString(_totalReservedKeyTests)));
        _log("--------------------------------------------------------------------------------");

        // Count total unique nonce keys tracked
        uint256 totalTrackedKeys = 0;
        for (uint256 a = 0; a < _actors.length; a++) {
            totalTrackedKeys += _accountNonceKeys[_actors[a]].length;
        }
        _log(string.concat("Total tracked nonce keys: ", vm.toString(totalTrackedKeys)));
        _log("--------------------------------------------------------------------------------");
    }

}
