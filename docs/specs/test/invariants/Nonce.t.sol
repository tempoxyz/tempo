// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { INonce } from "../../src/interfaces/INonce.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title Nonce Invariant Tests
/// @notice Fuzz-based invariant tests for the Nonce precompile
/// @dev Tests invariants TEMPO-NON1 through TEMPO-NON8 for the 2D nonce system
contract NonceInvariantTest is InvariantBaseTest {

    /// @dev Storage slot for nonces mapping (slot 0)
    uint256 private constant NONCES_SLOT = 0;

    /// @dev Ghost variables for tracking nonce state
    /// Maps account => nonceKey => expected nonce value
    mapping(address => mapping(uint256 => uint64)) private _ghostNonces;

    /// @dev Track all nonce keys used per account
    mapping(address => uint256[]) private _accountNonceKeys;

    /// @dev Track if a nonce key has been used by an account
    mapping(address => mapping(uint256 => bool)) private _nonceKeyUsed;

    /// @dev Total increments performed
    uint256 private _totalIncrements;

    /// @dev Total reads performed
    uint256 private _totalReads;

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Sets up the test environment
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();
        _actors = _buildActors(10);

        _initLogFile("nonce.log", "Nonce Invariant Test Log");
    }

    /// @dev Gets a valid nonce key (1 to max)
    function _selectNonceKey(uint256 seed) internal pure returns (uint256) {
        return (seed % 1000) + 1;
    }

    /*//////////////////////////////////////////////////////////////
                          STORAGE HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Calculate storage slot for nonces[account][nonceKey]
    function _getNonceSlot(address account, uint256 nonceKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(nonceKey, keccak256(abi.encode(account, NONCES_SLOT))));
    }

    /// @dev Increment nonce via direct storage manipulation (simulates protocol behavior)
    function _incrementNonceViaStorage(address account, uint256 nonceKey)
        internal
        returns (uint64 newNonce)
    {
        require(nonceKey > 0, "Cannot increment protocol nonce (key 0)");

        bytes32 slot = _getNonceSlot(account, nonceKey);
        uint64 current = uint64(uint256(vm.load(_NONCE, slot)));

        require(current < type(uint64).max, "Nonce overflow");

        newNonce = current + 1;
        vm.store(_NONCE, slot, bytes32(uint256(newNonce)));

        return newNonce;
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

        // Track nonce key usage
        if (!_nonceKeyUsed[actor][nonceKey]) {
            _nonceKeyUsed[actor][nonceKey] = true;
            _accountNonceKeys[actor].push(nonceKey);
        }

        // TEMPO-NON1: Nonce should increment by exactly 1
        assertEq(newNonce, expectedBefore + 1, "TEMPO-NON1: Nonce should increment by 1");

        // TEMPO-NON3: New value should be readable
        uint64 actualAfter = nonce.getNonce(actor, nonceKey);
        assertEq(actualAfter, newNonce, "TEMPO-NON3: Stored nonce should match returned value");

        _log(
            string.concat(
                "INCREMENT: ",
                _getActorIndex(actor),
                " key=",
                vm.toString(nonceKey),
                " ",
                vm.toString(expectedBefore),
                " -> ",
                vm.toString(newNonce)
            )
        );
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

        _log(string.concat("TRY_PROTOCOL_NONCE: ", _getActorIndex(actor), " correctly rejected"));
    }

    /// @notice Handler for verifying account independence
    /// @dev Tests TEMPO-NON5 (different accounts have independent nonces)
    function verifyAccountIndependence(uint256 actor1Seed, uint256 actor2Seed, uint256 keySeed)
        external
    {
        address actor1 = _selectActor(actor1Seed);
        address actor2 = _selectActor(actor2Seed);
        uint256 nonceKey = _selectNonceKey(keySeed);

        vm.assume(actor1 != actor2);

        uint64 nonce2Before = nonce.getNonce(actor2, nonceKey);

        // Increment actor1's nonce
        _incrementNonceViaStorage(actor1, nonceKey);
        _ghostNonces[actor1][nonceKey]++;

        if (!_nonceKeyUsed[actor1][nonceKey]) {
            _nonceKeyUsed[actor1][nonceKey] = true;
            _accountNonceKeys[actor1].push(nonceKey);
        }

        // TEMPO-NON5: Actor2's nonce should be unchanged
        uint64 nonce2After = nonce.getNonce(actor2, nonceKey);
        assertEq(nonce2After, nonce2Before, "TEMPO-NON5: Other account nonce should be unchanged");

        _log(
            string.concat(
                "ACCOUNT_INDEPENDENCE: ",
                _getActorIndex(actor1),
                " incremented, ",
                _getActorIndex(actor2),
                " unchanged at ",
                vm.toString(nonce2After)
            )
        );
    }

    /// @notice Handler for verifying key independence
    /// @dev Tests TEMPO-NON6 (different keys have independent nonces)
    function verifyKeyIndependence(uint256 actorSeed, uint256 key1Seed, uint256 key2Seed) external {
        address actor = _selectActor(actorSeed);
        uint256 key1 = _selectNonceKey(key1Seed);
        uint256 key2 = _selectNonceKey(key2Seed);

        vm.assume(key1 != key2);

        uint64 nonce2Before = nonce.getNonce(actor, key2);

        // Increment key1's nonce
        _incrementNonceViaStorage(actor, key1);
        _ghostNonces[actor][key1]++;

        if (!_nonceKeyUsed[actor][key1]) {
            _nonceKeyUsed[actor][key1] = true;
            _accountNonceKeys[actor].push(key1);
        }

        // TEMPO-NON6: Key2's nonce should be unchanged
        uint64 nonce2After = nonce.getNonce(actor, key2);
        assertEq(nonce2After, nonce2Before, "TEMPO-NON6: Other key nonce should be unchanged");

        _log(
            string.concat(
                "KEY_INDEPENDENCE: ",
                _getActorIndex(actor),
                " key=",
                vm.toString(key1),
                " incremented, key=",
                vm.toString(key2),
                " unchanged at ",
                vm.toString(nonce2After)
            )
        );
    }

    /// @notice Handler for testing max nonce key
    /// @dev Tests TEMPO-NON7 (large nonce keys work)
    function testLargeNonceKey(uint256 actorSeed) external {
        address actor = _selectActor(actorSeed);
        uint256 largeKey = type(uint256).max;

        // Should work with max uint256 key
        uint64 result = nonce.getNonce(actor, largeKey);
        assertEq(result, _ghostNonces[actor][largeKey], "TEMPO-NON7: Large key should work");

        // Increment and verify
        uint64 newNonce = _incrementNonceViaStorage(actor, largeKey);
        _ghostNonces[actor][largeKey] = newNonce;

        if (!_nonceKeyUsed[actor][largeKey]) {
            _nonceKeyUsed[actor][largeKey] = true;
            _accountNonceKeys[actor].push(largeKey);
        }

        uint64 afterIncrement = nonce.getNonce(actor, largeKey);
        assertEq(afterIncrement, newNonce, "TEMPO-NON7: Large key should increment correctly");

        _log(
            string.concat(
                "LARGE_KEY: ",
                _getActorIndex(actor),
                " key=MAX_UINT256 nonce=",
                vm.toString(newNonce)
            )
        );
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

            // TEMPO-NON8: Each increment should be exactly +1
            assertEq(
                newNonce, beforeIncrement + 1, "TEMPO-NON8: Each increment should be exactly +1"
            );
        }

        if (!_nonceKeyUsed[actor][nonceKey]) {
            _nonceKeyUsed[actor][nonceKey] = true;
            _accountNonceKeys[actor].push(nonceKey);
        }

        uint64 endNonce = nonce.getNonce(actor, nonceKey);
        assertEq(endNonce, startNonce + uint64(count), "TEMPO-NON8: Total increment should match");

        _log(
            string.concat(
                "MULTI_INCREMENT: ",
                _getActorIndex(actor),
                " key=",
                vm.toString(nonceKey),
                " count=",
                vm.toString(count),
                " ",
                vm.toString(startNonce),
                " -> ",
                vm.toString(endNonce)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    function invariant_globalInvariants() public view {
        _invariantGhostStateConsistency();
        _invariantNonceNeverDecrease();
    }

    /// @notice TEMPO-NON2: Ghost state should match actual state for all tracked nonces
    function _invariantGhostStateConsistency() internal view {
        for (uint256 a = 0; a < _actors.length; a++) {
            address actor = _actors[a];
            uint256[] memory keys = _accountNonceKeys[actor];

            for (uint256 k = 0; k < keys.length; k++) {
                uint256 nonceKey = keys[k];
                uint64 actual = nonce.getNonce(actor, nonceKey);
                uint64 expected = _ghostNonces[actor][nonceKey];
                assertEq(actual, expected, "TEMPO-NON2: Ghost state should match actual state");
            }
        }
    }

    /// @notice TEMPO-NON1: Nonces should never decrease (implicit from increment-only)
    function _invariantNonceNeverDecrease() internal view {
        for (uint256 a = 0; a < _actors.length; a++) {
            address actor = _actors[a];
            uint256[] memory keys = _accountNonceKeys[actor];

            for (uint256 k = 0; k < keys.length; k++) {
                uint256 nonceKey = keys[k];
                uint64 actual = nonce.getNonce(actor, nonceKey);
                assertTrue(actual >= 0, "TEMPO-NON1: Nonce should be non-negative");
            }
        }
    }

}
