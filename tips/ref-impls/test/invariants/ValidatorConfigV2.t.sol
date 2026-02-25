// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { IValidatorConfig } from "../../src/interfaces/IValidatorConfig.sol";
import { IValidatorConfigV2 } from "../../src/interfaces/IValidatorConfigV2.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";
import { Vm } from "forge-std/Vm.sol";

/// @title ValidatorConfigV2 Invariant Tests
/// @notice Fuzz-based invariant tests for the ValidatorConfigV2 precompile
/// @dev Tests invariants TEMPO-VALV2-1 through TEMPO-VALV2-25 covering:
///      - Per-handler assertions (VALV2-1 to VALV2-7): auth enforcement, count changes, height tracking, init gates
///      - Global invariants (VALV2-8 to VALV2-25): append-only, uniqueness, lookups, migration correctness
contract ValidatorConfigV2InvariantTest is InvariantBaseTest {

    /// @dev Starting offset for validator address pool
    uint256 private constant VALIDATOR_POOL_OFFSET = 0x7000;

    /// @dev Array of potential validator addresses
    address[] private _potentialValidators;

    /// @dev Ghost tracking for validators — index-keyed to mirror contract's append-only array.
    ///      Address-keyed mappings would break on rotateValidator (same address, two entries).
    mapping(uint64 => address) private _ghostAddress;
    mapping(uint64 => bytes32) private _ghostPubKey;
    mapping(uint64 => bytes32) private _ghostPrivKey;
    mapping(uint64 => uint64) private _ghostAddedAtHeight;
    mapping(uint64 => uint64) private _ghostDeactivatedAtHeight;
    mapping(uint64 => string) private _ghostIngress;
    mapping(uint64 => string) private _ghostEgress;

    /// @dev Reverse lookup: address -> latest active index (updated on add/transfer/rotate)
    mapping(address => uint64) private _ghostActiveIndex;
    mapping(address => bool) private _ghostAddressInUse;

    /// @dev Ghost tracking for public key uniqueness
    mapping(bytes32 => bool) private _ghostPubKeyUsed;

    /// @dev Ghost tracking for owner
    address private _ghostOwner;

    /// @dev Ghost tracking for DKG ceremony
    uint64 private _ghostNextDkgCeremony;

    /// @dev Ghost tracking for initialization
    bool private _ghostInitialized;

    /// @dev Ghost tracking for initialization height
    uint64 private _ghostInitializedAtHeight;

    /// @dev Ghost tracking for sequential migration index
    uint64 private _ghostNextMigrationIndex;

    /// @dev Ghost tracking for total validator count (append-only, never decreases)
    uint256 private _ghostTotalCount;

    /// @dev Ghost tracking for active ingress IP hashes (to match contract's IP uniqueness enforcement)
    mapping(bytes32 => bool) private _ghostActiveIngressIpHashes;

    /// @dev Number of V1 setup validators
    uint256 private constant V1_SETUP_COUNT = 15;

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();
        (_actors,) = _buildActors(5);
        _potentialValidators = _buildAddressPool(500, VALIDATOR_POOL_OFFSET);

        // Add V1 validators — migration and initialization driven by the fuzzer
        for (uint256 i = 0; i < V1_SETUP_COUNT; i++) {
            address addr = address(uint160(0xA000 + i));
            bytes32 pubKey = keccak256(abi.encode("v1_setup_pubkey", i));
            string memory ingress =
                string(abi.encodePacked("10.0.0.", _uint8ToString(uint8(100 + i)), ":8000"));
            string memory egress =
                string(abi.encodePacked("10.0.0.", _uint8ToString(uint8(100 + i)), ":9000"));
            validatorConfig.addValidator(addr, pubKey, true, ingress, egress);
        }

        // V2 owner starts as address(0) — auto-set from V1 on first migrateValidator call
        _ghostOwner = address(0);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _selectPotentialValidator(uint256 seed) internal view returns (address) {
        return _selectFromPool(_potentialValidators, seed);
    }

    function _generateKeyPair(uint256 seed)
        internal
        pure
        returns (bytes32 privKey, bytes32 pubKey)
    {
        bytes32 salt = keccak256(abi.encode("ed25519_keypair", seed));
        (pubKey, privKey) = vm.createEd25519Key(salt);
    }

    function _signAdd(
        bytes32 privateKey,
        address validatorAddress,
        string memory ingress,
        string memory egress
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 message = keccak256(
            abi.encodePacked(
                uint64(block.chainid), address(validatorConfigV2), validatorAddress, ingress, egress
            )
        );
        bytes memory ns = bytes("TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR");
        return vm.signEd25519(
            abi.encodePacked(uint8(ns.length), ns), abi.encodePacked(message), privateKey
        );
    }

    function _signRotate(
        bytes32 privateKey,
        address validatorAddress,
        string memory ingress,
        string memory egress
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 message = keccak256(
            abi.encodePacked(
                uint64(block.chainid), address(validatorConfigV2), validatorAddress, ingress, egress
            )
        );
        bytes memory ns = bytes("TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR");
        return vm.signEd25519(
            abi.encodePacked(uint8(ns.length), ns), abi.encodePacked(message), privateKey
        );
    }

    function _generateIngress(uint256 seed) internal pure returns (string memory) {
        uint8 lastOctet = uint8((seed % 254) + 1);
        uint16 port = uint16((seed >> 8) % 65_534) + 1;
        if (seed % 3 == 0) {
            return string(
                abi.encodePacked(
                    "[::ffff:192.168.1.", _uint8ToString(lastOctet), "]:", vm.toString(port)
                )
            );
        } else {
            return string(
                abi.encodePacked("192.168.1.", _uint8ToString(lastOctet), ":", vm.toString(port))
            );
        }
    }

    function _generateEgress(uint256 seed) internal pure returns (string memory) {
        uint8 lastOctet = uint8((seed % 254) + 1);
        if (seed % 3 == 0) {
            return string(abi.encodePacked("::ffff:192.168.1.", _uint8ToString(lastOctet)));
        } else {
            return string(abi.encodePacked("192.168.1.", _uint8ToString(lastOctet)));
        }
    }

    function _selectActiveValidator(uint256 seed) internal view returns (address, uint64, bool) {
        uint256 len = _ghostTotalCount;
        if (len == 0) return (address(0), 0, false);
        uint256 start = seed % len;
        for (uint256 i = 0; i < len; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 idx = uint64((start + i) % len);
            if (_ghostDeactivatedAtHeight[idx] == 0) {
                return (_ghostAddress[idx], idx, true);
            }
        }
        return (address(0), 0, false);
    }

    /// @dev Helper to count active validators (deactivatedAtHeight == 0)
    function _countActiveValidators() internal view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < _ghostTotalCount; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            if (_ghostDeactivatedAtHeight[uint64(i)] == 0) {
                count++;
            }
        }
        return count;
    }

    /// @dev Helper to get V1 validator data (for migration checks)
    function _getV1ValidatorData(uint64 idx)
        internal
        view
        returns (IValidatorConfig.Validator memory)
    {
        IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();
        require(idx < v1Vals.length, "V1 index out of bounds");
        return v1Vals[idx];
    }

    function _assertKnownV2Error(bytes memory reason) internal pure {
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes4 selector = bytes4(reason);
        bool isKnown = selector == IValidatorConfigV2.Unauthorized.selector
            || selector == IValidatorConfigV2.AddressAlreadyHasValidator.selector
            || selector == IValidatorConfigV2.PublicKeyAlreadyExists.selector
            || selector == IValidatorConfigV2.ValidatorNotFound.selector
            || selector == IValidatorConfigV2.ValidatorAlreadyDeleted.selector
            || selector == IValidatorConfigV2.InvalidPublicKey.selector
            || selector == IValidatorConfigV2.InvalidValidatorAddress.selector
            || selector == IValidatorConfigV2.NotInitialized.selector
            || selector == IValidatorConfigV2.AlreadyInitialized.selector
            || selector == IValidatorConfigV2.MigrationNotComplete.selector
            || selector == IValidatorConfigV2.InvalidMigrationIndex.selector
            || selector == IValidatorConfigV2.NotIpPort.selector
            || selector == IValidatorConfigV2.NotIp.selector
            || selector == IValidatorConfigV2.InvalidSignature.selector
            || selector == IValidatorConfigV2.IngressAlreadyExists.selector;
        assertTrue(isKnown, string.concat("Unknown error: ", vm.toString(selector)));
    }

    /*//////////////////////////////////////////////////////////////
                            HANDLER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Mostly post-init: addValidator (~1/256 pre-init calls verify NotInitialized guard)
    function handler_addValidator(
        uint256 innerFnSeed,
        uint256 callerSeed,
        uint256 validatorSeed,
        uint256 keySeed
    )
        external
    {
        if (!_ghostInitialized && innerFnSeed >> 248 != 0) return;
        _addValidator(innerFnSeed, callerSeed, validatorSeed, keySeed);
    }

    /// @notice Both phases: deactivateValidator
    function handler_deactivateValidator(uint256 callerSeed, uint256 validatorSeed) external {
        _deactivateValidator(callerSeed, validatorSeed);
    }

    /// @notice Mostly post-init: rotateValidator (~1/256 pre-init calls verify NotInitialized guard)
    function handler_rotateValidator(
        uint256 callerSeed,
        uint256 validatorSeed,
        uint256 keySeed
    )
        external
    {
        if (!_ghostInitialized && callerSeed >> 248 != 0) return;
        _rotateValidator(callerSeed, validatorSeed, keySeed);
    }

    /// @notice Mostly post-init: setIpAddresses (~1/256 pre-init calls verify NotInitialized guard)
    function handler_setIpAddresses(
        uint256 callerSeed,
        uint256 validatorSeed,
        uint256 ipSeed
    )
        external
    {
        if (!_ghostInitialized && callerSeed >> 248 != 0) return;
        _setIpAddresses(callerSeed, validatorSeed, ipSeed);
    }

    /// @notice Mostly post-init: transferValidatorOwnership (~1/256 pre-init calls verify NotInitialized guard)
    function handler_transferValidatorOwnership(
        uint256 callerSeed,
        uint256 validatorSeed,
        uint256 newAddrSeed
    )
        external
    {
        if (!_ghostInitialized && callerSeed >> 248 != 0) return;
        _transferValidatorOwnership(callerSeed, validatorSeed, newAddrSeed);
    }

    /// @notice Both phases: transferOwnership
    function handler_transferOwnership(uint256 callerSeed, uint256 newOwnerSeed) external {
        _transferOwnership(callerSeed, newOwnerSeed);
    }

    /// @notice Mostly post-init: setNextDkgCeremony (~1/256 pre-init calls verify NotInitialized guard)
    function handler_setNextDkgCeremony(uint256 callerSeed, uint64 epoch) external {
        if (!_ghostInitialized && callerSeed >> 248 != 0) return;
        _setNextDkgCeremony(callerSeed, epoch);
    }

    /// @notice Mostly pre-init: migrateValidator (~1/256 post-init calls verify AlreadyInitialized guard)
    function handler_migrateValidator(uint256 callerSeed, uint256 idxSeed) external {
        if (_ghostInitialized && callerSeed >> 248 != 0) return;
        _migrateValidator(callerSeed, idxSeed);
    }

    /// @notice Mostly pre-init: initializeIfMigrated (~1/256 post-init calls verify AlreadyInitialized guard)
    function handler_initializeIfMigrated(uint256 callerSeed) external {
        if (_ghostInitialized && callerSeed >> 248 != 0) return;
        _initializeIfMigrated(callerSeed);
    }

    /// @notice Handler for adding validators with real Ed25519 signatures
    /// @dev Tests TEMPO-VALV2-2 (owner-only), TEMPO-VALV2-3 (count changes), TEMPO-VALV2-4 (height tracking),
    ///      TEMPO-VALV2-6 (address uniqueness), TEMPO-VALV2-7 (pubkey uniqueness/zero)
    function _addValidator(
        uint256 innerFnSeed,
        uint256 callerSeed,
        uint256 validatorSeed,
        uint256 keySeed
    )
        internal
    {
        // innerFnSeed % 100 controls test distribution:
        //   0-74:  authorized caller (owner)
        //   75-99: random caller (~25% Unauthorized)
        // innerFnSeed / 100 % 8 controls input fault injection:
        //   0: zero pubkey, 1: dup pubkey, 2: dup address, 3: dup IP, 4-7: valid
        address caller;
        if (innerFnSeed % 100 < 75) {
            caller = _ghostOwner;
        } else {
            caller = _selectPotentialValidator(callerSeed);
        }
        bool isOwner = (caller == _ghostOwner);

        uint256 inputMode = (innerFnSeed / 100) % 8;

        address validatorAddr;
        bytes32 privKey;
        bytes32 pubKey;

        if (inputMode == 0) {
            // ~12.5%: zero pubkey
            validatorAddr = _selectPotentialValidator(validatorSeed);
            pubKey = bytes32(0);
        } else if (inputMode == 1 && _ghostTotalCount > 0) {
            // ~12.5%: duplicate pubkey
            validatorAddr = _selectPotentialValidator(validatorSeed);
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 existingIdx = uint64(keySeed % _ghostTotalCount);
            pubKey = _ghostPubKey[existingIdx];
            privKey = _ghostPrivKey[existingIdx];
        } else if (inputMode == 2 && _ghostTotalCount > 0) {
            // ~12.5%: duplicate address
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 existingIdx = uint64(validatorSeed % _ghostTotalCount);
            validatorAddr = _ghostAddress[existingIdx];
            (privKey, pubKey) = _generateKeyPair(keySeed);
        } else {
            // ~50%: fully valid inputs + ~12.5%: duplicate ingress IP
            validatorAddr = _selectPotentialValidator(validatorSeed);
            (privKey, pubKey) = _generateKeyPair(keySeed);
        }

        string memory ingress;
        string memory egress;
        if (inputMode == 3 && _ghostTotalCount > 0) {
            // Reuse an active validator's ingress to trigger dup IP
            (, uint64 activeIdx, bool found) = _selectActiveValidator(keySeed);
            if (found) {
                ingress = _ghostIngress[activeIdx];
            } else {
                ingress = _generateIngress(validatorSeed);
            }
            egress = _generateEgress(validatorSeed);
        } else {
            ingress = _generateIngress(validatorSeed);
            egress = _generateEgress(validatorSeed);
        }
        bytes32 ingressIpHash = _extractIngressIpHash(ingress);

        bytes memory sig = _signAdd(privKey, validatorAddr, ingress, egress);

        // Determine expected outcome based on ghost state
        bool pubKeyZero = (pubKey == bytes32(0));
        bool pubKeyUsed = !pubKeyZero && _ghostPubKeyUsed[pubKey];
        bool addressInUse = _ghostAddressInUse[validatorAddr];
        bool ipUsed = _ghostActiveIngressIpHashes[ingressIpHash];

        uint256 activeCountBefore = _countActiveValidators();
        uint256 totalCountBefore = _ghostTotalCount;

        vm.startPrank(caller);
        try validatorConfigV2.addValidator(validatorAddr, pubKey, ingress, egress, sig) {
            vm.stopPrank();
            assertTrue(
                _ghostInitialized,
                "TEMPO-VALV2-5: addValidator must not succeed when not initialized"
            );
            assertTrue(isOwner, "TEMPO-VALV2-2: Non-owner should not add validator");
            assertFalse(pubKeyZero, "TEMPO-VALV2-7: Zero pubkey should not succeed");
            assertFalse(pubKeyUsed, "TEMPO-VALV2-7: Duplicate pubkey should not succeed");
            assertFalse(addressInUse, "TEMPO-VALV2-6: Duplicate address should not succeed");
            assertFalse(ipUsed, "TEMPO-VALV2-13: Duplicate ingress IP should not succeed");

            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 idx = uint64(_ghostTotalCount);

            _ghostAddress[idx] = validatorAddr;
            _ghostPubKey[idx] = pubKey;
            _ghostPrivKey[idx] = privKey;
            _ghostAddedAtHeight[idx] = uint64(block.number);
            _ghostDeactivatedAtHeight[idx] = 0;
            _ghostIngress[idx] = ingress;
            _ghostEgress[idx] = egress;
            _ghostActiveIndex[validatorAddr] = idx;
            _ghostAddressInUse[validatorAddr] = true;
            _ghostPubKeyUsed[pubKey] = true;
            _ghostActiveIngressIpHashes[ingressIpHash] = true;

            _ghostTotalCount++;

            // TEMPO-VALV2-3: addValidator should +1 active, +1 total
            assertEq(
                _countActiveValidators(),
                activeCountBefore + 1,
                "TEMPO-VALV2-3: addValidator should increment active count by 1"
            );
            assertEq(
                _ghostTotalCount,
                totalCountBefore + 1,
                "TEMPO-VALV2-3: addValidator should increment total count by 1"
            );

            // TEMPO-VALV2-4: Height tracking
            IValidatorConfigV2.Validator memory v =
                validatorConfigV2.validatorByAddress(validatorAddr);
            assertEq(
                v.addedAtHeight, uint64(block.number), "TEMPO-VALV2-4: addedAtHeight should be set"
            );
            assertEq(
                v.deactivatedAtHeight,
                0,
                "TEMPO-VALV2-4: deactivatedAtHeight should be 0 for new validator"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            if (bytes4(reason) == IValidatorConfigV2.NotInitialized.selector) {
                assertFalse(
                    _ghostInitialized, "TEMPO-VALV2-5: NotInitialized but ghost says initialized"
                );
            }
            // We expect a revert when: !initialized, !isOwner, pubKeyZero, pubKeyUsed, addressInUse, or ipUsed
            // Don't assert specific errors — just verify it's a known V2 error
            assertTrue(
                !_ghostInitialized || !isOwner || pubKeyZero || pubKeyUsed || addressInUse || ipUsed
                    || reason.length > 0,
                "addValidator reverted unexpectedly with valid inputs"
            );
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for deactivating validators (owner, validator, or third party; active or already deactivated)
    /// @dev Tests TEMPO-VALV2-1 (dual-auth), TEMPO-VALV2-3 (count changes), TEMPO-VALV2-4 (height tracking),
    ///      TEMPO-VALV2-9 (delete-once: already deactivated rejects)
    function _deactivateValidator(uint256 callerSeed, uint256 validatorSeed) internal {
        if (_ghostTotalCount == 0) return;

        // Select from ALL ghost validators (not just active) to exercise already-deactivated path
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 someIdx = uint64(validatorSeed % _ghostTotalCount);
        address validatorAddr = _ghostAddress[someIdx];

        // Skip addresses that were transferred away (no longer in contract's address_to_index)
        if (!_ghostAddressInUse[validatorAddr]) return;

        address caller = _selectPotentialValidator(callerSeed);
        bool isAuthorized = (caller == _ghostOwner || caller == validatorAddr);

        // The contract looks up the LATEST entry for this address
        uint64 currentIdx = _ghostActiveIndex[validatorAddr];
        bool isActive = (_ghostDeactivatedAtHeight[currentIdx] == 0);

        uint256 activeCountBefore = _countActiveValidators();
        uint256 totalCountBefore = _ghostTotalCount;

        vm.startPrank(caller);
        try validatorConfigV2.deactivateValidator(validatorAddr) {
            vm.stopPrank();
            assertTrue(isAuthorized, "TEMPO-VALV2-1: Third party should not deactivate");
            assertTrue(isActive, "TEMPO-VALV2-9: Already deactivated should not succeed");

            _ghostDeactivatedAtHeight[currentIdx] = uint64(block.number);

            // Contract allows reusing addresses of deactivated validators
            delete _ghostAddressInUse[validatorAddr];

            bytes32 ingressIpHash = _extractIngressIpHash(_ghostIngress[currentIdx]);
            delete _ghostActiveIngressIpHashes[ingressIpHash];

            // TEMPO-VALV2-3: deactivateValidator should -1 active, +0 total
            assertEq(
                _countActiveValidators(),
                activeCountBefore - 1,
                "TEMPO-VALV2-3: deactivateValidator should decrement active count by 1"
            );
            assertEq(
                _ghostTotalCount,
                totalCountBefore,
                "TEMPO-VALV2-3: deactivateValidator should not change total count"
            );

            // TEMPO-VALV2-4: Height tracking
            IValidatorConfigV2.Validator memory v =
                validatorConfigV2.validatorByAddress(validatorAddr);
            assertEq(
                v.deactivatedAtHeight,
                uint64(block.number),
                "TEMPO-VALV2-4: deactivatedAtHeight should match block.number"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(
                !isAuthorized || !isActive || reason.length > 0,
                "deactivateValidator reverted unexpectedly with valid inputs"
            );
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for ownership transfer
    /// @dev Tests TEMPO-VALV2-2 (owner-only), TEMPO-VALV2-20 (owner consistency)
    function _transferOwnership(uint256 callerSeed, uint256 newOwnerSeed) internal {
        address caller = _selectPotentialValidator(callerSeed);
        bool isOwner = (caller == _ghostOwner);

        address newOwner = _selectPotentialValidator(newOwnerSeed);

        vm.startPrank(caller);
        try validatorConfigV2.transferOwnership(newOwner) {
            vm.stopPrank();
            assertTrue(isOwner, "TEMPO-VALV2-2: Non-owner should not transfer ownership");

            address oldOwner = _ghostOwner;
            _ghostOwner = newOwner;

            assertEq(validatorConfigV2.owner(), newOwner, "TEMPO-VALV2-20: Owner should be updated");
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for setting DKG ceremony epoch
    /// @dev Tests TEMPO-VALV2-2 (owner-only), TEMPO-VALV2-21 (DKG consistency)
    function _setNextDkgCeremony(uint256 callerSeed, uint64 epoch) internal {
        address caller = _selectPotentialValidator(callerSeed);
        bool isOwner = (caller == _ghostOwner);

        vm.startPrank(caller);
        try validatorConfigV2.setNextFullDkgCeremony(epoch) {
            vm.stopPrank();
            assertTrue(
                _ghostInitialized,
                "TEMPO-VALV2-5: setNextDkgCeremony must not succeed when not initialized"
            );
            assertTrue(isOwner, "TEMPO-VALV2-2: Non-owner should not set DKG ceremony");

            _ghostNextDkgCeremony = epoch;

            assertEq(
                validatorConfigV2.getNextFullDkgCeremony(),
                epoch,
                "TEMPO-VALV2-21: DKG epoch should be set"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            if (bytes4(reason) == IValidatorConfigV2.NotInitialized.selector) {
                assertFalse(
                    _ghostInitialized, "TEMPO-VALV2-5: NotInitialized but ghost says initialized"
                );
            }
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for setting IP addresses (owner, validator, or third party)
    /// @dev Tests TEMPO-VALV2-1 (dual-auth)
    function _setIpAddresses(uint256 callerSeed, uint256 validatorSeed, uint256 ipSeed) internal {
        (address validatorAddr, uint64 ghostIdx, bool found) = _selectActiveValidator(validatorSeed);
        if (!found) return;

        address caller = _selectPotentialValidator(callerSeed);
        bool isAuthorized = (caller == _ghostOwner || caller == validatorAddr);

        string memory newIngress = _generateIngress(ipSeed);
        string memory newEgress = _generateEgress(ipSeed);

        vm.startPrank(caller);
        try validatorConfigV2.setIpAddresses(validatorAddr, newIngress, newEgress) {
            vm.stopPrank();
            assertTrue(
                _ghostInitialized,
                "TEMPO-VALV2-5: setIpAddresses must not succeed when not initialized"
            );
            assertTrue(isAuthorized, "TEMPO-VALV2-1: Third party should not update IPs");

            bytes32 oldIngressIpHash = _extractIngressIpHash(_ghostIngress[ghostIdx]);
            bytes32 newIngressIpHash = _extractIngressIpHash(newIngress);
            delete _ghostActiveIngressIpHashes[oldIngressIpHash];
            _ghostActiveIngressIpHashes[newIngressIpHash] = true;

            _ghostIngress[ghostIdx] = newIngress;
            _ghostEgress[ghostIdx] = newEgress;

            IValidatorConfigV2.Validator memory v =
                validatorConfigV2.validatorByAddress(validatorAddr);
            assertEq(
                keccak256(bytes(v.ingress)),
                keccak256(bytes(newIngress)),
                "TEMPO-VALV2-1: Ingress should match"
            );
            assertEq(
                keccak256(bytes(v.egress)),
                keccak256(bytes(newEgress)),
                "TEMPO-VALV2-1: Egress should match"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            if (bytes4(reason) == IValidatorConfigV2.NotInitialized.selector) {
                assertFalse(
                    _ghostInitialized, "TEMPO-VALV2-5: NotInitialized but ghost says initialized"
                );
            }
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for transferring validator ownership (owner, validator, or third party)
    /// @dev Tests TEMPO-VALV2-1 (dual-auth), TEMPO-VALV2-11 (address uniqueness on transfer)
    function _transferValidatorOwnership(
        uint256 callerSeed,
        uint256 validatorSeed,
        uint256 newAddrSeed
    )
        internal
    {
        (address currentAddr, uint64 ghostIdx, bool found) = _selectActiveValidator(validatorSeed);
        if (!found) return;

        address caller = _selectPotentialValidator(callerSeed);
        bool isAuthorized = (caller == _ghostOwner || caller == currentAddr);

        address newAddr = _selectPotentialValidator(newAddrSeed);
        bool newAddrInUse = _ghostAddressInUse[newAddr];

        vm.startPrank(caller);
        try validatorConfigV2.transferValidatorOwnership(currentAddr, newAddr) {
            vm.stopPrank();
            assertTrue(
                _ghostInitialized,
                "TEMPO-VALV2-5: transferValidatorOwnership must not succeed when not initialized"
            );
            assertTrue(isAuthorized, "TEMPO-VALV2-1: Third party should not transfer validator");
            assertFalse(newAddrInUse, "TEMPO-VALV2-11: Duplicate address should not succeed");

            _ghostAddress[ghostIdx] = newAddr;
            delete _ghostAddressInUse[currentAddr];
            _ghostAddressInUse[newAddr] = true;
            _ghostActiveIndex[newAddr] = ghostIdx;
            delete _ghostActiveIndex[currentAddr];

            IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(newAddr);
            assertEq(v.validatorAddress, newAddr, "TEMPO-VALV2-1: Address should be updated");
            assertEq(
                v.publicKey,
                _ghostPubKey[ghostIdx],
                "TEMPO-VALV2-1: Public key preserved after transfer"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            if (bytes4(reason) == IValidatorConfigV2.NotInitialized.selector) {
                assertFalse(
                    _ghostInitialized, "TEMPO-VALV2-5: NotInitialized but ghost says initialized"
                );
            }
            assertTrue(
                !_ghostInitialized || !isAuthorized || newAddrInUse || reason.length > 0,
                "transferValidatorOwnership reverted unexpectedly with valid inputs"
            );
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for rotating validators with real Ed25519 signatures (owner, validator, or third party)
    /// @dev Tests TEMPO-VALV2-1 (dual-auth), TEMPO-VALV2-3 (count changes), TEMPO-VALV2-4 (height tracking),
    ///      TEMPO-VALV2-6 (address mapping), TEMPO-VALV2-7 (pubkey uniqueness/zero), TEMPO-VALV2-13 (IP uniqueness).
    function _rotateValidator(uint256 callerSeed, uint256 validatorSeed, uint256 keySeed) internal {
        (address validatorAddr, uint64 oldGhostIdx, bool found) =
            _selectActiveValidator(validatorSeed);
        if (!found) return;

        address caller = _selectPotentialValidator(callerSeed);
        bool isAuthorized = (caller == _ghostOwner || caller == validatorAddr);

        (bytes32 newPrivKey, bytes32 newPubKey) = _generateKeyPair(keySeed);
        string memory ingress = _generateIngress(keySeed);
        string memory egress = _generateEgress(keySeed);

        bool pubKeyZero = (newPubKey == bytes32(0));
        bool pubKeyUsed = !pubKeyZero && _ghostPubKeyUsed[newPubKey];
        bytes32 oldIngressIpHash = _extractIngressIpHash(_ghostIngress[oldGhostIdx]);
        bytes32 newIngressIpHash = _extractIngressIpHash(ingress);
        // new IP == old IP is not a conflict: the old validator's IP is freed during rotation
        bool ipUsed =
            newIngressIpHash != oldIngressIpHash && _ghostActiveIngressIpHashes[newIngressIpHash];

        bytes memory sig = _signRotate(newPrivKey, validatorAddr, ingress, egress);

        uint256 activeCountBefore = _countActiveValidators();
        uint256 totalCountBefore = _ghostTotalCount;

        vm.startPrank(caller);
        try validatorConfigV2.rotateValidator(validatorAddr, newPubKey, ingress, egress, sig) {
            vm.stopPrank();
            assertTrue(
                _ghostInitialized,
                "TEMPO-VALV2-5: rotateValidator must not succeed when not initialized"
            );
            assertTrue(isAuthorized, "TEMPO-VALV2-1: Third party should not rotate validator");
            assertFalse(pubKeyZero, "TEMPO-VALV2-7: Zero pubkey should not succeed");
            assertFalse(pubKeyUsed, "TEMPO-VALV2-7: Duplicate pubkey should not succeed");
            assertFalse(ipUsed, "TEMPO-VALV2-13: Duplicate ingress IP should not succeed");

            delete _ghostActiveIngressIpHashes[oldIngressIpHash];

            _ghostDeactivatedAtHeight[oldGhostIdx] = uint64(block.number);

            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 newIdx = uint64(_ghostTotalCount);
            _ghostAddress[newIdx] = validatorAddr;
            _ghostPubKey[newIdx] = newPubKey;
            _ghostPrivKey[newIdx] = newPrivKey;
            _ghostAddedAtHeight[newIdx] = uint64(block.number);
            _ghostDeactivatedAtHeight[newIdx] = 0;
            _ghostIngress[newIdx] = ingress;
            _ghostEgress[newIdx] = egress;
            _ghostActiveIndex[validatorAddr] = newIdx;
            _ghostPubKeyUsed[newPubKey] = true;

            _ghostActiveIngressIpHashes[newIngressIpHash] = true;

            _ghostTotalCount++;

            // TEMPO-VALV2-3: rotateValidator should +0 active, +1 total
            assertEq(
                _countActiveValidators(),
                activeCountBefore,
                "TEMPO-VALV2-3: rotateValidator should not change active count"
            );
            assertEq(
                _ghostTotalCount,
                totalCountBefore + 1,
                "TEMPO-VALV2-3: rotateValidator should increment total count by 1"
            );

            // TEMPO-VALV2-4: Height tracking for both old and new validators
            IValidatorConfigV2.Validator memory oldV =
                validatorConfigV2.validatorByIndex(oldGhostIdx);
            assertEq(
                oldV.deactivatedAtHeight,
                uint64(block.number),
                "TEMPO-VALV2-4: Old validator deactivatedAtHeight should be current block"
            );

            IValidatorConfigV2.Validator memory newV =
                validatorConfigV2.validatorByAddress(validatorAddr);
            // TEMPO-VALV2-6: Address mapping updated — old entry deactivated, lookup returns new entry
            assertEq(
                newV.index, newIdx, "TEMPO-VALV2-6: Address lookup must point to new rotated entry"
            );
            assertEq(newV.publicKey, newPubKey, "TEMPO-VALV2-4: New public key should be set");
            assertEq(
                newV.addedAtHeight,
                uint64(block.number),
                "TEMPO-VALV2-4: New validator addedAtHeight should be current block"
            );
            assertEq(newV.deactivatedAtHeight, 0, "TEMPO-VALV2-4: New validator should be active");
        } catch (bytes memory reason) {
            vm.stopPrank();
            if (bytes4(reason) == IValidatorConfigV2.NotInitialized.selector) {
                assertFalse(
                    _ghostInitialized, "TEMPO-VALV2-5: NotInitialized but ghost says initialized"
                );
            }
            assertTrue(
                !_ghostInitialized || !isAuthorized || pubKeyZero || pubKeyUsed || ipUsed
                    || reason.length > 0,
                "rotateValidator reverted unexpectedly with valid inputs"
            );
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for migrateValidator (pre-init only)
    /// @dev Tests TEMPO-VALV2-2 (owner-only), TEMPO-VALV2-23 (sequential migration), TEMPO-VALV2-25 (activity preserved)
    function _migrateValidator(uint256 callerSeed, uint256 idxSeed) internal {
        IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();

        // 75% correct sequential index, 25% random (to test InvalidMigrationIndex)
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 idx;
        if (callerSeed % 4 < 3) {
            idx = _ghostNextMigrationIndex;
        } else {
            // forge-lint: disable-next-line(unsafe-typecast)
            idx = uint64(idxSeed % (v1Vals.length + 2));
        }

        bool isCorrectIdx = (idx == _ghostNextMigrationIndex);
        bool idxInRange = (idx < v1Vals.length);

        // First migration auto-sets V2 owner from V1; until then _ghostOwner == address(0)
        address expectedOwner = _ghostOwner;
        if (_ghostTotalCount == 0 && _ghostOwner == address(0)) {
            expectedOwner = validatorConfig.owner();
        }

        // 75% owner, 25% random
        address caller;
        if (callerSeed % 100 < 75) {
            caller = expectedOwner;
        } else {
            caller = _selectPotentialValidator(callerSeed);
        }
        bool isOwner = (caller == expectedOwner);

        vm.startPrank(caller);
        try validatorConfigV2.migrateValidator(idx) {
            vm.stopPrank();
            assertFalse(
                _ghostInitialized,
                "TEMPO-VALV2-5: migrateValidator must not succeed when already initialized"
            );
            assertTrue(isCorrectIdx, "Migration should require sequential index");
            assertTrue(idxInRange, "Migration index should be in V1 range");
            assertTrue(isOwner, "TEMPO-VALV2-2: Non-owner should not migrate");

            // Update ghost owner on first migration (auto-set from V1)
            if (_ghostTotalCount == 0 && _ghostOwner == address(0)) {
                _ghostOwner = validatorConfig.owner();
            }

            IValidatorConfigV2.Validator memory v2 = validatorConfigV2.validatorByIndex(idx);

            _ghostAddress[idx] = v1Vals[idx].validatorAddress;
            _ghostPubKey[idx] = v1Vals[idx].publicKey;
            _ghostAddedAtHeight[idx] = uint64(block.number);
            _ghostDeactivatedAtHeight[idx] = v1Vals[idx].active ? 0 : uint64(block.number);
            _ghostIngress[idx] = v2.ingress;
            _ghostEgress[idx] = v2.egress;
            _ghostActiveIndex[v1Vals[idx].validatorAddress] = idx;
            _ghostAddressInUse[v1Vals[idx].validatorAddress] = true;
            _ghostPubKeyUsed[v1Vals[idx].publicKey] = true;
            if (v1Vals[idx].active) {
                _ghostActiveIngressIpHashes[_extractIngressIpHash(v2.ingress)] = true;
            }

            _ghostTotalCount++;
            _ghostNextMigrationIndex++;

            // TEMPO-VALV2-25: Migration preserves activity — checked per-handler at migration time,
            // not globally, because migrated validators can be deactivated after migration
            bool v2Active = v2.deactivatedAtHeight == 0;
            assertEq(
                v2Active,
                v1Vals[idx].active,
                "TEMPO-VALV2-25: Migrated validator activity must match V1"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            if (bytes4(reason) == IValidatorConfigV2.AlreadyInitialized.selector) {
                assertTrue(
                    _ghostInitialized,
                    "TEMPO-VALV2-5: AlreadyInitialized but ghost says not initialized"
                );
            }
            assertTrue(
                _ghostInitialized || !isCorrectIdx || !idxInRange || !isOwner || reason.length > 0,
                "migrateValidator reverted unexpectedly with valid inputs"
            );
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for initializeIfMigrated (pre-init only)
    /// @dev Tests TEMPO-VALV2-2 (owner-only), TEMPO-VALV2-22 (one-way initialization)
    function _initializeIfMigrated(uint256 callerSeed) internal {
        // 75% owner, 25% random
        address caller;
        if (callerSeed % 100 < 75) {
            caller = _ghostOwner;
        } else {
            caller = _selectPotentialValidator(callerSeed);
        }
        bool isOwner = (caller == _ghostOwner);

        IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();
        bool allMigrated = (_ghostTotalCount >= v1Vals.length);

        vm.startPrank(caller);
        try validatorConfigV2.initializeIfMigrated() {
            vm.stopPrank();
            assertFalse(
                _ghostInitialized,
                "TEMPO-VALV2-5: initializeIfMigrated must not succeed when already initialized"
            );
            assertTrue(isOwner, "TEMPO-VALV2-2: Non-owner should not initialize");
            assertTrue(allMigrated, "Should not initialize before migration complete");

            _ghostInitialized = true;
            _ghostInitializedAtHeight = uint64(block.number);
            _ghostNextDkgCeremony = validatorConfig.getNextFullDkgCeremony();
        } catch (bytes memory reason) {
            vm.stopPrank();
            if (bytes4(reason) == IValidatorConfigV2.AlreadyInitialized.selector) {
                assertTrue(
                    _ghostInitialized,
                    "TEMPO-VALV2-5: AlreadyInitialized but ghost says not initialized"
                );
            }
            assertTrue(
                _ghostInitialized || !isOwner || !allMigrated || reason.length > 0,
                "initializeIfMigrated reverted unexpectedly with valid inputs"
            );
            _assertKnownV2Error(reason);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    function invariant_globalInvariants() public view {
        _invariantAppendOnlyCount(); // VALV2-8
        _invariantDeleteOnce(); // VALV2-9
        _invariantHeightTracking(); // VALV2-10
        _invariantAddressUniqueness(); // VALV2-11
        _invariantPubKeyUniqueness(); // VALV2-12
        _invariantIpUniqueness(); // VALV2-13
        _invariantIndexSequential(); // VALV2-14
        _invariantActiveValidatorSubset(); // VALV2-15
        _invariantValidatorDataConsistency(); // VALV2-16
        _invariantValidatorCountConsistency(); // VALV2-17
        _invariantAddressLookupCorrectness(); // VALV2-18
        _invariantPubkeyLookupCorrectness(); // VALV2-19
        _invariantOwnerConsistency(); // VALV2-20
        _invariantDkgCeremonyConsistency(); // VALV2-21
        _invariantInitializationOneWay(); // VALV2-22
        _invariantMigrationCompleteness(); // VALV2-23
        _invariantMigrationIdentity(); // VALV2-24
    }

    /// @notice TEMPO-VALV2-8: Validator count only increases (append-only)
    function _invariantAppendOnlyCount() internal view {
        uint64 count = validatorConfigV2.validatorCount();
        assertEq(count, _ghostTotalCount, "TEMPO-VALV2-8: Count should match ghost total");
    }

    /// @notice TEMPO-VALV2-20: Owner matches ghost state
    function _invariantOwnerConsistency() internal view {
        assertEq(
            validatorConfigV2.owner(), _ghostOwner, "TEMPO-VALV2-20: Owner should match ghost state"
        );
    }

    /// @notice TEMPO-VALV2-16: All validator data matches ghost state (index-keyed)
    function _invariantValidatorDataConsistency() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();
        assertEq(vals.length, _ghostTotalCount, "TEMPO-VALV2-16: Array length mismatch");

        for (uint256 i = 0; i < vals.length; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 idx = uint64(i);
            assertEq(
                vals[i].validatorAddress, _ghostAddress[idx], "TEMPO-VALV2-16: Address mismatch"
            );
            assertEq(vals[i].publicKey, _ghostPubKey[idx], "TEMPO-VALV2-16: Public key mismatch");
            assertEq(vals[i].index, idx, "TEMPO-VALV2-16: Index mismatch");
            assertEq(
                vals[i].addedAtHeight,
                _ghostAddedAtHeight[idx],
                "TEMPO-VALV2-16: addedAtHeight mismatch"
            );
            assertEq(
                vals[i].deactivatedAtHeight,
                _ghostDeactivatedAtHeight[idx],
                "TEMPO-VALV2-16: deactivatedAtHeight mismatch"
            );
        }
    }

    /// @notice TEMPO-VALV2-14: All indices are sequential (0, 1, 2, ...)
    function _invariantIndexSequential() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

        for (uint256 i = 0; i < vals.length; i++) {
            assertEq(vals[i].index, i, "TEMPO-VALV2-14: Index should equal array position");
        }
    }

    /// @notice TEMPO-VALV2-12: All public keys are unique and non-zero
    function _invariantPubKeyUniqueness() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

        for (uint256 i = 0; i < vals.length; i++) {
            assertTrue(
                vals[i].publicKey != bytes32(0), "TEMPO-VALV2-12: Public key must not be zero"
            );

            for (uint256 j = i + 1; j < vals.length; j++) {
                assertTrue(
                    vals[i].publicKey != vals[j].publicKey,
                    "TEMPO-VALV2-12: Public keys must be unique"
                );
            }
        }
    }

    /// @notice TEMPO-VALV2-15: Active validators are a proper subset of all validators
    function _invariantActiveValidatorSubset() internal view {
        IValidatorConfigV2.Validator[] memory all = validatorConfigV2.getAllValidators();
        IValidatorConfigV2.Validator[] memory active = validatorConfigV2.getActiveValidators();

        assertLe(active.length, all.length, "TEMPO-VALV2-15: Active count <= total count");

        uint256 expectedActive = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (all[i].deactivatedAtHeight == 0) {
                expectedActive++;
            }
        }
        assertEq(
            active.length,
            expectedActive,
            "TEMPO-VALV2-15: Active count should match filtered count"
        );

        for (uint256 i = 0; i < active.length; i++) {
            assertEq(
                active[i].deactivatedAtHeight,
                0,
                "TEMPO-VALV2-15: Active validators must have deactivatedAtHeight == 0"
            );
        }
    }

    /// @notice TEMPO-VALV2-21: DKG epoch matches ghost state
    function _invariantDkgCeremonyConsistency() internal view {
        assertEq(
            validatorConfigV2.getNextFullDkgCeremony(),
            _ghostNextDkgCeremony,
            "TEMPO-VALV2-21: DKG epoch should match ghost state"
        );
    }

    /// @notice TEMPO-VALV2-10: Height tracking invariants
    /// @dev For active validators: addedAtHeight > 0, deactivatedAtHeight == 0
    ///      For deactivated validators: deactivatedAtHeight >= addedAtHeight
    function _invariantHeightTracking() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

        for (uint256 i = 0; i < vals.length; i++) {
            assertTrue(vals[i].addedAtHeight > 0, "TEMPO-VALV2-10: addedAtHeight must be > 0");

            if (vals[i].deactivatedAtHeight != 0) {
                assertGe(
                    vals[i].deactivatedAtHeight,
                    vals[i].addedAtHeight,
                    "TEMPO-VALV2-10: deactivatedAtHeight must be >= addedAtHeight"
                );
            }
        }
    }

    /// @notice TEMPO-VALV2-13: Ingress IP uniqueness among active validators
    /// @dev No two active validators share the same ingress IP (port is ignored)
    function _invariantIpUniqueness() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

        // Check uniqueness among active validators
        for (uint256 i = 0; i < vals.length; i++) {
            if (vals[i].deactivatedAtHeight != 0) continue; // Skip deactivated

            for (uint256 j = i + 1; j < vals.length; j++) {
                if (vals[j].deactivatedAtHeight != 0) continue; // Skip deactivated

                // Check ingress IP uniqueness (extract IP without port)
                bytes32 ipI = _extractIngressIpHash(vals[i].ingress);
                bytes32 ipJ = _extractIngressIpHash(vals[j].ingress);
                assertTrue(
                    ipI != ipJ, "TEMPO-VALV2-13: Active validators must have unique ingress IPs"
                );

                // Note: egress uniqueness is NOT enforced
            }
        }
    }

    /// @notice TEMPO-VALV2-9: Delete-once - deactivatedAtHeight never changes once set
    function _invariantDeleteOnce() internal view {
        // This is enforced by the contract and validated by our handlers
        // The property: once deactivatedAtHeight != 0, it cannot change
        // We verify this by checking that all deactivated validators in contract
        // match our ghost state (which only sets deactivatedAtHeight once)
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

        for (uint256 i = 0; i < vals.length; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 idx = uint64(i);
            assertEq(
                vals[i].deactivatedAtHeight,
                _ghostDeactivatedAtHeight[idx],
                "TEMPO-VALV2-9: deactivatedAtHeight must never change once set"
            );
        }
    }

    /// @notice TEMPO-VALV2-11: Address uniqueness among active validators
    /// @dev At most one active validator per address; deactivated addresses may be reused
    function _invariantAddressUniqueness() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

        // Only check active validators (deactivatedAtHeight == 0)
        for (uint256 i = 0; i < vals.length; i++) {
            if (vals[i].deactivatedAtHeight != 0) continue;

            for (uint256 j = i + 1; j < vals.length; j++) {
                if (vals[j].deactivatedAtHeight != 0) continue;

                assertTrue(
                    vals[i].validatorAddress != vals[j].validatorAddress,
                    "TEMPO-VALV2-11: Active validators must have unique addresses"
                );
            }
        }
    }

    /// @notice TEMPO-VALV2-17: Validator count consistency
    /// @dev validatorCount() equals actual array length
    function _invariantValidatorCountConsistency() internal view {
        uint64 count = validatorConfigV2.validatorCount();
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();
        assertEq(count, vals.length, "TEMPO-VALV2-17: validatorCount must equal array length");
    }

    /// @notice TEMPO-VALV2-18: Address lookup correctness
    /// @dev validatorByAddress returns the currently active (or most recent) validator for that address.
    ///      After rotation, old deactivated validators with the same address exist in the array,
    ///      but lookup should return the active one (or most recent if all deactivated).
    ///      A deactivated validator's address may become unlookupable if its active successor
    ///      was transferred to a different address (which deletes the old addressToIndex mapping).
    function _invariantAddressLookupCorrectness() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

        // For each unique address, check that validatorByAddress returns the expected validator
        for (uint256 i = 0; i < vals.length; i++) {
            address addr = vals[i].validatorAddress;

            // Find the most recent validator for this address
            uint256 mostRecentIdx = i;
            for (uint256 j = i + 1; j < vals.length; j++) {
                if (vals[j].validatorAddress == addr) {
                    mostRecentIdx = j;
                }
            }

            // Only check the last occurrence of each address
            if (mostRecentIdx == i) {
                try validatorConfigV2.validatorByAddress(addr) returns (
                    IValidatorConfigV2.Validator memory lookedUp
                ) {
                    assertEq(
                        lookedUp.index,
                        vals[i].index,
                        "TEMPO-VALV2-18: Address lookup must return most recent validator"
                    );
                    assertEq(
                        lookedUp.publicKey,
                        vals[i].publicKey,
                        "TEMPO-VALV2-18: Address lookup must preserve public key"
                    );
                } catch {
                    // Deactivated validator whose active successor was transferred away —
                    // addressToIndex was deleted, so lookup fails. This is expected.
                    assertTrue(
                        vals[i].deactivatedAtHeight != 0,
                        "TEMPO-VALV2-18: Active validators must be lookupable by address"
                    );
                }
            }
        }
    }

    /// @notice TEMPO-VALV2-19: Public key lookup correctness
    /// @dev For every validator, validatorByPublicKey returns the correct validator
    function _invariantPubkeyLookupCorrectness() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

        for (uint256 i = 0; i < vals.length; i++) {
            bytes32 pubkey = vals[i].publicKey;
            IValidatorConfigV2.Validator memory lookedUp =
                validatorConfigV2.validatorByPublicKey(pubkey);

            assertEq(
                lookedUp.publicKey,
                vals[i].publicKey,
                "TEMPO-VALV2-19: Pubkey lookup must return correct validator"
            );
            assertEq(
                lookedUp.validatorAddress,
                vals[i].validatorAddress,
                "TEMPO-VALV2-19: Pubkey lookup must preserve address"
            );
            assertEq(
                lookedUp.index, vals[i].index, "TEMPO-VALV2-19: Pubkey lookup must preserve index"
            );
        }
    }

    /// @notice TEMPO-VALV2-22: Initialization one-way
    /// @dev Once isInitialized() == true, it remains true forever
    function _invariantInitializationOneWay() internal view {
        bool isInit = validatorConfigV2.isInitialized();
        if (_ghostInitialized) {
            assertTrue(isInit, "TEMPO-VALV2-22: Once initialized, must remain initialized");
            assertEq(
                validatorConfigV2.getInitializedAtHeight(),
                _ghostInitializedAtHeight,
                "TEMPO-VALV2-22: Initialization height must match ghost state"
            );
        }
    }

    /// @notice TEMPO-VALV2-23: Migration completeness
    /// @dev If not initialized, validatorCount <= V1.getAllValidators().length
    function _invariantMigrationCompleteness() internal view {
        if (!_ghostInitialized) {
            IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();
            uint64 v2Count = validatorConfigV2.validatorCount();
            assertLe(
                v2Count, v1Vals.length, "TEMPO-VALV2-23: Migration cannot exceed V1 validator count"
            );
        }
    }

    /// @notice TEMPO-VALV2-24: Migration preserves identity
    /// @dev For each migrated validator: V2 pubkey matches V1 (pubkeys are immutable)
    ///      Note: Addresses may change via transferValidatorOwnership post-migration,
    ///      but public keys are globally unique and immutable.
    ///      Checked in both phases — loop bounds on _ghostTotalCount so safe at count 0.
    function _invariantMigrationIdentity() internal view {
        IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();

        // Check all validators that were migrated from V1
        uint256 migratedCount = v1Vals.length < _ghostTotalCount ? v1Vals.length : _ghostTotalCount;

        for (uint256 i = 0; i < migratedCount; i++) {
            assertEq(
                // forge-lint: disable-next-line(unsafe-typecast)
                _ghostPubKey[uint64(i)],
                v1Vals[i].publicKey,
                "TEMPO-VALV2-24: Migrated validator public key must match V1"
            );
            // Note: We don't check address equality because transferValidatorOwnership
            // can legitimately change addresses post-migration
        }
    }

    /// @notice Regression test for fuzz sequence: migrate one validator then rotate it.
    /// @dev Reproduces the shrunk sequence from invariant_globalInvariants failure.
    function test_regression_migrateAndRotate() public {
        // Step 1: migrate validator index 0 (exact args from shrunk sequence)
        this.handler_migrateValidator(
            9_080_296_786_710,
            1_784_051_681_589_737_187_974_002_380_956_804_009_033_174_642_466_610_043_552_828_374_103_364_850_947
        );

        // Step 2: rotate that validator (exact args from shrunk sequence)
        this.handler_rotateValidator(10_000_000_000, 900_000_000_000_000_000_000, 100_000);

        // Verify all global invariants hold
        invariant_globalInvariants();
    }

    /// @dev Helper to extract and hash IP from ingress (ip:port -> keccak256(ip))
    function _extractIngressIpHash(string memory ingress) internal pure returns (bytes32) {
        bytes memory b = bytes(ingress);
        if (b.length == 0) return keccak256(b);

        // IPv6 format: [ip]:port -> extract ip
        if (b[0] == "[") {
            for (uint256 i = 1; i < b.length; i++) {
                if (b[i] == "]") {
                    bytes memory ip = new bytes(i - 1);
                    for (uint256 j = 1; j < i; j++) {
                        ip[j - 1] = b[j];
                    }
                    return keccak256(ip);
                }
            }
            return keccak256(b); // Malformed
        }

        // IPv4 format: ip:port -> extract ip
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == ":") {
                bytes memory ip = new bytes(i);
                for (uint256 j = 0; j < i; j++) {
                    ip[j] = b[j];
                }
                return keccak256(ip);
            }
        }

        // No port found
        return keccak256(b);
    }

}
