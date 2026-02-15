// // SPDX-License-Identifier: UNLICENSED
// pragma solidity ^0.8.13;

// import { IValidatorConfig } from "../../src/interfaces/IValidatorConfig.sol";
// import { IValidatorConfigV2 } from "../../src/interfaces/IValidatorConfigV2.sol";
// import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

// /// @title ValidatorConfigV2 Invariant Tests
// /// @notice Fuzz-based invariant tests for the ValidatorConfigV2 precompile
// /// @dev Tests invariants TEMPO-VALV2-1 through TEMPO-VALV2-25 covering:
// ///      - Per-handler assertions (VALV2-1 to VALV2-7): auth enforcement, count changes, height tracking, init gates
// ///      - Global invariants (VALV2-8 to VALV2-25): append-only, uniqueness, lookups, migration correctness
// contract ValidatorConfigV2InvariantTest is InvariantBaseTest {

//     /// @dev Starting offset for validator address pool
//     uint256 private constant VALIDATOR_POOL_OFFSET = 0x7000;

//     /// @dev Array of potential validator addresses
//     address[] private _potentialValidators;

//     /// @dev Ghost tracking for validators — index-keyed to mirror contract's append-only array.
//     ///      Address-keyed mappings would break on rotateValidator (same address, two entries).
//     mapping(uint64 => address) private _ghostAddress;
//     mapping(uint64 => bytes32) private _ghostPubKey;
//     mapping(uint64 => uint64) private _ghostAddedAtHeight;
//     mapping(uint64 => uint64) private _ghostDeactivatedAtHeight;
//     mapping(uint64 => string) private _ghostIngress;
//     mapping(uint64 => string) private _ghostEgress;

//     /// @dev Reverse lookup: address -> latest active index (updated on add/transfer/rotate)
//     mapping(address => uint64) private _ghostActiveIndex;
//     mapping(address => bool) private _ghostAddressInUse;

//     /// @dev Ghost tracking for public key uniqueness
//     mapping(bytes32 => bool) private _ghostPubKeyUsed;

//     /// @dev Ghost tracking for owner
//     address private _ghostOwner;

//     /// @dev Ghost tracking for DKG ceremony
//     uint64 private _ghostNextDkgCeremony;

//     /// @dev Ghost tracking for initialization
//     bool private _ghostInitialized;

//     /// @dev Ghost tracking for initialization height
//     uint64 private _ghostInitializedAtHeight;

//     /// @dev Ghost tracking for total validator count (append-only, never decreases)
//     uint256 private _ghostTotalCount;

//     /// @dev Ghost tracking for active ingress IP hashes (to match contract's IP uniqueness enforcement)
//     mapping(bytes32 => bool) private _ghostActiveIngressIpHashes;

//     /// @dev V1 setup validators (migrated during setUp)
//     address private _setupVal1 = address(0xA000);
//     address private _setupVal2 = address(0xB000);
//     bytes32 private constant SETUP_PUB_KEY_A =
//         0x1111111111111111111111111111111111111111111111111111111111111111;
//     bytes32 private constant SETUP_PUB_KEY_B =
//         0x2222222222222222222222222222222222222222222222222222222222222222;

//     /*//////////////////////////////////////////////////////////////
//                                SETUP
//     //////////////////////////////////////////////////////////////*/

//     function setUp() public override {
//         super.setUp();
//         vm.skip(isTempo);

//         targetContract(address(this));

//         _setupInvariantBase();
//         _actors = _buildActors(5);
//         _potentialValidators = _buildAddressPool(500, VALIDATOR_POOL_OFFSET);
//         _ghostOwner = admin;

//         validatorConfig.addValidator(
//             _setupVal1, SETUP_PUB_KEY_A, true, "10.0.0.100:8000", "10.0.0.100:9000"
//         );
//         validatorConfig.addValidator(
//             _setupVal2, SETUP_PUB_KEY_B, true, "10.0.0.101:8000", "10.0.0.101:9000"
//         );

//         IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();
//         for (uint64 i = 0; i < v1Vals.length; i++) {
//             validatorConfigV2.migrateValidator(i);
//         }
//         validatorConfigV2.initializeIfMigrated();
//         _ghostInitialized = true;
//         _ghostInitializedAtHeight = uint64(block.number);

//         // Get migrated validators to track IPs
//         IValidatorConfigV2.Validator memory v0 = validatorConfigV2.validatorByIndex(0);
//         IValidatorConfigV2.Validator memory v1 = validatorConfigV2.validatorByIndex(1);

//         _ghostAddress[0] = _setupVal1;
//         _ghostPubKey[0] = SETUP_PUB_KEY_A;
//         _ghostAddedAtHeight[0] = uint64(block.number);
//         _ghostDeactivatedAtHeight[0] = 0;
//         _ghostIngress[0] = v0.ingress;
//         _ghostEgress[0] = v0.egress;
//         _ghostActiveIndex[_setupVal1] = 0;
//         _ghostAddressInUse[_setupVal1] = true;
//         _ghostPubKeyUsed[SETUP_PUB_KEY_A] = true;
//         _ghostActiveIngressIpHashes[_extractIngressIpHash(v0.ingress)] = true;

//         _ghostAddress[1] = _setupVal2;
//         _ghostPubKey[1] = SETUP_PUB_KEY_B;
//         _ghostAddedAtHeight[1] = uint64(block.number);
//         _ghostDeactivatedAtHeight[1] = 0;
//         _ghostIngress[1] = v1.ingress;
//         _ghostEgress[1] = v1.egress;
//         _ghostActiveIndex[_setupVal2] = 1;
//         _ghostAddressInUse[_setupVal2] = true;
//         _ghostPubKeyUsed[SETUP_PUB_KEY_B] = true;
//         _ghostActiveIngressIpHashes[_extractIngressIpHash(v1.ingress)] = true;

//         _ghostTotalCount = 2;

//         _initLogFile("validator_config_v2.log", "ValidatorConfigV2 Invariant Test Log");
//     }

//     /*//////////////////////////////////////////////////////////////
//                             HELPERS
//     //////////////////////////////////////////////////////////////*/

//     function _selectPotentialValidator(uint256 seed) internal view returns (address) {
//         return _selectFromPool(_potentialValidators, seed);
//     }

//     function _generatePublicKey(uint256 seed) internal pure returns (bytes32) {
//         return bytes32(uint256(keccak256(abi.encode("v2_pubkey", seed))) | 1);
//     }

//     function _generateIngress(uint256 seed) internal pure returns (string memory) {
//         uint8 lastOctet = uint8((seed % 254) + 1);
//         return string(abi.encodePacked("192.168.1.", _uint8ToString(lastOctet), ":8000"));
//     }

//     function _generateEgress(uint256 seed) internal pure returns (string memory) {
//         uint8 lastOctet = uint8((seed % 254) + 1);
//         return string(abi.encodePacked("192.168.1.", _uint8ToString(lastOctet)));
//     }

//     function _selectActiveValidator(uint256 seed) internal view returns (address, uint64, bool) {
//         uint256 len = _ghostTotalCount;
//         if (len == 0) return (address(0), 0, false);
//         uint256 start = seed % len;
//         for (uint256 i = 0; i < len; i++) {
//             uint64 idx = uint64((start + i) % len);
//             if (_ghostDeactivatedAtHeight[idx] == 0) {
//                 return (_ghostAddress[idx], idx, true);
//             }
//         }
//         return (address(0), 0, false);
//     }

//     /// @dev Helper to count active validators (deactivatedAtHeight == 0)
//     function _countActiveValidators() internal view returns (uint256) {
//         uint256 count = 0;
//         for (uint256 i = 0; i < _ghostTotalCount; i++) {
//             if (_ghostDeactivatedAtHeight[uint64(i)] == 0) {
//                 count++;
//             }
//         }
//         return count;
//     }

//     /// @dev Helper to get V1 validator data (for migration checks)
//     function _getV1ValidatorData(uint64 idx)
//         internal
//         view
//         returns (IValidatorConfig.Validator memory)
//     {
//         IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();
//         require(idx < v1Vals.length, "V1 index out of bounds");
//         return v1Vals[idx];
//     }

//     // Storage slot constants for ValidatorConfigV2
//     // Slot 0: _owner (address) + _initialized (bool) — packed
//     // Slot 1: validatorsArray.length
//     // Slot 2: addressToIndex mapping base
//     // Slot 3: pubkeyToIndex mapping base
//     // Slot 4: nextDkgCeremony
//     uint256 private constant SLOT_VALIDATORS_ARRAY = 1;
//     uint256 private constant SLOT_ADDRESS_TO_INDEX = 2;
//     uint256 private constant SLOT_PUBKEY_TO_INDEX = 3;
//     uint256 private constant VALIDATOR_SLOT_SIZE = 5;

//     function _assertKnownV2Error(bytes memory reason) internal pure {
//         bytes4 selector = bytes4(reason);
//         bool isKnown = selector == IValidatorConfigV2.Unauthorized.selector
//             || selector == IValidatorConfigV2.ValidatorAlreadyExists.selector
//             || selector == IValidatorConfigV2.PublicKeyAlreadyExists.selector
//             || selector == IValidatorConfigV2.ValidatorNotFound.selector
//             || selector == IValidatorConfigV2.ValidatorAlreadyDeleted.selector
//             || selector == IValidatorConfigV2.InvalidPublicKey.selector
//             || selector == IValidatorConfigV2.InvalidValidatorAddress.selector
//             || selector == IValidatorConfigV2.NotInitialized.selector
//             || selector == IValidatorConfigV2.AlreadyInitialized.selector
//             || selector == IValidatorConfigV2.MigrationNotComplete.selector
//             || selector == IValidatorConfigV2.InvalidMigrationIndex.selector
//             || selector == IValidatorConfigV2.NotIpPort.selector
//             || selector == IValidatorConfigV2.InvalidSignature.selector;
//         assertTrue(isKnown, string.concat("Unknown error: ", vm.toString(selector)));
//     }

//     /// @dev Encodes a short string (<=31 bytes) for inline Solidity storage.
//     ///      Format: data left-aligned in upper bytes, length*2 in lowest byte.
//     function _encodeShortString(string memory s) internal pure returns (bytes32) {
//         bytes memory b = bytes(s);
//         require(b.length <= 31, "string too long for inline storage");
//         bytes32 result;
//         assembly {
//             result := mload(add(b, 32))
//         }
//         uint256 shift = (31 - b.length) * 8;
//         result = bytes32((uint256(result) >> shift) << shift);
//         result = result | bytes32(b.length * 2);
//         return result;
//     }

//     /// @dev Directly writes a Validator into ValidatorConfigV2 storage via vm.store,
//     ///      bypassing addValidator (and thus Ed25519 signature verification).
//     ///      Only works for inline strings (<=31 bytes).
//     ///      Safety: verifies addressToIndex and pubkeyToIndex slots are empty before writing.
//     ///      Storage layout for slot 4: index (0-63) | addedAtHeight (64-127) | deactivatedAtHeight (128-191)
//     function _addValidatorDirect(
//         address validatorAddr,
//         bytes32 publicKey,
//         string memory ingress,
//         string memory egress,
//         uint64 addedAtHeight,
//         uint64 deactivatedAtHeight
//     )
//         internal
//     {
//         address target = address(validatorConfigV2);

//         bytes32 addrSlot = keccak256(abi.encode(validatorAddr, SLOT_ADDRESS_TO_INDEX));
//         require(uint256(vm.load(target, addrSlot)) == 0, "addressToIndex slot not empty");

//         bytes32 pubkeySlot = keccak256(abi.encode(publicKey, SLOT_PUBKEY_TO_INDEX));
//         require(uint256(vm.load(target, pubkeySlot)) == 0, "pubkeyToIndex slot not empty");

//         uint256 arrayLen = uint256(vm.load(target, bytes32(SLOT_VALIDATORS_ARRAY)));
//         uint64 idx = uint64(arrayLen);

//         bytes32 arrayBase = keccak256(abi.encode(SLOT_VALIDATORS_ARRAY));
//         uint256 elemBase = uint256(arrayBase) + arrayLen * VALIDATOR_SLOT_SIZE;

//         // Slot 0: publicKey (bytes32)
//         vm.store(target, bytes32(elemBase), publicKey);

//         // Slot 1: validatorAddress (address, right-aligned in bytes32)
//         vm.store(target, bytes32(elemBase + 1), bytes32(uint256(uint160(validatorAddr))));

//         // Slot 2: ingress (string)
//         vm.store(target, bytes32(elemBase + 2), _encodeShortString(ingress));

//         // Slot 3: egress (string)
//         vm.store(target, bytes32(elemBase + 3), _encodeShortString(egress));

//         // Slot 4: packed uint64s - index (0-63) | addedAtHeight (64-127) | deactivatedAtHeight (128-191)
//         uint256 packed = uint256(idx)
//             | (uint256(addedAtHeight) << 64)
//             | (uint256(deactivatedAtHeight) << 128);
//         vm.store(target, bytes32(elemBase + 4), bytes32(packed));

//         // Update array length
//         vm.store(target, bytes32(SLOT_VALIDATORS_ARRAY), bytes32(arrayLen + 1));

//         // Update mappings (1-indexed: 0 means not found)
//         vm.store(target, addrSlot, bytes32(uint256(idx) + 1));
//         vm.store(target, pubkeySlot, bytes32(uint256(idx) + 1));
//     }

//     /// @dev Adds a validator via vm.store and updates ghost state.
//     function _tryAddValidator(
//         address validatorAddr,
//         bytes32 publicKey,
//         string memory ingress,
//         string memory egress
//     )
//         internal
//     {
//         uint64 idx = uint64(_ghostTotalCount);

//         // Add validator: addedAtHeight = current block, deactivatedAtHeight = 0 (active)
//         _addValidatorDirect(
//             validatorAddr,
//             publicKey,
//             ingress,
//             egress,
//             uint64(block.number), // addedAtHeight
//             0                      // deactivatedAtHeight (0 = active)
//         );

//         _ghostAddress[idx] = validatorAddr;
//         _ghostPubKey[idx] = publicKey;
//         _ghostAddedAtHeight[idx] = uint64(block.number);
//         _ghostDeactivatedAtHeight[idx] = 0;
//         _ghostIngress[idx] = ingress;
//         _ghostEgress[idx] = egress;
//         _ghostActiveIndex[validatorAddr] = idx;
//         _ghostAddressInUse[validatorAddr] = true;
//         _ghostPubKeyUsed[publicKey] = true;

//         // Track active ingress IP hash (IP only, without port)
//         _ghostActiveIngressIpHashes[_extractIngressIpHash(ingress)] = true;

//         _ghostTotalCount++;
//     }

//     /*//////////////////////////////////////////////////////////////
//                             FUZZ HANDLERS
//     //////////////////////////////////////////////////////////////*/

//     /// @notice Handler for adding validators via vm.store (bypasses Ed25519 sig verification)
//     /// @dev Tests TEMPO-VALV2-3 (count changes), TEMPO-VALV2-4 (height tracking)
//     function addValidator(uint256 validatorSeed, uint256 keySeed) external {
//         address validatorAddr = _selectPotentialValidator(validatorSeed);

//         if (_ghostAddressInUse[validatorAddr]) return;

//         bytes32 publicKey = _generatePublicKey(keySeed);
//         if (_ghostPubKeyUsed[publicKey]) return;

//         string memory ingress = _generateIngress(validatorSeed);
//         string memory egress = _generateEgress(validatorSeed);

//         // Check ingress IP uniqueness (match contract behavior - IP only, without port)
//         bytes32 ingressIpHash = _extractIngressIpHash(ingress);
//         if (_ghostActiveIngressIpHashes[ingressIpHash]) return;

//         // TEMPO-VALV2-3: Track counts before operation
//         uint256 activeCountBefore = _countActiveValidators();
//         uint256 totalCountBefore = _ghostTotalCount;

//         _tryAddValidator(validatorAddr, publicKey, ingress, egress);

//         // TEMPO-VALV2-3: addValidator should +1 active, +1 total
//         uint256 activeCountAfter = _countActiveValidators();
//         uint256 totalCountAfter = _ghostTotalCount;
//         assertEq(
//             activeCountAfter,
//             activeCountBefore + 1,
//             "TEMPO-VALV2-3: addValidator should increment active count by 1"
//         );
//         assertEq(
//             totalCountAfter,
//             totalCountBefore + 1,
//             "TEMPO-VALV2-3: addValidator should increment total count by 1"
//         );

//         // TEMPO-VALV2-4: Height tracking
//         IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validatorAddr);
//         assertEq(
//             v.addedAtHeight, uint64(block.number), "TEMPO-VALV2-4: addedAtHeight should be set"
//         );
//         assertEq(
//             v.deactivatedAtHeight,
//             0,
//             "TEMPO-VALV2-4: deactivatedAtHeight should be 0 for new validator"
//         );

//         if (_loggingEnabled) {
//             _log(
//                 string.concat(
//                     "ADD_VALIDATOR: ",
//                     vm.toString(validatorAddr),
//                     " index=",
//                     vm.toString(totalCountBefore)
//                 )
//             );
//         }
//     }

//     /// @notice Handler for unauthorized add attempts
//     /// @dev Tests TEMPO-VALV2-1 (owner-only enforcement)
//     function tryAddValidatorUnauthorized(uint256 callerSeed, uint256 validatorSeed) external {
//         address caller = _selectPotentialValidator(callerSeed);

//         if (caller == _ghostOwner) return;

//         address validatorAddr = _selectPotentialValidator(validatorSeed);
//         bytes32 publicKey = _generatePublicKey(validatorSeed);
//         string memory ingress = _generateIngress(validatorSeed);
//         string memory egress = _generateEgress(validatorSeed);

//         vm.startPrank(caller);
//         try validatorConfigV2.addValidator(validatorAddr, publicKey, ingress, egress, "") {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-1: Non-owner should not be able to add validator");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.Unauthorized.selector,
//                 "TEMPO-VALV2-1: Should revert with Unauthorized"
//             );
//         }
//     }

//     /// @notice Handler for deactivating validators (owner or validator)
//     /// @dev Tests TEMPO-VALV2-1 (dual-auth), TEMPO-VALV2-3 (count changes), TEMPO-VALV2-4 (height tracking)
//     function deactivateValidator(uint256 validatorSeed, bool asValidator) external {
//         (address validatorAddr, uint64 ghostIdx, bool found) = _selectActiveValidator(validatorSeed);
//         if (!found) return;

//         if (validatorAddr == _setupVal1 || validatorAddr == _setupVal2) return;

//         address caller = asValidator ? validatorAddr : _ghostOwner;

//         // TEMPO-VALV2-3: Track counts before operation
//         uint256 activeCountBefore = _countActiveValidators();
//         uint256 totalCountBefore = _ghostTotalCount;

//         vm.startPrank(caller);
//         try validatorConfigV2.deactivateValidator(validatorAddr) {
//             vm.stopPrank();

//             // Update ghost state
//             _ghostDeactivatedAtHeight[ghostIdx] = uint64(block.number);

//             // Remove ingress IP hash from active tracking
//             bytes32 ingressIpHash = _extractIngressIpHash(_ghostIngress[ghostIdx]);
//             delete _ghostActiveIngressIpHashes[ingressIpHash];

//             // TEMPO-VALV2-3: deactivateValidator should -1 active, +0 total
//             uint256 activeCountAfter = _countActiveValidators();
//             uint256 totalCountAfter = _ghostTotalCount;
//             assertEq(
//                 activeCountAfter,
//                 activeCountBefore - 1,
//                 "TEMPO-VALV2-3: deactivateValidator should decrement active count by 1"
//             );
//             assertEq(
//                 totalCountAfter,
//                 totalCountBefore,
//                 "TEMPO-VALV2-3: deactivateValidator should not change total count"
//             );

//             // TEMPO-VALV2-4: Height tracking
//             IValidatorConfigV2.Validator memory v =
//                 validatorConfigV2.validatorByAddress(validatorAddr);
//             assertEq(
//                 v.deactivatedAtHeight,
//                 uint64(block.number),
//                 "TEMPO-VALV2-4: deactivatedAtHeight should match block.number"
//             );

//             if (_loggingEnabled) {
//                 _log(
//                     string.concat(
//                         "DEACTIVATE: ",
//                         vm.toString(validatorAddr),
//                         " by ",
//                         asValidator ? "validator" : "owner",
//                         " at height=",
//                         vm.toString(block.number)
//                     )
//                 );
//             }
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             _assertKnownV2Error(reason);
//         }
//     }

//     /// @notice Handler for double-deactivation (should fail)
//     /// @dev Tests TEMPO-VALV2-5 (deactivate-once semantics)
//     ///      Must find a deactivated entry whose address's current mapping also points to a
//     ///      deactivated entry (i.e. not rotated into a new active entry).
//     function tryDeactivateAlreadyDeleted(uint256 validatorSeed) external {
//         uint256 len = _ghostTotalCount;
//         if (len == 0) return;

//         uint256 start = validatorSeed % len;
//         for (uint256 i = 0; i < len; i++) {
//             uint64 idx = uint64((start + i) % len);
//             if (_ghostDeactivatedAtHeight[idx] != 0) {
//                 address addr = _ghostAddress[idx];
//                 if (!_ghostAddressInUse[addr]) continue;
//                 uint64 activeIdx = _ghostActiveIndex[addr];
//                 if (_ghostDeactivatedAtHeight[activeIdx] == 0) continue;

//                 vm.startPrank(_ghostOwner);
//                 try validatorConfigV2.deactivateValidator(addr) {
//                     vm.stopPrank();
//                     revert("TEMPO-VALV2-5: Should not be able to deactivate twice");
//                 } catch (bytes memory reason) {
//                     vm.stopPrank();
//                     assertEq(
//                         bytes4(reason),
//                         IValidatorConfigV2.ValidatorAlreadyDeleted.selector,
//                         "TEMPO-VALV2-5: Should revert with ValidatorAlreadyDeleted"
//                     );
//                 }
//                 return;
//             }
//         }
//     }

//     /// @notice Handler for unauthorized deactivation attempts
//     /// @dev Tests TEMPO-VALV2-1 (third-party deactivation rejected)
//     function tryDeactivateUnauthorized(uint256 callerSeed, uint256 validatorSeed) external {
//         address caller = _selectPotentialValidator(callerSeed);
//         if (caller == _ghostOwner) return;

//         (address validatorAddr,, bool found) = _selectActiveValidator(validatorSeed);
//         if (!found) return;
//         if (caller == validatorAddr) return;

//         vm.startPrank(caller);
//         try validatorConfigV2.deactivateValidator(validatorAddr) {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-1: Third party should not be able to deactivate");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.Unauthorized.selector,
//                 "TEMPO-VALV2-1: Should revert with Unauthorized (deactivate)"
//             );
//         }
//     }

//     /// @notice Handler for duplicate address rejection
//     /// @dev Tests TEMPO-VALV2-6 (address uniqueness)
//     function tryAddDuplicateAddress(uint256 validatorSeed, uint256 keySeed) external {
//         (address existingAddr,, bool found) = _selectActiveValidator(validatorSeed);
//         if (!found) return;
//         bytes32 publicKey = _generatePublicKey(keySeed);
//         string memory ingress = _generateIngress(validatorSeed);
//         string memory egress = _generateEgress(validatorSeed);

//         vm.startPrank(_ghostOwner);
//         try validatorConfigV2.addValidator(existingAddr, publicKey, ingress, egress, "") {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-6: Should not add duplicate address");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.ValidatorAlreadyExists.selector,
//                 "TEMPO-VALV2-6: Should revert with ValidatorAlreadyExists"
//             );
//         }
//     }

//     /// @notice Handler for duplicate public key rejection
//     /// @dev Tests TEMPO-VALV2-7 (public key uniqueness)
//     function tryAddDuplicatePubKey(uint256 validatorSeed, uint256 existingSeed) external {
//         if (_ghostTotalCount == 0) return;

//         uint64 existingIdx = uint64(existingSeed % _ghostTotalCount);
//         bytes32 existingPubKey = _ghostPubKey[existingIdx];
//         if (existingPubKey == bytes32(0)) return;

//         address newAddr = _selectPotentialValidator(validatorSeed);
//         if (_ghostAddressInUse[newAddr]) return;

//         string memory ingress = _generateIngress(validatorSeed);
//         string memory egress = _generateEgress(validatorSeed);

//         vm.startPrank(_ghostOwner);
//         try validatorConfigV2.addValidator(newAddr, existingPubKey, ingress, egress, "") {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-7: Should not add duplicate public key");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.PublicKeyAlreadyExists.selector,
//                 "TEMPO-VALV2-7: Should revert with PublicKeyAlreadyExists"
//             );
//         }
//     }

//     /// @notice Handler for zero public key rejection
//     /// @dev Tests TEMPO-VALV2-7 (zero key rejection)
//     function tryAddZeroPubKey(uint256 validatorSeed) external {
//         address validatorAddr = _selectPotentialValidator(validatorSeed);
//         if (_ghostAddressInUse[validatorAddr]) return;

//         string memory ingress = _generateIngress(validatorSeed);
//         string memory egress = _generateEgress(validatorSeed);

//         vm.startPrank(_ghostOwner);
//         try validatorConfigV2.addValidator(validatorAddr, bytes32(0), ingress, egress, "") {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-7: Should reject zero public key");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.InvalidPublicKey.selector,
//                 "TEMPO-VALV2-7: Should revert with InvalidPublicKey"
//             );
//         }
//     }

//     /// @notice Handler for ownership transfer
//     /// @dev Tests TEMPO-VALV2-8 (owner transfer)
//     function transferOwnership(uint256 newOwnerSeed) external {
//         address newOwner = _selectPotentialValidator(newOwnerSeed);

//         vm.startPrank(_ghostOwner);
//         try validatorConfigV2.transferOwnership(newOwner) {
//             vm.stopPrank();

//             address oldOwner = _ghostOwner;
//             _ghostOwner = newOwner;

//             assertEq(validatorConfigV2.owner(), newOwner, "TEMPO-VALV2-8: Owner should be updated");

//             if (_loggingEnabled) {
//                 _log(
//                     string.concat(
//                         "TRANSFER_OWNERSHIP: ", vm.toString(oldOwner), " -> ", vm.toString(newOwner)
//                     )
//                 );
//             }
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             _assertKnownV2Error(reason);
//         }
//     }

//     /// @notice Handler for unauthorized ownership transfer
//     /// @dev Tests TEMPO-VALV2-8 (only owner can transfer)
//     function tryTransferOwnershipUnauthorized(uint256 callerSeed, uint256 newOwnerSeed) external {
//         address caller = _selectPotentialValidator(callerSeed);
//         if (caller == _ghostOwner) return;

//         address newOwner = _selectPotentialValidator(newOwnerSeed);

//         vm.startPrank(caller);
//         try validatorConfigV2.transferOwnership(newOwner) {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-8: Non-owner should not transfer ownership");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.Unauthorized.selector,
//                 "TEMPO-VALV2-8: Should revert with Unauthorized"
//             );
//         }
//     }

//     /// @notice Handler for setting DKG ceremony epoch
//     /// @dev Tests TEMPO-VALV2-9 (DKG ceremony setting)
//     function setNextDkgCeremony(uint64 epoch) external {
//         vm.startPrank(_ghostOwner);
//         try validatorConfigV2.setNextFullDkgCeremony(epoch) {
//             vm.stopPrank();

//             _ghostNextDkgCeremony = epoch;

//             assertEq(
//                 validatorConfigV2.getNextFullDkgCeremony(),
//                 epoch,
//                 "TEMPO-VALV2-9: DKG epoch should be set"
//             );

//             if (_loggingEnabled) {
//                 _log(string.concat("SET_DKG: epoch=", vm.toString(epoch)));
//             }
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             _assertKnownV2Error(reason);
//         }
//     }

//     /// @notice Handler for unauthorized DKG ceremony setting
//     /// @dev Tests TEMPO-VALV2-9 (only owner can set DKG)
//     function trySetDkgUnauthorized(uint256 callerSeed, uint64 epoch) external {
//         address caller = _selectPotentialValidator(callerSeed);
//         if (caller == _ghostOwner) return;

//         vm.startPrank(caller);
//         try validatorConfigV2.setNextFullDkgCeremony(epoch) {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-9: Non-owner should not set DKG ceremony");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.Unauthorized.selector,
//                 "TEMPO-VALV2-9: Should revert with Unauthorized"
//             );
//         }
//     }

//     /// @notice Handler for setting IP addresses (owner or validator)
//     /// @dev Tests TEMPO-VALV2-10 (dual-auth IP update)
//     function setIpAddresses(uint256 validatorSeed, uint256 ipSeed, bool asValidator) external {
//         (address validatorAddr, uint64 ghostIdx, bool found) = _selectActiveValidator(validatorSeed);
//         if (!found) return;

//         string memory newIngress = _generateIngress(ipSeed);
//         string memory newEgress = _generateEgress(ipSeed);

//         address caller = asValidator ? validatorAddr : _ghostOwner;

//         vm.startPrank(caller);
//         try validatorConfigV2.setIpAddresses(validatorAddr, newIngress, newEgress) {
//             vm.stopPrank();

//             // Update ghost ingress IP tracking
//             bytes32 oldIngressIpHash = _extractIngressIpHash(_ghostIngress[ghostIdx]);
//             bytes32 newIngressIpHash = _extractIngressIpHash(newIngress);
//             delete _ghostActiveIngressIpHashes[oldIngressIpHash];
//             _ghostActiveIngressIpHashes[newIngressIpHash] = true;

//             _ghostIngress[ghostIdx] = newIngress;
//             _ghostEgress[ghostIdx] = newEgress;

//             IValidatorConfigV2.Validator memory v =
//                 validatorConfigV2.validatorByAddress(validatorAddr);
//             assertEq(
//                 keccak256(bytes(v.ingress)),
//                 keccak256(bytes(newIngress)),
//                 "TEMPO-VALV2-10: Ingress should match"
//             );
//             assertEq(
//                 keccak256(bytes(v.egress)),
//                 keccak256(bytes(newEgress)),
//                 "TEMPO-VALV2-10: Egress should match"
//             );

//             if (_loggingEnabled) {
//                 _log(
//                     string.concat(
//                         "SET_IP: ",
//                         vm.toString(validatorAddr),
//                         " by ",
//                         asValidator ? "validator" : "owner"
//                     )
//                 );
//             }
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             _assertKnownV2Error(reason);
//         }
//     }

//     /// @notice Handler for unauthorized IP address update
//     /// @dev Tests TEMPO-VALV2-10 (only owner or validator can update IPs)
//     function trySetIpUnauthorized(uint256 callerSeed, uint256 validatorSeed) external {
//         address caller = _selectPotentialValidator(callerSeed);
//         if (caller == _ghostOwner) return;

//         (address validatorAddr,, bool found) = _selectActiveValidator(validatorSeed);
//         if (!found) return;
//         if (caller == validatorAddr) return;

//         string memory ingress = _generateIngress(callerSeed);
//         string memory egress = _generateEgress(callerSeed);

//         vm.startPrank(caller);
//         try validatorConfigV2.setIpAddresses(validatorAddr, ingress, egress) {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-10: Third party should not update IPs");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.Unauthorized.selector,
//                 "TEMPO-VALV2-10: Should revert with Unauthorized"
//             );
//         }
//     }

//     /// @notice Handler for transferring validator ownership (owner or validator)
//     /// @dev Tests TEMPO-VALV2-11 (validator address transfer)
//     function transferValidatorOwnership(
//         uint256 validatorSeed,
//         uint256 newAddrSeed,
//         bool asValidator
//     )
//         external
//     {
//         (address currentAddr, uint64 ghostIdx, bool found) = _selectActiveValidator(validatorSeed);
//         if (!found) return;

//         // Skip setup validators (indices 0 and 1) to preserve migration invariants
//         if (ghostIdx == 0 || ghostIdx == 1) return;

//         address newAddr = _selectPotentialValidator(newAddrSeed);
//         if (_ghostAddressInUse[newAddr] || newAddr == currentAddr) return;

//         address caller = asValidator ? currentAddr : _ghostOwner;

//         vm.startPrank(caller);
//         try validatorConfigV2.transferValidatorOwnership(currentAddr, newAddr) {
//             vm.stopPrank();

//             _ghostAddress[ghostIdx] = newAddr;
//             delete _ghostAddressInUse[currentAddr];
//             _ghostAddressInUse[newAddr] = true;
//             _ghostActiveIndex[newAddr] = ghostIdx;
//             delete _ghostActiveIndex[currentAddr];

//             IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(newAddr);
//             assertEq(v.validatorAddress, newAddr, "TEMPO-VALV2-11: Address should be updated");
//             assertEq(
//                 v.publicKey,
//                 _ghostPubKey[ghostIdx],
//                 "TEMPO-VALV2-11: Public key preserved after transfer"
//             );

//             if (_loggingEnabled) {
//                 _log(
//                     string.concat(
//                         "TRANSFER_VAL_OWNERSHIP: ",
//                         vm.toString(currentAddr),
//                         " -> ",
//                         vm.toString(newAddr)
//                     )
//                 );
//             }
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             _assertKnownV2Error(reason);
//         }
//     }

//     /// @notice Handler for transferring to existing address (should fail)
//     /// @dev Tests TEMPO-VALV2-11 (duplicate address on transfer)
//     function tryTransferValidatorToDuplicate(uint256 seed1, uint256 seed2) external {
//         if (_ghostTotalCount < 2) return;

//         uint64 idx1 = uint64(seed1 % _ghostTotalCount);
//         uint64 idx2 = uint64(seed2 % _ghostTotalCount);
//         address addr1 = _ghostAddress[idx1];
//         address addr2 = _ghostAddress[idx2];
//         if (addr1 == addr2) return;
//         if (!_ghostAddressInUse[addr1] || !_ghostAddressInUse[addr2]) return;

//         vm.startPrank(_ghostOwner);
//         try validatorConfigV2.transferValidatorOwnership(addr1, addr2) {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-11: Should not transfer to existing address");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.ValidatorAlreadyExists.selector,
//                 "TEMPO-VALV2-11: Should revert with ValidatorAlreadyExists"
//             );
//         }
//     }

//     /// @notice Handler for rotating validators (owner or validator)
//     /// @dev Tests TEMPO-VALV2-1 (dual-auth), TEMPO-VALV2-3 (count changes), TEMPO-VALV2-4 (height tracking)
//     ///      Skips setup validators to keep the set functional.
//     function rotateValidator(uint256 validatorSeed, uint256 keySeed, bool asValidator) external {
//         (address validatorAddr, uint64 oldGhostIdx, bool found) =
//             _selectActiveValidator(validatorSeed);
//         if (!found) return;

//         if (validatorAddr == _setupVal1 || validatorAddr == _setupVal2) return;

//         bytes32 newPubKey = _generatePublicKey(keySeed);
//         if (_ghostPubKeyUsed[newPubKey]) return;

//         string memory ingress = _generateIngress(keySeed);
//         string memory egress = _generateEgress(keySeed);

//         // Check ingress IP uniqueness before rotation (unless reusing same IP)
//         bytes32 oldIngressIpHash = _extractIngressIpHash(_ghostIngress[oldGhostIdx]);
//         bytes32 newIngressIpHash = _extractIngressIpHash(ingress);
//         if (newIngressIpHash != oldIngressIpHash && _ghostActiveIngressIpHashes[newIngressIpHash]) {
//             return;
//         }

//         address caller = asValidator ? validatorAddr : _ghostOwner;

//         // TEMPO-VALV2-3: Track counts before operation
//         uint256 activeCountBefore = _countActiveValidators();
//         uint256 totalCountBefore = _ghostTotalCount;

//         vm.startPrank(caller);
//         try validatorConfigV2.rotateValidator(validatorAddr, newPubKey, ingress, egress, "") {
//             vm.stopPrank();

//             // Remove old ingress IP hash
//             delete _ghostActiveIngressIpHashes[oldIngressIpHash];

//             _ghostDeactivatedAtHeight[oldGhostIdx] = uint64(block.number);

//             uint64 newIdx = uint64(_ghostTotalCount);
//             _ghostAddress[newIdx] = validatorAddr;
//             _ghostPubKey[newIdx] = newPubKey;
//             _ghostAddedAtHeight[newIdx] = uint64(block.number);
//             _ghostDeactivatedAtHeight[newIdx] = 0;
//             _ghostIngress[newIdx] = ingress;
//             _ghostEgress[newIdx] = egress;
//             _ghostActiveIndex[validatorAddr] = newIdx;
//             _ghostPubKeyUsed[newPubKey] = true;

//             // Add new ingress IP hash
//             _ghostActiveIngressIpHashes[newIngressIpHash] = true;

//             _ghostTotalCount++;

//             // TEMPO-VALV2-3: rotateValidator should +0 active, +1 total
//             uint256 activeCountAfter = _countActiveValidators();
//             uint256 totalCountAfter = _ghostTotalCount;
//             assertEq(
//                 activeCountAfter,
//                 activeCountBefore,
//                 "TEMPO-VALV2-3: rotateValidator should not change active count"
//             );
//             assertEq(
//                 totalCountAfter,
//                 totalCountBefore + 1,
//                 "TEMPO-VALV2-3: rotateValidator should increment total count by 1"
//             );

//             // TEMPO-VALV2-4: Height tracking for both old and new validators
//             IValidatorConfigV2.Validator memory oldV =
//                 validatorConfigV2.validatorByIndex(oldGhostIdx);
//             assertEq(
//                 oldV.deactivatedAtHeight,
//                 uint64(block.number),
//                 "TEMPO-VALV2-4: Old validator deactivatedAtHeight should be current block"
//             );

//             IValidatorConfigV2.Validator memory newV =
//                 validatorConfigV2.validatorByAddress(validatorAddr);
//             assertEq(
//                 newV.publicKey, newPubKey, "TEMPO-VALV2-4: New public key should be set"
//             );
//             assertEq(
//                 newV.addedAtHeight,
//                 uint64(block.number),
//                 "TEMPO-VALV2-4: New validator addedAtHeight should be current block"
//             );
//             assertEq(
//                 newV.deactivatedAtHeight, 0, "TEMPO-VALV2-4: New validator should be active"
//             );

//             if (_loggingEnabled) {
//                 _log(
//                     string.concat(
//                         "ROTATE: ",
//                         vm.toString(validatorAddr),
//                         " oldIdx=",
//                         vm.toString(oldGhostIdx),
//                         " newIdx=",
//                         vm.toString(newIdx)
//                     )
//                 );
//             }
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             _assertKnownV2Error(reason);
//         }
//     }

//     /// @notice Handler to test that operations fail pre-initialization
//     /// @dev Tests TEMPO-VALV2-5: addValidator blocked pre-init
//     function tryAddValidatorPreInit(uint256 validatorSeed) external {
//         // This test is only relevant if we're not initialized
//         // Since our setUp initializes, we skip this handler
//         if (_ghostInitialized) return;

//         address validatorAddr = _selectPotentialValidator(validatorSeed);
//         bytes32 publicKey = _generatePublicKey(validatorSeed);
//         string memory ingress = _generateIngress(validatorSeed);
//         string memory egress = _generateEgress(validatorSeed);

//         vm.startPrank(_ghostOwner);
//         try validatorConfigV2.addValidator(validatorAddr, publicKey, ingress, egress, "") {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-5: addValidator should fail pre-initialization");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.NotInitialized.selector,
//                 "TEMPO-VALV2-5: Should revert with NotInitialized"
//             );
//         }
//     }

//     /// @notice Handler to test that migration fails post-initialization
//     /// @dev Tests TEMPO-VALV2-6: migrateValidator blocked post-init
//     function tryMigrateValidatorPostInit(uint64 idx) external {
//         // This test is only relevant if we're initialized
//         if (!_ghostInitialized) return;

//         vm.startPrank(_ghostOwner);
//         try validatorConfigV2.migrateValidator(idx) {
//             vm.stopPrank();
//             revert("TEMPO-VALV2-6: migrateValidator should fail post-initialization");
//         } catch (bytes memory reason) {
//             vm.stopPrank();
//             assertEq(
//                 bytes4(reason),
//                 IValidatorConfigV2.AlreadyInitialized.selector,
//                 "TEMPO-VALV2-6: Should revert with AlreadyInitialized"
//             );
//         }
//     }

//     /*//////////////////////////////////////////////////////////////
//                          GLOBAL INVARIANTS
//     //////////////////////////////////////////////////////////////*/

//     /// @notice Run all invariant checks
//     function invariant_globalInvariants() public view {
//         _invariantAppendOnlyCount();           // VALV2-8
//         _invariantDeleteOnce();                // VALV2-9
//         _invariantHeightTracking();            // VALV2-10
//         _invariantAddressUniqueness();         // VALV2-11
//         _invariantPubKeyUniqueness();          // VALV2-12
//         _invariantIpUniqueness();              // VALV2-13
//         _invariantIndexSequential();           // VALV2-14
//         _invariantActiveValidatorSubset();     // VALV2-15
//         _invariantValidatorDataConsistency();  // VALV2-16
//         _invariantValidatorCountConsistency(); // VALV2-17
//         _invariantAddressLookupCorrectness();  // VALV2-18
//         _invariantPubkeyLookupCorrectness();   // VALV2-19
//         _invariantOwnerConsistency();          // VALV2-20
//         _invariantDkgCeremonyConsistency();    // VALV2-21
//         _invariantInitializationOneWay();      // VALV2-22
//         _invariantMigrationCompleteness();     // VALV2-23
//         _invariantMigrationIdentity();         // VALV2-24
//         _invariantMigrationActivity();         // VALV2-25
//     }

//     /// @notice TEMPO-VALV2-8: Validator count only increases (append-only)
//     function _invariantAppendOnlyCount() internal view {
//         uint64 count = validatorConfigV2.validatorCount();
//         assertEq(count, _ghostTotalCount, "TEMPO-VALV2-8: Count should match ghost total");
//         assertGe(count, 2, "TEMPO-VALV2-8: Count should be at least 2 (setup validators)");
//     }

//     /// @notice TEMPO-VALV2-20: Owner matches ghost state
//     function _invariantOwnerConsistency() internal view {
//         assertEq(
//             validatorConfigV2.owner(), _ghostOwner, "TEMPO-VALV2-20: Owner should match ghost state"
//         );
//     }

//     /// @notice TEMPO-VALV2-16: All validator data matches ghost state (index-keyed)
//     function _invariantValidatorDataConsistency() internal view {
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();
//         assertEq(vals.length, _ghostTotalCount, "TEMPO-VALV2-16: Array length mismatch");

//         for (uint256 i = 0; i < vals.length; i++) {
//             uint64 idx = uint64(i);
//             assertEq(
//                 vals[i].validatorAddress, _ghostAddress[idx], "TEMPO-VALV2-16: Address mismatch"
//             );
//             assertEq(vals[i].publicKey, _ghostPubKey[idx], "TEMPO-VALV2-16: Public key mismatch");
//             assertEq(vals[i].index, idx, "TEMPO-VALV2-16: Index mismatch");
//             assertEq(
//                 vals[i].addedAtHeight,
//                 _ghostAddedAtHeight[idx],
//                 "TEMPO-VALV2-16: addedAtHeight mismatch"
//             );
//             assertEq(
//                 vals[i].deactivatedAtHeight,
//                 _ghostDeactivatedAtHeight[idx],
//                 "TEMPO-VALV2-16: deactivatedAtHeight mismatch"
//             );
//         }
//     }

//     /// @notice TEMPO-VALV2-14: All indices are sequential (0, 1, 2, ...)
//     function _invariantIndexSequential() internal view {
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

//         for (uint256 i = 0; i < vals.length; i++) {
//             assertEq(vals[i].index, i, "TEMPO-VALV2-14: Index should equal array position");
//         }
//     }

//     /// @notice TEMPO-VALV2-12: All public keys are unique and non-zero
//     function _invariantPubKeyUniqueness() internal view {
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

//         for (uint256 i = 0; i < vals.length; i++) {
//             assertTrue(
//                 vals[i].publicKey != bytes32(0), "TEMPO-VALV2-12: Public key must not be zero"
//             );

//             for (uint256 j = i + 1; j < vals.length; j++) {
//                 assertTrue(
//                     vals[i].publicKey != vals[j].publicKey,
//                     "TEMPO-VALV2-12: Public keys must be unique"
//                 );
//             }
//         }
//     }

//     /// @notice TEMPO-VALV2-15: Active validators are a proper subset of all validators
//     function _invariantActiveValidatorSubset() internal view {
//         IValidatorConfigV2.Validator[] memory all = validatorConfigV2.getAllValidators();
//         IValidatorConfigV2.Validator[] memory active = validatorConfigV2.getActiveValidators();

//         assertLe(active.length, all.length, "TEMPO-VALV2-15: Active count <= total count");

//         uint256 expectedActive = 0;
//         for (uint256 i = 0; i < all.length; i++) {
//             if (all[i].deactivatedAtHeight == 0) {
//                 expectedActive++;
//             }
//         }
//         assertEq(
//             active.length,
//             expectedActive,
//             "TEMPO-VALV2-15: Active count should match filtered count"
//         );

//         for (uint256 i = 0; i < active.length; i++) {
//             assertEq(
//                 active[i].deactivatedAtHeight,
//                 0,
//                 "TEMPO-VALV2-15: Active validators must have deactivatedAtHeight == 0"
//             );
//         }
//     }

//     /// @notice TEMPO-VALV2-21: DKG epoch matches ghost state
//     function _invariantDkgCeremonyConsistency() internal view {
//         assertEq(
//             validatorConfigV2.getNextFullDkgCeremony(),
//             _ghostNextDkgCeremony,
//             "TEMPO-VALV2-21: DKG epoch should match ghost state"
//         );
//     }

//     /// @notice TEMPO-VALV2-10: Height tracking invariants
//     /// @dev For active validators: addedAtHeight > 0, deactivatedAtHeight == 0
//     ///      For deactivated validators: deactivatedAtHeight >= addedAtHeight
//     function _invariantHeightTracking() internal view {
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

//         for (uint256 i = 0; i < vals.length; i++) {
//             assertTrue(
//                 vals[i].addedAtHeight > 0,
//                 "TEMPO-VALV2-10: addedAtHeight must be > 0"
//             );

//             if (vals[i].deactivatedAtHeight != 0) {
//                 assertGe(
//                     vals[i].deactivatedAtHeight,
//                     vals[i].addedAtHeight,
//                     "TEMPO-VALV2-10: deactivatedAtHeight must be >= addedAtHeight"
//                 );
//             }
//         }
//     }

//     /// @notice TEMPO-VALV2-13: Ingress IP uniqueness among active validators
//     /// @dev No two active validators share the same ingress IP (port is ignored)
//     function _invariantIpUniqueness() internal view {
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

//         // Check uniqueness among active validators
//         for (uint256 i = 0; i < vals.length; i++) {
//             if (vals[i].deactivatedAtHeight != 0) continue; // Skip deactivated

//             for (uint256 j = i + 1; j < vals.length; j++) {
//                 if (vals[j].deactivatedAtHeight != 0) continue; // Skip deactivated

//                 // Check ingress IP uniqueness (extract IP without port)
//                 bytes32 ipI = _extractIngressIpHash(vals[i].ingress);
//                 bytes32 ipJ = _extractIngressIpHash(vals[j].ingress);
//                 assertTrue(
//                     ipI != ipJ, "TEMPO-VALV2-13: Active validators must have unique ingress IPs"
//                 );

//                 // Note: egress uniqueness is NOT enforced
//             }
//         }
//     }

//     /// @notice TEMPO-VALV2-9: Delete-once - deactivatedAtHeight never changes once set
//     function _invariantDeleteOnce() internal view {
//         // This is enforced by the contract and validated by our handlers
//         // The property: once deactivatedAtHeight != 0, it cannot change
//         // We verify this by checking that all deactivated validators in contract
//         // match our ghost state (which only sets deactivatedAtHeight once)
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

//         for (uint256 i = 0; i < vals.length; i++) {
//             uint64 idx = uint64(i);
//             assertEq(
//                 vals[i].deactivatedAtHeight,
//                 _ghostDeactivatedAtHeight[idx],
//                 "TEMPO-VALV2-9: deactivatedAtHeight must never change once set"
//             );
//         }
//     }

//     /// @notice TEMPO-VALV2-11: Address uniqueness among active validators
//     /// @dev At most one active validator per address; deactivated addresses may be reused
//     function _invariantAddressUniqueness() internal view {
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

//         // Only check active validators (deactivatedAtHeight == 0)
//         for (uint256 i = 0; i < vals.length; i++) {
//             if (vals[i].deactivatedAtHeight != 0) continue;

//             for (uint256 j = i + 1; j < vals.length; j++) {
//                 if (vals[j].deactivatedAtHeight != 0) continue;

//                 assertTrue(
//                     vals[i].validatorAddress != vals[j].validatorAddress,
//                     "TEMPO-VALV2-11: Active validators must have unique addresses"
//                 );
//             }
//         }
//     }

//     /// @notice TEMPO-VALV2-17: Validator count consistency
//     /// @dev validatorCount() equals actual array length
//     function _invariantValidatorCountConsistency() internal view {
//         uint64 count = validatorConfigV2.validatorCount();
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();
//         assertEq(
//             count,
//             vals.length,
//             "TEMPO-VALV2-17: validatorCount must equal array length"
//         );
//     }

//     /// @notice TEMPO-VALV2-18: Address lookup correctness
//     /// @dev validatorByAddress returns the currently active (or most recent) validator for that address
//     ///      After rotation, old deactivated validators with the same address exist in the array,
//     ///      but lookup should return the active one (or most recent if all deactivated)
//     function _invariantAddressLookupCorrectness() internal view {
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

//         // For each unique address, check that validatorByAddress returns the expected validator
//         // (the active one, or most recent if all deactivated)
//         for (uint256 i = 0; i < vals.length; i++) {
//             address addr = vals[i].validatorAddress;

//             // Find the most recent validator for this address
//             uint256 mostRecentIdx = i;
//             for (uint256 j = i + 1; j < vals.length; j++) {
//                 if (vals[j].validatorAddress == addr) {
//                     mostRecentIdx = j;
//                 }
//             }

//             // validatorByAddress should return the most recent validator for this address
//             if (mostRecentIdx == i) {
//                 IValidatorConfigV2.Validator memory lookedUp =
//                     validatorConfigV2.validatorByAddress(addr);

//                 assertEq(
//                     lookedUp.index,
//                     vals[i].index,
//                     "TEMPO-VALV2-18: Address lookup must return most recent validator"
//                 );
//                 assertEq(
//                     lookedUp.publicKey,
//                     vals[i].publicKey,
//                     "TEMPO-VALV2-18: Address lookup must preserve public key"
//                 );
//             }
//         }
//     }

//     /// @notice TEMPO-VALV2-19: Public key lookup correctness
//     /// @dev For every validator, validatorByPublicKey returns the correct validator
//     function _invariantPubkeyLookupCorrectness() internal view {
//         IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getAllValidators();

//         for (uint256 i = 0; i < vals.length; i++) {
//             bytes32 pubkey = vals[i].publicKey;
//             IValidatorConfigV2.Validator memory lookedUp =
//                 validatorConfigV2.validatorByPublicKey(pubkey);

//             assertEq(
//                 lookedUp.publicKey,
//                 vals[i].publicKey,
//                 "TEMPO-VALV2-19: Pubkey lookup must return correct validator"
//             );
//             assertEq(
//                 lookedUp.validatorAddress,
//                 vals[i].validatorAddress,
//                 "TEMPO-VALV2-19: Pubkey lookup must preserve address"
//             );
//             assertEq(
//                 lookedUp.index,
//                 vals[i].index,
//                 "TEMPO-VALV2-19: Pubkey lookup must preserve index"
//             );
//         }
//     }

//     /// @notice TEMPO-VALV2-22: Initialization one-way
//     /// @dev Once isInitialized() == true, it remains true forever
//     function _invariantInitializationOneWay() internal view {
//         bool isInit = validatorConfigV2.isInitialized();
//         if (_ghostInitialized) {
//             assertTrue(
//                 isInit,
//                 "TEMPO-VALV2-22: Once initialized, must remain initialized"
//             );
//             assertEq(
//                 validatorConfigV2.getInitializedAtHeight(),
//                 _ghostInitializedAtHeight,
//                 "TEMPO-VALV2-22: Initialization height must match ghost state"
//             );
//         }
//     }

//     /// @notice TEMPO-VALV2-23: Migration completeness
//     /// @dev If not initialized, validatorCount <= V1.getAllValidators().length
//     function _invariantMigrationCompleteness() internal view {
//         if (!_ghostInitialized) {
//             IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();
//             uint64 v2Count = validatorConfigV2.validatorCount();
//             assertLe(
//                 v2Count,
//                 v1Vals.length,
//                 "TEMPO-VALV2-23: Migration cannot exceed V1 validator count"
//             );
//         }
//     }

//     /// @notice TEMPO-VALV2-24: Migration preserves identity
//     /// @dev For each migrated validator: V2 pubkey matches V1 (pubkeys are immutable)
//     ///      Note: Addresses may change via transferValidatorOwnership post-migration,
//     ///      but public keys are globally unique and immutable
//     function _invariantMigrationIdentity() internal view {
//         if (_ghostInitialized) {
//             IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();

//             // Check all validators that were migrated from V1
//             uint256 migratedCount = v1Vals.length < _ghostTotalCount
//                 ? v1Vals.length
//                 : _ghostTotalCount;

//             for (uint256 i = 0; i < migratedCount; i++) {
//                 assertEq(
//                     _ghostPubKey[uint64(i)],
//                     v1Vals[i].publicKey,
//                     "TEMPO-VALV2-24: Migrated validator public key must match V1"
//                 );
//                 // Note: We don't check address equality because transferValidatorOwnership
//                 // can legitimately change addresses post-migration
//             }
//         }
//     }

//     /// @notice TEMPO-VALV2-25: Migration preserves activity
//     /// @dev For each migrated validator: V2 active status matches V1
//     function _invariantMigrationActivity() internal view {
//         if (_ghostInitialized) {
//             IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();

//             // Check all validators that were migrated from V1
//             uint256 migratedCount = v1Vals.length < _ghostTotalCount
//                 ? v1Vals.length
//                 : _ghostTotalCount;

//             for (uint256 i = 0; i < migratedCount; i++) {
//                 uint64 idx = uint64(i);
//                 bool v1Active = v1Vals[i].active;
//                 bool v2Active = _ghostDeactivatedAtHeight[idx] == 0;

//                 assertEq(
//                     v2Active,
//                     v1Active,
//                     "TEMPO-VALV2-25: Migrated validator activity status must match V1"
//                 );
//             }
//         }
//     }

//     /// @dev Helper to extract and hash IP from ingress (ip:port -> keccak256(ip))
//     function _extractIngressIpHash(string memory ingress) internal pure returns (bytes32) {
//         bytes memory b = bytes(ingress);
//         if (b.length == 0) return keccak256(b);

//         // IPv6 format: [ip]:port -> extract ip
//         if (b[0] == "[") {
//             for (uint256 i = 1; i < b.length; i++) {
//                 if (b[i] == "]") {
//                     bytes memory ip = new bytes(i - 1);
//                     for (uint256 j = 1; j < i; j++) {
//                         ip[j - 1] = b[j];
//                     }
//                     return keccak256(ip);
//                 }
//             }
//             return keccak256(b); // Malformed
//         }

//         // IPv4 format: ip:port -> extract ip
//         for (uint256 i = 0; i < b.length; i++) {
//             if (b[i] == ":") {
//                 bytes memory ip = new bytes(i);
//                 for (uint256 j = 0; j < i; j++) {
//                     ip[j] = b[j];
//                 }
//                 return keccak256(ip);
//             }
//         }

//         // No port found
//         return keccak256(b);
//     }

// }
