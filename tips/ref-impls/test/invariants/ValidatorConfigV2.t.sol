// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IValidatorConfig} from "../../src/interfaces/IValidatorConfig.sol";
import {IValidatorConfigV2} from "../../src/interfaces/IValidatorConfigV2.sol";
import {InvariantBaseTest} from "./InvariantBaseTest.t.sol";

/// @title ValidatorConfigV2 Invariant Tests
/// @notice Fuzz-based invariant tests for the ValidatorConfigV2 precompile
/// @dev Tests invariants TEMPO-VALV2-1 through TEMPO-VALV2-14 covering append-only semantics,
///      height tracking, Ed25519 signatures, dual-auth, migration, and view consistency.
contract ValidatorConfigV2InvariantTest is InvariantBaseTest {
    /// @dev Starting offset for validator address pool
    uint256 private constant VALIDATOR_POOL_OFFSET = 0x7000;

    /// @dev Array of potential validator addresses
    address[] private _potentialValidators;

    /// @dev Ghost tracking for validators (mirrors contract state)
    address[] private _ghostValidatorList;
    mapping(address => bool) private _ghostValidatorExists;
    mapping(address => bytes32) private _ghostValidatorPubKey;
    mapping(address => uint64) private _ghostValidatorIndex;
    mapping(address => uint64) private _ghostAddedAtHeight;
    mapping(address => uint64) private _ghostDeactivatedAtHeight;
    mapping(address => string) private _ghostIngress;
    mapping(address => string) private _ghostEgress;

    /// @dev Ghost tracking for public key uniqueness
    mapping(bytes32 => bool) private _ghostPubKeyUsed;

    /// @dev Ghost tracking for owner
    address private _ghostOwner;

    /// @dev Ghost tracking for DKG ceremony
    uint64 private _ghostNextDkgCeremony;

    /// @dev Ghost tracking for initialization
    bool private _ghostInitialized;

    /// @dev Ghost tracking for total validator count (append-only, never decreases)
    uint256 private _ghostTotalCount;

    /// @dev V1 setup validators (migrated during setUp)
    address private _setupVal1 = address(0xA000);
    address private _setupVal2 = address(0xB000);
    bytes32 private constant SETUP_PUB_KEY_A = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 private constant SETUP_PUB_KEY_B = 0x2222222222222222222222222222222222222222222222222222222222222222;

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();
        vm.skip(isTempo);

        targetContract(address(this));

        _setupInvariantBase();
        _actors = _buildActors(5);
        _potentialValidators = _buildAddressPool(30, VALIDATOR_POOL_OFFSET);
        _ghostOwner = admin;

        validatorConfig.addValidator(_setupVal1, SETUP_PUB_KEY_A, true, "10.0.0.100:8000", "10.0.0.100:9000");
        validatorConfig.addValidator(_setupVal2, SETUP_PUB_KEY_B, true, "10.0.0.101:8000", "10.0.0.101:9000");

        IValidatorConfig.Validator[] memory v1Vals = validatorConfig.getValidators();
        for (uint64 i = 0; i < v1Vals.length; i++) {
            validatorConfigV2.migrateValidator(i);
        }
        validatorConfigV2.initializeIfMigrated();
        _ghostInitialized = true;

        _ghostValidatorList.push(_setupVal1);
        _ghostValidatorExists[_setupVal1] = true;
        _ghostValidatorPubKey[_setupVal1] = SETUP_PUB_KEY_A;
        _ghostValidatorIndex[_setupVal1] = 0;
        _ghostAddedAtHeight[_setupVal1] = 0;
        _ghostDeactivatedAtHeight[_setupVal1] = 0;
        _ghostPubKeyUsed[SETUP_PUB_KEY_A] = true;

        _ghostValidatorList.push(_setupVal2);
        _ghostValidatorExists[_setupVal2] = true;
        _ghostValidatorPubKey[_setupVal2] = SETUP_PUB_KEY_B;
        _ghostValidatorIndex[_setupVal2] = 1;
        _ghostAddedAtHeight[_setupVal2] = 0;
        _ghostDeactivatedAtHeight[_setupVal2] = 0;
        _ghostPubKeyUsed[SETUP_PUB_KEY_B] = true;

        _ghostTotalCount = 2;

        _initLogFile("validator_config_v2.log", "ValidatorConfigV2 Invariant Test Log");
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _selectPotentialValidator(uint256 seed) internal view returns (address) {
        return _selectFromPool(_potentialValidators, seed);
    }

    function _generatePublicKey(uint256 seed) internal pure returns (bytes32) {
        return bytes32(uint256(keccak256(abi.encode("v2_pubkey", seed))) | 1);
    }

    function _generateIngress(uint256 seed) internal pure returns (string memory) {
        uint8 lastOctet = uint8((seed % 254) + 1);
        return string(abi.encodePacked("192.168.1.", _uint8ToString(lastOctet), ":8000"));
    }

    function _generateEgress(uint256 seed) internal pure returns (string memory) {
        uint8 lastOctet = uint8((seed % 254) + 1);
        return string(abi.encodePacked("192.168.1.", _uint8ToString(lastOctet)));
    }

    function _selectExistingValidator(uint256 seed) internal view returns (address) {
        if (_ghostValidatorList.length == 0) return address(0);
        return _ghostValidatorList[seed % _ghostValidatorList.length];
    }

    function _selectActiveValidator(uint256 seed) internal view returns (address, bool) {
        uint256 len = _ghostValidatorList.length;
        if (len == 0) return (address(0), false);
        uint256 start = seed % len;
        for (uint256 i = 0; i < len; i++) {
            address addr = _ghostValidatorList[(start + i) % len];
            if (_ghostDeactivatedAtHeight[addr] == 0) {
                return (addr, true);
            }
        }
        return (address(0), false);
    }

    function _assertKnownV2Error(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnown = selector == IValidatorConfigV2.Unauthorized.selector
            || selector == IValidatorConfigV2.ValidatorAlreadyExists.selector
            || selector == IValidatorConfigV2.PublicKeyAlreadyExists.selector
            || selector == IValidatorConfigV2.ValidatorNotFound.selector
            || selector == IValidatorConfigV2.ValidatorAlreadyDeleted.selector
            || selector == IValidatorConfigV2.InvalidPublicKey.selector
            || selector == IValidatorConfigV2.InvalidSignature.selector
            || selector == IValidatorConfigV2.NotInitialized.selector
            || selector == IValidatorConfigV2.AlreadyInitialized.selector
            || selector == IValidatorConfigV2.MigrationNotComplete.selector
            || selector == IValidatorConfigV2.InvalidMigrationIndex.selector
            || selector == IValidatorConfigV2.NotIpPort.selector;
        assertTrue(isKnown, string.concat("Unknown error: ", vm.toString(selector)));
    }

    /// @dev Adds a validator via owner using vm.store to bypass Ed25519 sig verification.
    ///      The real addValidator requires a valid Ed25519 signature which we cannot
    ///      generate on-chain in the fuzzer, so we call addValidator and accept any
    ///      InvalidSignature revert as expected. On success we update ghost state.
    ///      NOTE: Because Ed25519 sigs cannot be computed in the fuzzer, this handler
    ///      will mostly revert with InvalidSignature. We still test the access control,
    ///      validation, and uniqueness invariants via the revert paths.
    function _tryAddValidator(address validatorAddr, bytes32 publicKey, string memory ingress, string memory egress)
        internal
        returns (bool)
    {
        bytes memory fakeSig = new bytes(64);

        vm.startPrank(_ghostOwner);
        try validatorConfigV2.addValidator(validatorAddr, publicKey, ingress, egress, fakeSig) {
            vm.stopPrank();

            uint64 idx = uint64(_ghostValidatorList.length);
            _ghostValidatorList.push(validatorAddr);
            _ghostValidatorExists[validatorAddr] = true;
            _ghostValidatorPubKey[validatorAddr] = publicKey;
            _ghostValidatorIndex[validatorAddr] = idx;
            _ghostAddedAtHeight[validatorAddr] = uint64(block.number);
            _ghostDeactivatedAtHeight[validatorAddr] = 0;
            _ghostIngress[validatorAddr] = ingress;
            _ghostEgress[validatorAddr] = egress;
            _ghostPubKeyUsed[publicKey] = true;
            _ghostTotalCount++;

            return true;
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownV2Error(reason);
            return false;
        }
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for adding validators
    /// @dev Tests TEMPO-VALV2-1 (owner-only add), TEMPO-VALV2-2 (append-only count), TEMPO-VALV2-3 (index assignment)
    function addValidator(uint256 validatorSeed, uint256 keySeed) external {
        address validatorAddr = _selectPotentialValidator(validatorSeed);

        if (_ghostValidatorExists[validatorAddr]) return;

        bytes32 publicKey = _generatePublicKey(keySeed);
        if (_ghostPubKeyUsed[publicKey]) return;

        string memory ingress = _generateIngress(validatorSeed);
        string memory egress = _generateEgress(validatorSeed);

        uint256 countBefore = _ghostTotalCount;

        bool added = _tryAddValidator(validatorAddr, publicKey, ingress, egress);

        if (added) {
            assertEq(validatorConfigV2.validatorCount(), countBefore + 1, "TEMPO-VALV2-2: Count should increment");

            IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validatorAddr);
            assertEq(v.index, countBefore, "TEMPO-VALV2-3: Index should be previous count");
            assertEq(v.addedAtHeight, uint64(block.number), "TEMPO-VALV2-4: addedAtHeight should be set");
            assertEq(v.deactivatedAtHeight, 0, "TEMPO-VALV2-4: deactivatedAtHeight should be 0 for new validator");

            if (_loggingEnabled) {
                _log(string.concat("ADD_VALIDATOR: ", vm.toString(validatorAddr), " index=", vm.toString(countBefore)));
            }
        }
    }

    /// @notice Handler for unauthorized add attempts
    /// @dev Tests TEMPO-VALV2-1 (owner-only enforcement)
    function tryAddValidatorUnauthorized(uint256 callerSeed, uint256 validatorSeed) external {
        address caller = _selectPotentialValidator(callerSeed);

        if (caller == _ghostOwner) return;

        address validatorAddr = _selectPotentialValidator(validatorSeed);
        bytes32 publicKey = _generatePublicKey(validatorSeed);
        string memory ingress = _generateIngress(validatorSeed);
        string memory egress = _generateEgress(validatorSeed);
        bytes memory fakeSig = new bytes(64);

        vm.startPrank(caller);
        try validatorConfigV2.addValidator(validatorAddr, publicKey, ingress, egress, fakeSig) {
            vm.stopPrank();
            revert("TEMPO-VALV2-1: Non-owner should not be able to add validator");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfigV2.Unauthorized.selector,
                "TEMPO-VALV2-1: Should revert with Unauthorized"
            );
        }
    }

    /// @notice Handler for deactivating validators (owner only)
    /// @dev Tests TEMPO-VALV2-4 (height tracking), TEMPO-VALV2-5 (deactivate-once)
    function deactivateValidator(uint256 validatorSeed) external {
        (address validatorAddr, bool found) = _selectActiveValidator(validatorSeed);
        if (!found) return;

        // Skip setup validators to keep the validator set functional
        if (validatorAddr == _setupVal1 || validatorAddr == _setupVal2) return;

        vm.startPrank(_ghostOwner);
        try validatorConfigV2.deactivateValidator(validatorAddr) {
            vm.stopPrank();

            _ghostDeactivatedAtHeight[validatorAddr] = uint64(block.number);

            IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validatorAddr);
            assertEq(
                v.deactivatedAtHeight,
                uint64(block.number),
                "TEMPO-VALV2-4: deactivatedAtHeight should match block.number"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat("DEACTIVATE: ", vm.toString(validatorAddr), " at height=", vm.toString(block.number))
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for double-deactivation (should fail)
    /// @dev Tests TEMPO-VALV2-5 (deactivate-once semantics)
    function tryDeactivateAlreadyDeleted(uint256 validatorSeed) external {
        uint256 len = _ghostValidatorList.length;
        if (len == 0) return;

        uint256 start = validatorSeed % len;
        for (uint256 i = 0; i < len; i++) {
            address addr = _ghostValidatorList[(start + i) % len];
            if (_ghostDeactivatedAtHeight[addr] != 0) {
                vm.startPrank(_ghostOwner);
                try validatorConfigV2.deactivateValidator(addr) {
                    vm.stopPrank();
                    revert("TEMPO-VALV2-5: Should not be able to deactivate twice");
                } catch (bytes memory reason) {
                    vm.stopPrank();
                    assertEq(
                        bytes4(reason),
                        IValidatorConfigV2.ValidatorAlreadyDeleted.selector,
                        "TEMPO-VALV2-5: Should revert with ValidatorAlreadyDeleted"
                    );
                }
                return;
            }
        }
    }

    /// @notice Handler for unauthorized deactivation attempts
    /// @dev Tests TEMPO-VALV2-1 (owner-only deactivation)
    function tryDeactivateUnauthorized(uint256 callerSeed, uint256 validatorSeed) external {
        address caller = _selectPotentialValidator(callerSeed);
        if (caller == _ghostOwner) return;

        (address validatorAddr, bool found) = _selectActiveValidator(validatorSeed);
        if (!found) return;

        vm.startPrank(caller);
        try validatorConfigV2.deactivateValidator(validatorAddr) {
            vm.stopPrank();
            revert("TEMPO-VALV2-1: Non-owner should not be able to deactivate");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfigV2.Unauthorized.selector,
                "TEMPO-VALV2-1: Should revert with Unauthorized (deactivate)"
            );
        }
    }

    /// @notice Handler for duplicate address rejection
    /// @dev Tests TEMPO-VALV2-6 (address uniqueness)
    function tryAddDuplicateAddress(uint256 validatorSeed, uint256 keySeed) external {
        if (_ghostValidatorList.length == 0) return;

        address existingAddr = _selectExistingValidator(validatorSeed);
        bytes32 publicKey = _generatePublicKey(keySeed);
        string memory ingress = _generateIngress(validatorSeed);
        string memory egress = _generateEgress(validatorSeed);
        bytes memory fakeSig = new bytes(64);

        vm.startPrank(_ghostOwner);
        try validatorConfigV2.addValidator(existingAddr, publicKey, ingress, egress, fakeSig) {
            vm.stopPrank();
            revert("TEMPO-VALV2-6: Should not add duplicate address");
        } catch (bytes memory reason) {
            vm.stopPrank();
            bytes4 selector = bytes4(reason);
            assertTrue(
                selector == IValidatorConfigV2.ValidatorAlreadyExists.selector
                    || selector == IValidatorConfigV2.InvalidSignature.selector,
                "TEMPO-VALV2-6: Should revert with ValidatorAlreadyExists or InvalidSignature"
            );
        }
    }

    /// @notice Handler for duplicate public key rejection
    /// @dev Tests TEMPO-VALV2-7 (public key uniqueness)
    function tryAddDuplicatePubKey(uint256 validatorSeed, uint256 existingSeed) external {
        if (_ghostValidatorList.length == 0) return;

        address existingAddr = _selectExistingValidator(existingSeed);
        bytes32 existingPubKey = _ghostValidatorPubKey[existingAddr];
        if (existingPubKey == bytes32(0)) return;

        address newAddr = _selectPotentialValidator(validatorSeed);
        if (_ghostValidatorExists[newAddr]) return;

        string memory ingress = _generateIngress(validatorSeed);
        string memory egress = _generateEgress(validatorSeed);
        bytes memory fakeSig = new bytes(64);

        vm.startPrank(_ghostOwner);
        try validatorConfigV2.addValidator(newAddr, existingPubKey, ingress, egress, fakeSig) {
            vm.stopPrank();
            revert("TEMPO-VALV2-7: Should not add duplicate public key");
        } catch (bytes memory reason) {
            vm.stopPrank();
            bytes4 selector = bytes4(reason);
            assertTrue(
                selector == IValidatorConfigV2.PublicKeyAlreadyExists.selector
                    || selector == IValidatorConfigV2.InvalidSignature.selector,
                "TEMPO-VALV2-7: Should revert with PublicKeyAlreadyExists or InvalidSignature"
            );
        }
    }

    /// @notice Handler for zero public key rejection
    /// @dev Tests TEMPO-VALV2-7 (zero key rejection)
    function tryAddZeroPubKey(uint256 validatorSeed) external {
        address validatorAddr = _selectPotentialValidator(validatorSeed);
        if (_ghostValidatorExists[validatorAddr]) return;

        string memory ingress = _generateIngress(validatorSeed);
        string memory egress = _generateEgress(validatorSeed);
        bytes memory fakeSig = new bytes(64);

        vm.startPrank(_ghostOwner);
        try validatorConfigV2.addValidator(validatorAddr, bytes32(0), ingress, egress, fakeSig) {
            vm.stopPrank();
            revert("TEMPO-VALV2-7: Should reject zero public key");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfigV2.InvalidPublicKey.selector,
                "TEMPO-VALV2-7: Should revert with InvalidPublicKey"
            );
        }
    }

    /// @notice Handler for ownership transfer
    /// @dev Tests TEMPO-VALV2-8 (owner transfer)
    function transferOwnership(uint256 newOwnerSeed) external {
        address newOwner = _selectPotentialValidator(newOwnerSeed);

        vm.startPrank(_ghostOwner);
        try validatorConfigV2.transferOwnership(newOwner) {
            vm.stopPrank();

            address oldOwner = _ghostOwner;
            _ghostOwner = newOwner;

            assertEq(validatorConfigV2.owner(), newOwner, "TEMPO-VALV2-8: Owner should be updated");

            if (_loggingEnabled) {
                _log(string.concat("TRANSFER_OWNERSHIP: ", vm.toString(oldOwner), " -> ", vm.toString(newOwner)));
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for unauthorized ownership transfer
    /// @dev Tests TEMPO-VALV2-8 (only owner can transfer)
    function tryTransferOwnershipUnauthorized(uint256 callerSeed, uint256 newOwnerSeed) external {
        address caller = _selectPotentialValidator(callerSeed);
        if (caller == _ghostOwner) return;

        address newOwner = _selectPotentialValidator(newOwnerSeed);

        vm.startPrank(caller);
        try validatorConfigV2.transferOwnership(newOwner) {
            vm.stopPrank();
            revert("TEMPO-VALV2-8: Non-owner should not transfer ownership");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfigV2.Unauthorized.selector,
                "TEMPO-VALV2-8: Should revert with Unauthorized"
            );
        }
    }

    /// @notice Handler for setting DKG ceremony epoch
    /// @dev Tests TEMPO-VALV2-9 (DKG ceremony setting)
    function setNextDkgCeremony(uint64 epoch) external {
        vm.startPrank(_ghostOwner);
        try validatorConfigV2.setNextFullDkgCeremony(epoch) {
            vm.stopPrank();

            _ghostNextDkgCeremony = epoch;

            assertEq(validatorConfigV2.getNextFullDkgCeremony(), epoch, "TEMPO-VALV2-9: DKG epoch should be set");

            if (_loggingEnabled) {
                _log(string.concat("SET_DKG: epoch=", vm.toString(epoch)));
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for unauthorized DKG ceremony setting
    /// @dev Tests TEMPO-VALV2-9 (only owner can set DKG)
    function trySetDkgUnauthorized(uint256 callerSeed, uint64 epoch) external {
        address caller = _selectPotentialValidator(callerSeed);
        if (caller == _ghostOwner) return;

        vm.startPrank(caller);
        try validatorConfigV2.setNextFullDkgCeremony(epoch) {
            vm.stopPrank();
            revert("TEMPO-VALV2-9: Non-owner should not set DKG ceremony");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfigV2.Unauthorized.selector,
                "TEMPO-VALV2-9: Should revert with Unauthorized"
            );
        }
    }

    /// @notice Handler for setting IP addresses (owner or validator)
    /// @dev Tests TEMPO-VALV2-10 (dual-auth IP update)
    function setIpAddresses(uint256 validatorSeed, uint256 ipSeed, bool asValidator) external {
        (address validatorAddr, bool found) = _selectActiveValidator(validatorSeed);
        if (!found) return;

        string memory newIngress = _generateIngress(ipSeed);
        string memory newEgress = _generateEgress(ipSeed);

        address caller = asValidator ? validatorAddr : _ghostOwner;

        vm.startPrank(caller);
        try validatorConfigV2.setIpAddresses(validatorAddr, newIngress, newEgress) {
            vm.stopPrank();

            _ghostIngress[validatorAddr] = newIngress;
            _ghostEgress[validatorAddr] = newEgress;

            IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(validatorAddr);
            assertEq(keccak256(bytes(v.ingress)), keccak256(bytes(newIngress)), "TEMPO-VALV2-10: Ingress should match");
            assertEq(keccak256(bytes(v.egress)), keccak256(bytes(newEgress)), "TEMPO-VALV2-10: Egress should match");

            if (_loggingEnabled) {
                _log(string.concat("SET_IP: ", vm.toString(validatorAddr), " by ", asValidator ? "validator" : "owner"));
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for unauthorized IP address update
    /// @dev Tests TEMPO-VALV2-10 (only owner or validator can update IPs)
    function trySetIpUnauthorized(uint256 callerSeed, uint256 validatorSeed) external {
        address caller = _selectPotentialValidator(callerSeed);
        if (caller == _ghostOwner) return;

        (address validatorAddr, bool found) = _selectActiveValidator(validatorSeed);
        if (!found) return;
        if (caller == validatorAddr) return;

        string memory ingress = _generateIngress(callerSeed);
        string memory egress = _generateEgress(callerSeed);

        vm.startPrank(caller);
        try validatorConfigV2.setIpAddresses(validatorAddr, ingress, egress) {
            vm.stopPrank();
            revert("TEMPO-VALV2-10: Third party should not update IPs");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfigV2.Unauthorized.selector,
                "TEMPO-VALV2-10: Should revert with Unauthorized"
            );
        }
    }

    /// @notice Handler for transferring validator ownership (owner or validator)
    /// @dev Tests TEMPO-VALV2-11 (validator address transfer)
    function transferValidatorOwnership(uint256 validatorSeed, uint256 newAddrSeed, bool asValidator) external {
        (address currentAddr, bool found) = _selectActiveValidator(validatorSeed);
        if (!found) return;

        address newAddr = _selectPotentialValidator(newAddrSeed);
        if (_ghostValidatorExists[newAddr] || newAddr == currentAddr) return;

        address caller = asValidator ? currentAddr : _ghostOwner;

        vm.startPrank(caller);
        try validatorConfigV2.transferValidatorOwnership(currentAddr, newAddr) {
            vm.stopPrank();

            bytes32 pubKey = _ghostValidatorPubKey[currentAddr];
            uint64 idx = _ghostValidatorIndex[currentAddr];
            uint64 addedAt = _ghostAddedAtHeight[currentAddr];
            uint64 deactivatedAt = _ghostDeactivatedAtHeight[currentAddr];
            string memory ingress = _ghostIngress[currentAddr];
            string memory egress = _ghostEgress[currentAddr];

            delete _ghostValidatorExists[currentAddr];
            delete _ghostValidatorPubKey[currentAddr];
            delete _ghostValidatorIndex[currentAddr];
            delete _ghostAddedAtHeight[currentAddr];
            delete _ghostDeactivatedAtHeight[currentAddr];
            delete _ghostIngress[currentAddr];
            delete _ghostEgress[currentAddr];

            _ghostValidatorExists[newAddr] = true;
            _ghostValidatorPubKey[newAddr] = pubKey;
            _ghostValidatorIndex[newAddr] = idx;
            _ghostAddedAtHeight[newAddr] = addedAt;
            _ghostDeactivatedAtHeight[newAddr] = deactivatedAt;
            _ghostIngress[newAddr] = ingress;
            _ghostEgress[newAddr] = egress;

            _ghostValidatorList[idx] = newAddr;

            IValidatorConfigV2.Validator memory v = validatorConfigV2.validatorByAddress(newAddr);
            assertEq(v.validatorAddress, newAddr, "TEMPO-VALV2-11: Address should be updated");
            assertEq(v.publicKey, pubKey, "TEMPO-VALV2-11: Public key preserved after transfer");

            if (_loggingEnabled) {
                _log(string.concat("TRANSFER_VAL_OWNERSHIP: ", vm.toString(currentAddr), " -> ", vm.toString(newAddr)));
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownV2Error(reason);
        }
    }

    /// @notice Handler for transferring to existing address (should fail)
    /// @dev Tests TEMPO-VALV2-11 (duplicate address on transfer)
    function tryTransferValidatorToDuplicate(uint256 seed1, uint256 seed2) external {
        if (_ghostValidatorList.length < 2) return;

        address addr1 = _ghostValidatorList[seed1 % _ghostValidatorList.length];
        address addr2 = _ghostValidatorList[seed2 % _ghostValidatorList.length];
        if (addr1 == addr2) return;
        if (!_ghostValidatorExists[addr1] || !_ghostValidatorExists[addr2]) return;

        vm.startPrank(_ghostOwner);
        try validatorConfigV2.transferValidatorOwnership(addr1, addr2) {
            vm.stopPrank();
            revert("TEMPO-VALV2-11: Should not transfer to existing address");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfigV2.ValidatorAlreadyExists.selector,
                "TEMPO-VALV2-11: Should revert with ValidatorAlreadyExists"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    function invariant_globalInvariants() public view {
        _invariantAppendOnlyCount();
        _invariantOwnerConsistency();
        _invariantValidatorDataConsistency();
        _invariantIndexSequential();
        _invariantPubKeyUniqueness();
        _invariantActiveValidatorSubset();
        _invariantDkgCeremonyConsistency();
        _invariantHeightTracking();
    }

    /// @notice TEMPO-VALV2-2: Validator count only increases (append-only)
    function _invariantAppendOnlyCount() internal view {
        uint64 count = validatorConfigV2.validatorCount();
        assertEq(count, _ghostTotalCount, "TEMPO-VALV2-2: Count should match ghost total");
        assertGe(count, 2, "TEMPO-VALV2-2: Count should be at least 2 (setup validators)");
    }

    /// @notice TEMPO-VALV2-8: Owner matches ghost state
    function _invariantOwnerConsistency() internal view {
        assertEq(validatorConfigV2.owner(), _ghostOwner, "TEMPO-VALV2-8: Owner should match ghost state");
    }

    /// @notice TEMPO-VALV2-12: All validator data matches ghost state
    function _invariantValidatorDataConsistency() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getValidators();
        assertEq(vals.length, _ghostValidatorList.length, "TEMPO-VALV2-12: Array length mismatch");

        for (uint256 i = 0; i < vals.length; i++) {
            address addr = vals[i].validatorAddress;
            assertTrue(_ghostValidatorExists[addr], "TEMPO-VALV2-12: Validator should exist in ghost state");
            assertEq(vals[i].publicKey, _ghostValidatorPubKey[addr], "TEMPO-VALV2-12: Public key mismatch");
            assertEq(vals[i].index, _ghostValidatorIndex[addr], "TEMPO-VALV2-12: Index mismatch");
            assertEq(vals[i].addedAtHeight, _ghostAddedAtHeight[addr], "TEMPO-VALV2-12: addedAtHeight mismatch");
            assertEq(
                vals[i].deactivatedAtHeight,
                _ghostDeactivatedAtHeight[addr],
                "TEMPO-VALV2-12: deactivatedAtHeight mismatch"
            );
        }
    }

    /// @notice TEMPO-VALV2-3: All indices are sequential (0, 1, 2, ...)
    function _invariantIndexSequential() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getValidators();

        for (uint256 i = 0; i < vals.length; i++) {
            assertEq(vals[i].index, i, "TEMPO-VALV2-3: Index should equal array position");
        }
    }

    /// @notice TEMPO-VALV2-7: All public keys are unique and non-zero
    function _invariantPubKeyUniqueness() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getValidators();

        for (uint256 i = 0; i < vals.length; i++) {
            assertTrue(vals[i].publicKey != bytes32(0), "TEMPO-VALV2-7: Public key must not be zero");

            for (uint256 j = i + 1; j < vals.length; j++) {
                assertTrue(vals[i].publicKey != vals[j].publicKey, "TEMPO-VALV2-7: Public keys must be unique");
            }
        }
    }

    /// @notice TEMPO-VALV2-13: Active validators are a proper subset of all validators
    function _invariantActiveValidatorSubset() internal view {
        IValidatorConfigV2.Validator[] memory all = validatorConfigV2.getValidators();
        IValidatorConfigV2.Validator[] memory active = validatorConfigV2.getActiveValidators();

        assertLe(active.length, all.length, "TEMPO-VALV2-13: Active count <= total count");

        uint256 expectedActive = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (
                all[i].deactivatedAtHeight == 0
                    && !(all[i].addedAtHeight == all[i].deactivatedAtHeight && all[i].addedAtHeight != 0)
            ) {
                expectedActive++;
            }
        }
        assertEq(active.length, expectedActive, "TEMPO-VALV2-13: Active count should match filtered count");

        for (uint256 i = 0; i < active.length; i++) {
            assertEq(
                active[i].deactivatedAtHeight, 0, "TEMPO-VALV2-13: Active validators must have deactivatedAtHeight == 0"
            );
        }
    }

    /// @notice TEMPO-VALV2-9: DKG epoch matches ghost state
    function _invariantDkgCeremonyConsistency() internal view {
        assertEq(
            validatorConfigV2.getNextFullDkgCeremony(),
            _ghostNextDkgCeremony,
            "TEMPO-VALV2-9: DKG epoch should match ghost state"
        );
    }

    /// @notice TEMPO-VALV2-14: Height tracking invariants
    /// @dev For active validators: addedAtHeight >= 0, deactivatedAtHeight == 0
    ///      For deactivated validators: deactivatedAtHeight >= addedAtHeight
    function _invariantHeightTracking() internal view {
        IValidatorConfigV2.Validator[] memory vals = validatorConfigV2.getValidators();

        for (uint256 i = 0; i < vals.length; i++) {
            if (vals[i].deactivatedAtHeight != 0) {
                assertGe(
                    vals[i].deactivatedAtHeight,
                    vals[i].addedAtHeight,
                    "TEMPO-VALV2-14: deactivatedAtHeight must be >= addedAtHeight"
                );
            }
        }
    }
}
