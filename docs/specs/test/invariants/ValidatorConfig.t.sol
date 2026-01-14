// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { IValidatorConfig } from "../../src/interfaces/IValidatorConfig.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title ValidatorConfig Invariant Tests
/// @notice Fuzz-based invariant tests for the ValidatorConfig precompile
/// @dev Tests invariants TEMPO-VAL1 through TEMPO-VAL15 for validator management
contract ValidatorConfigInvariantTest is InvariantBaseTest {

    /// @dev Array of potential validator addresses
    address[] private _potentialValidators;

    /// @dev Ghost tracking for validators
    mapping(address => bool) private _ghostValidatorExists;
    mapping(address => bool) private _ghostValidatorActive;
    mapping(address => bytes32) private _ghostValidatorPublicKey;
    mapping(address => uint64) private _ghostValidatorIndex;
    address[] private _ghostValidatorList;

    /// @dev Ghost tracking for owner
    address private _ghostOwner;

    /// @dev Ghost tracking for DKG ceremony
    uint64 private _ghostNextDkgCeremony;

    /// @dev Counters for operations
    uint256 private _totalValidatorsAdded;
    uint256 private _totalValidatorsUpdated;
    uint256 private _totalStatusChanges;
    uint256 private _totalOwnerChanges;

    /*//////////////////////////////////////////////////////////////
                               SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();
        _actors = _buildActors(10);
        _potentialValidators = _buildPotentialValidators(20);
        _ghostOwner = admin;

        _initLogFile("validator_config.log", "ValidatorConfig Invariant Test Log");
    }

    /// @dev Creates potential validator addresses
    function _buildPotentialValidators(uint256 count) internal pure returns (address[] memory) {
        address[] memory validators = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            validators[i] = address(uint160(0x2000 + i));
        }
        return validators;
    }

    /// @dev Selects a potential validator address based on seed
    function _selectPotentialValidator(uint256 seed) internal view returns (address) {
        return _potentialValidators[seed % _potentialValidators.length];
    }

    /// @dev Generates a public key from seed (non-zero)
    function _generatePublicKey(uint256 seed) internal pure returns (bytes32) {
        return bytes32(uint256(keccak256(abi.encode(seed))) | 1);
    }

    /// @dev Generates valid inbound address
    function _generateInboundAddress(uint256 seed) internal pure returns (string memory) {
        uint8 lastOctet = uint8((seed % 254) + 1);
        return string(abi.encodePacked("192.168.1.", _uint8ToString(lastOctet), ":8000"));
    }

    /// @dev Generates valid outbound address
    function _generateOutboundAddress(uint256 seed) internal pure returns (string memory) {
        uint8 lastOctet = uint8((seed % 254) + 1);
        return string(abi.encodePacked("192.168.1.", _uint8ToString(lastOctet), ":9000"));
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for adding validators (owner only)
    /// @dev Tests TEMPO-VAL1 (owner-only add), TEMPO-VAL2 (index assignment)
    function addValidator(uint256 validatorSeed, uint256 keySeed, bool active) external {
        address validatorAddr = _selectPotentialValidator(validatorSeed);

        // Skip if validator already exists
        if (_ghostValidatorExists[validatorAddr]) return;

        bytes32 publicKey = _generatePublicKey(keySeed);
        string memory inbound = _generateInboundAddress(validatorSeed);
        string memory outbound = _generateOutboundAddress(validatorSeed);

        uint256 countBefore = _ghostValidatorList.length;

        vm.startPrank(_ghostOwner);
        try validatorConfig.addValidator(validatorAddr, publicKey, active, inbound, outbound) {
            vm.stopPrank();

            _totalValidatorsAdded++;

            // Update ghost state
            _ghostValidatorExists[validatorAddr] = true;
            _ghostValidatorActive[validatorAddr] = active;
            _ghostValidatorPublicKey[validatorAddr] = publicKey;
            _ghostValidatorIndex[validatorAddr] = uint64(countBefore);
            _ghostValidatorList.push(validatorAddr);

            // TEMPO-VAL2: Index should be count before addition
            IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
            assertEq(
                validators.length, countBefore + 1, "TEMPO-VAL2: Validator count should increment"
            );
            assertEq(
                validators[countBefore].index,
                countBefore,
                "TEMPO-VAL2: New validator index should be previous count"
            );

            _log(
                string.concat(
                    "ADD_VALIDATOR: ",
                    vm.toString(validatorAddr),
                    " index=",
                    vm.toString(countBefore),
                    " active=",
                    active ? "true" : "false"
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownValidatorError(reason);
        }
    }

    /// @notice Handler for unauthorized add attempts
    /// @dev Tests TEMPO-VAL1 (owner-only enforcement)
    function tryAddValidatorUnauthorized(uint256 callerSeed, uint256 validatorSeed) external {
        address caller = _selectPotentialValidator(callerSeed);
        address validatorAddr = _selectPotentialValidator(validatorSeed);

        // Skip if caller is the owner
        if (caller == _ghostOwner) return;

        bytes32 publicKey = _generatePublicKey(validatorSeed);
        string memory inbound = _generateInboundAddress(validatorSeed);
        string memory outbound = _generateOutboundAddress(validatorSeed);

        vm.startPrank(caller);
        try validatorConfig.addValidator(validatorAddr, publicKey, true, inbound, outbound) {
            vm.stopPrank();
            revert("TEMPO-VAL1: Non-owner should not be able to add validator");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfig.Unauthorized.selector,
                "TEMPO-VAL1: Should revert with Unauthorized"
            );
        }

        _log(
            string.concat(
                "TRY_ADD_UNAUTHORIZED: ",
                vm.toString(caller),
                " blocked from adding ",
                vm.toString(validatorAddr)
            )
        );
    }

    /// @notice Handler for validator self-update
    /// @dev Tests TEMPO-VAL3 (validator can update self), TEMPO-VAL4 (only validator can update)
    function updateValidator(uint256 validatorSeed, uint256 keySeed) external {
        if (_ghostValidatorList.length == 0) return;

        address validatorAddr = _ghostValidatorList[validatorSeed % _ghostValidatorList.length];

        bytes32 newPublicKey = _generatePublicKey(keySeed);
        string memory newInbound = _generateInboundAddress(keySeed);
        string memory newOutbound = _generateOutboundAddress(keySeed);

        vm.startPrank(validatorAddr);
        try validatorConfig.updateValidator(validatorAddr, newPublicKey, newInbound, newOutbound) {
            vm.stopPrank();

            _totalValidatorsUpdated++;

            // Update ghost state
            _ghostValidatorPublicKey[validatorAddr] = newPublicKey;

            // TEMPO-VAL3: Verify update persisted
            IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
            bool found = false;
            for (uint256 i = 0; i < validators.length; i++) {
                if (validators[i].validatorAddress == validatorAddr) {
                    assertEq(
                        validators[i].publicKey,
                        newPublicKey,
                        "TEMPO-VAL3: Public key should be updated"
                    );
                    found = true;
                    break;
                }
            }
            assertTrue(found, "TEMPO-VAL3: Updated validator should exist");

            _log(
                string.concat(
                    "UPDATE_VALIDATOR: ", vm.toString(validatorAddr), " updated public key"
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownValidatorError(reason);
        }
    }

    /// @notice Handler for owner trying to update validator (should fail)
    /// @dev Tests TEMPO-VAL4 (only validator can update self)
    function tryOwnerUpdateValidator(uint256 validatorSeed, uint256 keySeed) external {
        if (_ghostValidatorList.length == 0) return;

        address validatorAddr = _ghostValidatorList[validatorSeed % _ghostValidatorList.length];

        // Skip if owner is also a validator
        if (_ghostValidatorExists[_ghostOwner]) return;

        bytes32 newPublicKey = _generatePublicKey(keySeed);
        string memory newInbound = _generateInboundAddress(keySeed);
        string memory newOutbound = _generateOutboundAddress(keySeed);

        vm.startPrank(_ghostOwner);
        try validatorConfig.updateValidator(validatorAddr, newPublicKey, newInbound, newOutbound) {
            vm.stopPrank();
            revert("TEMPO-VAL4: Owner should not be able to update validator");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfig.ValidatorNotFound.selector,
                "TEMPO-VAL4: Should revert with ValidatorNotFound"
            );
        }

        _log(
            string.concat(
                "TRY_OWNER_UPDATE: Owner blocked from updating ", vm.toString(validatorAddr)
            )
        );
    }

    /// @notice Handler for changing validator status (owner only)
    /// @dev Tests TEMPO-VAL5 (owner can change status), TEMPO-VAL6 (status toggle)
    function changeValidatorStatus(uint256 validatorSeed, bool newStatus) external {
        if (_ghostValidatorList.length == 0) return;

        address validatorAddr = _ghostValidatorList[validatorSeed % _ghostValidatorList.length];

        vm.startPrank(_ghostOwner);
        try validatorConfig.changeValidatorStatus(validatorAddr, newStatus) {
            vm.stopPrank();

            _totalStatusChanges++;

            // Update ghost state
            _ghostValidatorActive[validatorAddr] = newStatus;

            // TEMPO-VAL6: Verify status changed
            IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
            for (uint256 i = 0; i < validators.length; i++) {
                if (validators[i].validatorAddress == validatorAddr) {
                    assertEq(
                        validators[i].active, newStatus, "TEMPO-VAL6: Status should be updated"
                    );
                    break;
                }
            }

            _log(
                string.concat(
                    "CHANGE_STATUS: ",
                    vm.toString(validatorAddr),
                    " -> ",
                    newStatus ? "ACTIVE" : "INACTIVE"
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownValidatorError(reason);
        }
    }

    /// @notice Handler for validator trying to change own status (should fail)
    /// @dev Tests TEMPO-VAL5 (only owner can change status)
    function tryValidatorChangeOwnStatus(uint256 validatorSeed) external {
        if (_ghostValidatorList.length == 0) return;

        address validatorAddr = _ghostValidatorList[validatorSeed % _ghostValidatorList.length];

        // Skip if validator is the owner
        if (validatorAddr == _ghostOwner) return;

        vm.startPrank(validatorAddr);
        try validatorConfig.changeValidatorStatus(validatorAddr, false) {
            vm.stopPrank();
            revert("TEMPO-VAL5: Validator should not be able to change own status");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfig.Unauthorized.selector,
                "TEMPO-VAL5: Should revert with Unauthorized"
            );
        }

        _log(
            string.concat(
                "TRY_SELF_STATUS_CHANGE: ", vm.toString(validatorAddr), " blocked from self-change"
            )
        );
    }

    /// @notice Handler for changing owner
    /// @dev Tests TEMPO-VAL7 (owner transfer), TEMPO-VAL8 (new owner has authority)
    function changeOwner(uint256 newOwnerSeed) external {
        address newOwner = _selectPotentialValidator(newOwnerSeed);

        vm.startPrank(_ghostOwner);
        try validatorConfig.changeOwner(newOwner) {
            vm.stopPrank();

            _totalOwnerChanges++;
            address oldOwner = _ghostOwner;
            _ghostOwner = newOwner;

            // TEMPO-VAL7: Verify owner changed
            assertEq(validatorConfig.owner(), newOwner, "TEMPO-VAL7: Owner should be updated");

            _log(
                string.concat(
                    "CHANGE_OWNER: ", vm.toString(oldOwner), " -> ", vm.toString(newOwner)
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownValidatorError(reason);
        }
    }

    /// @notice Handler for unauthorized owner change
    /// @dev Tests TEMPO-VAL8 (only owner can transfer ownership)
    function tryChangeOwnerUnauthorized(uint256 callerSeed, uint256 newOwnerSeed) external {
        address caller = _selectPotentialValidator(callerSeed);
        address newOwner = _selectPotentialValidator(newOwnerSeed);

        // Skip if caller is the owner
        if (caller == _ghostOwner) return;

        vm.startPrank(caller);
        try validatorConfig.changeOwner(newOwner) {
            vm.stopPrank();
            revert("TEMPO-VAL8: Non-owner should not be able to change owner");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfig.Unauthorized.selector,
                "TEMPO-VAL8: Should revert with Unauthorized"
            );
        }

        _log(
            string.concat(
                "TRY_CHANGE_OWNER_UNAUTHORIZED: ", vm.toString(caller), " blocked from ownership"
            )
        );
    }

    /// @notice Handler for adding duplicate validator
    /// @dev Tests TEMPO-VAL9 (duplicate rejection)
    function tryAddDuplicateValidator(uint256 validatorSeed) external {
        if (_ghostValidatorList.length == 0) return;

        address existingValidator = _ghostValidatorList[validatorSeed % _ghostValidatorList.length];
        bytes32 publicKey = _generatePublicKey(validatorSeed);
        string memory inbound = _generateInboundAddress(validatorSeed);
        string memory outbound = _generateOutboundAddress(validatorSeed);

        vm.startPrank(_ghostOwner);
        try validatorConfig.addValidator(existingValidator, publicKey, true, inbound, outbound) {
            vm.stopPrank();
            revert("TEMPO-VAL9: Adding duplicate validator should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfig.ValidatorAlreadyExists.selector,
                "TEMPO-VAL9: Should revert with ValidatorAlreadyExists"
            );
        }

        _log(
            string.concat(
                "TRY_ADD_DUPLICATE: ", vm.toString(existingValidator), " correctly rejected"
            )
        );
    }

    /// @notice Handler for adding validator with zero public key
    /// @dev Tests TEMPO-VAL10 (zero public key rejection)
    function tryAddValidatorZeroPublicKey(uint256 validatorSeed) external {
        address validatorAddr = _selectPotentialValidator(validatorSeed);

        // Skip if validator already exists
        if (_ghostValidatorExists[validatorAddr]) return;

        bytes32 zeroPublicKey = bytes32(0);
        string memory inbound = _generateInboundAddress(validatorSeed);
        string memory outbound = _generateOutboundAddress(validatorSeed);

        vm.startPrank(_ghostOwner);
        try validatorConfig.addValidator(validatorAddr, zeroPublicKey, true, inbound, outbound) {
            vm.stopPrank();
            revert("TEMPO-VAL10: Adding validator with zero public key should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfig.InvalidPublicKey.selector,
                "TEMPO-VAL10: Should revert with InvalidPublicKey"
            );
        }

        _log(
            string.concat("TRY_ZERO_PUBKEY: ", vm.toString(validatorAddr), " zero pubkey rejected")
        );
    }

    /// @notice Handler for validator rotation
    /// @dev Tests TEMPO-VAL11 (validator can rotate address)
    function rotateValidator(uint256 validatorSeed, uint256 newAddrSeed, uint256 keySeed) external {
        if (_ghostValidatorList.length == 0) return;

        address oldAddr = _ghostValidatorList[validatorSeed % _ghostValidatorList.length];
        address newAddr = _selectPotentialValidator(newAddrSeed);

        // Skip if new address already exists or is same as old
        if (_ghostValidatorExists[newAddr] || newAddr == oldAddr) return;

        bytes32 newPublicKey = _generatePublicKey(keySeed);
        string memory newInbound = _generateInboundAddress(keySeed);
        string memory newOutbound = _generateOutboundAddress(keySeed);

        uint64 oldIndex = _ghostValidatorIndex[oldAddr];
        bool oldActive = _ghostValidatorActive[oldAddr];

        vm.startPrank(oldAddr);
        try validatorConfig.updateValidator(newAddr, newPublicKey, newInbound, newOutbound) {
            vm.stopPrank();

            _totalValidatorsUpdated++;

            // Update ghost state
            _ghostValidatorExists[oldAddr] = false;
            _ghostValidatorExists[newAddr] = true;
            _ghostValidatorActive[newAddr] = oldActive;
            _ghostValidatorPublicKey[newAddr] = newPublicKey;
            _ghostValidatorIndex[newAddr] = oldIndex;
            _ghostValidatorList[oldIndex] = newAddr;

            // TEMPO-VAL11: Verify rotation
            IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
            bool found = false;
            for (uint256 i = 0; i < validators.length; i++) {
                if (validators[i].validatorAddress == newAddr) {
                    assertEq(
                        validators[i].index, oldIndex, "TEMPO-VAL11: Index should be preserved"
                    );
                    assertEq(
                        validators[i].active, oldActive, "TEMPO-VAL11: Active should be preserved"
                    );
                    found = true;
                    break;
                }
            }
            assertTrue(found, "TEMPO-VAL11: Rotated validator should exist");

            _log(
                string.concat(
                    "ROTATE_VALIDATOR: ", vm.toString(oldAddr), " -> ", vm.toString(newAddr)
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownValidatorError(reason);
        }
    }

    /// @notice Handler for setting DKG ceremony epoch (owner only)
    /// @dev Tests TEMPO-VAL12 (DKG ceremony setting)
    function setNextDkgCeremony(uint64 epoch) external {
        vm.startPrank(_ghostOwner);
        try validatorConfig.setNextFullDkgCeremony(epoch) {
            vm.stopPrank();

            _ghostNextDkgCeremony = epoch;

            // TEMPO-VAL12: Verify epoch set
            assertEq(
                validatorConfig.getNextFullDkgCeremony(),
                epoch,
                "TEMPO-VAL12: DKG epoch should be set"
            );

            _log(string.concat("SET_DKG_CEREMONY: epoch=", vm.toString(epoch)));
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownValidatorError(reason);
        }
    }

    /// @notice Handler for unauthorized DKG ceremony setting
    /// @dev Tests TEMPO-VAL13 (only owner can set DKG ceremony)
    function trySetDkgCeremonyUnauthorized(uint256 callerSeed, uint64 epoch) external {
        address caller = _selectPotentialValidator(callerSeed);

        // Skip if caller is the owner
        if (caller == _ghostOwner) return;

        vm.startPrank(caller);
        try validatorConfig.setNextFullDkgCeremony(epoch) {
            vm.stopPrank();
            revert("TEMPO-VAL13: Non-owner should not be able to set DKG ceremony");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                IValidatorConfig.Unauthorized.selector,
                "TEMPO-VAL13: Should revert with Unauthorized"
            );
        }

        _log(
            string.concat(
                "TRY_SET_DKG_UNAUTHORIZED: ", vm.toString(caller), " blocked from setting DKG"
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    function invariant_globalInvariants() public view {
        _invariantOwnerConsistency();
        _invariantValidatorCountConsistency();
        _invariantValidatorDataConsistency();
        _invariantIndexUniqueness();
        _invariantDkgCeremonyConsistency();
    }

    /// @notice TEMPO-VAL14: Owner in contract matches ghost state
    function _invariantOwnerConsistency() internal view {
        assertEq(
            validatorConfig.owner(), _ghostOwner, "TEMPO-VAL14: Owner should match ghost state"
        );
    }

    /// @notice TEMPO-VAL2: Validator count matches ghost list
    function _invariantValidatorCountConsistency() internal view {
        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        assertEq(
            validators.length,
            _ghostValidatorList.length,
            "TEMPO-VAL2: Validator count should match ghost list"
        );
    }

    /// @notice TEMPO-VAL15: Validator data matches ghost state
    function _invariantValidatorDataConsistency() internal view {
        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();

        for (uint256 i = 0; i < validators.length; i++) {
            address addr = validators[i].validatorAddress;
            assertTrue(
                _ghostValidatorExists[addr], "TEMPO-VAL15: Validator should exist in ghost state"
            );
            assertEq(
                validators[i].active,
                _ghostValidatorActive[addr],
                "TEMPO-VAL15: Active status should match"
            );
            assertEq(
                validators[i].publicKey,
                _ghostValidatorPublicKey[addr],
                "TEMPO-VAL15: Public key should match"
            );
        }
    }

    /// @notice TEMPO-VAL2: All validator indices are unique and sequential
    function _invariantIndexUniqueness() internal view {
        IValidatorConfig.Validator[] memory validators = validatorConfig.getValidators();
        bool[] memory usedIndices = new bool[](validators.length);

        for (uint256 i = 0; i < validators.length; i++) {
            uint64 idx = validators[i].index;
            assertTrue(idx < validators.length, "TEMPO-VAL2: Index should be within bounds");
            assertFalse(usedIndices[idx], "TEMPO-VAL2: Index should be unique");
            usedIndices[idx] = true;
        }
    }

    /// @notice TEMPO-VAL12: DKG ceremony epoch matches ghost state
    function _invariantDkgCeremonyConsistency() internal view {
        assertEq(
            validatorConfig.getNextFullDkgCeremony(),
            _ghostNextDkgCeremony,
            "TEMPO-VAL12: DKG epoch should match ghost state"
        );
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Checks if an error is known/expected for ValidatorConfig
    function _assertKnownValidatorError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnown = selector == IValidatorConfig.Unauthorized.selector
            || selector == IValidatorConfig.ValidatorAlreadyExists.selector
            || selector == IValidatorConfig.ValidatorNotFound.selector
            || selector == IValidatorConfig.InvalidPublicKey.selector
            || selector == IValidatorConfig.NotHostPort.selector
            || selector == IValidatorConfig.NotIpPort.selector;
        assertTrue(isKnown, "Unknown error encountered");
    }

    /// @dev Converts uint8 to string
    function _uint8ToString(uint8 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }

        uint8 temp = value;
        uint8 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }

        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + value % 10));
            value /= 10;
        }

        return string(buffer);
    }

}
