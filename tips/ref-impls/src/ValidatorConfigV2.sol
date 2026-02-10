// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { IValidatorConfig } from "./interfaces/IValidatorConfig.sol";
import { IValidatorConfigV2 } from "./interfaces/IValidatorConfigV2.sol";

/// @title ValidatorConfigV2 - Validator Config V2 Precompile
/// @notice Manages consensus validators with append-only, delete-once semantics
/// @dev Replaces V1's mutable state with immutable height-based tracking (addedAtHeight,
///      deactivatedAtHeight) to enable historical validator set reconstruction without
///      requiring historical state access.
contract ValidatorConfigV2 is IValidatorConfigV2 {

    // =========================================================================
    // Constants
    // =========================================================================

    // =========================================================================
    // Storage
    // =========================================================================

    /// @dev Slot 0: bit 255 = initialized flag, bits 0-159 = owner address
    address private _owner;
    bool private _initialized;

    IValidatorConfig public immutable v1 =
        IValidatorConfig(0xCccCcCCC00000000000000000000000000000000);

    Validator[] internal validatorsArray;

    /// @dev 1-indexed: 0 means not found. Stored value is arrayIndex + 1.
    mapping(address => uint256) internal addressToIndex;

    /// @dev 1-indexed: 0 means not found. Stored value is arrayIndex + 1.
    mapping(bytes32 => uint256) internal pubkeyToIndex;

    uint64 internal nextDkgCeremony;

    // =========================================================================
    // Modifiers
    // =========================================================================

    modifier onlyOwner() {
        if (msg.sender != _owner) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyInitialized() {
        if (!_initialized) {
            revert NotInitialized();
        }
        _;
    }

    modifier onlyOwnerOrValidator(address validatorAddress) {
        if (msg.sender != _owner && msg.sender != validatorAddress) {
            revert Unauthorized();
        }
        _;
    }

    // =========================================================================
    // Owner-Only State-Changing Functions
    // =========================================================================

    /// @inheritdoc IValidatorConfigV2
    function addValidator(
        address validatorAddress,
        bytes32 publicKey,
        string calldata ingress,
        string calldata egress,
        bytes calldata signature
    )
        external
        onlyInitialized
        onlyOwner
    {
        _validateAddParams(validatorAddress, publicKey, ingress, egress);

        bytes32 message = keccak256(
            abi.encodePacked(
                "TEMPO",
                "_VALIDATOR_CONFIG_V2_ADD_VALIDATOR",
                block.chainid,
                address(this),
                validatorAddress,
                ingress,
                egress
            )
        );
        _verifyEd25519Signature(publicKey, message, signature);

        _addValidator(validatorAddress, publicKey, ingress, egress, uint64(block.number));
    }

    /// @inheritdoc IValidatorConfigV2
    function deactivateValidator(address validatorAddress) external onlyInitialized onlyOwner {
        uint256 idx = addressToIndex[validatorAddress];
        if (idx == 0) {
            revert ValidatorNotFound();
        }

        Validator storage v = validatorsArray[idx - 1];
        if (v.deactivatedAtHeight != 0) {
            revert ValidatorAlreadyDeleted();
        }

        v.deactivatedAtHeight = uint64(block.number);
    }

    /// @inheritdoc IValidatorConfigV2
    function transferOwnership(address newOwner) external onlyOwner {
        _owner = newOwner;
    }

    /// @inheritdoc IValidatorConfigV2
    function setNextFullDkgCeremony(uint64 epoch) external onlyInitialized onlyOwner {
        nextDkgCeremony = epoch;
    }

    // =========================================================================
    // Dual-Auth Functions (owner or validator)
    // =========================================================================

    /// @inheritdoc IValidatorConfigV2
    function rotateValidator(
        address validatorAddress,
        bytes32 publicKey,
        string calldata ingress,
        string calldata egress,
        bytes calldata signature
    )
        external
        onlyInitialized
        onlyOwnerOrValidator(validatorAddress)
    {
        uint256 idx = addressToIndex[validatorAddress];
        if (idx == 0) {
            revert ValidatorNotFound();
        }

        Validator storage oldValidator = validatorsArray[idx - 1];
        if (oldValidator.deactivatedAtHeight != 0) {
            revert ValidatorAlreadyDeleted();
        }

        _validateRotateParams(publicKey, ingress, egress);

        bytes32 message = keccak256(
            abi.encodePacked(
                "TEMPO",
                "_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR",
                block.chainid,
                address(this),
                validatorAddress,
                ingress,
                egress
            )
        );
        _verifyEd25519Signature(publicKey, message, signature);

        oldValidator.deactivatedAtHeight = uint64(block.number);

        _addValidator(validatorAddress, publicKey, ingress, egress, uint64(block.number));
    }

    /// @inheritdoc IValidatorConfigV2
    function setIpAddresses(
        address validatorAddress,
        string calldata ingress,
        string calldata egress
    )
        external
        onlyInitialized
        onlyOwnerOrValidator(validatorAddress)
    {
        uint256 idx = addressToIndex[validatorAddress];
        if (idx == 0) {
            revert ValidatorNotFound();
        }

        Validator storage v = validatorsArray[idx - 1];
        if (v.deactivatedAtHeight != 0) {
            revert ValidatorAlreadyDeleted();
        }

        _validateIpPort(ingress, "ingress");
        _validateIp(egress, "egress");

        v.ingress = ingress;
        v.egress = egress;
    }

    /// @inheritdoc IValidatorConfigV2
    function transferValidatorOwnership(
        address currentAddress,
        address newAddress
    )
        external
        onlyInitialized
        onlyOwnerOrValidator(currentAddress)
    {
        if (newAddress == address(0)) {
            revert InvalidValidatorAddress();
        }

        uint256 idx = addressToIndex[currentAddress];
        if (idx == 0) {
            revert ValidatorNotFound();
        }
        if (addressToIndex[newAddress] != 0) {
            revert ValidatorAlreadyExists();
        }

        Validator storage v = validatorsArray[idx - 1];
        if (v.deactivatedAtHeight != 0) {
            revert ValidatorAlreadyDeleted();
        }

        v.validatorAddress = newAddress;
        addressToIndex[newAddress] = idx;
        delete addressToIndex[currentAddress];
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /// @inheritdoc IValidatorConfigV2
    function getValidators() external view returns (Validator[] memory) {
        return validatorsArray;
    }

    /// @inheritdoc IValidatorConfigV2
    function getActiveValidators() external view returns (Validator[] memory validators) {
        uint256 len = validatorsArray.length;
        validators = new Validator[](len);
        uint256 idx = 0;
        for (uint256 i = 0; i < len; i++) {
            Validator storage v = validatorsArray[i];
            if (
                v.deactivatedAtHeight == 0
                    && !(v.addedAtHeight == v.deactivatedAtHeight && v.addedAtHeight != 0)
            ) {
                validators[idx] = v;
                idx++;
            }
        }
        // Modify array.length to the correct length
        // We're doing this in assembly because it's not possible to do in solidity
        assembly {
            mstore(validators, idx)
        }
    }

    /// @inheritdoc IValidatorConfigV2
    /// @dev If addValidator has not been called yet, this will return address(0)
    function owner() external view returns (address) {
        return _owner;
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorCount() external view returns (uint64) {
        return uint64(validatorsArray.length);
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorByIndex(uint256 index) external view returns (Validator memory) {
        if (index >= validatorsArray.length) {
            revert ValidatorNotFound();
        }
        return validatorsArray[index];
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorByAddress(address validatorAddress) external view returns (Validator memory) {
        uint256 idx = addressToIndex[validatorAddress];
        if (idx == 0) {
            revert ValidatorNotFound();
        }
        return validatorsArray[idx - 1];
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorByPublicKey(bytes32 publicKey) external view returns (Validator memory) {
        uint256 idx = pubkeyToIndex[publicKey];
        if (idx == 0) {
            revert ValidatorNotFound();
        }
        return validatorsArray[idx - 1];
    }

    /// @inheritdoc IValidatorConfigV2
    function getNextFullDkgCeremony() external view returns (uint64) {
        return nextDkgCeremony;
    }

    /// @inheritdoc IValidatorConfigV2
    function isInitialized() external view returns (bool) {
        return _initialized;
    }

    // =========================================================================
    // Migration Functions (V1 -> V2)
    // =========================================================================

    /// @inheritdoc IValidatorConfigV2
    function migrateValidator(uint64 idx) external {
        if (_initialized) {
            revert AlreadyInitialized();
        }
        if (idx != validatorsArray.length) {
            revert InvalidMigrationIndex();
        }

        IValidatorConfig.Validator[] memory v1Validators = v1.getValidators();
        if (idx >= v1Validators.length) {
            revert ValidatorNotFound();
        }

        if (validatorsArray.length == 0 && _owner == address(0)) {
            _owner = v1.owner();
        }

        if (msg.sender != _owner) {
            revert Unauthorized();
        }

        IValidatorConfig.Validator memory v1Val = v1Validators[idx];

        uint64 addedAt;
        uint64 deactivatedAt;
        if (v1Val.active) {
            addedAt = 0;
            deactivatedAt = 0;
        } else {
            addedAt = uint64(block.timestamp);
            deactivatedAt = uint64(block.timestamp);
        }

        Validator memory newVal = Validator({
            publicKey: v1Val.publicKey,
            validatorAddress: v1Val.validatorAddress,
            ingress: v1Val.inboundAddress,
            egress: v1Val.outboundAddress,
            index: uint64(validatorsArray.length),
            addedAtHeight: addedAt,
            deactivatedAtHeight: deactivatedAt
        });

        validatorsArray.push(newVal);
        addressToIndex[v1Val.validatorAddress] = idx + 1; // 1-indexed
        pubkeyToIndex[v1Val.publicKey] = idx + 1; // 1-indexed
    }

    /// @inheritdoc IValidatorConfigV2
    function initializeIfMigrated() external onlyOwner {
        if (_initialized) {
            revert AlreadyInitialized();
        }

        IValidatorConfig.Validator[] memory v1Validators = v1.getValidators();
        if (validatorsArray.length < v1Validators.length) {
            revert MigrationNotComplete();
        }

        for (uint256 i = 0; i < v1Validators.length; i++) {
            Validator storage v2Val = validatorsArray[i];
            if (v1Validators[i].active && v2Val.deactivatedAtHeight != 0) {
                revert MigrationNotComplete();
            }
            if (!v1Validators[i].active && v2Val.deactivatedAtHeight == 0) {
                revert MigrationNotComplete();
            }
        }

        nextDkgCeremony = v1.getNextFullDkgCeremony();

        _initialized = true;
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    function _validateAddParams(
        address validatorAddress,
        bytes32 publicKey,
        string calldata ingress,
        string calldata egress
    )
        internal
        view
    {
        if (validatorAddress == address(0)) {
            revert InvalidValidatorAddress();
        }
        if (addressToIndex[validatorAddress] != 0) {
            revert ValidatorAlreadyExists();
        }
        _validateRotateParams(publicKey, ingress, egress);
    }

    function _validateRotateParams(
        bytes32 publicKey,
        string calldata ingress,
        string calldata egress
    )
        internal
        view
    {
        if (publicKey == bytes32(0)) {
            revert InvalidPublicKey();
        }
        if (pubkeyToIndex[publicKey] != 0) {
            revert PublicKeyAlreadyExists();
        }
        _validateIpPort(ingress, "ingress");
        _validateIp(egress, "egress");
    }

    function _addValidator(
        address validatorAddress,
        bytes32 publicKey,
        string calldata ingress,
        string calldata egress,
        uint64 height
    )
        internal
    {
        uint64 idx = uint64(validatorsArray.length);
        Validator memory newVal = Validator({
            publicKey: publicKey,
            validatorAddress: validatorAddress,
            ingress: ingress,
            egress: egress,
            index: idx,
            addedAtHeight: height,
            deactivatedAtHeight: 0
        });

        validatorsArray.push(newVal);
        addressToIndex[validatorAddress] = idx + 1; // 1-indexed
        pubkeyToIndex[publicKey] = idx + 1; // 1-indexed
    }

    // Note: This is a stub implementation. The precompile implementation
    // would perform Ed25519 signature verification.
    function _verifyEd25519Signature(
        bytes32, /* publicKey */
        bytes32, /* message */
        bytes calldata /* signature */
    )
        internal
        pure { }

    function _validateIpPort(string calldata input, string memory field) internal pure {
        bytes memory b = bytes(input);

        if (b.length == 0) {
            revert NotIpPort(field, input, "Empty address");
        }

        if (b[0] == "[") {
            _validateIpv6Port(b, field, input);
        } else {
            _validateIpv4Port(b, field, input);
        }
    }

    function _validateIp(string calldata input, string memory field) internal pure {
        bytes memory b = bytes(input);

        if (b.length == 0) {
            revert NotIpPort(field, input, "Empty address");
        }

        if (b[0] == "[") {
            _validateIpv6Address(b, 1, b.length - 1, field, input);
        } else {
            _validateIpv4(b, field, input);
        }
    }

    function _validateIpv4Port(
        bytes memory b,
        string memory field,
        string calldata input
    )
        internal
        pure
    {
        if (b.length < 9) {
            revert NotIpPort(field, input, "Address too short");
        }

        uint256 i = 0;

        for (uint256 octet = 0; octet < 4; octet++) {
            uint256 value = 0;
            uint256 digitCount = 0;

            while (i < b.length && b[i] != "." && b[i] != ":") {
                bytes1 c = b[i];
                if (c < "0" || c > "9") {
                    revert NotIpPort(field, input, "Invalid character in octet");
                }
                value = value * 10 + uint8(c) - 48;
                digitCount++;
                i++;
            }

            if (digitCount == 0 || digitCount > 3) {
                revert NotIpPort(field, input, "Invalid octet length");
            }
            if (value > 255) {
                revert NotIpPort(field, input, "Octet out of range");
            }
            if (digitCount > 1 && b[i - digitCount] == "0") {
                revert NotIpPort(field, input, "Leading zeros not allowed");
            }

            if (octet < 3) {
                if (i >= b.length || b[i] != ".") {
                    revert NotIpPort(field, input, "Expected dot separator");
                }
                i++;
            }
        }

        if (i >= b.length || b[i] != ":") {
            revert NotIpPort(field, input, "Missing port separator");
        }
        i++;

        _validatePort(b, i, field, input);
    }

    function _validateIpv4(
        bytes memory b,
        string memory field,
        string calldata input
    )
        internal
        pure
    {
        if (b.length < 7) {
            revert NotIpPort(field, input, "Address too short");
        }

        uint256 i = 0;

        for (uint256 octet = 0; octet < 4; octet++) {
            uint256 value = 0;
            uint256 digitCount = 0;

            while (i < b.length && b[i] != ".") {
                bytes1 c = b[i];
                if (c < "0" || c > "9") {
                    revert NotIpPort(field, input, "Invalid character in octet");
                }
                value = value * 10 + uint8(c) - 48;
                digitCount++;
                i++;
            }

            if (digitCount == 0 || digitCount > 3) {
                revert NotIpPort(field, input, "Invalid octet length");
            }
            if (value > 255) {
                revert NotIpPort(field, input, "Octet out of range");
            }
            if (digitCount > 1 && b[i - digitCount] == "0") {
                revert NotIpPort(field, input, "Leading zeros not allowed");
            }

            if (octet < 3) {
                if (i >= b.length || b[i] != ".") {
                    revert NotIpPort(field, input, "Expected dot separator");
                }
                i++;
            }
        }

        if (i != b.length) {
            revert NotIpPort(field, input, "Unexpected trailing characters");
        }
    }

    function _validateIpv6Port(
        bytes memory b,
        string memory field,
        string calldata input
    )
        internal
        pure
    {
        if (b.length < 6) {
            revert NotIpPort(field, input, "Address too short");
        }

        uint256 closeBracket = 0;
        for (uint256 i = 1; i < b.length; i++) {
            if (b[i] == "]") {
                closeBracket = i;
                break;
            }
        }

        if (closeBracket == 0) {
            revert NotIpPort(field, input, "Missing closing bracket");
        }

        _validateIpv6Address(b, 1, closeBracket, field, input);

        if (closeBracket + 1 >= b.length || b[closeBracket + 1] != ":") {
            revert NotIpPort(field, input, "Missing port separator after bracket");
        }

        _validatePort(b, closeBracket + 2, field, input);
    }

    function _validateIpv6Address(
        bytes memory b,
        uint256 start,
        uint256 end,
        string memory field,
        string calldata input
    )
        internal
        pure
    {
        if (start >= end) {
            revert NotIpPort(field, input, "Empty IPv6 address");
        }

        uint256 groupCount = 0;
        uint256 doubleColonPos = type(uint256).max;
        uint256 i = start;

        if (i + 1 < end && b[i] == ":" && b[i + 1] == ":") {
            doubleColonPos = 0;
            i += 2;
            if (i == end) {
                return;
            }
        }

        while (i < end) {
            uint256 digitCount = 0;

            while (i < end && b[i] != ":") {
                bytes1 c = b[i];
                bool isHex =
                    (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
                if (!isHex) {
                    revert NotIpPort(field, input, "Invalid hex character");
                }
                digitCount++;
                i++;
            }

            if (digitCount == 0) {
                if (doubleColonPos == type(uint256).max) {
                    revert NotIpPort(field, input, "Empty group without ::");
                }
            } else {
                if (digitCount > 4) {
                    revert NotIpPort(field, input, "Group exceeds 4 hex digits");
                }
                groupCount++;
            }

            if (i < end) {
                if (b[i] == ":") {
                    if (i + 1 < end && b[i + 1] == ":") {
                        if (doubleColonPos != type(uint256).max) {
                            revert NotIpPort(field, input, "Multiple :: not allowed");
                        }
                        doubleColonPos = groupCount;
                        i += 2;
                        if (i == end) {
                            break;
                        }
                    } else {
                        i++;
                    }
                }
            }
        }

        if (doubleColonPos == type(uint256).max) {
            if (groupCount != 8) {
                revert NotIpPort(field, input, "Must have 8 groups without ::");
            }
        } else {
            if (groupCount >= 8) {
                revert NotIpPort(field, input, "Too many groups with ::");
            }
        }
    }

    function _validatePort(
        bytes memory b,
        uint256 start,
        string memory field,
        string calldata input
    )
        internal
        pure
    {
        if (start >= b.length) {
            revert NotIpPort(field, input, "Missing port number");
        }

        uint256 port = 0;
        uint256 digitCount = 0;

        for (uint256 i = start; i < b.length; i++) {
            bytes1 c = b[i];
            if (c < "0" || c > "9") {
                revert NotIpPort(field, input, "Invalid port character");
            }
            port = port * 10 + uint8(c) - 48;
            digitCount++;
        }

        if (digitCount == 0) {
            revert NotIpPort(field, input, "Empty port number");
        }
        if (digitCount > 5) {
            revert NotIpPort(field, input, "Port too long");
        }
        if (port > 65_535) {
            revert NotIpPort(field, input, "Port out of range");
        }
        if (digitCount > 1 && b[start] == "0") {
            revert NotIpPort(field, input, "Leading zeros in port");
        }
    }

}
