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

    uint256 private constant _SLOADS_PER_VALIDATOR = 9; // worst case value
    uint256 private constant _GAS_PER_COLD_SLOAD = 2100;
    uint256 private constant _GAS_BUFFER = 10_000;

    // =========================================================================
    // Storage
    // =========================================================================

    /// @dev Slot 0: bit 255 = initialized flag, bits 191-254 = initializedAtHeight, bits 0-159 = owner address
    address private _owner;
    bool private _initialized;
    uint64 private _initializedAtHeight;

    IValidatorConfig public immutable v1 =
        IValidatorConfig(0xCccCcCCC00000000000000000000000000000000);

    Validator[] internal activeValidatorsArray;
    Validator[] internal inactiveValidatorsArray;

    /// @dev 1-indexed: 0 means not found. Stored value is arrayIndex + 1.
    mapping(address => uint64) internal addressToIndex;

    /// @dev 1-indexed: 0 means not found. Stored value is arrayIndex + 1.
    mapping(bytes32 => uint64) internal pubkeyToIndex;

    uint64 internal nextDkgCeremony;

    /// @dev Tracks active ingress IPs by their keccak256 hash
    mapping(bytes32 => bool) internal activeIngressIpHashes;

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

    function _checkOnlyOwnerOrValidator(address validatorAddress) internal view {
        if (msg.sender != _owner && msg.sender != validatorAddress) {
            revert Unauthorized();
        }
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
            abi.encodePacked(block.chainid, address(this), validatorAddress, ingress, egress)
        );
        _verifyEd25519Signature(
            bytes("TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR"), publicKey, message, signature
        );

        _addValidator(validatorAddress, publicKey, ingress, egress, 0);
    }

    /// @inheritdoc IValidatorConfigV2
    function deactivateValidator(uint64 idx) external {
        uint64 activeValsLength = uint64(activeValidatorsArray.length);
        if (idx >= activeValsLength) {
            revert ValidatorNotFound();
        }

        Validator memory toDeactivate = activeValidatorsArray[idx];

        _checkOnlyOwnerOrValidator(toDeactivate.validatorAddress);

        bytes32 ingressIpHash = _getIngressIpHash(toDeactivate.ingress);
        delete activeIngressIpHashes[ingressIpHash];

        toDeactivate.deactivatedAtHeight = uint64(block.number);
        inactiveValidatorsArray.push(toDeactivate);
        addressToIndex[toDeactivate.validatorAddress] = 0;
        pubkeyToIndex[toDeactivate.publicKey] = 0;

        // swap and pop
        if (idx != activeValsLength - 1) {
            Validator memory lastValidator = activeValidatorsArray[activeValsLength - 1];
            lastValidator.index = idx;
            activeValidatorsArray[idx] = lastValidator;
            addressToIndex[lastValidator.validatorAddress] = idx + 1;
            pubkeyToIndex[lastValidator.publicKey] = idx + 1;
        }
        activeValidatorsArray.pop();
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
        uint64 idx,
        bytes32 publicKey,
        string calldata ingress,
        string calldata egress,
        bytes calldata signature
    )
        external
        onlyInitialized
    {
        if (idx >= activeValidatorsArray.length) {
            revert ValidatorNotFound();
        }
        Validator memory oldValidator = activeValidatorsArray[idx];

        _checkOnlyOwnerOrValidator(oldValidator.validatorAddress);

        _validateRotateParams(publicKey, ingress, egress);

        bytes32 message = keccak256(
            abi.encodePacked(
                block.chainid, address(this), oldValidator.validatorAddress, ingress, egress
            )
        );
        _verifyEd25519Signature(
            bytes("TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR"), publicKey, message, signature
        );

        _updateIngressIp(oldValidator.ingress, ingress);

        oldValidator.deactivatedAtHeight = uint64(block.number);
        oldValidator.index = 0;
        inactiveValidatorsArray.push(oldValidator);
        pubkeyToIndex[oldValidator.publicKey] = 0;

        // Replace in place. Ingress hash uniqueness tracked above
        activeValidatorsArray[idx] = Validator({
            publicKey: publicKey,
            validatorAddress: oldValidator.validatorAddress,
            ingress: ingress,
            egress: egress,
            index: idx,
            addedAtHeight: uint64(block.number),
            deactivatedAtHeight: 0
        });
        pubkeyToIndex[publicKey] = idx + 1; // 1-indexed
    }

    /// @inheritdoc IValidatorConfigV2
    function setIpAddresses(uint64 idx, string calldata ingress, string calldata egress) external {
        if (idx >= activeValidatorsArray.length) {
            revert ValidatorNotFound();
        }
        Validator storage v = activeValidatorsArray[idx];

        _checkOnlyOwnerOrValidator(v.validatorAddress);

        _validateIpPort(ingress, "ingress");
        _validateIp(egress, "egress");
        _updateIngressIp(v.ingress, ingress);

        v.ingress = ingress;
        v.egress = egress;
    }

    /// @inheritdoc IValidatorConfigV2
    function transferValidatorOwnership(uint64 idx, address newAddress) external onlyInitialized {
        if (idx >= activeValidatorsArray.length) {
            revert ValidatorNotFound();
        }

        if (newAddress == address(0)) {
            revert InvalidValidatorAddress();
        }

        if (addressToIndex[newAddress] != 0) {
            revert AddressAlreadyHasValidator();
        }

        Validator storage v = activeValidatorsArray[idx];
        address currAddr = v.validatorAddress;

        _checkOnlyOwnerOrValidator(currAddr);

        v.validatorAddress = newAddress;
        addressToIndex[newAddress] = idx + 1;
        delete addressToIndex[currAddr];
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /// @inheritdoc IValidatorConfigV2
    function getActiveValidators() external view returns (Validator[] memory validators) {
        return activeValidatorsArray;
    }

    /// @inheritdoc IValidatorConfigV2
    function getInactiveValidators(uint64 startIndex) external view returns (Validator[] memory) {
        uint256 len = inactiveValidatorsArray.length;
        if (startIndex >= len) {
            return new Validator[](0);
        }

        Validator[] memory result = new Validator[](len - startIndex);
        uint256 gasPerIteration = _SLOADS_PER_VALIDATOR * _GAS_PER_COLD_SLOAD + _GAS_BUFFER;

        uint256 count;
        for (uint256 i = startIndex; i < len; i++) {
            if (gasleft() < gasPerIteration) {
                assembly {
                    mstore(result, count)
                }
                return result;
            }
            result[count] = inactiveValidatorsArray[i];
            unchecked {
                ++count;
            }
        }

        return result;
    }

    /// @inheritdoc IValidatorConfigV2
    function inactiveValidatorCount() external view returns (uint64) {
        return uint64(inactiveValidatorsArray.length);
    }

    /// @inheritdoc IValidatorConfigV2
    /// @dev If addValidator has not been called yet, this will return address(0)
    function owner() external view returns (address) {
        return _owner;
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorCount() external view returns (uint64) {
        return uint64(activeValidatorsArray.length) + uint64(inactiveValidatorsArray.length);
    }

    /// @inheritdoc IValidatorConfigV2
    function activeValidatorCount() external view returns (uint64) {
        return uint64(activeValidatorsArray.length);
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorByIndex(uint64 index) external view returns (Validator memory) {
        if (index >= activeValidatorsArray.length) {
            revert ValidatorNotFound();
        }
        return activeValidatorsArray[index];
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorByAddress(address validatorAddress) external view returns (Validator memory) {
        uint64 idx = addressToIndex[validatorAddress];
        if (idx == 0) {
            revert ValidatorNotFound();
        }
        return activeValidatorsArray[idx - 1];
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorByPublicKey(bytes32 publicKey) external view returns (Validator memory) {
        uint64 idx = pubkeyToIndex[publicKey];
        if (idx == 0) {
            revert ValidatorNotFound();
        }
        return activeValidatorsArray[idx - 1];
    }

    /// @inheritdoc IValidatorConfigV2
    function getNextFullDkgCeremony() external view returns (uint64) {
        return nextDkgCeremony;
    }

    /// @inheritdoc IValidatorConfigV2
    function isInitialized() external view returns (bool) {
        return _initialized;
    }

    /// @inheritdoc IValidatorConfigV2
    function getInitializedAtHeight() external view returns (uint64) {
        return _initializedAtHeight;
    }

    // =========================================================================
    // Migration Functions (V1 -> V2)
    // =========================================================================

    /// @inheritdoc IValidatorConfigV2
    function migrateValidator(uint64 idx) external {
        if (_initialized) {
            revert AlreadyInitialized();
        }
        if (idx != inactiveValidatorsArray.length + activeValidatorsArray.length) {
            revert InvalidMigrationIndex();
        }

        IValidatorConfig.Validator[] memory v1Validators = v1.getValidators();
        if (idx >= v1Validators.length) {
            revert ValidatorNotFound();
        }

        if (_owner == address(0)) {
            _owner = v1.owner();
        }

        if (msg.sender != _owner) {
            revert Unauthorized();
        }

        IValidatorConfig.Validator memory v1Val = v1Validators[idx];

        string memory egress = _extractIpFromSocket(v1Val.outboundAddress);

        _requireUniqueIngressIp(v1Val.inboundAddress);

        _addValidator(
            v1Val.validatorAddress,
            v1Val.publicKey,
            v1Val.inboundAddress,
            egress,
            v1Val.active ? 0 : uint64(block.number)
        );
    }

    /// @inheritdoc IValidatorConfigV2
    function initializeIfMigrated() external onlyOwner {
        if (_initialized) {
            revert AlreadyInitialized();
        }

        IValidatorConfig.Validator[] memory v1Validators = v1.getValidators();
        if (activeValidatorsArray.length + inactiveValidatorsArray.length < v1Validators.length) {
            revert MigrationNotComplete();
        }

        nextDkgCeremony = v1.getNextFullDkgCeremony();

        _initialized = true;
        _initializedAtHeight = uint64(block.number);
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
        // Allow reusing addresses of deactivated validators
        uint64 idx1 = addressToIndex[validatorAddress];
        if (idx1 != 0) {
            revert AddressAlreadyHasValidator();
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
        _requireUniqueIngressIp(ingress);
    }

    function _addValidator(
        address validatorAddress,
        bytes32 publicKey,
        string memory ingress,
        string memory egress,
        uint64 deactivatedAtHeight
    )
        internal
    {
        uint64 idx = deactivatedAtHeight == 0 ? uint64(activeValidatorsArray.length) : 0;

        Validator memory newVal = Validator({
            publicKey: publicKey,
            validatorAddress: validatorAddress,
            ingress: ingress,
            egress: egress,
            index: idx,
            addedAtHeight: uint64(block.number),
            deactivatedAtHeight: deactivatedAtHeight
        });

        if (deactivatedAtHeight == 0) {
            activeValidatorsArray.push(newVal);
            addressToIndex[validatorAddress] = idx + 1; // 1-indexed
            pubkeyToIndex[publicKey] = idx + 1; // 1-indexed
            bytes32 ingressIpHash = _getIngressIpHash(ingress);
            activeIngressIpHashes[ingressIpHash] = true;
        } else {
            inactiveValidatorsArray.push(newVal);
        }
    }

    // Note: This is a stub implementation. The precompile implementation
    // would perform Ed25519 signature verification.
    function _verifyEd25519Signature(
        bytes memory, /* namespace */
        bytes32, /* publicKey */
        bytes32, /* message */
        bytes calldata /* signature */
    )
        internal
        pure { }

    /// @dev Check that ingress IP is not already in use by active validators
    function _requireUniqueIngressIp(string memory ingress) internal view {
        bytes32 ingressIpHash = _getIngressIpHash(ingress);
        if (activeIngressIpHashes[ingressIpHash]) {
            revert IngressAlreadyExists(ingress);
        }
    }

    /// @dev Update ingress IP tracking when ingress changes
    function _updateIngressIp(string memory oldIngress, string memory newIngress) internal {
        bytes32 oldIngressIpHash = _getIngressIpHash(oldIngress);
        bytes32 newIngressIpHash = _getIngressIpHash(newIngress);

        if (oldIngressIpHash != newIngressIpHash) {
            if (activeIngressIpHashes[newIngressIpHash]) {
                revert IngressAlreadyExists(newIngress);
            }
            delete activeIngressIpHashes[oldIngressIpHash];
            activeIngressIpHashes[newIngressIpHash] = true;
        }
    }

    /// @dev Extract and hash IP from ingress (ip:port -> keccak256(ip))
    /// Handles both IPv4 (192.168.1.1:8000) and IPv6 ([::1]:8000)
    function _getIngressIpHash(string memory ingress) internal pure returns (bytes32) {
        string memory ip = _extractIpFromSocket(ingress);
        return keccak256(bytes(ip));
    }

    /// @dev Extract IP from socket address format (ip:port -> ip)
    /// Handles both IPv4 (192.168.1.1:8000 -> 192.168.1.1) and IPv6 ([::1]:8000 -> ::1)
    function _extractIpFromSocket(string memory socketAddr) internal pure returns (string memory) {
        bytes memory b = bytes(socketAddr);
        if (b.length == 0) return socketAddr;

        // IPv6 format: [ip]:port
        if (b[0] == "[") {
            for (uint256 i = 1; i < b.length; i++) {
                if (b[i] == "]") {
                    // Extract IPv6 without brackets
                    bytes memory ip = new bytes(i - 1);
                    for (uint256 j = 1; j < i; j++) {
                        ip[j - 1] = b[j];
                    }
                    return string(ip);
                }
            }
            return socketAddr; // Malformed, return as-is
        }

        // IPv4 format: ip:port
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == ":") {
                // Extract IP before colon
                bytes memory ip = new bytes(i);
                for (uint256 j = 0; j < i; j++) {
                    ip[j] = b[j];
                }
                return string(ip);
            }
        }

        // No port found, return as-is
        return socketAddr;
    }

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
