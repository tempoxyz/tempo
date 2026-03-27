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

    /// @dev Slot 0: bit 255 = initialized flag, bits 191-254 = initializedAtHeight, bits 0-159 = owner address
    address private _owner;
    bool private _initialized;
    uint64 private _initializedAtHeight;
    uint8 internal _migrationSkippedCount;
    uint8 internal _v1ValidatorCount;

    IValidatorConfig public immutable v1 =
        IValidatorConfig(0xCccCcCCC00000000000000000000000000000000);

    ValidatorStorage[] internal validatorsArray;

    /// @notice Indices into the validatorsArray. This array does not preserve order.
    /// @dev 1-indexed: 0 means not found. Stored value is arrayIndex + 1.
    uint64[] internal activeIndices;

    /// @dev 1-indexed: 0 means not found. Stored value is arrayIndex + 1.
    mapping(address => uint64) internal addressToIndex;

    /// @dev 1-indexed: 0 means not found. Stored value is arrayIndex + 1.
    mapping(bytes32 => uint64) internal pubkeyToIndex;

    uint64 internal _nextNetworkIdentityRotationEpoch;

    /// @dev Tracks active ingress socket addresses by their keccak256 hash
    mapping(bytes32 => bool) internal activeIngressHashes;

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
        address feeRecipient,
        bytes calldata signature
    )
        external
        onlyInitialized
        onlyOwner
        returns (uint64 index)
    {
        _validateAddParams(validatorAddress, publicKey, ingress, egress);

        bytes32 message = keccak256(
            abi.encodePacked(
                uint64(block.chainid),
                address(this),
                validatorAddress,
                uint8(bytes(ingress).length),
                ingress,
                uint8(bytes(egress).length),
                egress,
                feeRecipient
            )
        );
        _verifyEd25519Signature(
            bytes("TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR"), publicKey, message, signature
        );

        index = _addValidator(validatorAddress, publicKey, ingress, egress, feeRecipient, 0);
        emit ValidatorAdded(index, validatorAddress, publicKey, ingress, egress, feeRecipient);
    }

    /// @inheritdoc IValidatorConfigV2
    function deactivateValidator(uint64 idx) external {
        if (idx >= validatorsArray.length) {
            revert ValidatorNotFound();
        }

        ValidatorStorage storage v = validatorsArray[idx];
        if (v.deactivatedAtHeight != 0) {
            revert ValidatorAlreadyDeactivated();
        }

        _checkOnlyOwnerOrValidator(v.validatorAddress);

        bytes32 ingressHash = _getIngressHash(v.ingress);
        delete activeIngressHashes[ingressHash];

        v.deactivatedAtHeight = uint64(block.number);
        emit ValidatorDeactivated(idx, v.validatorAddress);

        // do a pop-and-swap for validatorsArray
        uint64 toDeactivateIndex = v.activeIdx - 1;
        uint256 lastPos = activeIndices.length - 1;

        if (toDeactivateIndex != lastPos) {
            uint64 movedVal = activeIndices[lastPos];
            activeIndices[toDeactivateIndex] = movedVal;
            validatorsArray[movedVal - 1].activeIdx = toDeactivateIndex + 1;
        }
        activeIndices.pop();
        v.activeIdx = 0;
    }

    /// @inheritdoc IValidatorConfigV2
    function transferOwnership(address newOwner) external onlyInitialized onlyOwner {
        if (newOwner == address(0)) revert InvalidOwner();
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    /// @inheritdoc IValidatorConfigV2
    function setNetworkIdentityRotationEpoch(uint64 epoch) external onlyInitialized onlyOwner {
        uint64 previousEpoch = _nextNetworkIdentityRotationEpoch;
        _nextNetworkIdentityRotationEpoch = epoch;
        emit NetworkIdentityRotationEpochSet(previousEpoch, epoch);
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
        if (idx >= validatorsArray.length) {
            revert ValidatorNotFound();
        }

        ValidatorStorage storage oldValidator = validatorsArray[idx];
        if (oldValidator.deactivatedAtHeight != 0) {
            revert ValidatorAlreadyDeactivated();
        }

        address validatorAddress = oldValidator.validatorAddress;
        _checkOnlyOwnerOrValidator(validatorAddress);

        _validateRotateParams(publicKey, ingress, egress);

        bytes32 message = keccak256(
            abi.encodePacked(
                uint64(block.chainid),
                address(this),
                validatorAddress,
                uint8(bytes(ingress).length),
                ingress,
                uint8(bytes(egress).length),
                egress
            )
        );
        _verifyEd25519Signature(
            bytes("TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR"), publicKey, message, signature
        );

        _updateIngress(oldValidator.ingress, ingress);

        // Append deactivated snapshot of current values
        uint64 appendedIdx = uint64(validatorsArray.length);
        validatorsArray.push(
            ValidatorStorage({
                publicKey: oldValidator.publicKey,
                validatorAddress: validatorAddress,
                ingress: oldValidator.ingress,
                egress: oldValidator.egress,
                feeRecipient: oldValidator.feeRecipient,
                index: appendedIdx,
                activeIdx: 0,
                addedAtHeight: oldValidator.addedAtHeight,
                deactivatedAtHeight: uint64(block.number)
            })
        );

        // Update pubkeyToIndex: old pubkey → deactivated copy
        pubkeyToIndex[oldValidator.publicKey] = appendedIdx + 1;
        bytes32 oldPublicKey = oldValidator.publicKey;

        // Modify slot in-place with new identity
        oldValidator.publicKey = publicKey;
        oldValidator.ingress = ingress;
        oldValidator.egress = egress;
        oldValidator.addedAtHeight = uint64(block.number);

        // Point new pubkey to original slot
        pubkeyToIndex[publicKey] = idx + 1;

        emit ValidatorRotated(
            idx, appendedIdx, validatorAddress, oldPublicKey, publicKey, ingress, egress, msg.sender
        );
    }

    /// @inheritdoc IValidatorConfigV2
    function setIpAddresses(
        uint64 idx,
        string calldata ingress,
        string calldata egress
    )
        external
        onlyInitialized
    {
        if (idx >= validatorsArray.length) {
            revert ValidatorNotFound();
        }

        ValidatorStorage storage v = validatorsArray[idx];
        if (v.deactivatedAtHeight != 0) {
            revert ValidatorAlreadyDeactivated();
        }

        _checkOnlyOwnerOrValidator(v.validatorAddress);

        _validateIpPort(ingress);
        _validateIp(egress);
        _updateIngress(v.ingress, ingress);

        v.ingress = ingress;
        v.egress = egress;
        emit IpAddressesUpdated(idx, ingress, egress, msg.sender);
    }

    /// @inheritdoc IValidatorConfigV2
    function setFeeRecipient(uint64 idx, address feeRecipient) external onlyInitialized {
        if (idx >= validatorsArray.length) {
            revert ValidatorNotFound();
        }

        ValidatorStorage storage v = validatorsArray[idx];
        if (v.deactivatedAtHeight != 0) {
            revert ValidatorAlreadyDeactivated();
        }

        _checkOnlyOwnerOrValidator(v.validatorAddress);

        v.feeRecipient = feeRecipient;

        emit FeeRecipientUpdated(idx, feeRecipient, msg.sender);
    }

    /// @inheritdoc IValidatorConfigV2
    function transferValidatorOwnership(uint64 idx, address newAddress) external onlyInitialized {
        if (idx >= validatorsArray.length) {
            revert ValidatorNotFound();
        }

        if (newAddress == address(0)) {
            revert InvalidValidatorAddress();
        }

        if (
            addressToIndex[newAddress] != 0
                && validatorsArray[addressToIndex[newAddress] - 1].deactivatedAtHeight == 0
        ) {
            revert AddressAlreadyHasValidator();
        }

        ValidatorStorage storage v = validatorsArray[idx];
        if (v.deactivatedAtHeight != 0) {
            revert ValidatorAlreadyDeactivated();
        }

        address currentAddress = v.validatorAddress;
        _checkOnlyOwnerOrValidator(currentAddress);

        v.validatorAddress = newAddress;
        delete addressToIndex[currentAddress];
        addressToIndex[newAddress] = idx + 1;
        emit ValidatorOwnershipTransferred(idx, currentAddress, newAddress, msg.sender);
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    /// @inheritdoc IValidatorConfigV2
    function getActiveValidators() external view returns (Validator[] memory validators) {
        uint64 len = uint64(activeIndices.length);
        validators = new Validator[](len);
        for (uint64 i = 0; i < len; i++) {
            validators[i] = _toValidator(validatorsArray[activeIndices[i] - 1]);
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
    function validatorByIndex(uint64 index) external view returns (Validator memory) {
        if (index >= validatorsArray.length) {
            revert ValidatorNotFound();
        }
        return _toValidator(validatorsArray[index]);
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorByAddress(address validatorAddress) external view returns (Validator memory) {
        uint64 idx = addressToIndex[validatorAddress];
        if (idx == 0) {
            revert ValidatorNotFound();
        }
        return _toValidator(validatorsArray[idx - 1]);
    }

    /// @inheritdoc IValidatorConfigV2
    function validatorByPublicKey(bytes32 publicKey) external view returns (Validator memory) {
        uint64 idx = pubkeyToIndex[publicKey];
        if (idx == 0) {
            revert ValidatorNotFound();
        }
        return _toValidator(validatorsArray[idx - 1]);
    }

    /// @inheritdoc IValidatorConfigV2
    function getNextNetworkIdentityRotationEpoch() external view returns (uint64) {
        return _nextNetworkIdentityRotationEpoch;
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

        IValidatorConfig.Validator[] memory v1Validators = v1.getValidators();
        uint64 v1Count;
        if (validatorsArray.length == 0 && _owner == address(0)) {
            if (v1Validators.length == 0) {
                revert EmptyV1ValidatorSet();
            }
            _owner = v1.owner();
            _v1ValidatorCount = uint8(v1Validators.length);
            v1Count = _v1ValidatorCount;
        } else {
            v1Count = _v1ValidatorCount;
        }

        if (msg.sender != _owner) {
            revert Unauthorized();
        }

        if (idx + uint64(validatorsArray.length) + _migrationSkippedCount + 1 != v1Count) {
            revert InvalidMigrationIndex();
        }

        IValidatorConfig.Validator memory v1Val = v1Validators[idx];

        if (v1Val.publicKey == bytes32(0) || v1Val.validatorAddress == address(0)) {
            _migrationSkippedCount++;
            emit SkippedValidatorMigration(idx, v1Val.validatorAddress, v1Val.publicKey);
            return;
        }

        string memory egress = _extractIpFromSocket(v1Val.outboundAddress);

        if (pubkeyToIndex[v1Val.publicKey] != 0) {
            _migrationSkippedCount++;
            emit SkippedValidatorMigration(idx, v1Val.validatorAddress, v1Val.publicKey);
            return;
        }

        uint64 addrIdx = addressToIndex[v1Val.validatorAddress];
        if (addrIdx != 0 && validatorsArray[addrIdx - 1].deactivatedAtHeight == 0) {
            revert AddressAlreadyHasValidator();
        }

        bool nowActive = v1Val.active;
        bytes32 ingressHash = _getIngressHash(v1Val.inboundAddress);

        if (nowActive && activeIngressHashes[ingressHash]) {
            _migrationSkippedCount++;
            emit SkippedValidatorMigration(idx, v1Val.validatorAddress, v1Val.publicKey);
            return;
        }

        uint64 migratedIdx = _addValidator(
            v1Val.validatorAddress,
            v1Val.publicKey,
            v1Val.inboundAddress,
            egress,
            address(0),
            nowActive ? 0 : uint64(block.number)
        );
        emit ValidatorMigrated(migratedIdx, v1Val.validatorAddress, v1Val.publicKey);
    }

    /// @inheritdoc IValidatorConfigV2
    function initializeIfMigrated() external onlyOwner {
        if (_initialized) {
            revert AlreadyInitialized();
        }

        if (
            _v1ValidatorCount == 0
                || validatorsArray.length + _migrationSkippedCount < _v1ValidatorCount
        ) {
            revert MigrationNotComplete();
        }

        _nextNetworkIdentityRotationEpoch = v1.getNextFullDkgCeremony();

        _initialized = true;
        _initializedAtHeight = uint64(block.number);
        emit Initialized(uint64(block.number));
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    function _toValidator(ValidatorStorage storage v) internal view returns (Validator memory) {
        return Validator({
            publicKey: v.publicKey,
            validatorAddress: v.validatorAddress,
            ingress: v.ingress,
            egress: v.egress,
            feeRecipient: v.feeRecipient,
            index: v.index,
            addedAtHeight: v.addedAtHeight,
            deactivatedAtHeight: v.deactivatedAtHeight
        });
    }

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
        if (idx1 != 0 && validatorsArray[idx1 - 1].deactivatedAtHeight == 0) {
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
        _validateIpPort(ingress);
        _validateIp(egress);
        _requireUniqueIngress(ingress);
    }

    function _addValidator(
        address validatorAddress,
        bytes32 publicKey,
        string memory ingress,
        string memory egress,
        address feeRecipient,
        uint64 deactivatedAtHeight
    )
        internal
        returns (uint64 idx)
    {
        idx = uint64(validatorsArray.length);
        uint64 activeIdx = 0;

        if (deactivatedAtHeight == 0) {
            activeIndices.push(idx + 1); // 1-indexed
            activeIdx = uint64(activeIndices.length); // 1-indexed
            bytes32 ingressHash = _getIngressHash(ingress);
            activeIngressHashes[ingressHash] = true;
        }

        ValidatorStorage memory newVal = ValidatorStorage({
            publicKey: publicKey,
            validatorAddress: validatorAddress,
            ingress: ingress,
            egress: egress,
            feeRecipient: feeRecipient,
            index: idx,
            activeIdx: activeIdx,
            addedAtHeight: uint64(block.number),
            deactivatedAtHeight: deactivatedAtHeight
        });

        validatorsArray.push(newVal);
        pubkeyToIndex[publicKey] = idx + 1; // 1-indexed
        // if there are duplicated vals with addresses, the latter validator entry is correct
        addressToIndex[validatorAddress] = idx + 1; // 1-indexed.
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

    /// @dev Check that ingress is not already in use by active validators
    function _requireUniqueIngress(string memory ingress) internal view {
        bytes32 ingressHash = _getIngressHash(ingress);
        if (activeIngressHashes[ingressHash]) {
            revert IngressAlreadyExists(ingress);
        }
    }

    /// @dev Update ingress tracking when ingress changes
    function _updateIngress(string memory oldIngress, string memory newIngress) internal {
        bytes32 oldIngressHash = _getIngressHash(oldIngress);
        bytes32 newIngressHash = _getIngressHash(newIngress);

        if (oldIngressHash != newIngressHash) {
            if (activeIngressHashes[newIngressHash]) {
                revert IngressAlreadyExists(newIngress);
            }
            delete activeIngressHashes[oldIngressHash];
            activeIngressHashes[newIngressHash] = true;
        }
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

    /// @dev Hash ingress socket address
    /// Handles both IPv4 (192.168.1.1:8000) and IPv6 ([::1]:8000)
    function _getIngressHash(string memory ingress) internal pure returns (bytes32) {
        return keccak256(bytes(ingress));
    }

    function _validateIpPort(string calldata input) internal pure {
        bytes memory b = bytes(input);

        if (b.length == 0) {
            revert NotIpPort(input, "Empty address");
        }

        if (b[0] == "[") {
            _validateIpv6Port(b, input);
        } else {
            _validateIpv4Port(b, input);
        }
    }

    function _validateIp(string calldata input) internal pure {
        bytes memory b = bytes(input);

        if (b.length == 0) {
            revert NotIp(input, "Empty address");
        }

        if (b[0] == "[") {
            _validateIpv6Address(b, 1, b.length - 1, input);
        } else {
            _validateIpv4(b, input);
        }
    }

    function _validateIpv4Port(bytes memory b, string calldata input) internal pure {
        if (b.length < 9) {
            revert NotIpPort(input, "Address too short");
        }

        uint256 i = 0;

        for (uint256 octet = 0; octet < 4; octet++) {
            uint256 value = 0;
            uint256 digitCount = 0;

            while (i < b.length && b[i] != "." && b[i] != ":") {
                bytes1 c = b[i];
                if (c < "0" || c > "9") {
                    revert NotIpPort(input, "Invalid character in octet");
                }
                value = value * 10 + uint8(c) - 48;
                digitCount++;
                i++;
            }

            if (digitCount == 0 || digitCount > 3) {
                revert NotIpPort(input, "Invalid octet length");
            }
            if (value > 255) {
                revert NotIpPort(input, "Octet out of range");
            }
            if (digitCount > 1 && b[i - digitCount] == "0") {
                revert NotIpPort(input, "Leading zeros not allowed");
            }

            if (octet < 3) {
                if (i >= b.length || b[i] != ".") {
                    revert NotIpPort(input, "Expected dot separator");
                }
                i++;
            }
        }

        if (i >= b.length || b[i] != ":") {
            revert NotIpPort(input, "Missing port separator");
        }
        i++;

        _validatePort(b, i, input);
    }

    function _validateIpv4(bytes memory b, string calldata input) internal pure {
        if (b.length < 7) {
            revert NotIp(input, "Address too short");
        }

        uint256 i = 0;

        for (uint256 octet = 0; octet < 4; octet++) {
            uint256 value = 0;
            uint256 digitCount = 0;

            while (i < b.length && b[i] != ".") {
                bytes1 c = b[i];
                if (c < "0" || c > "9") {
                    revert NotIp(input, "Invalid character in octet");
                }
                value = value * 10 + uint8(c) - 48;
                digitCount++;
                i++;
            }

            if (digitCount == 0 || digitCount > 3) {
                revert NotIp(input, "Invalid octet length");
            }
            if (value > 255) {
                revert NotIp(input, "Octet out of range");
            }
            if (digitCount > 1 && b[i - digitCount] == "0") {
                revert NotIp(input, "Leading zeros not allowed");
            }

            if (octet < 3) {
                if (i >= b.length || b[i] != ".") {
                    revert NotIp(input, "Expected dot separator");
                }
                i++;
            }
        }

        if (i != b.length) {
            revert NotIp(input, "Unexpected trailing characters");
        }
    }

    function _validateIpv6Port(bytes memory b, string calldata input) internal pure {
        if (b.length < 6) {
            revert NotIpPort(input, "Address too short");
        }

        uint256 closeBracket = 0;
        for (uint256 i = 1; i < b.length; i++) {
            if (b[i] == "]") {
                closeBracket = i;
                break;
            }
        }

        if (closeBracket == 0) {
            revert NotIpPort(input, "Missing closing bracket");
        }

        _validateIpv6Address(b, 1, closeBracket, input);

        if (closeBracket + 1 >= b.length || b[closeBracket + 1] != ":") {
            revert NotIpPort(input, "Missing port separator after bracket");
        }

        _validatePort(b, closeBracket + 2, input);
    }

    function _validateIpv6Address(
        bytes memory b,
        uint256 start,
        uint256 end,
        string calldata input
    )
        internal
        pure
    {
        if (start >= end) {
            revert NotIpPort(input, "Empty IPv6 address");
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
                    revert NotIpPort(input, "Invalid hex character");
                }
                digitCount++;
                i++;
            }

            if (digitCount == 0) {
                if (doubleColonPos == type(uint256).max) {
                    revert NotIpPort(input, "Empty group without ::");
                }
            } else {
                if (digitCount > 4) {
                    revert NotIpPort(input, "Group exceeds 4 hex digits");
                }
                groupCount++;
            }

            if (i < end) {
                if (b[i] == ":") {
                    if (i + 1 < end && b[i + 1] == ":") {
                        if (doubleColonPos != type(uint256).max) {
                            revert NotIpPort(input, "Multiple :: not allowed");
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
                revert NotIpPort(input, "Must have 8 groups without ::");
            }
        } else {
            if (groupCount >= 8) {
                revert NotIpPort(input, "Too many groups with ::");
            }
        }
    }

    function _validatePort(bytes memory b, uint256 start, string calldata input) internal pure {
        if (start >= b.length) {
            revert NotIpPort(input, "Missing port number");
        }

        uint256 port = 0;
        uint256 digitCount = 0;

        for (uint256 i = start; i < b.length; i++) {
            bytes1 c = b[i];
            if (c < "0" || c > "9") {
                revert NotIpPort(input, "Invalid port character");
            }
            port = port * 10 + uint8(c) - 48;
            digitCount++;
        }

        if (digitCount == 0) {
            revert NotIpPort(input, "Empty port number");
        }
        if (digitCount > 5) {
            revert NotIpPort(input, "Port too long");
        }
        if (port > 65_535) {
            revert NotIpPort(input, "Port out of range");
        }
        if (digitCount > 1 && b[start] == "0") {
            revert NotIpPort(input, "Leading zeros in port");
        }
    }

}
