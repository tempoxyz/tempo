// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IValidatorConfig } from "./interfaces/IValidatorConfig.sol";

/// @title ValidatorConfig - Validator Config Precompile
/// @notice Manages the set of validators that participate in consensus
/// @dev Validators can update their own information, rotate their identity to a new address,
///      and the owner can manage validator status.
contract ValidatorConfig is IValidatorConfig {

    /// @notice The owner of the precompile
    address public owner;

    /// @notice The count of validators
    uint64 public validatorCount;

    /// @notice Array of validator addresses
    address[] public validatorsArray;

    /// @notice Mapping from validator address to validator info
    mapping(address => Validator) public validators;

    /// @notice Mapping from pending validator address to pending info
    mapping(address => PendingValidator) public pendingValidators;

    /// @notice Check if caller is the owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert Unauthorized();
        }
        _;
    }

    /// @notice Constructor to set the owner
    /// @param _owner The initial owner address
    constructor(address _owner) {
        owner = _owner;
    }

    /// @inheritdoc IValidatorConfig
    function getPendingValidator(address pendingAddress)
        external
        view
        returns (PendingValidator memory)
    {
        PendingValidator memory pending = pendingValidators[pendingAddress];
        if (pending.publicKey == bytes32(0)) {
            revert PendingValidatorNotFound();
        }
        return pending;
    }

    /// @inheritdoc IValidatorConfig
    function getValidators() external view returns (Validator[] memory) {
        Validator[] memory result = new Validator[](validatorCount);

        for (uint64 i = 0; i < validatorCount; i++) {
            address validatorAddress = validatorsArray[i];
            result[i] = validators[validatorAddress];
        }

        return result;
    }

    /// @inheritdoc IValidatorConfig
    function addValidator(
        address newValidatorAddress,
        bytes32 publicKey,
        bool active,
        string calldata inboundAddress,
        string calldata outboundAddress
    ) external onlyOwner {
        // Reject zero public key - zero is used as sentinel value for non-existence
        if (publicKey == bytes32(0)) {
            revert InvalidPublicKey();
        }

        // Check if validator already exists (public key must be non-zero for existing validators)
        if (validators[newValidatorAddress].publicKey != bytes32(0)) {
            revert ValidatorAlreadyExists();
        }

        // Check if pending entry already exists for this address
        if (pendingValidators[newValidatorAddress].publicKey != bytes32(0)) {
            revert PendingValidatorAlreadyExists();
        }

        // Validate addresses (basic validation - actual validation happens in precompile)
        _validateHostPort(inboundAddress, "inboundAddress");
        _validateIpPort(outboundAddress, "outboundAddress");

        // Create pending entry - requires acceptance by the new validator address
        pendingValidators[newValidatorAddress] = PendingValidator({
            publicKey: publicKey,
            active: active,
            fromValidator: address(0),
            inboundAddress: inboundAddress,
            outboundAddress: outboundAddress
        });
    }

    /// @inheritdoc IValidatorConfig
    function updateValidator(
        address newValidatorAddress,
        bytes32 publicKey,
        string calldata inboundAddress,
        string calldata outboundAddress
    ) external {
        // Reject zero public key - zero is used as sentinel value for non-existence
        if (publicKey == bytes32(0)) {
            revert InvalidPublicKey();
        }

        // Check if caller is a validator
        if (validators[msg.sender].publicKey == bytes32(0)) {
            revert ValidatorNotFound();
        }

        // Validate addresses
        _validateHostPort(inboundAddress, "inboundAddress");
        _validateIpPort(outboundAddress, "outboundAddress");

        // Check if rotating to a new address
        if (newValidatorAddress != msg.sender) {
            // Check if new address already exists as validator
            if (validators[newValidatorAddress].publicKey != bytes32(0)) {
                revert ValidatorAlreadyExists();
            }

            // Check if pending entry already exists for this address
            if (pendingValidators[newValidatorAddress].publicKey != bytes32(0)) {
                revert PendingValidatorAlreadyExists();
            }

            // Create pending entry for rotation - requires acceptance by the new validator address
            pendingValidators[newValidatorAddress] = PendingValidator({
                publicKey: publicKey,
                active: validators[msg.sender].active,
                fromValidator: msg.sender,
                inboundAddress: inboundAddress,
                outboundAddress: outboundAddress
            });
        } else {
            // In-place update (no rotation) - apply immediately
            validators[msg.sender].publicKey = publicKey;
            validators[msg.sender].inboundAddress = inboundAddress;
            validators[msg.sender].outboundAddress = outboundAddress;
        }
    }

    /// @inheritdoc IValidatorConfig
    function acceptValidator() external {
        // Check if there's a pending entry for caller
        PendingValidator memory pending = pendingValidators[msg.sender];
        if (pending.publicKey == bytes32(0)) {
            revert PendingValidatorNotFound();
        }

        // Check if this is a rotation (fromValidator != address(0)) or new addition
        if (pending.fromValidator != address(0)) {
            // Rotation: update the old validator's slot in the array
            Validator memory oldValidator = validators[pending.fromValidator];

            // Update the validators array
            validatorsArray[oldValidator.index] = msg.sender;

            // Store the new validator with the old index
            validators[msg.sender] = Validator({
                publicKey: pending.publicKey,
                active: pending.active,
                index: oldValidator.index,
                validatorAddress: msg.sender,
                inboundAddress: pending.inboundAddress,
                outboundAddress: pending.outboundAddress
            });

            // Clear the old validator
            delete validators[pending.fromValidator];
        } else {
            // New addition
            validators[msg.sender] = Validator({
                publicKey: pending.publicKey,
                active: pending.active,
                index: validatorCount,
                validatorAddress: msg.sender,
                inboundAddress: pending.inboundAddress,
                outboundAddress: pending.outboundAddress
            });

            // Add to array
            validatorsArray.push(msg.sender);

            // Increment count
            validatorCount++;
        }

        // Clear the pending entry
        delete pendingValidators[msg.sender];
    }

    /// @inheritdoc IValidatorConfig
    function cancelPendingValidator(address pendingAddress) external onlyOwner {
        // Check if there's a pending entry
        if (pendingValidators[pendingAddress].publicKey == bytes32(0)) {
            revert PendingValidatorNotFound();
        }

        // Clear the pending entry
        delete pendingValidators[pendingAddress];
    }

    /// @inheritdoc IValidatorConfig
    function changeValidatorStatus(address validator, bool active) external onlyOwner {
        // Check if validator exists
        if (validators[validator].publicKey == bytes32(0)) {
            revert ValidatorNotFound();
        }

        validators[validator].active = active;
    }

    /// @inheritdoc IValidatorConfig
    function changeOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    /// @notice Internal function to validate host:port format (for inboundAddress)
    function _validateHostPort(string calldata input, string memory field) internal pure {
        bytes memory inputBytes = bytes(input);

        // Must have at least "a:0" format (minimum 3 characters)
        if (inputBytes.length < 3) {
            revert NotHostPort(field, input, "Address too short");
        }

        // Must contain a colon for the port separator
        for (uint256 i = 0; i < inputBytes.length; i++) {
            if (inputBytes[i] == ":") {
                return;
            }
        }

        revert NotHostPort(field, input, "Missing port separator");
    }

    /// @notice Internal function to validate IP:port format (IPv4 or IPv6)
    function _validateIpPort(string calldata input, string memory field) internal pure {
        bytes memory b = bytes(input);

        if (b.length == 0) {
            revert NotIpPort(field, input, "Empty address");
        }

        // Check if IPv6 (starts with '[') or IPv4
        if (b[0] == "[") {
            _validateIpv6Port(b, field, input);
        } else {
            _validateIpv4Port(b, field, input);
        }
    }

    /// @notice Validate IPv4:port format (e.g., 192.168.1.1:8080)
    function _validateIpv4Port(bytes memory b, string memory field, string calldata input)
        internal
        pure
    {
        // Minimum: "0.0.0.0:0" = 9 chars
        if (b.length < 9) {
            revert NotIpPort(field, input, "Address too short");
        }

        uint256 i = 0;

        // Parse 4 octets separated by dots
        for (uint256 octet = 0; octet < 4; octet++) {
            uint256 value = 0;
            uint256 digitCount = 0;

            // Read digits until dot or colon
            while (i < b.length && b[i] != "." && b[i] != ":") {
                bytes1 c = b[i];
                if (c < "0" || c > "9") {
                    revert NotIpPort(field, input, "Invalid character in octet");
                }
                value = value * 10 + uint8(c) - 48;
                digitCount++;
                i++;
            }

            // Validate octet
            if (digitCount == 0 || digitCount > 3) {
                revert NotIpPort(field, input, "Invalid octet length");
            }
            if (value > 255) {
                revert NotIpPort(field, input, "Octet out of range");
            }
            // Disallow leading zeros (except "0" itself)
            if (digitCount > 1 && b[i - digitCount] == "0") {
                revert NotIpPort(field, input, "Leading zeros not allowed");
            }

            // First 3 octets must end in a dot
            if (octet < 3) {
                if (i >= b.length || b[i] != ".") {
                    revert NotIpPort(field, input, "Expected dot separator");
                }
                i++;
            }
        }

        // 4th octet must end in a colon and port
        if (i >= b.length || b[i] != ":") {
            revert NotIpPort(field, input, "Missing port separator");
        }
        i++;

        // Validate port
        _validatePort(b, i, field, input);
    }

    /// @notice Validate [IPv6]:port format (e.g., [2001:db8::1]:8080)
    function _validateIpv6Port(bytes memory b, string memory field, string calldata input)
        internal
        pure
    {
        // Minimum: "[::]:0" = 6 chars
        if (b.length < 6) {
            revert NotIpPort(field, input, "Address too short");
        }

        // Opening bracket guaranteed from calling function. Find closing bracket
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

        // Validate IPv6 address between brackets
        _validateIpv6Address(b, 1, closeBracket, field, input);

        // Expect ']:' followed by port
        if (closeBracket + 1 >= b.length || b[closeBracket + 1] != ":") {
            revert NotIpPort(field, input, "Missing port separator after bracket");
        }

        // Validate port
        _validatePort(b, closeBracket + 2, field, input);
    }

    /// @notice Validate IPv6 address (without brackets)
    /// @dev Handles full form and :: compression
    function _validateIpv6Address(
        bytes memory b,
        uint256 start,
        uint256 end,
        string memory field,
        string calldata input
    ) internal pure {
        if (start >= end) {
            revert NotIpPort(field, input, "Empty IPv6 address");
        }

        uint256 groupCount = 0;
        uint256 doubleColonPos = type(uint256).max; // Position of ::
        uint256 i = start;

        // Handle leading ::
        if (i + 1 < end && b[i] == ":" && b[i + 1] == ":") {
            doubleColonPos = 0;
            i += 2;
            if (i == end) {
                // Just "::" is valid (represents all zeros)
                return;
            }
        }

        while (i < end) {
            // Parse hex group
            uint256 digitCount = 0;

            while (i < end && b[i] != ":") {
                bytes1 c = b[i];

                // Validate hex character
                bool isHex =
                    (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
                if (!isHex) {
                    revert NotIpPort(field, input, "Invalid hex character");
                }

                digitCount++;
                i++;
            }

            // Validate group (0-4 hex digits)
            if (digitCount == 0) {
                // Empty group only valid at :: position
                if (doubleColonPos == type(uint256).max) {
                    revert NotIpPort(field, input, "Empty group without ::");
                }
            } else {
                if (digitCount > 4) {
                    revert NotIpPort(field, input, "Group exceeds 4 hex digits");
                }
                // Note: 4 hex digits max = 0xFFFF, so value is always in range
                groupCount++;
            }

            // Check for :: or single :
            if (i < end) {
                if (b[i] == ":") {
                    if (i + 1 < end && b[i + 1] == ":") {
                        // Double colon
                        if (doubleColonPos != type(uint256).max) {
                            revert NotIpPort(field, input, "Multiple :: not allowed");
                        }
                        doubleColonPos = groupCount;
                        i += 2;

                        // Handle trailing ::
                        if (i == end) {
                            break;
                        }
                    } else {
                        // Single colon - move past it
                        i++;
                    }
                }
            }
        }

        // Validate group count
        if (doubleColonPos == type(uint256).max) {
            // No ::, must have exactly 8 groups
            if (groupCount != 8) {
                revert NotIpPort(field, input, "Must have 8 groups without ::");
            }
        } else {
            // With ::, must have fewer than 8 groups (:: fills the rest)
            if (groupCount >= 8) {
                revert NotIpPort(field, input, "Too many groups with ::");
            }
        }
    }

    /// @notice Validate port number (0-65535)
    function _validatePort(
        bytes memory b,
        uint256 start,
        string memory field,
        string calldata input
    ) internal pure {
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
        // Disallow leading zeros (except "0" itself)
        if (digitCount > 1 && b[start] == "0") {
            revert NotIpPort(field, input, "Leading zeros in port");
        }
    }

}
