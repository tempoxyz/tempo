// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title IValidatorConfig - Validator Config Precompile Interface
/// @notice Interface for managing consensus validators
/// @dev This precompile manages the set of validators that participate in consensus.
///      Validators can update their own information, rotate their identity to a new address,
///      and the owner can manage validator status.
interface IValidatorConfig {

    /// @notice Thrown when caller lacks authorization to perform the requested action
    error Unauthorized();

    /// @notice Thrown when trying to add a validator that already exists
    error ValidatorAlreadyExists();

    /// @notice Thrown when validator is not found
    error ValidatorNotFound();

    /// @notice Thrown when inbound address is not in valid host:port format
    /// @param field The field name that failed validation
    /// @param input The invalid input that was provided
    /// @param backtrace Additional error context
    error NotHostPort(string field, string input, string backtrace);

    /// @notice Thrown when outbound address is not in valid ip:port format
    /// @param field The field name that failed validation
    /// @param input The invalid input that was provided
    /// @param backtrace Additional error context
    error NotIpPort(string field, string input, string backtrace);

    /// @notice Validator information
    /// @param publicKey The validator's communication public key
    /// @param active Whether the validator is active in consensus
    /// @param index The validator's index in the validators array
    /// @param validatorAddress The validator's address
    /// @param inboundAddress Address where other validators can connect to this validator (format: `<hostname|ip>:<port>`)
    /// @param outboundAddress IP address for firewall whitelisting by other validators (format: `<ip>:<port>`)
    struct Validator {
        bytes32 publicKey;
        bool active;
        uint64 index;
        address validatorAddress;
        string inboundAddress;
        string outboundAddress;
    }

    /// @notice Get the complete set of validators
    /// @return validators Array of all validators with their information
    function getValidators() external view returns (Validator[] memory validators);

    /// @notice Add a new validator (owner only)
    /// @param newValidatorAddress The address of the new validator
    /// @param publicKey The validator's communication public key
    /// @param active Whether the validator should be active
    /// @param inboundAddress The validator's inbound address `<hostname|ip>:<port>` for incoming connections
    /// @param outboundAddress The validator's outbound IP address `<ip>:<port>` for firewall whitelisting (IP only, no hostnames)
    function addValidator(
        address newValidatorAddress,
        bytes32 publicKey,
        bool active,
        string calldata inboundAddress,
        string calldata outboundAddress
    ) external;

    /// @notice Update validator information (only validator)
    /// @param newValidatorAddress The new address for this validator
    /// @param publicKey The validator's new communication public key
    /// @param inboundAddress The validator's inbound address `<hostname|ip>:<port>` for incoming connections
    /// @param outboundAddress The validator's outbound IP address `<ip>:<port>` for firewall whitelisting (IP only, no hostnames)
    function updateValidator(
        address newValidatorAddress,
        bytes32 publicKey,
        string calldata inboundAddress,
        string calldata outboundAddress
    ) external;

    /// @notice Change validator active status (owner only)
    /// @param validator The validator address
    /// @param active Whether the validator should be active
    function changeValidatorStatus(address validator, bool active) external;

    /// @notice Get the owner of the precompile
    /// @return The owner address
    function owner() external view returns (address);

    /// @notice Change owner
    /// @param newOwner The new owner address
    function changeOwner(address newOwner) external;

}
