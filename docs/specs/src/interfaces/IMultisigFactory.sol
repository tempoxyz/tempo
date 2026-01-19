// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title The interface for Multisig Factory
/// @notice Factory contract for creating multisig wallets at deterministic addresses
interface IMultisigFactory {
    /// @notice Emitted when a new multisig wallet is created
    /// @param multisig The address of the created multisig
    /// @param owners Array of owner addresses (sorted ascending)
    /// @param threshold Number of required confirmations
    /// @param creator The address that called createMultisig
    event MultisigCreated(address indexed multisig, address[] owners, uint8 threshold, address indexed creator);

    /// @notice A multisig already exists at this address
    error MultisigAlreadyExists(address multisig);

    /// @notice Invalid threshold (zero, or greater than owner count)
    error InvalidThreshold(uint8 threshold, uint8 ownerCount);

    /// @notice Owner list is empty
    error NoOwners();

    /// @notice Too many owners (exceeds MAX_OWNERS)
    error TooManyOwners(uint8 count, uint8 max);

    /// @notice Duplicate owner in the list
    error DuplicateOwner(address owner);

    /// @notice Zero address in owner list
    error ZeroAddressOwner();

    /// @notice Creates a new multisig wallet
    /// @param owners Array of owner addresses (will be sorted internally, max 50)
    /// @param threshold Number of required confirmations (1 <= threshold <= owners.length)
    /// @return multisig The address of the created multisig
    function createMultisig(address[] calldata owners, uint8 threshold)
        external
        returns (address multisig);

    /// @notice Computes the deterministic address for a multisig configuration
    /// @param owners Array of owner addresses
    /// @param threshold Number of required confirmations
    /// @return The address where the multisig would be deployed
    function getMultisigAddress(address[] calldata owners, uint8 threshold)
        external
        view
        returns (address);

    /// @notice Checks if an address is a deployed multisig
    /// @param addr The address to check
    /// @return True if the address is a valid, deployed multisig
    function isMultisig(address addr) external view returns (bool);
}
