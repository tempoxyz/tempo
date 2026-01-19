// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { SimpleMultisig } from "./SimpleMultisig.sol";
import { IMultisigFactory } from "./interfaces/IMultisigFactory.sol";

/// @title Multisig Factory Implementation
/// @notice Factory for creating multisig wallets at deterministic addresses
contract MultisigFactory is IMultisigFactory {
    /// @dev Maximum number of owners per multisig
    uint8 internal constant MAX_OWNERS = 50;

    /// @dev Magic bytes to identify multisig contracts: "MSIG" = 0x4d534947
    bytes4 internal constant MULTISIG_MAGIC = 0x4d534947;

    // ============ External Functions ============

    function createMultisig(address[] calldata owners, uint8 threshold)
        external
        override
        returns (address multisig)
    {
        // Validate inputs
        if (owners.length == 0) revert NoOwners();
        if (owners.length > MAX_OWNERS) revert TooManyOwners(uint8(owners.length), MAX_OWNERS);
        if (threshold == 0 || threshold > owners.length) {
            revert InvalidThreshold(threshold, uint8(owners.length));
        }

        // Validate and sort owners
        address[] memory sorted = _sortOwners(owners);
        for (uint256 i = 0; i < sorted.length; i++) {
            if (sorted[i] == address(0)) revert ZeroAddressOwner();
            if (i > 0 && sorted[i] == sorted[i - 1]) revert DuplicateOwner(sorted[i]);
        }

        // Check if already exists using standard CREATE2 address
        bytes32 salt = keccak256(abi.encode(sorted, threshold));
        multisig = _computeCreate2Address(salt, sorted, threshold);

        if (multisig.code.length != 0) revert MultisigAlreadyExists(multisig);

        // Deploy using CREATE2 for deterministic address
        SimpleMultisig deployed = new SimpleMultisig{salt: salt}(sorted, threshold);
        multisig = address(deployed);

        emit MultisigCreated(multisig, sorted, threshold, msg.sender);
    }

    function getMultisigAddress(address[] calldata owners, uint8 threshold)
        external
        view
        override
        returns (address)
    {
        address[] memory sorted = _sortOwners(owners);
        bytes32 salt = keccak256(abi.encode(sorted, threshold));
        return _computeCreate2Address(salt, sorted, threshold);
    }

    function isMultisig(address addr) external view override returns (bool) {
        if (addr.code.length == 0) return false;

        // Check for MULTISIG_MAGIC constant in bytecode
        // The constant is stored at a known position in the runtime bytecode
        // We check if the contract has the magic selector available
        try SimpleMultisig(addr).MULTISIG_MAGIC() returns (bytes4 magic) {
            return magic == MULTISIG_MAGIC;
        } catch {
            return false;
        }
    }

    // ============ Internal Functions ============

    /// @dev Computes CREATE2 address using standard formula
    function _computeCreate2Address(bytes32 salt, address[] memory owners, uint8 threshold)
        internal
        view
        returns (address)
    {
        bytes memory bytecode = abi.encodePacked(
            type(SimpleMultisig).creationCode,
            abi.encode(owners, threshold)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode))
        );
        return address(uint160(uint256(hash)));
    }

    /// @dev Sorts owners in ascending order (copy to memory)
    function _sortOwners(address[] calldata owners) internal pure returns (address[] memory) {
        address[] memory sorted = new address[](owners.length);
        for (uint256 i = 0; i < owners.length; i++) {
            sorted[i] = owners[i];
        }

        // Bubble sort (fine for small arrays, max 50)
        uint256 n = sorted.length;
        if (n <= 1) return sorted;

        for (uint256 i = 0; i < n - 1; i++) {
            for (uint256 j = 0; j < n - i - 1; j++) {
                if (uint160(sorted[j]) > uint160(sorted[j + 1])) {
                    (sorted[j], sorted[j + 1]) = (sorted[j + 1], sorted[j]);
                }
            }
        }

        return sorted;
    }
}
