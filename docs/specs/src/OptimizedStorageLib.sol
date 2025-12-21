// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title OptimizedStorageLib
/// @notice Library for optimized storage slot usage that doesn't require maps
/// @dev Inner keys must at most be 31 bytes long. The storage slot used is uint8(slot) | bytes31(innerKey).
/// @dev Collision resistance between different OptimizedStorageLib maps are guaranteed as long as variables have different storage slots.
library OptimizedStorageLib {

    error SlotTooLarge(uint256 slot);

    /// @notice Equivalent to mapping(address => uint256)
    struct AddressUint256Map {
        bytes32 _placeholder;
    }

    /// Intended to be used as a compile safety check to ensure that the slot used fits within a single byte
    function check(AddressUint256Map storage map) internal pure {
        uint256 slot;
        assembly ("memory-safe") {
            slot := map.slot
        }
        if (slot >= uint256(type(uint8).max)) {
            revert SlotTooLarge(slot);
        }
    }

    /// @notice Gets a value from the map given the key
    function get(AddressUint256Map storage map, address key) internal view returns (uint256 val) {
        assembly ("memory-safe") {
            let slot := or(shl(248, map.slot), shl(88, key))
            val := sload(slot)
        }
    }

    function set(AddressUint256Map storage map, address key, uint256 val) internal {
        assembly ("memory-safe") {
            let slot := or(shl(248, map.slot), shl(88, key))
            sstore(slot, val)
        }
    }

    /// @notice Equivalent to mapping(address => address)
    struct AddressAddressMap {
        bytes32 _placeholder;
    }

    /// Intended to be used as a compile safety check to ensure that the slot used fits within a single byte
    function check(AddressAddressMap storage map) internal pure {
        uint256 slot;
        assembly ("memory-safe") {
            slot := map.slot
        }
        if (slot >= uint256(type(uint8).max)) {
            revert SlotTooLarge(slot);
        }
    }

    /// @notice Gets a value from the map given the key
    function get(AddressAddressMap storage map, address key) internal view returns (address val) {
        assembly ("memory-safe") {
            let slot := or(shl(248, map.slot), shl(88, key))
            val := sload(slot)
        }
    }

    function set(AddressAddressMap storage map, address key, address val) internal {
        assembly ("memory-safe") {
            let slot := or(shl(248, map.slot), shl(88, key))
            sstore(slot, val)
        }
    }

}
