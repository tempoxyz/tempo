// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title TIP1016Storage - Contract for testing TIP-1016 gas semantics
contract TIP1016Storage {

    mapping(bytes32 => uint256) private _storage;

    function storeValue(bytes32 slot, uint256 value) external {
        _storage[slot] = value;
    }

    function storeMultiple(bytes32[] calldata slots) external {
        for (uint256 i = 0; i < slots.length; i++) {
            _storage[slots[i]] = 1;
        }
    }

    function storeAndClear(bytes32 slot, uint256 value) external {
        _storage[slot] = value;
        _storage[slot] = 0;
    }

    function getValue(bytes32 slot) external view returns (uint256) {
        return _storage[slot];
    }

}

/// @title GasLeftChecker - Contract that records gasleft() for RES1 testing
contract GasLeftChecker {

    uint256 public lastGasLeft;

    function checkGasLeft() external {
        lastGasLeft = gasleft();
    }

}
