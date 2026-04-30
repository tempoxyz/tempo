// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

/// Test contract with fixed-size array storage.
contract Arrays {
    uint256 public fieldA; // slot 0
    uint256[5] public largeArray; // slots 1-5
    uint256 public fieldB; // slot 6
    uint8[4][8] public nestedArray; // slot 7-14 (8 slots)
    uint16[2][6] public anotherNestedArray; // slots 15-20 (6 slots)
}
