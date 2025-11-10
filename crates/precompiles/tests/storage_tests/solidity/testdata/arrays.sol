// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test contract with fixed-size array storage.
contract Arrays {
    uint256 public fieldA; // slot 0
    uint256[5] public largeArray; // slots 1-5
    uint256 public fieldB; // slot 6
}
