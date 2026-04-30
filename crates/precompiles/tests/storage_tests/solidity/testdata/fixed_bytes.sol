// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

contract FixedBytesLayout {
    uint256 fieldA; // slot 0
    bytes4 bytes4Field; // slot 1 (first 4 bytes)
    bytes16 bytes16Field; // slot 1 (next 16 bytes)
    bytes10 bytes10Field; // slot 1 (last 10 bytes, 2 leftover bytes)
    uint256 fieldB; // slot 2
}
