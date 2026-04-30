// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

/// Test contract with mapping storage.
contract Mappings {
    uint256 public fieldA; // slot 0
    mapping(address => uint256) public addressMapping; // slot 1
    mapping(uint64 => uint256) public uintMapping; // slot 2
}
