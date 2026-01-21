// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

/// Test contract with nested mapping storage.
contract DoubleMappings {
    uint256 public fieldA; // slot 0
    mapping(address => mapping(bytes32 => bool)) public accountRole; // slot 1
    mapping(address => mapping(address => uint256)) public allowances; // slot 2
}
