// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

/// Test contract with struct storage.
contract Structs {
    struct TestBlock {
        uint256 field1;
        uint256 field2;
        uint64 field3;
    }

    uint256 public fieldA; // slot 0
    TestBlock public blockData; // slots 1-3
    uint256 public fieldB; // slot 4
}
