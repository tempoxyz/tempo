// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

/// Test contract with enum storage.
contract Enums {
    enum PolicyType {
        WHITELISTED,
        BLACKLISTED
    }

    uint16 public fieldA; // slot 0
    PolicyType public fieldB; // slots 0
    address public fieldC; // slot 0
}
