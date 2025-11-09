// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test contract with enum storage.
contract Enums {
    enum PolicyType {
        WHITELISTED,
        BLACKLISTED
    }

    uint16 public field_a; // slot 0
    Auth public field_b; // slots 0
    address public field_c; // slot 0
}
