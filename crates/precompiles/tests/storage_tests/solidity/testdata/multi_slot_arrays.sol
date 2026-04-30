// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

// Test contract with dynamic arrays containing multi-slot struct elements.
contract MultiSlotArrays {
    // 2-slot struct with inner packing
    struct PackedTwoSlot {
        uint256 value;
        uint64 timestamp;
        uint32 nonce;
        address owner;
    }

    // 3-slot struct with inner packing
    struct PackedThreeSlot {
        uint256 value;
        uint64 timestamp;
        uint64 startTime;
        uint64 endTime;
        uint64 nonce;
        address owner;
        bool active;
    }

    // Dynamic array of 2-slot structs
    PackedTwoSlot[] public dynTwoSlot;

    // Dynamic array of 3-slot structs
    PackedThreeSlot[] public dynThreeSlot;
}
