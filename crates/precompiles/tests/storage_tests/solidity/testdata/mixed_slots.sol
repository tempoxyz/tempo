// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

/// Test contract with mixed auto and explicit slot allocation.
/// This matches the test in crates/precompiles-macros/tests/layout.rs
contract MixedSlots {
    uint256 public fieldA; // Auto: slot 0
    uint256 public fieldC; // Auto: slot 1
}
