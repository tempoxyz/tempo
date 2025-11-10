// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test contract for TIP403Registry storage layout.
/// Policy registry for authorization and transfer policies.
contract TIP403Registry {
    // ========== Structs ==========

    struct PolicyData {
        uint8 policy_type;
        address admin;
    }

    // ========== Storage ==========

    /// Counter for policy IDs
    uint64 public policy_id_counter;

    /// Mapping of policy ID to policy data
    mapping(uint64 => PolicyData) public policy_data;

    /// Nested mapping for policy sets: policy_id -> address -> is_in_set
    /// Used for whitelist/blacklist entries
    mapping(uint64 => mapping(address => bool)) public policy_set;
}
