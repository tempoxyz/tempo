// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

/// Test contract for TIP403Registry storage layout.
/// Policy registry for authorization and transfer policies.
contract TIP403Registry {
    // ========== Structs ==========

    struct PolicyData {
        uint8 policyType;
        address admin;
    }

    struct CompoundPolicyData {
        uint64 senderPolicyId;
        uint64 recipientPolicyId;
        uint64 mintRecipientPolicyId;
    }

    // ========== Storage ==========

    /// Counter for policy IDs
    uint64 public policyIdCounter;

    /// Mapping of policy ID to policy data
    mapping(uint64 => PolicyData) internal policyData;

    /// Nested mapping for policy sets: policy_id -> address -> is_in_set
    /// Used for whitelist/blacklist entries
    mapping(uint64 => mapping(address => bool)) public policySet;

    /// Compound policy data (TIP-1015). Only relevant when policyType == COMPOUND.
    /// Stored in a separate mapping to preserve storage slot compatibility for policyData.
    mapping(uint64 => CompoundPolicyData) internal compoundPolicyData;
}
