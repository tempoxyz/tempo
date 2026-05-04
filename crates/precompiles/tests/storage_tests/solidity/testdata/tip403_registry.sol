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

    struct PolicyRecord {
        PolicyData base;
        CompoundPolicyData compound;
    }

    struct TokenFilterData {
        uint8 filterType;
        address admin;
    }

    // ========== Storage ==========

    /// Counter for policy IDs
    uint64 public policyIdCounter;

    /// Mapping of policy ID to policy record (internal, not exposed in ABI)
    mapping(uint64 => PolicyRecord) internal policyRecords;

    /// Nested mapping for policy sets: policy_id -> address -> is_in_set
    /// Used for whitelist/blacklist entries
    mapping(uint64 => mapping(address => bool)) public policySet;

    /// Counter for token filter IDs
    uint64 public tokenFilterIdCounter;

    /// Mapping of token filter ID to filter metadata
    mapping(uint64 => TokenFilterData) internal tokenFilterData;

    /// Nested mapping for token filter members: filter_id -> token -> is_in_set
    mapping(uint64 => mapping(address => bool)) public tokenFilterMembers;

    /// Packed receive policy configuration per account
    mapping(address => uint256) public addressReceiveConfig;

    /// Recovery contract configured per account
    mapping(address => address) public addressRecoveryContract;
}
