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

    struct ReceivePolicyConfig {
        bool hasReceivePolicy;
        uint64 senderPolicyId;
        uint8 senderPolicyType;
        uint64 tokenFilterId;
        uint8 tokenFilterType;
        uint8 recoveryMode;
    }

    struct ReceivePolicy {
        ReceivePolicyConfig config;
        address recoveryAddress;
    }

    struct TokenTransferPolicy {
        uint64 policyId;
        bool isSet;
    }

    /// TIP-1145 token-specific issuer policy
    struct TokenPolicy {
        bool isSet;
        uint8 sender;
        uint8 recipient;
        uint8 mintRecipient;
    }

    // ========== Storage ==========

    /// Counter for policy IDs
    uint64 public policyIdCounter;

    /// Mapping of policy ID to policy record (internal, not exposed in ABI)
    mapping(uint64 => PolicyRecord) internal policyRecords;

    /// Nested mapping for policy sets: policy_id -> address -> is_in_set
    /// Used for whitelist/blacklist entries
    mapping(uint64 => mapping(address => bool)) public policySet;

    /// Account receive policy configuration
    mapping(address => ReceivePolicy) internal receivePolicies;

    /// TIP-1092 token-to-policy bindings
    mapping(address => TokenTransferPolicy) internal tokenTransferPolicies;

    /// TIP-1145 token-specific issuer policies
    mapping(address => TokenPolicy) internal tokenPolicies;

    /// TIP-1145 packed issuer and receive-token memberships
    mapping(address => mapping(address => uint8)) internal tokenUserFlags;

    /// TIP-1145 receive-sender memberships
    mapping(address => mapping(address => bool)) internal receiveSenderMembers;
}
