// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test contract for TIP20 token storage layout.
/// Includes roles, metadata, ERC20, and rewards storage.
contract TIP20 {
    // ========== Structs ==========

    struct RewardStream {
        address funder;
        uint64 startTime;
        uint64 endTime;
        uint256 ratePerSecondScaled;
        uint256 amountTotal;
    }

    struct UserRewardInfo {
        address rewardRecipient;
        uint256 rewardPerToken;
        uint256 rewardBalance;
    }

    // ========== RolesAuth Storage ==========

    /// Nested mapping for role assignments: user -> role -> hasRole
    mapping(address => mapping(bytes32 => bool)) public roles;

    /// Mapping of role to its admin role
    mapping(bytes32 => bytes32) public roleAdmins;

    // ========== Metadata Storage ==========

    string public name;
    string public symbol;
    string public currency;
    bytes32 public domainSeparator;
    address public quoteToken;
    address public nextQuoteToken;
    uint64 public transferPolicyId;

    // ========== ERC20 Storage ==========

    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => uint256) public nonces;
    bool public paused;
    uint256 public supplyCap;
    mapping(bytes32 => bool) public salts;

    // ========== Rewards Storage ==========

    uint256 public globalRewardPerToken;
    uint128 public optedInSupply;

    /// Mapping of user address to their reward info
    mapping(address => UserRewardInfo) public userRewardInfo;
}
