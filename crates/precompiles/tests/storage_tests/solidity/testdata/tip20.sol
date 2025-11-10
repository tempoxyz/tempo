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
    mapping(bytes32 => bytes32) public role_admins;

    // ========== Metadata Storage ==========

    string public name;
    string public symbol;
    string public currency;
    bytes32 public domain_separator;
    address public quote_token;
    address public next_quote_token;
    uint64 public transfer_policy_id;

    // ========== ERC20 Storage ==========

    uint256 public total_supply;
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => uint256) public nonces;
    bool public paused;
    uint256 public supply_cap;
    mapping(bytes32 => bool) public salts;

    // ========== Rewards Storage ==========

    uint256 public global_reward_per_token;
    uint64 public last_update_time;
    uint256 public total_reward_per_second;
    uint128 public opted_in_supply;
    uint64 public next_stream_id;

    /// Mapping of stream ID to reward stream data
    mapping(uint64 => RewardStream) public streams;

    /// Mapping of timestamp to scheduled rate decrease
    mapping(uint128 => uint256) public scheduled_rate_decrease;

    /// Mapping of user address to their reward info
    mapping(address => UserRewardInfo) public user_reward_info;
}
