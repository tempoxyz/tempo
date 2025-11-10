// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test contract for TipFeeManager storage layout.
/// Fee collection and management system with AMM pools.
contract FeeManager {
    // ========== Structs ==========

    struct Pool {
        uint128 reserveUserToken;
        uint128 reserveValidatorToken;
    }

    // ========== Storage ==========

    /// Mapping of validator address to their preferred fee token
    mapping(address => address) public validator_tokens;

    /// Mapping of user address to their preferred fee token
    mapping(address => address) public user_tokens;

    /// Total collected fees
    uint256 public collected_fees;

    /// Dynamic array of tokens with pending fees
    address[] public tokens_with_fees;

    /// Tracking boolean for whether a token is in tokens_with_fees array
    mapping(address => bool) public token_in_fees_array;

    /// Mapping of pool key to pool data (AMM reserves)
    mapping(bytes32 => Pool) public pools;

    /// Mapping of pool key to pending swap amounts
    mapping(bytes32 => uint128) public pending_fee_swap_in;

    /// Mapping of pool key to total LP token supply
    mapping(bytes32 => uint256) public total_supply;

    /// Nested mapping for LP token balances: pool_key -> user -> balance
    mapping(bytes32 => mapping(address => uint256)) public liquidity_balances;
}
