// SPDX-License-Identifier: MIT OR Apache-2.0
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
    mapping(address => address) public validatorTokens;

    /// Mapping of user address to their preferred fee token
    mapping(address => address) public userTokens;

    /// Collected fees per validator
    mapping(address => uint256) public collectedFees;

    /// Mapping of pool key to pool data (AMM reserves)
    mapping(bytes32 => Pool) public pools;

    /// Mapping of pool key to total LP token supply
    mapping(bytes32 => uint256) public totalSupply;

    /// Nested mapping for LP token balances: pool_key -> user -> balance
    mapping(bytes32 => mapping(address => uint256)) public liquidityBalances;
}
