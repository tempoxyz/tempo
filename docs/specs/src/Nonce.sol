// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { INonce } from "./interfaces/INonce.sol";

/// @title Nonce - 2D Nonce Manager Precompile
/// @notice Manages user nonce keys (1-N) as per the Account Abstraction spec
/// @dev Protocol nonce (key 0) is stored directly in account state, not here.
///      Only user nonce keys (1-N) are managed by this precompile.
///
/// Storage Layout:
/// ```solidity
/// contract Nonce {
///     mapping(address => mapping(uint256 => uint64)) public nonces;      // slot 0
///     mapping(address => uint256) public activeKeyCount;                 // slot 1
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
/// - Slot 1: Active key count - keccak256(abi.encode(account, 1))
contract Nonce is INonce {

    // ============ Storage Mappings ============

    /// @dev Mapping from account -> nonce key -> nonce value
    mapping(address => mapping(uint256 => uint64)) private nonces;

    /// @dev Mapping from account -> count of active nonce keys
    mapping(address => uint256) private activeKeyCount;

    // ============ View Functions ============

    /// @inheritdoc INonce
    function getNonce(address account, uint256 nonceKey) external view returns (uint64 nonce) {
        // Protocol nonce (key 0) is stored in account state, not in this precompile
        // Users should query account nonce directly, not through this precompile
        if (nonceKey == 0) {
            revert ProtocolNonceNotSupported();
        }

        return nonces[account][nonceKey];
    }

    /// @inheritdoc INonce
    function getActiveNonceKeyCount(address account) external view returns (uint256 count) {
        return activeKeyCount[account];
    }

    // ============ Internal Functions ============

    /// @notice Internal function to increment nonce for a specific account and nonce key
    /// @dev This function would be called by the protocol during transaction execution
    /// @param account The account whose nonce to increment
    /// @param nonceKey The nonce key to increment (must be > 0)
    /// @return newNonce The new nonce value after incrementing
    function _incrementNonce(address account, uint256 nonceKey) internal returns (uint64 newNonce) {
        if (nonceKey == 0) {
            revert InvalidNonceKey();
        }

        uint64 currentNonce = nonces[account][nonceKey];

        // If transitioning from 0 to 1, increment active key count
        if (currentNonce == 0) {
            activeKeyCount[account]++;
            emit ActiveKeyCountChanged(account, activeKeyCount[account]);
        }

        // Check for overflow
        if (currentNonce == type(uint64).max) {
            revert NonceOverflow();
        }

        newNonce = currentNonce + 1;
        nonces[account][nonceKey] = newNonce;

        emit NonceIncremented(account, nonceKey, newNonce);
    }

}
