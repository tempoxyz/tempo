// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { INonce } from "./interfaces/INonce.sol";

/// @title Nonce - 2D Nonce Manager Precompile
/// @notice Manages user nonce keys (1-N) as per the Tempo Transaction spec
/// @dev Protocol nonce (key 0) is stored directly in account state, not here.
///      Only user nonce keys (1-N) are managed by this precompile.
///
/// Storage Layout:
/// ```solidity
/// contract Nonce {
///     mapping(address => mapping(uint256 => uint64)) public nonces;      // slot 0
/// }
/// ```
///
/// - Slot 0: 2D nonce mapping - keccak256(abi.encode(nonce_key, keccak256(abi.encode(account, 0))))
contract Nonce is INonce {

    // ============ Storage Mappings ============

    /// @dev Mapping from account -> nonce key -> nonce value
    mapping(address => mapping(uint256 => uint64)) private nonces;

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

        // Check for overflow
        if (currentNonce == type(uint64).max) {
            revert NonceOverflow();
        }

        newNonce = currentNonce + 1;
        nonces[account][nonceKey] = newNonce;

        emit NonceIncremented(account, nonceKey, newNonce);
    }

}
