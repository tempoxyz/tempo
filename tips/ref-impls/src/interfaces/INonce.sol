// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title INonce - Nonce Precompile Interface
/// @notice Interface for managing 2D nonces as per the Tempo Transaction spec
/// @dev This precompile manages user nonce keys (1-N) while protocol nonces (key 0)
///      are handled directly by account state. Each account can have multiple
///      independent nonce sequences identified by a nonce key.
interface INonce {

    /// @notice Emitted when a nonce is incremented for an account and nonce key
    /// @param account The account whose nonce was incremented
    /// @param nonceKey The nonce key that was incremented
    /// @param newNonce The new nonce value after incrementing
    event NonceIncremented(address indexed account, uint256 indexed nonceKey, uint64 newNonce);

    /// @notice Thrown when trying to access protocol nonce (key 0) through the precompile
    /// @dev Protocol nonce should be accessed through account state, not this precompile
    error ProtocolNonceNotSupported();

    /// @notice Thrown when an invalid nonce key is provided
    error InvalidNonceKey();

    /// @notice Thrown when a nonce value would overflow
    error NonceOverflow();

    /// @notice Get the current nonce for a specific account and nonce key
    /// @param account The account address
    /// @param nonceKey The nonce key (must be > 0, protocol nonce key 0 not supported)
    /// @return nonce The current nonce value
    function getNonce(address account, uint256 nonceKey) external view returns (uint64 nonce);

}
