pub use INonce::{INonceErrors as NonceError, INonceEvents as NonceEvent};

use alloy::sol;

sol! {
    /// Nonce interface for managing 2D nonces as per the Account Abstraction spec.
    ///
    /// This precompile manages user nonce keys (1-N) while protocol nonces (key 0)
    /// are handled directly by account state. Each account can have multiple
    /// independent nonce sequences identified by a nonce key.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    interface INonce {
        /// Get the current nonce for a specific account and nonce key
        /// @param account The account address
        /// @param nonceKey The nonce key (must be > 0, protocol nonce key 0 not supported)
        /// @return nonce The current nonce value
        function getNonce(address account, uint256 nonceKey) external view returns (uint64 nonce);

        /// Get the number of active nonce keys for an account
        /// @param account The account address
        /// @return count The number of nonce keys that have been used (nonce > 0)
        /// @dev Deprecated: This function is kept for backwards compatibility pre-AllegroModerato
        function getActiveNonceKeyCount(address account) external view returns (uint256 count);

        // Events
        event NonceIncremented(address indexed account, uint256 indexed nonceKey, uint64 newNonce);
        /// @dev Deprecated: This event is only emitted pre-AllegroModerato for backwards compatibility
        event ActiveKeyCountChanged(address indexed account, uint256 newCount);

        // Errors
        error ProtocolNonceNotSupported();
        error InvalidNonceKey();
        error NonceOverflow();
    }
}

impl NonceError {
    /// Creates an error for protocol nonce not supported
    pub const fn protocol_nonce_not_supported() -> Self {
        Self::ProtocolNonceNotSupported(INonce::ProtocolNonceNotSupported)
    }

    /// Creates an error for invalid nonce key
    pub const fn invalid_nonce_key() -> Self {
        Self::InvalidNonceKey(INonce::InvalidNonceKey)
    }

    /// Creates an error for when nonce overflows
    pub const fn nonce_overflow() -> Self {
        Self::NonceOverflow(INonce::NonceOverflow)
    }
}
