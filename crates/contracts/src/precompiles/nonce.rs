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
        function getActiveNonceKeyCount(address account) external view returns (uint256 count);

        // Events
        event NonceIncremented(address indexed account, uint256 indexed nonceKey, uint64 newNonce);
        event ActiveKeyCountChanged(address indexed account, uint256 newCount);

        // Precompile Errors
        error ProtocolNonceNotSupported();
        error InvalidNonceKey();
        error NonceOverflow();

        // Errors that can occur while the revm handler validates nonces
        error NonceTooHigh(uint64 tx, uint64 state);
        error NonceTooLow(uint64 tx, uint64 state);
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

    /// Creates an error when the given nonce is greater than the one stored in the NonceManger
    pub const fn nonce_too_high(tx: u64, state: u64) -> Self {
        Self::NonceTooHigh(INonce::NonceTooHigh { tx, state })
    }

    /// Creates an error when the given nonce is smaller than the one stored in the NonceManger
    pub const fn nonce_too_low(tx: u64, state: u64) -> Self {
        Self::NonceTooLow(INonce::NonceTooLow { tx, state })
    }
}
