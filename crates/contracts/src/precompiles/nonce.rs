pub use INonce::{INonceErrors as NonceError, INonceEvents as NonceEvent};

crate::sol! {
    /// Nonce interface for managing 2D nonces as per the Account Abstraction spec.
    ///
    /// This precompile manages user nonce keys (1-N) while protocol nonces (key 0)
    /// are handled directly by account state. Each account can have multiple
    /// independent nonce sequences identified by a nonce key.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface INonce {
        /// Get the current nonce for a specific account and nonce key
        /// @param account The account address
        /// @param nonceKey The nonce key (must be > 0, protocol nonce key 0 not supported)
        /// @return nonce The current nonce value
        function getNonce(address account, uint256 nonceKey) external view returns (uint64 nonce);

        // Events
        event NonceIncremented(address indexed account, uint256 indexed nonceKey, uint64 newNonce);

        // Errors
        error ProtocolNonceNotSupported();
        error InvalidNonceKey();
        error NonceOverflow();

        // Expiring nonce errors
        /// Returned when an expiring nonce tx hash has already been seen
        error ExpiringNonceReplay();
        /// Returned when the expiring nonce seen set is at capacity
        error ExpiringNonceSetFull();
        /// Returned when valid_before is not within the allowed window
        error InvalidExpiringNonceExpiry();
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

    /// Creates an error for expiring nonce replay
    pub const fn expiring_nonce_replay() -> Self {
        Self::ExpiringNonceReplay(INonce::ExpiringNonceReplay)
    }

    /// Creates an error for expiring nonce set being full
    pub const fn expiring_nonce_set_full() -> Self {
        Self::ExpiringNonceSetFull(INonce::ExpiringNonceSetFull)
    }

    /// Creates an error for invalid expiring nonce expiry
    pub const fn invalid_expiring_nonce_expiry() -> Self {
        Self::InvalidExpiringNonceExpiry(INonce::InvalidExpiringNonceExpiry)
    }
}
